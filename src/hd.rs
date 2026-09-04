// SPDX-License-Identifier: ISC
//! BIP32 HD key derivation with Decred serialization.
//!
//! Standard wallet path: `m / 44' / coin' / account' / branch / index`
//!   * coin type from SLIP-0044 via [`Network::slip44`] (42 on mainnet)
//!   * branch 0 = external (receive), 1 = internal (change)
//!
//! The master key derivation is identical to Bitcoin (HMAC key
//! `"Bitcoin seed"`), and Decred's `dprv`/`dpub` version bytes and
//! double-BLAKE256 base58 checksum are the visible differences. Confirmed by the
//! dcrd `hdkeychain/extendedkey_test.go` vectors in `tests/vectors.rs`: BIP32
//! test-vector-1 re-encodes to `dprv3hCznBesA6jBt…` / `dpubZ9169KDAEUny…`.
//!
//! # Hardened derivation is NOT plain BIP32
//!
//! Decred also differs in the hardened child function, and the difference is
//! load-bearing. dcrd's `hdkeychain` strips leading zero bytes from a child
//! private key and carries the shortened string into the next hardened HMAC:
//!
//! > Note that per \[BIP32\] this should be the fully zero-padded 32-bytes,
//! > however, the Decred variation strips leading zeros for legacy reasons and
//! > changing it now would break derivation for a lot of Decred wallets that rely
//! > on this behavior.
//!
//! So for a parent private key with a leading zero byte the hardened HMAC input
//! is `0x00 ‖ key31 ‖ 0x00 ‖ ser32(i)` rather than BIP32's
//! `0x00 ‖ 0x00 ‖ key31 ‖ ser32(i)`, and every descendant diverges. Measured
//! against the local dcrd `hdkeychain` over 200 000 seeds, the account key at
//! `m/44'/42'/0'` differs between the two variants for 1 seed in 130 — which is
//! the `1 - (255/256)²` the path implies, since exactly two of its three
//! hardened parents can be stripped (see below).
//!
//! ## Which keys are stripped
//!
//! Stripping is a property of the STORED key, not of the derivation being
//! performed. In dcrd it is literally `[]byte` length: only `child()` strips,
//! and only the key it has just produced, so
//!
//! * the master is never stripped — `NewMaster` stores the full 32 HMAC bytes;
//! * a key from `NewKeyFromString` is never stripped — a serialized extended
//!   key is zero-padded to 32 bytes, so a round trip restores the padded form
//!   and CHANGES that key's hardened children;
//! * `strictBIP32` decides whether the CHILD is stored stripped; the preimage
//!   layout comes from how the PARENT already was. A strict child of a stripped
//!   parent therefore still sees the short form.
//!
//! A [`secp256k1::SecretKey`] is always 32 zero-padded bytes, so this crate has
//! to carry that provenance explicitly rather than recover it from the key. An
//! earlier version stripped at use time unconditionally, which also stripped the
//! master: for the ~1 seed in 256 whose master private key begins with a zero
//! byte that produced an account key NEITHER `Child` nor `ChildBIP32Std`
//! reproduces. `tests/vectors.rs` pins the master case, a mixed-variant path and
//! the round-trip, none of which the pure-legacy and pure-strict vectors could
//! discriminate.
//!
//! dcrd exposes both (`Child` legacy, `ChildBIP32Std` strict) and dcrwallet uses
//! the legacy one for the entire wallet path, so this crate mirrors that:
//! [`ExtPrivKey::derive_child`] is the Decred variant and is what
//! [`ExtPrivKey::account_key`] / [`ExtPrivKey::address_key`] use, while
//! [`ExtPrivKey::derive_child_bip32_std`] is available for strict BIP32.
//!
//! Getting this wrong is silent: a signer that derived strictly would show a user
//! restoring their decrediton seed a different, empty wallet, with coins sent to
//! its addresses invisible to every other Decred wallet holding the same phrase.
//! `tests/vectors.rs` pins both variants against dcrd-generated vectors.
//!
//! Public (non-hardened) derivation is unaffected — there is no private key to
//! strip — so an account `dpub` and every address below it agree between the two.

use alloc::string::String;
use alloc::vec::Vec;

#[cfg(feature = "mnemonic")]
use bip39::Mnemonic;
use hmac::{Hmac, Mac};
use secp256k1::{All, PublicKey, Scalar, Secp256k1, SecretKey};
use sha2::Sha512;

use zeroize::Zeroize;

use crate::address::Address;
use crate::blake256;
use crate::network::Network;
use crate::Error;

type HmacSha512 = Hmac<Sha512>;

/// dcrd `hdkeychain` seed bounds (BIP32: 128–512 bits).
const MIN_SEED_BYTES: usize = 16;
const MAX_SEED_BYTES: usize = 64;

/// Bit marking a BIP32 child index as hardened.
pub const HARDENED: u32 = 0x8000_0000;
/// Receive branch below the account key.
pub const BRANCH_EXTERNAL: u32 = 0;
/// Change branch below the account key.
pub const BRANCH_INTERNAL: u32 = 1;

/// Parse the left half of a derivation HMAC into the tweak `parse256(Il)`,
/// rejecting both of the values dcrd rejects.
///
/// dcrd tests `overflow || ilModN.IsZero()` once, ahead of the private/public
/// split (`hdkeychain/extendedkey.go`, `child`), so a bad `Il` is
/// `ErrInvalidChild` on either path. [`Scalar::from_be_bytes`] is only the
/// `overflow` half of that: it rejects values at or above the curve order and
/// accepts zero. Nor does libsecp256k1 object to a zero tweak —
/// `eckey_privkey_tweak_add` fails only when the SUM is zero and
/// `eckey_pubkey_tweak_add` only when it is the point at infinity — so without
/// the second test `add_tweak`/`add_exp_tweak` SUCCEED and return a child
/// carrying its parent's key verbatim, which no dcrd API can hand back. One
/// helper for both call sites, so the private and public paths cannot drift the
/// way dcrd's single pre-split check cannot.
///
/// The opposite edge is a deliberate divergence rather than an oversight: dcrd
/// never checks the SUM, so `Il + parentKey ≡ 0 (mod n)` leaves it storing 32
/// zero bytes — which the legacy stripping loop then reduces to an EMPTY key —
/// or serializing the point at infinity on the public path. The `add_tweak` and
/// `add_exp_tweak` calls at the two call sites refuse that instead. Matching
/// dcrd there would mean manufacturing a degenerate key and calling it valid.
fn child_tweak(il: [u8; 32]) -> Result<Scalar, Error> {
    let tweak = Scalar::from_be_bytes(il).map_err(|_| Error::Derivation)?;
    if tweak == Scalar::ZERO {
        return Err(Error::Derivation);
    }
    Ok(tweak)
}

/// A BIP32 extended private key carrying its target [`Network`].
#[derive(Clone)]
pub struct ExtPrivKey {
    /// Network used for serialization, addresses and the SLIP44 coin type.
    pub network: Network,
    /// The private scalar.
    pub secret: SecretKey,
    /// BIP32 chain code.
    pub chain_code: [u8; 32],
    /// Depth below the master (master = 0).
    ///
    /// dcrd holds this as a `uint16` but serializes `byte(k.depth % 256)`
    /// (`hdkeychain/extendedkey.go`, `String`), so a key past 255 levels cannot
    /// round-trip there. One byte plus a `checked_add` is the fail-closed
    /// spelling of that same one-byte wire slot: the 256th step returns
    /// [`Error::Derivation`] rather than a key whose serialization silently
    /// carries the wrong depth. No key material rides on it either way — depth
    /// enters neither an HMAC preimage nor a fingerprint.
    pub depth: u8,
    /// First 4 bytes of the parent key's hash160 (zero for the master).
    pub parent_fingerprint: [u8; 4],
    /// Child index this key was derived at (0 for the master).
    pub child_number: u32,
    /// Whether this key's dcrd-equivalent STORED form has had its leading zero
    /// bytes removed — which decides the byte layout of the HMAC preimage when
    /// this key is used as a hardened parent.
    ///
    /// In dcrd this is not a flag but a consequence of `[]byte` length. Only
    /// `child()` strips, and only the key it just produced
    /// (`hdkeychain/extendedkey.go`, the `for !strictBIP32 && childKey[0] == 0`
    /// loop); `NewMaster` stores the full 32 bytes from HMAC and
    /// `NewKeyFromString` the full 32 from the serialization, and
    /// `newExtendedKey` never normalizes. `child()` then lays the parent out
    /// with `copy(data[1:], k.key)`, so a 31-byte stored key lands
    /// left-aligned and a 32-byte one does not.
    ///
    /// A [`SecretKey`] is always 32 zero-padded bytes, so that length — the
    /// entire mechanism — is not recoverable from the key itself and has to be
    /// carried alongside it. Stripping at use time without it strips the MASTER
    /// too, which dcrd never does: for the ~1 seed in 256 whose master private
    /// key begins with a zero byte, that produces an account key no dcrd API
    /// reproduces, under either `Child` or `ChildBIP32Std`.
    ///
    /// Private (not `pub`) deliberately: set wrongly it silently relocates an
    /// entire wallet, so only this module's constructors ever set it.
    zeros_stripped: bool,
}

/// Scrub private material when an `ExtPrivKey` (master or any derived child)
/// is dropped. Every intermediate produced along a derivation path is erased as
/// it goes out of scope — [`ExtPrivKey::derive_path`] reassigns, and assignment
/// drops the previous key — so seed-derived secrets never linger in freed
/// memory.
///
/// Both wipes are volatile writes behind a barrier, so neither is elided.
/// `non_secure_erase` fills the secp256k1 secret with 0x01 rather than zeros,
/// because the all-zero scalar is not a valid key; `zeroize` zeroes the chain
/// code. What neither reaches is a copy something else already made:
/// [`SecretKey`] is `Copy` and `add_tweak` takes it by value, so a derivation
/// leaves the parent secret in a callee frame this `Drop` never sees. It
/// shrinks the window rather than closing it.
impl Drop for ExtPrivKey {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.secret.non_secure_erase();
        self.chain_code.zeroize();
    }
}

impl ExtPrivKey {
    /// BIP32 master from a BIP39 seed (16–64 bytes, per BIP32/dcrd; a BIP39
    /// mnemonic always expands to 64).
    pub fn master_from_seed(seed: &[u8], network: Network) -> Result<Self, Error> {
        if seed.len() < MIN_SEED_BYTES || seed.len() > MAX_SEED_BYTES {
            return Err(Error::Derivation);
        }
        let mut mac = HmacSha512::new_from_slice(b"Bitcoin seed").expect("hmac key");
        mac.update(seed);
        let mut i = mac.finalize().into_bytes();
        // `i` is the master secret candidate ‖ chain code, so *every* exit has to
        // wipe it. The fallible tail therefore runs inside a closure, the shape
        // `parse_ext_key` uses for the same reason: written as a bare `?`, the
        // invalid-scalar arm left the function before reaching the wipe below.
        let key = (|| {
            let secret = SecretKey::from_slice(&i[..32]).map_err(|_| Error::Derivation)?;
            let mut chain_code = [0u8; 32];
            chain_code.copy_from_slice(&i[32..]);
            Ok(ExtPrivKey {
                network,
                secret,
                chain_code,
                depth: 0,
                parent_fingerprint: [0; 4],
                child_number: 0,
                // dcrd `NewMaster` hands the full 32 HMAC bytes to `newExtendedKey`
                // and nothing strips them, so a master whose key begins with a zero
                // byte keeps it and derives its hardened children BIP32-style.
                zeros_stripped: false,
            })
        })();
        i.zeroize(); // wipe the secret ‖ chain-code intermediate
        key
    }

    /// Derive the master key from BIP39 entropy (16–32 bytes) and passphrase,
    /// expanding through the English mnemonic exactly like any BIP39 wallet.
    /// The mnemonic (ZeroizeOnDrop) and the 64-byte seed are wiped on exit.
    #[cfg(feature = "mnemonic")]
    pub fn from_entropy(entropy: &[u8], passphrase: &str, network: Network) -> Result<Self, Error> {
        let mnemonic = Mnemonic::from_entropy(entropy).map_err(|_| Error::Derivation)?;
        let mut seed = mnemonic.to_seed(passphrase);
        let key = Self::master_from_seed(&seed, network);
        seed.zeroize();
        key
    }

    /// Derive the master key from an English BIP39 mnemonic phrase.
    /// The mnemonic (ZeroizeOnDrop) and the 64-byte seed are wiped on exit.
    #[cfg(feature = "mnemonic")]
    pub fn from_phrase(phrase: &str, passphrase: &str, network: Network) -> Result<Self, Error> {
        let mnemonic = Mnemonic::parse(phrase).map_err(|_| Error::Derivation)?;
        let mut seed = mnemonic.to_seed(passphrase);
        let key = Self::master_from_seed(&seed, network);
        seed.zeroize();
        key
    }

    /// The corresponding public key.
    pub fn public_key(&self, secp: &Secp256k1<All>) -> PublicKey {
        PublicKey::from_secret_key(secp, &self.secret)
    }

    /// 33-byte compressed pubkey — the form committed in Decred addresses/scripts.
    pub fn compressed_pubkey(&self, secp: &Secp256k1<All>) -> [u8; 33] {
        self.public_key(secp).serialize()
    }

    /// BIP32 fingerprint: first 4 bytes of `hash160(compressed_pubkey)`.
    pub fn fingerprint(&self, secp: &Secp256k1<All>) -> [u8; 4] {
        let h = crate::hashing::hash160(&self.compressed_pubkey(secp));
        [h[0], h[1], h[2], h[3]]
    }

    /// BIP32 CKDpriv, **Decred variant** — the equivalent of dcrd
    /// `hdkeychain.Child`, and what dcrwallet and decrediton use for the whole
    /// wallet path. `index >= HARDENED` performs hardened derivation.
    ///
    /// This is the default because it is what the Decred ecosystem derives; see
    /// [`Self::derive_child_bip32_std`] for the strict form and the module docs
    /// for why they differ.
    pub fn derive_child(&self, secp: &Secp256k1<All>, index: u32) -> Result<Self, Error> {
        self.derive_child_inner(secp, index, false)
    }

    /// BIP32 CKDpriv, **strict BIP32** — the equivalent of dcrd
    /// `hdkeychain.ChildBIP32Std`, retaining the leading zero bytes of the parent
    /// private key that [`Self::derive_child`] strips.
    ///
    /// Produces different hardened children from [`Self::derive_child`] for any
    /// parent private key with a leading zero byte, which is about 1 key in 256 at
    /// each hardened step. Use it only when strict BIP32 is what you want;
    /// anything that has to agree with a dcrwallet or decrediton seed must not.
    pub fn derive_child_bip32_std(&self, secp: &Secp256k1<All>, index: u32) -> Result<Self, Error> {
        self.derive_child_inner(secp, index, true)
    }

    fn derive_child_inner(
        &self,
        secp: &Secp256k1<All>,
        index: u32,
        strict_bip32: bool,
    ) -> Result<Self, Error> {
        let depth = self.depth.checked_add(1).ok_or(Error::Derivation)?;
        // One point multiplication, reused for both the non-hardened HMAC input
        // and the child's parent fingerprint. Computing it twice (as an earlier
        // version did) doubled the curve work of every non-hardened step, which
        // is the hot path when deriving address keys.
        let parent_pubkey = self.compressed_pubkey(secp);
        let mut mac = HmacSha512::new_from_slice(&self.chain_code).expect("hmac key");
        if index >= HARDENED {
            // dcrd builds a zeroed 37-byte buffer, copies the parent private key
            // in at offset 1, and writes ser32(index) at offset 33
            // (`hdkeychain/extendedkey.go` `child`). In the Decred variant the
            // stored parent key has had its leading zero bytes stripped, so it
            // lands LEFT-aligned at offset 1 and the gap before ser32(index) stays
            // zero:
            //
            //   strict:  0x00 ‖ 0x00 ‖ key31 ‖ ser32(i)
            //   Decred:  0x00 ‖ key31 ‖ 0x00 ‖ ser32(i)
            //
            // Same length, different bytes — hence a different child.
            let mut key = self.secret.secret_bytes();
            // The layout is decided by how THIS key is stored, not by the
            // variant being derived now: dcrd's `child` copies `k.key` in
            // whatever length it already has, and its `strictBIP32` argument
            // only governs whether the CHILD it returns is stored stripped.
            // So `ChildBIP32Std` on a stripped parent still sees the short
            // form, and `Child` on the master still sees the full 32 bytes.
            let skip = if self.zeros_stripped {
                key.iter().take_while(|&&b| b == 0).count()
            } else {
                0
            };
            let mut data = [0u8; 37];
            data[1..1 + (32 - skip)].copy_from_slice(&key[skip..]);
            data[33..].copy_from_slice(&index.to_be_bytes());
            mac.update(&data);
            // Both buffers held the parent secret.
            data.zeroize();
            key.zeroize();
        } else {
            mac.update(&parent_pubkey);
            mac.update(&index.to_be_bytes());
        }
        let mut i = mac.finalize().into_bytes();

        // The intermediate's left half is the tweak that, together with the
        // parent key, yields the child secret, so *every* exit has to wipe it.
        // Both fallible steps therefore run inside a closure: `child_tweak`'s
        // `?` used to leave the function before the wipe, and deferring
        // `add_tweak`'s error past it only covered that one path — the child
        // chain code copied out of `i` beforehand still dropped unwiped.
        let key = (|| {
            let tweak = child_tweak(<[u8; 32]>::try_from(&i[..32]).unwrap())?;
            let secret = self
                .secret
                .add_tweak(&tweak)
                .map_err(|_| Error::Derivation)?;

            let mut chain_code = [0u8; 32];
            chain_code.copy_from_slice(&i[32..]);

            let h = crate::hashing::hash160(&parent_pubkey);
            Ok(ExtPrivKey {
                network: self.network,
                secret,
                chain_code,
                depth,
                parent_fingerprint: [h[0], h[1], h[2], h[3]],
                child_number: index,
                // dcrd strips the key it just produced only on the legacy path, so
                // that is exactly when the child's stored form is the short one.
                zeros_stripped: !strict_bip32,
            })
        })();
        i.zeroize();
        key
    }

    /// Derive along `path` (each element optionally `| HARDENED`) with the Decred
    /// variant, i.e. repeated [`Self::derive_child`].
    pub fn derive_path(&self, secp: &Secp256k1<All>, path: &[u32]) -> Result<Self, Error> {
        let mut key = self.clone();
        for &idx in path {
            key = key.derive_child(secp, idx)?;
        }
        Ok(key)
    }

    /// Derive along `path` with strict BIP32, i.e. repeated
    /// [`Self::derive_child_bip32_std`].
    pub fn derive_path_bip32_std(
        &self,
        secp: &Secp256k1<All>,
        path: &[u32],
    ) -> Result<Self, Error> {
        let mut key = self.clone();
        for &idx in path {
            key = key.derive_child_bip32_std(secp, idx)?;
        }
        Ok(key)
    }

    /// Account key at `m/44'/coin'/account'` (coin from [`Network::slip44`]).
    pub fn account_key(&self, secp: &Secp256k1<All>, account: u32) -> Result<Self, Error> {
        self.derive_path(
            secp,
            &[
                44 | HARDENED,
                self.network.slip44() | HARDENED,
                account | HARDENED,
            ],
        )
    }

    /// Address key at `.../branch/index` relative to an account key.
    ///
    /// Both components must be non-hardened: a watch-only companion holding only
    /// the account `dpub` has to be able to derive the same address, which it
    /// cannot do for a hardened index. Rejecting them here keeps the private and
    /// public sides of the wallet in agreement instead of silently producing a
    /// key the companion can never see.
    pub fn address_key(
        &self,
        secp: &Secp256k1<All>,
        branch: u32,
        index: u32,
    ) -> Result<Self, Error> {
        if branch >= HARDENED || index >= HARDENED {
            return Err(Error::HardenedIndex);
        }
        self.derive_path(secp, &[branch, index])
    }

    /// The neutered (watch-only) extended public key. Carries no private
    /// material; this is what a companion wallet imports to track balances
    /// and build unsigned transactions.
    pub fn neuter(&self, secp: &Secp256k1<All>) -> ExtPubKey {
        ExtPubKey {
            network: self.network,
            public_key: self.public_key(secp),
            chain_code: self.chain_code,
            depth: self.depth,
            parent_fingerprint: self.parent_fingerprint,
            child_number: self.child_number,
        }
    }

    /// P2PKH address for this key on its network.
    pub fn p2pkh_address(&self, secp: &Secp256k1<All>) -> String {
        Address::from_pubkey(&self.compressed_pubkey(secp), self.network).encode()
    }

    /// Serialize as a `dprv…`/`tprv…`/`sprv…`/`rprv…` extended private key.
    pub fn to_base58(&self) -> String {
        serialize_ext_key(
            self.network.hd_priv_id(),
            self.depth,
            self.parent_fingerprint,
            self.child_number,
            &self.chain_code,
            KeyData::Private(&self.secret),
        )
    }

    /// Parse an extended private key string, detecting the network from the
    /// version bytes.
    ///
    /// Deliberately narrower than dcrd `NewKeyFromString`, twice over. The
    /// version prefix fixes the key TYPE here, where dcrd takes only the network
    /// from it and reads the type off the key data — so a `dprv…` carrying
    /// public key data, which dcrd parses as a public key, is rejected. And no
    /// expected network is passed in, so where dcrd answers `ErrWrongNetwork`
    /// for a foreign prefix this returns the key with its own [`Network`]: a
    /// caller that accepts only one network has to compare the field itself.
    pub fn from_base58(s: &str) -> Result<Self, Error> {
        let mut raw = parse_ext_key(s)?;
        let result = (|| {
            let network = Network::from_hd_priv_id(raw.version).ok_or(Error::UnknownPrefix)?;
            // Load-bearing, and not a duplicate of the `SecretKey::from_slice`
            // below: bytes 1..33 of a compressed pubkey are its X coordinate,
            // which is a valid scalar with overwhelming probability. Drop this
            // and a public key parses as a private key whose secret is public
            // knowledge. dcrd instead reads the type off the key data
            // (`hdkeychain/extendedkey.go`, `NewKeyFromString`), which is why a
            // `dpub…` can be a private key over there; `tests/vectors.rs` pins
            // the two strings.
            if raw.key_data[0] != 0 {
                return Err(Error::Parse);
            }
            let secret = SecretKey::from_slice(&raw.key_data[1..]).map_err(|_| Error::Parse)?;
            Ok(ExtPrivKey {
                network,
                secret,
                chain_code: raw.chain_code,
                depth: raw.depth,
                parent_fingerprint: raw.parent_fingerprint,
                child_number: raw.child_number,
                // An extended key serializes zero-padded to 32 bytes, and dcrd
                // `NewKeyFromString` stores exactly those bytes — so a key that
                // was stored stripped comes back unstripped, and its hardened
                // children change accordingly. Faithful to dcrd, surprising as
                // it is: serializing and reparsing is not derivation-neutral.
                zeros_stripped: false,
            })
        })();
        // The decoded key-data slot held the raw secret; wipe it either way.
        raw.key_data.zeroize();
        result
    }
}

/// A BIP32 extended public key (watch-only) carrying its target [`Network`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExtPubKey {
    /// Network used for serialization and addresses.
    pub network: Network,
    /// The public point.
    pub public_key: PublicKey,
    /// BIP32 chain code.
    pub chain_code: [u8; 32],
    /// Depth below the master (master = 0); bounded as [`ExtPrivKey::depth`] is.
    pub depth: u8,
    /// First 4 bytes of the parent key's hash160 (zero for the master).
    pub parent_fingerprint: [u8; 4],
    /// Child index this key was derived at (0 for the master).
    pub child_number: u32,
}

impl ExtPubKey {
    /// 33-byte compressed pubkey.
    pub fn compressed_pubkey(&self) -> [u8; 33] {
        self.public_key.serialize()
    }

    /// BIP32 fingerprint: first 4 bytes of `hash160(compressed_pubkey)`.
    pub fn fingerprint(&self) -> [u8; 4] {
        let h = crate::hashing::hash160(&self.compressed_pubkey());
        [h[0], h[1], h[2], h[3]]
    }

    /// BIP32 CKDpub. Hardened indices are impossible from a public key and
    /// return [`Error::HardenedFromPublic`].
    pub fn derive_child(&self, secp: &Secp256k1<All>, index: u32) -> Result<Self, Error> {
        if index >= HARDENED {
            return Err(Error::HardenedFromPublic);
        }
        let depth = self.depth.checked_add(1).ok_or(Error::Derivation)?;
        let mut mac = HmacSha512::new_from_slice(&self.chain_code).expect("hmac key");
        mac.update(&self.compressed_pubkey());
        mac.update(&index.to_be_bytes());
        let mut i = mac.finalize().into_bytes();

        // Nothing here is secret — an `ExtPubKey` carries its own chain code in
        // the clear and both halves of `i` are recomputable from it — but the
        // private path's discipline is cheaper to hold everywhere than to
        // reason about per call site, so this exit wipes too, on every path.
        let key = (|| {
            let tweak = child_tweak(<[u8; 32]>::try_from(&i[..32]).unwrap())?;
            let public_key = self
                .public_key
                .add_exp_tweak(secp, &tweak)
                .map_err(|_| Error::Derivation)?;

            let mut chain_code = [0u8; 32];
            chain_code.copy_from_slice(&i[32..]);

            Ok(ExtPubKey {
                network: self.network,
                public_key,
                chain_code,
                depth,
                parent_fingerprint: self.fingerprint(),
                child_number: index,
            })
        })();
        i.zeroize();
        key
    }

    /// Derive along `path` (non-hardened indices only).
    pub fn derive_path(&self, secp: &Secp256k1<All>, path: &[u32]) -> Result<Self, Error> {
        let mut key = *self;
        for &idx in path {
            key = key.derive_child(secp, idx)?;
        }
        Ok(key)
    }

    /// Compressed pubkey at `branch/index` below this (account-level) key.
    pub fn pubkey_at(
        &self,
        secp: &Secp256k1<All>,
        branch: u32,
        index: u32,
    ) -> Result<[u8; 33], Error> {
        Ok(self
            .derive_path(secp, &[branch, index])?
            .compressed_pubkey())
    }

    /// P2PKH address for this key on its network.
    pub fn p2pkh_address(&self) -> String {
        Address::from_pubkey(&self.compressed_pubkey(), self.network).encode()
    }

    /// Serialize as a `dpub…`/`tpub…`/`spub…`/`rpub…` extended public key.
    pub fn to_base58(&self) -> String {
        serialize_ext_key(
            self.network.hd_pub_id(),
            self.depth,
            self.parent_fingerprint,
            self.child_number,
            &self.chain_code,
            KeyData::Public(&self.public_key),
        )
    }

    /// Parse an extended public key string, detecting the network from the
    /// version bytes.
    ///
    /// The mirror of [`ExtPrivKey::from_base58`], narrower than dcrd for the
    /// same reason: `PublicKey::from_slice` refuses the 0x00-prefixed private
    /// form, which dcrd accepts under a `dpub…` version and hands back as a
    /// private key. As there, no expected network is passed in.
    pub fn from_base58(s: &str) -> Result<Self, Error> {
        let raw = parse_ext_key(s)?;
        let network = Network::from_hd_pub_id(raw.version).ok_or(Error::UnknownPrefix)?;
        let public_key = PublicKey::from_slice(&raw.key_data).map_err(|_| Error::Parse)?;
        Ok(ExtPubKey {
            network,
            public_key,
            chain_code: raw.chain_code,
            depth: raw.depth,
            parent_fingerprint: raw.parent_fingerprint,
            child_number: raw.child_number,
        })
    }
}

enum KeyData<'a> {
    Private(&'a SecretKey),
    Public(&'a PublicKey),
}

/// Decred extended keys are the 78-byte BIP32 body base58-encoded with a
/// 4-byte double-BLAKE256 checksum over the whole body (version included).
fn serialize_ext_key(
    version: [u8; 4],
    depth: u8,
    parent_fingerprint: [u8; 4],
    child_number: u32,
    chain_code: &[u8; 32],
    key: KeyData<'_>,
) -> String {
    let is_private = matches!(key, KeyData::Private(_));
    let mut data = Vec::with_capacity(82);
    data.extend_from_slice(&version);
    data.push(depth);
    data.extend_from_slice(&parent_fingerprint);
    data.extend_from_slice(&child_number.to_be_bytes());
    data.extend_from_slice(chain_code);
    match key {
        KeyData::Private(sk) => {
            data.push(0x00);
            data.extend_from_slice(&sk.secret_bytes());
        }
        KeyData::Public(pk) => data.extend_from_slice(&pk.serialize()),
    }
    let cksum = blake256::sum256d(&data);
    data.extend_from_slice(&cksum[..4]);
    let s = bs58::encode(&data).into_string();
    if is_private {
        // The buffer held the raw secret (and chain code); wipe before drop.
        data.zeroize();
    }
    s
}

struct RawExtKey {
    version: [u8; 4],
    depth: u8,
    parent_fingerprint: [u8; 4],
    child_number: u32,
    chain_code: [u8; 32],
    key_data: [u8; 33],
}

fn parse_ext_key(s: &str) -> Result<RawExtKey, Error> {
    // Length-gate before the quadratic base58 decode.
    if s.len() > crate::hashing::MAX_BASE58_LEN {
        return Err(Error::Parse);
    }
    let mut raw = bs58::decode(s).into_vec().map_err(|_| Error::Base58)?;
    // For a dprv this Vec holds the raw secret, so *every* exit has to wipe it.
    // The checks below therefore run inside a closure: written as early returns
    // they fell out of the function before reaching the wipe, leaving a decoded
    // secret in freed heap whenever the length or checksum was wrong.
    let key = (|| {
        if raw.len() != 82 {
            return Err(Error::Parse);
        }
        let (body, cksum) = raw.split_at(78);
        if blake256::sum256d(body)[..4] != *cksum {
            return Err(Error::BadChecksum);
        }
        Ok(RawExtKey {
            version: body[0..4].try_into().unwrap(),
            depth: body[4],
            parent_fingerprint: body[5..9].try_into().unwrap(),
            child_number: u32::from_be_bytes(body[9..13].try_into().unwrap()),
            chain_code: body[13..45].try_into().unwrap(),
            key_data: body[45..78].try_into().unwrap(),
        })
    })();
    raw.zeroize();
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Both halves of dcrd's `overflow || ilModN.IsZero()`. The zero case is
    /// the one [`child_tweak`] adds: no HMAC input can reach it, so this is the
    /// only place the guard can be exercised at all.
    #[test]
    fn invalid_hmac_left_halves_are_rejected() {
        assert!(child_tweak([0u8; 32]).is_err());
        assert!(child_tweak([0xffu8; 32]).is_err());
    }

    /// Why that guard has to exist: libsecp256k1 treats a zero tweak as a
    /// perfectly good no-op on both paths, so without it the "child" would
    /// carry its parent's key verbatim. Should a future secp256k1 start
    /// refusing a zero tweak itself, this fails and the guard can be revisited.
    #[test]
    fn a_zero_tweak_would_return_the_parent_unchanged() {
        let secp = Secp256k1::new();
        let parent = SecretKey::from_slice(&[0x11u8; 32]).unwrap();
        assert_eq!(
            parent.add_tweak(&Scalar::ZERO).unwrap().secret_bytes(),
            parent.secret_bytes()
        );
        let parent_pub = PublicKey::from_secret_key(&secp, &parent);
        assert_eq!(
            parent_pub.add_exp_tweak(&secp, &Scalar::ZERO).unwrap(),
            parent_pub
        );
    }

    /// `non_secure_erase` fills with 0x01 rather than zeros, because the
    /// all-zero scalar is not a valid key. Pinned so the [`Drop`] comment above
    /// cannot go stale across a secp256k1 bump.
    #[test]
    fn secret_erasure_fills_with_ones() {
        let mut secret = SecretKey::from_slice(&[0x11u8; 32]).unwrap();
        secret.non_secure_erase();
        assert_eq!(secret.secret_bytes(), [0x01u8; 32]);
    }
}
