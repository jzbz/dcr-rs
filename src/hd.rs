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
//! `0x00 ‖ 0x00 ‖ key31 ‖ ser32(i)`, and every descendant diverges. Measured over
//! 20 000 seeds, the account key at `m/44'/42'/0'` differs between the two
//! variants for about 1 seed in 112.
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
    pub depth: u8,
    /// First 4 bytes of the parent key's hash160 (zero for the master).
    pub parent_fingerprint: [u8; 4],
    /// Child index this key was derived at (0 for the master).
    pub child_number: u32,
}

/// Scrub private material when an `ExtPrivKey` (master or any derived child)
/// is dropped. Every intermediate produced along a derivation path is erased
/// as it goes out of scope, so seed-derived secrets never linger in freed
/// memory. `non_secure_erase` zeroes the secp256k1 secret; `zeroize` does a
/// volatile (non-elidable) wipe of the chain code.
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
        let secret = SecretKey::from_slice(&i[..32]).map_err(|_| Error::Derivation)?;
        let mut chain_code = [0u8; 32];
        chain_code.copy_from_slice(&i[32..]);
        i.zeroize(); // wipe the secret ‖ chain-code intermediate
        Ok(ExtPrivKey {
            network,
            secret,
            chain_code,
            depth: 0,
            parent_fingerprint: [0; 4],
            child_number: 0,
        })
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
            let skip = if strict_bip32 {
                0
            } else {
                key.iter().take_while(|&&b| b == 0).count()
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

        let tweak = Scalar::from_be_bytes(<[u8; 32]>::try_from(&i[..32]).unwrap())
            .map_err(|_| Error::Derivation)?;
        let secret = self.secret.add_tweak(&tweak);

        let mut chain_code = [0u8; 32];
        chain_code.copy_from_slice(&i[32..]);
        // Wipe the intermediate: its left half is the tweak that, together
        // with the parent key, yields the child secret.
        i.zeroize();
        let secret = secret.map_err(|_| Error::Derivation)?;

        let h = crate::hashing::hash160(&parent_pubkey);
        Ok(ExtPrivKey {
            network: self.network,
            secret,
            chain_code,
            depth,
            parent_fingerprint: [h[0], h[1], h[2], h[3]],
            child_number: index,
        })
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
    pub fn from_base58(s: &str) -> Result<Self, Error> {
        let mut raw = parse_ext_key(s)?;
        let result = (|| {
            let network = Network::from_hd_priv_id(raw.version).ok_or(Error::UnknownPrefix)?;
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
    /// Depth below the master (master = 0).
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
        let i = mac.finalize().into_bytes();

        let tweak = Scalar::from_be_bytes(<[u8; 32]>::try_from(&i[..32]).unwrap())
            .map_err(|_| Error::Derivation)?;
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
