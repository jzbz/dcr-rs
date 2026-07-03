// SPDX-License-Identifier: ISC
//! BIP32 HD key derivation with Decred serialization.
//!
//! Standard wallet path: `m / 44' / coin' / account' / branch / index`
//!   * coin type from SLIP-0044 via [`Network::slip44`] (42 on mainnet)
//!   * branch 0 = external (receive), 1 = internal (change)
//!
//! BIP32 math is identical to Bitcoin (HMAC key `"Bitcoin seed"`); Decred
//! differs only in the `dprv`/`dpub` version bytes and the double-BLAKE256
//! base58 checksum. Confirmed by the dcrd `hdkeychain/extendedkey_test.go`
//! vectors in `tests/vectors.rs`: BIP32 test-vector-1 re-encodes to
//! `dprv3hCznBesA6jBt…` / `dpubZ9169KDAEUny…`.

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

    /// BIP32 CKDpriv. `index >= HARDENED` performs hardened derivation.
    pub fn derive_child(&self, secp: &Secp256k1<All>, index: u32) -> Result<Self, Error> {
        let depth = self.depth.checked_add(1).ok_or(Error::Derivation)?;
        let mut mac = HmacSha512::new_from_slice(&self.chain_code).expect("hmac key");
        if index >= HARDENED {
            mac.update(&[0u8]);
            mac.update(&self.secret.secret_bytes());
        } else {
            mac.update(&self.compressed_pubkey(secp));
        }
        mac.update(&index.to_be_bytes());
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

        Ok(ExtPrivKey {
            network: self.network,
            secret,
            chain_code,
            depth,
            parent_fingerprint: self.fingerprint(secp),
            child_number: index,
        })
    }

    /// Derive along `path` (each element optionally `| HARDENED`).
    pub fn derive_path(&self, secp: &Secp256k1<All>, path: &[u32]) -> Result<Self, Error> {
        let mut key = self.clone();
        for &idx in path {
            key = key.derive_child(secp, idx)?;
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
    pub fn address_key(
        &self,
        secp: &Secp256k1<All>,
        branch: u32,
        index: u32,
    ) -> Result<Self, Error> {
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
    let mut raw = bs58::decode(s).into_vec().map_err(|_| Error::Base58)?;
    if raw.len() != 82 {
        return Err(Error::Parse);
    }
    let (body, cksum) = raw.split_at(78);
    if blake256::sum256d(body)[..4] != *cksum {
        return Err(Error::BadChecksum);
    }
    let key = RawExtKey {
        version: body[0..4].try_into().unwrap(),
        depth: body[4],
        parent_fingerprint: body[5..9].try_into().unwrap(),
        child_number: u32::from_be_bytes(body[9..13].try_into().unwrap()),
        chain_code: body[13..45].try_into().unwrap(),
        key_data: body[45..78].try_into().unwrap(),
    };
    // For a dprv this Vec held the raw secret; wipe unconditionally (cheap).
    raw.zeroize();
    Ok(key)
}
