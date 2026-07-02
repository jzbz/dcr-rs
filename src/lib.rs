// SPDX-License-Identifier: ISC
//! dcr-rs: Decred (DCR) primitives for Rust.
//!
//! Scope: the consensus-critical byte formats and key handling a wallet or
//! signer needs — BLAKE-256, base58check addresses, BIP32 HD keys with Decred
//! serialization (`dprv`/`dpub`), the transaction wire format, the Decred
//! signature hash, and low-S ECDSA P2PKH signing. No networking, no staking,
//! no transaction-construction policy.
//!
//! EC math, HMAC/SHA/RIPEMD, BIP39 wordlists, base58 and CBOR are delegated to
//! audited crates. The only Decred-specific cryptographic primitive vendored
//! here is BLAKE-256 (the 14-round SHA-3 finalist Decred uses for
//! *everything*, not BLAKE2/3), implemented in [`blake256`] and checked
//! against dcrd-generated known-answer vectors.
//!
//! Every algorithm was written against dcrd source and is exercised by
//! reference vectors lifted from dcrd plus a real mainnet transaction in
//! `tests/`. Run them first:
//!
//! ```text
//! cargo test --all-features
//! ```
//!
//! # Feature flags
//!
//! * `std` (default) — links std into dependencies; the crate itself is
//!   `no_std + alloc` and builds without it.
//! * `mnemonic` (default) — BIP39 seed expansion ([`hd::ExtPrivKey::from_entropy`]).
//! * `airgap` (default) — the CBOR air-gapped signing package shared with the
//!   KeyOS and Keystone Decred signers ([`airgap`]).

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

extern crate alloc;

// Re-export the curve library so downstream code uses the exact version this
// crate was built against (contexts and types are not compatible across
// semver-incompatible secp256k1 releases).
pub use secp256k1;

pub mod address;
#[cfg(feature = "airgap")]
pub mod airgap;
pub mod amount;
pub mod blake256;
pub mod hashing;
pub mod hd;
pub mod network;
pub mod sighash;
pub mod sign;
pub mod tx;

/// Crate-wide error. Kept small and `Copy` so it threads cheaply through the
/// signing path and maps cleanly onto UI strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// BIP32 derivation failed (bad seed length, invalid scalar, depth
    /// overflow, or a 1-in-2^127 child-key overflow). Treated as fatal; the
    /// caller should retry rather than silently skipping an index.
    Derivation,
    /// A hardened child was requested from an extended *public* key, which is
    /// cryptographically impossible.
    HardenedFromPublic,
    /// A byte buffer could not be parsed (short read, bad varint, malformed
    /// tx, wrong payload length).
    Parse,
    /// A string is not valid base58.
    Base58,
    /// A base58check checksum did not verify.
    BadChecksum,
    /// An address or extended-key version prefix matches no known network.
    UnknownPrefix,
    /// CBOR encoding of an airgap package failed.
    Encode,
    /// The airgap package declared a format version this build does not speak.
    UnsupportedVersion,
    /// A signature-hash request referenced an input index outside the tx.
    SigHashIndex,
    /// A re-derived input key did not reproduce the prev_script the companion
    /// claimed we were spending. This is the anti-tamper tripwire: refuse.
    ScriptMismatch,
    /// An airgap sign request failed structural validation; the message says
    /// which rule.
    InvalidRequest(&'static str),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = match self {
            Error::Derivation => "key derivation failed",
            Error::HardenedFromPublic => "cannot derive a hardened child from a public key",
            Error::Parse => "could not parse data",
            Error::Base58 => "invalid base58 string",
            Error::BadChecksum => "base58check checksum mismatch",
            Error::UnknownPrefix => "version prefix matches no known network",
            Error::Encode => "could not encode data",
            Error::UnsupportedVersion => "unsupported package version",
            Error::SigHashIndex => "input index out of range",
            Error::ScriptMismatch => "input script does not match key (refusing to sign)",
            Error::InvalidRequest(msg) => msg,
        };
        f.write_str(s)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

// Convenience re-exports so app code can `use dcr_rs::{...}` without reaching
// into submodules for the common path.
pub use address::Address;
#[cfg(feature = "airgap")]
pub use airgap::{
    decode_sign_request, encode_sign_request, sign_request, InputMeta, OutputMeta, ReviewSummary,
    SignRequest, FORMAT_VERSION,
};
pub use amount::{format_amount, ATOMS_PER_DCR};
pub use hd::{ExtPrivKey, ExtPubKey, BRANCH_EXTERNAL, BRANCH_INTERNAL, HARDENED};
pub use network::Network;
pub use tx::{MsgTx, OutPoint, TxIn, TxOut};
