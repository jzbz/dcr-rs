// SPDX-License-Identifier: ISC
//! Decred signature hash — `txscript/sighash.go` `calcSignatureHash`.
//!
//! This is **not** Bitcoin's BIP143. The message signed for input `idx` is:
//!
//! ```text
//! prefixHash  = blake256( version|(1<<16) ‖ inputs(outpoint+seq) ‖ outputs ‖ locktime ‖ expiry )
//! witnessHash = blake256( version|(3<<16) ‖ count ‖ per-input: signScript for idx else empty )
//! sighash     = blake256( LE32(hashType) ‖ prefixHash ‖ witnessHash )
//! ```
//!
//! `signScript` is the prevout pkScript being spent (for P2PKH inputs, the
//! 25-byte DUP HASH160 … CHECKSIG script). Only SigHashAll is implemented —
//! a send/receive wallet never needs the other modes.

use alloc::vec::Vec;

use crate::blake256;
use crate::tx::{put_varint, varint_size, MsgTx};
use crate::Error;

/// The SigHashAll hash-type word.
pub const SIGHASH_ALL: u32 = 0x1;

const SIGHASH_SERIALIZE_WITNESS: u32 = 3;

/// The prefix half of the SigHashAll signature hash.
///
/// Under SigHashAll every input and output is committed verbatim, so the bytes
/// hashed here are exactly the prefix serialization — the same bytes
/// [`MsgTx::tx_hash`] hashes. Two consequences, both of which dcrd relies on:
///
///  * the prefix hash **is** the transaction's txid; and
///  * it does not depend on which input is being signed, nor on any signature
///    script (those live in the witness), so it is invariant while a tx is
///    being signed input by input.
///
/// Compute it once and pass it to [`signature_hash_all_cached`], as dcrd's
/// `cachedPrefix` does, so signing each input stops re-serializing and
/// re-hashing the whole prefix. The witness half still covers every input, so
/// signing all N inputs remains O(N²), with a far smaller constant.
pub fn prefix_hash_all(tx: &MsgTx) -> [u8; 32] {
    tx.tx_hash()
}

/// Compute the SigHashAll signature hash for input `idx`, spending a prevout
/// whose pkScript is `sign_script`.
///
/// This recomputes the prefix hash on every call. When signing more than one
/// input, hoist it out with [`prefix_hash_all`] and use
/// [`signature_hash_all_cached`]; the result is identical.
pub fn signature_hash_all(tx: &MsgTx, idx: usize, sign_script: &[u8]) -> Result<[u8; 32], Error> {
    signature_hash_all_cached(tx, idx, sign_script, &prefix_hash_all(tx))
}

/// [`signature_hash_all`] with the input-independent prefix hash supplied by the
/// caller.
///
/// `prefix_hash` must come from [`prefix_hash_all`] for **this** transaction; it
/// is the one part of the sighash that is shared across inputs. Passing a hash
/// from a different transaction produces a signature over that other
/// transaction's inputs and outputs, so treat it as part of the message.
pub fn signature_hash_all_cached(
    tx: &MsgTx,
    idx: usize,
    sign_script: &[u8],
    prefix_hash: &[u8; 32],
) -> Result<[u8; 32], Error> {
    if idx >= tx.tx_in.len() {
        return Err(Error::SigHashIndex);
    }

    // ---- witness hash (commits sign_script for idx, empty for the rest) ----
    let n_in = tx.tx_in.len();
    let mut witness = Vec::with_capacity(
        4 + varint_size(n_in as u64)
            + (n_in - 1)
            + varint_size(sign_script.len() as u64)
            + sign_script.len(),
    );
    let wver = (tx.version as u32) | (SIGHASH_SERIALIZE_WITNESS << 16);
    witness.extend_from_slice(&wver.to_le_bytes());
    put_varint(&mut witness, n_in as u64);
    for i in 0..n_in {
        if i == idx {
            put_varint(&mut witness, sign_script.len() as u64);
            witness.extend_from_slice(sign_script);
        } else {
            put_varint(&mut witness, 0);
        }
    }
    let witness_hash = blake256::sum256(&witness);

    // ---- final hash ----
    let mut buf = [0u8; 4 + 64];
    buf[..4].copy_from_slice(&SIGHASH_ALL.to_le_bytes());
    buf[4..36].copy_from_slice(prefix_hash);
    buf[36..].copy_from_slice(&witness_hash);
    Ok(blake256::sum256(&buf))
}
