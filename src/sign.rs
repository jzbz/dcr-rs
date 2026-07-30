// SPDX-License-Identifier: ISC
//! ECDSA signing for Decred P2PKH inputs.
//!
//! Standard Decred spends use DER-encoded ECDSA secp256k1 signatures with the
//! sighash-type byte appended, pushed alongside the compressed pubkey:
//! `sigScript = PUSH(der_sig ‖ hashType) PUSH(compressed_pubkey)`.
//!
//! Signatures are RFC6979-deterministic and low-S normalized (consensus
//! requires canonical S; the `secp256k1` crate normalizes on signing).

use alloc::vec::Vec;

use secp256k1::{ecdsa::Signature, All, Message, PublicKey, Secp256k1, SecretKey};

use crate::address::p2pkh_script;
use crate::hashing::hash160;
use crate::sighash::{prefix_hash_all, signature_hash_all_cached, SIGHASH_ALL};
use crate::tx::MsgTx;
use crate::Error;

/// Sign input `idx` (P2PKH) and return the complete signature script.
///
/// The public key published in the script is derived from `secret` here rather
/// than supplied by the caller, so the two cannot disagree. `prevout_script` must
/// be the P2PKH script of that key, and is checked: together those make it
/// impossible to produce a well-formed-looking sigScript that does not actually
/// satisfy the script being spent.
///
/// That combination matters because the failure is otherwise invisible. A
/// signature made by key A published alongside key B's pubkey is canonical DER,
/// low-S, and exactly the usual 107 bytes; nothing about it looks wrong until
/// every node rejects the transaction with "false stack entry at end of script
/// execution", or the companion silently drops it and the payment simply never
/// confirms.
///
/// When signing more than one input, use [`sign_p2pkh_input_cached`] so the
/// input-independent half of the sighash is computed once.
pub fn sign_p2pkh_input(
    secp: &Secp256k1<All>,
    tx: &MsgTx,
    idx: usize,
    prevout_script: &[u8],
    secret: &SecretKey,
) -> Result<Vec<u8>, Error> {
    sign_p2pkh_input_cached(secp, tx, idx, prevout_script, secret, &prefix_hash_all(tx))
}

/// [`sign_p2pkh_input`] with the input-independent prefix hash supplied by the
/// caller (see [`prefix_hash_all`]). Signing every input of an N-input
/// transaction this way is O(N) rather than O(N²).
pub fn sign_p2pkh_input_cached(
    secp: &Secp256k1<All>,
    tx: &MsgTx,
    idx: usize,
    prevout_script: &[u8],
    secret: &SecretKey,
    prefix_hash: &[u8; 32],
) -> Result<Vec<u8>, Error> {
    // Derive the pubkey from the signing key, then bind it to the script being
    // spent. One point multiplication and one hash160 — the same multiplication
    // the caller would otherwise have done to build the script.
    let compressed_pubkey = PublicKey::from_secret_key(secp, secret).serialize();
    if prevout_script != p2pkh_script(&hash160(&compressed_pubkey)) {
        return Err(Error::ScriptMismatch);
    }

    let sighash = signature_hash_all_cached(tx, idx, prevout_script, prefix_hash)?;
    let msg = Message::from_digest(sighash);
    let mut sig: Signature = secp.sign_ecdsa(&msg, secret);
    // Defense in depth — normalize even though sign_ecdsa already produces low-S.
    sig.normalize_s();

    Ok(build_sig_script(&sig, &compressed_pubkey))
}

/// `PUSH(der ‖ hashType) PUSH(pubkey)` with canonical single-byte pushes (a DER
/// signature is at most 72 bytes and a compressed pubkey is 33, so both operands
/// are < 76 and the length byte *is* the push opcode).
fn build_sig_script(sig: &Signature, pubkey: &[u8; 33]) -> Vec<u8> {
    let der = sig.serialize_der();
    debug_assert!(der.len() + 1 < 76);
    let mut s = Vec::with_capacity(1 + der.len() + 1 + 1 + pubkey.len());
    s.push((der.len() + 1) as u8);
    s.extend_from_slice(&der);
    s.push(SIGHASH_ALL as u8);
    s.push(pubkey.len() as u8);
    s.extend_from_slice(pubkey);
    s
}
