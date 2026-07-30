// SPDX-License-Identifier: ISC
//
//! Independent correctness oracle for the sighash + tx parsing path.
//!
//! This is the strongest test in the crate: it takes a REAL Decred mainnet
//! transaction (one the live network already validated and mined), recomputes
//! our `signature_hash_all` for each input, and checks that the signature
//! embedded in the on-chain witness verifies against *our* sighash. If our
//! sighash byte layout disagreed with dcrd by even one byte, the on-chain
//! signature would fail to verify here.
//!
//! Fixtures (mainnet, fetched from dcrdata):
//!   spending tx  37564c16ef112d03c1fd44df93c0fd2703b057580797de6489463bcabfe5d954
//!   both inputs spend P2PKH outputs

use dcr_rs::secp256k1::{ecdsa::Signature, Message, PublicKey, Secp256k1};
use dcr_rs::sighash::signature_hash_all;
use dcr_rs::tx::MsgTx;

// Full (prefix+witness) serialization of the mainnet spending tx.
const SPEND_TX_HEX: &str = "0100000002fb224c02e29fe8ef01db6642ac95859275afb98054bb7ced04afb9a8e1f7a6450100000000ffffffffb74693e2169e31e13cc6f8173cbba1de1ab510c3ad07aebdb4ede4b093a6cfcc0100000000ffffffff02a08601000000000000001976a9143afaebcdfd8cda72e687f0e4f72f8f0a6b14bb9f88ac741d00000000000000001976a914375e93a7837bb62d3d1ce1193476431661bc75ea88ac000000000000000002387601000000000001ab1000100000006a473044022032ee361b77874b6a69dc4764631231b2f571c3f8fc2027972f39a835a694d5e002201502b44f5833c672881cbcf21f2b2f7967b401bda8987f55d5b42b7d9d130a760121034acc9646d41489c7756bfd6e74ef9fb8928a54b27bfb5ca602a26c47af2558b21c3e0000000000000dab1000060000006b483045022100dc8bffcbdfc240195f30e47de9855978f0facd9dba24665fe83781421884a952022020f63bcfc76a80d1c705cf85eeb0b399a2148924e5a13b0ec6c271c7b3bdd6d0012102f1c87bee1183a241b857e97f05d0fac9d0a1ea32b1b0cc59b20e7bd12a986125";

// Prevout pkScript for each input.
const PREVOUT_SCRIPTS: [&str; 2] = [
    "76a91407151738f9d10dd5912dc26e6fc5606daebb43f488ac",
    "76a914a055c8f4f3d5a173d1aa3051fa11c305ab59bd6d88ac",
];

/// Split a standard P2PKH sigScript `PUSH(der||hashtype) PUSH(pubkey)` into its
/// DER signature, the trailing sighash-type byte, and the compressed pubkey.
fn split_sig_script(ss: &[u8]) -> (Vec<u8>, u8, Vec<u8>) {
    let l1 = ss[0] as usize;
    let sig_and_type = &ss[1..1 + l1];
    let hashtype = sig_and_type[l1 - 1];
    let der = sig_and_type[..l1 - 1].to_vec();
    let l2 = ss[1 + l1] as usize;
    let pubkey = ss[2 + l1..2 + l1 + l2].to_vec();
    (der, hashtype, pubkey)
}

#[test]
fn onchain_tx_signatures_verify_against_our_sighash() {
    let secp = Secp256k1::new();
    let tx = MsgTx::parse_full(&hex::decode(SPEND_TX_HEX).unwrap()).expect("parse mainnet tx");
    assert_eq!(tx.tx_in.len(), 2, "fixture has two inputs");

    for (idx, prevout_hex) in PREVOUT_SCRIPTS.iter().enumerate() {
        let prevout_script = hex::decode(prevout_hex).unwrap();
        let (der, hashtype, pubkey) = split_sig_script(&tx.tx_in[idx].signature_script);
        assert_eq!(hashtype, 0x01, "input {idx} is SigHashAll");

        let sighash = signature_hash_all(&tx, idx, &prevout_script).expect("sighash");
        let msg = Message::from_digest(sighash);
        let mut sig = Signature::from_der(&der).expect("der sig");
        sig.normalize_s();
        let pk = PublicKey::from_slice(&pubkey).expect("pubkey");

        secp.verify_ecdsa(&msg, &sig, &pk).unwrap_or_else(|e| {
            panic!("input {idx}: on-chain signature failed against our sighash: {e}")
        });
    }
}

/// Round-trips the same real tx through our parser and serializer: parse_full →
/// serialize_full must reproduce the exact network bytes.
#[test]
fn onchain_tx_serialize_roundtrip() {
    let raw = hex::decode(SPEND_TX_HEX).unwrap();
    let tx = MsgTx::parse_full(&raw).expect("parse");
    assert_eq!(
        tx.serialize_full(),
        raw,
        "serialize_full must be byte-exact"
    );
}

/// Malformed input must fail cleanly: every truncation of the real tx parses
/// to an error (never a panic), and hostile count/length varints are rejected
/// before they can force huge allocations.
#[test]
fn parse_full_rejects_malformed_input() {
    let raw = hex::decode(SPEND_TX_HEX).unwrap();
    for n in 0..raw.len() {
        assert!(MsgTx::parse_full(&raw[..n]).is_err(), "truncated at {n}");
    }

    // Version word claiming 2^64-1 inputs.
    let mut evil = vec![0x01, 0x00, 0x00, 0x00, 0xff];
    evil.extend_from_slice(&u64::MAX.to_le_bytes());
    assert!(MsgTx::parse_full(&evil).is_err());

    // Real tx with the first output's script length inflated to 2^32.
    let mut evil = raw.clone();
    let script_len_pos = 4 + 1 + 2 * 41 + 1 + 8 + 2; // varints + 2 inputs + value + version
    assert_eq!(
        evil[script_len_pos], 0x19,
        "fixture layout check (25-byte script)"
    );
    evil[script_len_pos] = 0xfe;
    assert!(MsgTx::parse_full(&evil).is_err());
}

/// The txid (BLAKE256 of the prefix serialization) must match the network txid.
#[test]
fn onchain_txid_matches() {
    let tx = MsgTx::parse_full(&hex::decode(SPEND_TX_HEX).unwrap()).expect("parse");
    // Network/display txid is the reverse of the internal hash.
    let mut id = tx.tx_hash();
    id.reverse();
    assert_eq!(
        hex::encode(id),
        "37564c16ef112d03c1fd44df93c0fd2703b057580797de6489463bcabfe5d954"
    );
}

/// Non-canonical compact-size varints must be refused, as dcrd's
/// `wire.ReadVarInt` does (`ErrNonCanonicalVarInt`).
///
/// Without this check two distinct byte strings decode to the same transaction,
/// so `parse_full` is not the inverse of `serialize_full` and a signer accepts
/// bytes the network rejects. Re-encoding the real fixture's input count `0x02`
/// as the three-byte `0xfd 0x0002` is the minimal case.
#[test]
fn parse_full_rejects_non_canonical_varints() {
    let raw = hex::decode(SPEND_TX_HEX).unwrap();
    assert_eq!(
        raw[4], 0x02,
        "fixture layout check (2 inputs, 1-byte count)"
    );

    let mut evil = Vec::new();
    evil.extend_from_slice(&raw[..4]);
    evil.extend_from_slice(&[0xfd, 0x02, 0x00]); // 2, encoded non-minimally
    evil.extend_from_slice(&raw[5..]);
    assert!(
        MsgTx::parse_full(&evil).is_err(),
        "a 3-byte encoding of 2 must be refused"
    );

    // The same value in its shortest form still parses.
    assert!(MsgTx::parse_full(&raw).is_ok());

    // And every wider encoding of a small count is refused too.
    for wide in [
        vec![0xfe, 0x02, 0x00, 0x00, 0x00],
        vec![0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    ] {
        let mut evil = Vec::new();
        evil.extend_from_slice(&raw[..4]);
        evil.extend_from_slice(&wide);
        evil.extend_from_slice(&raw[5..]);
        assert!(MsgTx::parse_full(&evil).is_err());
    }
}

/// Trailing bytes after a complete transaction must be refused. They are
/// invisible to `serialize_full`, so accepting them would make `parse_full`
/// non-injective the same way a non-canonical varint does.
#[test]
fn parse_full_rejects_trailing_bytes() {
    let raw = hex::decode(SPEND_TX_HEX).unwrap();
    for tail in [vec![0x00], vec![0xde, 0xad, 0xbe, 0xef]] {
        let mut padded = raw.clone();
        padded.extend_from_slice(&tail);
        assert!(
            MsgTx::parse_full(&padded).is_err(),
            "{} trailing byte(s) must be refused",
            tail.len()
        );
    }
}

/// `parse_prefix` reads the prefix-only serialization, which is all that is
/// needed to recompute a txid — and is ~40% of the bytes of a full transaction,
/// since it carries no signature scripts.
#[test]
fn parse_prefix_reproduces_the_mainnet_txid() {
    let full = MsgTx::parse_full(&hex::decode(SPEND_TX_HEX).unwrap()).expect("parse full");
    let prefix_bytes = full.serialize_prefix();

    let from_prefix = MsgTx::parse_prefix(&prefix_bytes).expect("parse prefix");
    assert_eq!(
        from_prefix.tx_hash(),
        full.tx_hash(),
        "the txid is a function of the prefix alone"
    );
    assert_eq!(from_prefix.tx_out, full.tx_out, "outputs survive verbatim");
    assert_eq!(from_prefix.tx_in.len(), full.tx_in.len());
    for (a, b) in from_prefix.tx_in.iter().zip(&full.tx_in) {
        assert_eq!(a.previous_outpoint, b.previous_outpoint);
        assert_eq!(a.sequence, b.sequence);
    }
    assert_eq!(from_prefix.serialize_prefix(), prefix_bytes, "byte-exact");

    // Strictness applies here too.
    let mut padded = prefix_bytes.clone();
    padded.push(0x00);
    assert!(MsgTx::parse_prefix(&padded).is_err());
    // A full serialization is not a prefix serialization.
    assert!(MsgTx::parse_prefix(&full.serialize_full()).is_err());
}

/// The prefix half of a SigHashAll sighash is the transaction's txid, is
/// independent of which input is signed, and is unaffected by signature scripts
/// (those live in the witness). That is what lets it be hoisted out of the
/// signing loop, turning O(N²) work into O(N).
///
/// Checked against the real mainnet fixture, whose inputs already carry their
/// signature scripts — the case where a stale cache would show up.
#[test]
fn cached_prefix_hash_matches_the_uncached_sighash() {
    use dcr_rs::sighash::{prefix_hash_all, signature_hash_all_cached};

    let mut tx = MsgTx::parse_full(&hex::decode(SPEND_TX_HEX).unwrap()).expect("parse");
    assert!(
        tx.tx_in.iter().all(|i| !i.signature_script.is_empty()),
        "fixture inputs carry signature scripts"
    );

    let prefix = prefix_hash_all(&tx);
    assert_eq!(prefix, tx.tx_hash(), "the prefix hash IS the txid");

    for (idx, prevout_hex) in PREVOUT_SCRIPTS.iter().enumerate() {
        let script = hex::decode(prevout_hex).unwrap();
        assert_eq!(
            signature_hash_all_cached(&tx, idx, &script, &prefix).unwrap(),
            signature_hash_all(&tx, idx, &script).unwrap(),
        );
    }

    // Clearing the signature scripts must not move the prefix hash.
    for ti in tx.tx_in.iter_mut() {
        ti.signature_script.clear();
    }
    assert_eq!(
        prefix_hash_all(&tx),
        prefix,
        "signature scripts are not committed by the prefix"
    );

    // An out-of-range index is still refused on the cached path.
    assert!(signature_hash_all_cached(&tx, 99, &[], &prefix).is_err());
}
