// SPDX-License-Identifier: ISC
//
//! Tests for the air-gap package and the trustless-review logic — the security
//! core of the format. Covers: CBOR round-trip + version gating, ownership
//! classification (change vs recipient vs mislabelled-change), pre-sign input
//! validation, end-to-end signing self-consistency, and the anti-tamper
//! prev_script tripwire.

#![cfg(all(feature = "airgap", feature = "mnemonic"))]

use dcr_rs::address::p2pkh_script;
use dcr_rs::airgap::{
    decode_sign_request, encode_sign_request, sign_request, InputMeta, OutputMeta, SignRequest,
    FORMAT_VERSION,
};
use dcr_rs::hashing::hash160;
use dcr_rs::hd::{ExtPrivKey, ExtPubKey, BRANCH_EXTERNAL, BRANCH_INTERNAL};
use dcr_rs::secp256k1::{ecdsa::Signature, Message, PublicKey, Secp256k1};
use dcr_rs::sighash::signature_hash_all;
use dcr_rs::tx::{MsgTx, OutPoint, TxIn, TxOut};
use dcr_rs::{Error, Network};

const ENTROPY_HEX: &str = "348360ae0a69b1883b0dfc060136108dfcabe9f4bf8af3e866b742fb53f1caa5";

fn master() -> ExtPrivKey {
    let entropy = hex::decode(ENTROPY_HEX).unwrap();
    ExtPrivKey::from_entropy(&entropy, "", Network::Mainnet).unwrap()
}

fn account_pub(secp: &Secp256k1<dcr_rs::secp256k1::All>, m: &ExtPrivKey) -> ExtPubKey {
    m.account_key(secp, 0).unwrap().neuter(secp)
}

/// A 25-byte P2PKH script that is NOT ours (arbitrary hash160).
fn foreign_script(tag: u8) -> Vec<u8> {
    p2pkh_script(&[tag; 20]).to_vec()
}

/// Build a funding transaction whose output 0 pays `value` to `script`, and
/// return `(txid, serialized)`.
///
/// Format version 3 requires every input to carry the PREFIX serialization of the
/// transaction that created its prevout, and the device recomputes the txid from
/// those bytes. So a fixture
/// can no longer use an arbitrary `prev_hash` like `[9u8; 32]` — the hash has to
/// belong to a real transaction that really does pay the declared amount to the
/// declared script. That is the whole point of the change.
fn funding_for(value: i64, script: &[u8]) -> ([u8; 32], Vec<u8>) {
    let tx = MsgTx {
        version: 1,
        tx_in: vec![TxIn {
            previous_outpoint: OutPoint {
                hash: [0u8; 32],
                index: 0xffff_ffff,
                tree: 0,
            },
            sequence: 0xffff_ffff,
            value_in: value,
            block_height: 0,
            block_index: 0xffff_ffff,
            signature_script: vec![0x00],
        }],
        tx_out: vec![TxOut {
            value,
            version: 0,
            pk_script: script.to_vec(),
        }],
        lock_time: 0,
        expiry: 0,
    };
    (tx.tx_hash(), tx.serialize_prefix())
}

/// A funding transaction with TWO outputs, both paying `script`, so a fixture can
/// legitimately spend index 0 and index 1 of the same transaction. Needed because
/// verification now checks that `prev_index` actually exists in `prev_tx_prefix`.
fn funding_two_outputs(value: i64, script: &[u8]) -> ([u8; 32], Vec<u8>) {
    let out = || TxOut {
        value,
        version: 0,
        pk_script: script.to_vec(),
    };
    let tx = MsgTx {
        version: 1,
        tx_in: vec![TxIn {
            previous_outpoint: OutPoint {
                hash: [0u8; 32],
                index: 0xffff_ffff,
                tree: 0,
            },
            sequence: 0xffff_ffff,
            value_in: value * 2,
            block_height: 0,
            block_index: 0xffff_ffff,
            signature_script: vec![0x00],
        }],
        tx_out: vec![out(), out()],
        lock_time: 0,
        expiry: 0,
    };
    (tx.tx_hash(), tx.serialize_prefix())
}

/// An external recipient output: no derivation path, so the device files it under
/// the headline amount.
fn recipient(value: i64, pk_script: Vec<u8>) -> OutputMeta {
    OutputMeta {
        value,
        version: 0,
        pk_script,
        is_change: false,
        branch: None,
        index: None,
    }
}

/// A change output, carrying the path that proves the device owns it.
fn change_at(value: i64, pk_script: Vec<u8>, branch: u32, index: u32) -> OutputMeta {
    OutputMeta {
        value,
        version: 0,
        pk_script,
        is_change: true,
        branch: Some(branch),
        index: Some(index),
    }
}

fn basic_request(prev_script: Vec<u8>, outputs: Vec<OutputMeta>) -> SignRequest {
    let value_in = 100_000;
    let (prev_hash, prev_prefix) = funding_for(value_in, &prev_script);
    SignRequest {
        format_version: FORMAT_VERSION,
        tx_version: 1,
        account: 0,
        lock_time: 0,
        expiry: 0,
        inputs: vec![InputMeta {
            prev_hash,
            prev_index: 0,
            tree: 0,
            sequence: 0xffff_ffff,
            value_in,
            branch: 0,
            index: 0,
            prev_script,
            prev_tx_prefix: Some(prev_prefix),
        }],
        outputs,
        account_fp: None,
    }
}

#[test]
fn cbor_roundtrip_and_version_gate() {
    let req = basic_request(
        foreign_script(0xaa),
        vec![OutputMeta {
            value: 12000,
            version: 0,
            pk_script: foreign_script(0xbb),
            is_change: false,
            branch: None,
            index: None,
        }],
    );
    let bytes = encode_sign_request(&req).unwrap();
    let back = decode_sign_request(&bytes).unwrap();
    assert_eq!(back.inputs.len(), 1);
    assert_eq!(back.outputs[0].value, 12000);
    assert_eq!(back.inputs[0].value_in, 100_000);

    // A package declaring an unknown FORMAT_VERSION must be rejected.
    let mut bad = req;
    bad.format_version = FORMAT_VERSION + 1;
    let bad_bytes = encode_sign_request(&bad).unwrap();
    assert!(matches!(
        decode_sign_request(&bad_bytes),
        Err(Error::UnsupportedVersion)
    ));
}

/// Pins the exact CBOR layout of a format version 3 package.
///
/// The version 1 form of this test compared against bytes produced by the KeyOS
/// `decred-core` encoder, which made it a genuine cross-implementation interop
/// check. Versions 2 and 3 each changed the layout, and no KeyOS encoder speaks
/// either yet, so these bytes are generated by dcr-rs itself: a regression pin
/// against accidental layout drift, NOT proof of interop.
///
/// The byte-string headers are the point of version 3: `5820` (bytes(32)) for
/// prev_hash where version 2 emitted `9820` (array(32) of one-or-two-byte ints),
/// and `46`/`44` byte strings for the scripts.
///
/// MUST be regenerated from KeyOS `decred-core` once that side speaks version 3,
/// restoring the cross-check. Until then, treat agreement with KeyOS as unverified.
///
/// This request is shaped for layout coverage, not validity — `prev_tx_prefix` here
/// is a placeholder rather than a prefix hashing to `prev_hash`, since
/// `encode_sign_request` does no validation. Semantic checks live in the
/// verify/review tests.
#[test]
fn cbor_layout_pins_v3_encoding() {
    const GOLDEN_HEX: &str = "87030100001a00067932818958200707070707070707070707070707\
                              07070707070707070707070707070707070701001affffffff1a075b\
                              cd1500054676a914aa88ac44deadbeef81861a05f5e100004676a914\
                              bb88acf50107";
    let req = SignRequest {
        format_version: FORMAT_VERSION,
        tx_version: 1,
        account: 0,
        lock_time: 0,
        expiry: 424242,
        inputs: vec![InputMeta {
            prev_hash: [7u8; 32],
            prev_index: 1,
            tree: 0,
            sequence: 0xffff_ffff,
            value_in: 123_456_789,
            branch: 0,
            index: 5,
            prev_script: vec![0x76, 0xa9, 0x14, 0xaa, 0x88, 0xac],
            prev_tx_prefix: Some(vec![0xde, 0xad, 0xbe, 0xef]),
        }],
        outputs: vec![OutputMeta {
            value: 100_000_000,
            version: 0,
            pk_script: vec![0x76, 0xa9, 0x14, 0xbb, 0x88, 0xac],
            is_change: true,
            branch: Some(1),
            index: Some(7),
        }],
        account_fp: None,
    };
    let golden: String = GOLDEN_HEX.split_whitespace().collect();
    assert_eq!(hex::encode(encode_sign_request(&req).unwrap()), golden);

    let back = decode_sign_request(&hex::decode(golden).unwrap()).unwrap();
    assert_eq!(back.expiry, 424242);
    assert_eq!(back.inputs[0].index, 5);
    assert_eq!(
        back.inputs[0].prev_tx_prefix.as_deref(),
        Some(&[0xde, 0xad, 0xbe, 0xef][..])
    );
    assert!(back.outputs[0].is_change);
    assert_eq!(back.outputs[0].branch, Some(1));
    assert_eq!(back.outputs[0].index, Some(7));
}

/// THE test for the reason the funding-transaction check exists: an understated
/// amount must be
/// refused.
///
/// Decred's sighash does not commit to input amounts, and dcrd's mempool
/// substitutes the true value from the utxo set before computing the fee. So a
/// companion that declares a small `value_in` gets a small fee on screen and a
/// huge one on chain, with the difference paid to the miner. Under version 1 no
/// device-side check could see it, because every number came from the companion.
///
/// Here the funding transaction pays 100 DCR while the package claims 10.01 DCR —
/// exactly the scenario from the review — and verification must reject it.
#[test]
fn verify_prev_txs_refuses_understated_input_amount() {
    const TRUE_VALUE: i64 = 100 * 100_000_000; // 100 DCR
    const CLAIMED: i64 = 1_001_000_000; // 10.01 DCR

    let script = foreign_script(0x11);
    let (prev_hash, prev_prefix) = funding_for(TRUE_VALUE, &script);

    let mut req = basic_request(script, vec![recipient(1_000_000_000, foreign_script(0xcc))]);
    req.inputs[0].prev_hash = prev_hash;
    req.inputs[0].prev_tx_prefix = Some(prev_prefix);
    req.inputs[0].value_in = CLAIMED;

    // The declared fee looks tiny and plausible — precisely why version 1 could
    // not catch this. Every term the old checks saw is internally consistent.
    assert_eq!(req.input_total() - req.output_total(), 1_000_000);

    // Refused by verify_prev_txs directly...
    match req.verify_prev_txs() {
        Err(Error::InvalidRequest(msg)) => assert!(
            msg.contains("amount"),
            "must reject on the amount mismatch: {msg}"
        ),
        other => panic!("understated value_in must be refused, got {other:?}"),
    }

    // ...and, critically, by validate() itself. Verification lives inside the gate
    // every entry point already calls, so the display path cannot show unverified
    // amounts and the signer cannot sign them, even if a caller forgets to ask.
    match req.validate() {
        Err(Error::InvalidRequest(msg)) => assert!(msg.contains("amount"), "got: {msg}"),
        other => panic!("validate must refuse an unverifiable amount, got {other:?}"),
    }

    // And therefore the signer refuses too, without needing its own check.
    assert!(matches!(
        sign_request(&Secp256k1::new(), &master(), &req),
        Err(Error::InvalidRequest(_))
    ));
}

/// The rest of the prev_tx_prefix tripwire: a funding transaction that does not hash to
/// the declared prevout, an index past its outputs, and a script that disagrees.
#[test]
fn verify_prev_txs_refuses_wrong_hash_index_and_script() {
    let script = foreign_script(0x11);
    let value = 100_000;

    // Wrong hash: real funding tx, but prev_hash points elsewhere.
    let (_, prev_prefix) = funding_for(value, &script);
    let mut req = basic_request(
        script.clone(),
        vec![recipient(99_000, foreign_script(0xcc))],
    );
    req.inputs[0].prev_hash = [0xab; 32];
    req.inputs[0].prev_tx_prefix = Some(prev_prefix.clone());
    assert!(
        matches!(req.verify_prev_txs(), Err(Error::InvalidRequest(m)) if m.contains("hash")),
        "prev_tx_prefix must hash to the declared prevout"
    );

    // Index past the end of the funding transaction's outputs.
    let (prev_hash, prev_prefix) = funding_for(value, &script);
    let mut req = basic_request(
        script.clone(),
        vec![recipient(99_000, foreign_script(0xcc))],
    );
    req.inputs[0].prev_hash = prev_hash;
    req.inputs[0].prev_tx_prefix = Some(prev_prefix);
    req.inputs[0].prev_index = 7;
    assert!(
        matches!(req.verify_prev_txs(), Err(Error::InvalidRequest(m)) if m.contains("prev_index")),
        "prev_index past the end must be refused"
    );

    // Script disagreement: funding tx pays a different script than claimed.
    let (prev_hash, prev_prefix) = funding_for(value, &foreign_script(0x22));
    let mut req = basic_request(script, vec![recipient(99_000, foreign_script(0xcc))]);
    req.inputs[0].prev_hash = prev_hash;
    req.inputs[0].prev_tx_prefix = Some(prev_prefix);
    assert!(
        matches!(req.verify_prev_txs(), Err(Error::InvalidRequest(m)) if m.contains("script")),
        "declared prev_script must match the funding output"
    );

    // Unparseable bytes are refused rather than panicking.
    let mut req = basic_request(
        foreign_script(0x11),
        vec![recipient(99_000, foreign_script(0xcc))],
    );
    req.inputs[0].prev_tx_prefix = Some(vec![0xde, 0xad]);
    assert!(matches!(
        req.verify_prev_txs(),
        Err(Error::InvalidRequest(_))
    ));
}

/// An honest package must pass verification end to end.
#[test]
fn verify_prev_txs_accepts_an_honest_package() {
    let script = foreign_script(0x11);
    let req = basic_request(script, vec![recipient(99_000, foreign_script(0xcc))]);
    req.validate().expect("valid");
    req.verify_prev_txs()
        .expect("honest package verifies against its funding transaction");
}

/// A change output carrying a path that really derives to it is classified as
/// change, and a genuine recipient is classified as a recipient.
///
/// Note the index used: 900, far beyond the +20 window the old address scan
/// derived from the highest *input* index (0). Under that scan this output was
/// misfiled as an external recipient AND simultaneously reported as evidence of a
/// hostile companion — against the user's own address. Proving one supplied path
/// makes the wallet's usage depth irrelevant, so this is the regression test for
/// that bug.
#[test]
fn review_owned_proves_change_at_any_index() {
    let secp = Secp256k1::new();
    let m = master();
    let acct = m.account_key(&secp, 0).unwrap();

    let own = acct.address_key(&secp, BRANCH_INTERNAL, 900).unwrap();
    let own_script = p2pkh_script(&hash160(&own.compressed_pubkey(&secp))).to_vec();
    let input_key = acct.address_key(&secp, BRANCH_EXTERNAL, 0).unwrap();
    let input_script = p2pkh_script(&hash160(&input_key.compressed_pubkey(&secp))).to_vec();

    let mut req = basic_request(
        input_script,
        vec![
            change_at(1_000, own_script, BRANCH_INTERNAL, 900),
            recipient(5_000, foreign_script(0xcc)),
        ],
    );
    let value_in = 10_000;
    let (prev_hash, prev_prefix) = funding_for(value_in, &req.inputs[0].prev_script);
    req.inputs[0].value_in = value_in;
    req.inputs[0].prev_hash = prev_hash;
    req.inputs[0].prev_tx_prefix = Some(prev_prefix);

    req.validate().expect("well-formed v3 package");
    let summary = req.review_owned(&secp, &account_pub(&secp, &m)).unwrap();
    assert_eq!(
        summary.change.iter().map(|c| c.1).sum::<i64>(),
        1_000,
        "change at index 900 is proven, not guessed"
    );
    assert_eq!(summary.recipients.len(), 1);
    assert_eq!(summary.recipients[0].1, 5_000);
    assert_eq!(summary.fee, value_in - (1_000 + 5_000));
    assert!(summary.recipients.iter().all(|r| r.0.starts_with("Ds")));
}

/// Claiming a foreign output is change must be REFUSED, not merely flagged.
///
/// Two ways a companion can try it, both fatal:
///   * `is_change` set with no path — `validate` refuses, because version 3
///     requires the two to agree.
///   * a path supplied that does not derive to the output's script —
///     `review_owned` refuses with [`Error::ScriptMismatch`].
///
/// Under the old scan this was a soft `flagged_mismatches` entry the UI had to
/// render and the user had to heed. Now it cannot reach the screen at all.
#[test]
fn review_owned_refuses_mislabelled_change() {
    let secp = Secp256k1::new();
    let m = master();
    let account = account_pub(&secp, &m);
    let acct = m.account_key(&secp, 0).unwrap();
    let input_key = acct.address_key(&secp, BRANCH_EXTERNAL, 0).unwrap();
    let input_script = p2pkh_script(&hash160(&input_key.compressed_pubkey(&secp))).to_vec();

    // (a) is_change without a path.
    let mut claimed = OutputMeta {
        value: 2_000,
        version: 0,
        pk_script: foreign_script(0xdd),
        is_change: true,
        branch: None,
        index: None,
    };
    let req = basic_request(input_script.clone(), vec![claimed.clone()]);
    assert!(
        matches!(req.validate(), Err(Error::InvalidRequest(_))),
        "change output without a derivation path must be refused"
    );

    // (b) a path that derives to some other script.
    claimed.branch = Some(BRANCH_INTERNAL);
    claimed.index = Some(4);
    let req = basic_request(input_script, vec![claimed]);
    req.validate().expect("structurally well-formed");
    assert!(
        matches!(
            req.review_owned(&secp, &account),
            Err(Error::ScriptMismatch)
        ),
        "a path that does not derive to the output must be refused"
    );
}

#[test]
fn check_owned_inputs_accepts_our_own_and_rejects_tampering() {
    let secp = Secp256k1::new();
    let m = master();
    let acct = m.account_key(&secp, 0).unwrap();
    let account = account_pub(&secp, &m);

    let key0 = acct.address_key(&secp, BRANCH_EXTERNAL, 0).unwrap();
    let script0 = p2pkh_script(&hash160(&key0.compressed_pubkey(&secp))).to_vec();
    let outputs = vec![OutputMeta {
        value: 90_000,
        version: 0,
        pk_script: foreign_script(0xee),
        is_change: false,
        branch: None,
        index: None,
    }];

    // A well-formed request from a correct companion passes.
    let good = basic_request(script0.clone(), outputs.clone());
    good.check_owned_inputs(&secp, &account).unwrap();

    // prev_script not re-derivable from our key → tripwire.
    let evil = basic_request(foreign_script(0x11), outputs.clone());
    assert_eq!(
        evil.check_owned_inputs(&secp, &account),
        Err(Error::ScriptMismatch)
    );

    // Stake-tree input, unknown branch, absurd fee: all structurally invalid.
    let mut bad = basic_request(script0.clone(), outputs.clone());
    bad.inputs[0].tree = 1;
    assert!(matches!(
        bad.check_owned_inputs(&secp, &account),
        Err(Error::InvalidRequest(_))
    ));

    let mut bad = basic_request(script0.clone(), outputs.clone());
    bad.inputs[0].branch = 2;
    assert!(matches!(
        bad.check_owned_inputs(&secp, &account),
        Err(Error::InvalidRequest(_))
    ));

    let mut bad = basic_request(script0, outputs);
    bad.outputs[0].value = 200_000; // exceeds the 100_000 input
    assert!(matches!(
        bad.check_owned_inputs(&secp, &account),
        Err(Error::InvalidRequest(_))
    ));
}

#[test]
fn sign_request_is_self_consistent_and_low_s() {
    let secp = Secp256k1::new();
    let m = master();
    let acct = m.account_key(&secp, 0).unwrap();
    let key0 = acct.address_key(&secp, BRANCH_EXTERNAL, 0).unwrap();
    let pk0 = key0.compressed_pubkey(&secp);
    let script0 = p2pkh_script(&hash160(&pk0)).to_vec();

    let req = basic_request(
        script0.clone(),
        vec![OutputMeta {
            value: 90_000,
            version: 0,
            pk_script: foreign_script(0xee),
            is_change: false,
            branch: None,
            index: None,
        }],
    );

    let signed = sign_request(&secp, &m, &req).unwrap();
    let tx = MsgTx::parse_full(&signed).unwrap();

    // Extract sig + pubkey from the produced sigScript and verify it against the
    // sighash we recompute — proves sign and sighash agree end to end.
    let ss = &tx.tx_in[0].signature_script;
    let l1 = ss[0] as usize;
    let hashtype = ss[l1]; // last byte of the first push
    let der = &ss[1..l1];
    let l2 = ss[1 + l1] as usize;
    let pubkey = &ss[2 + l1..2 + l1 + l2];
    assert_eq!(hashtype, 0x01, "SigHashAll");
    assert_eq!(pubkey, &pk0[..], "signs with the re-derived key");

    let sighash = signature_hash_all(&tx, 0, &script0).unwrap();
    let mut sig = Signature::from_der(der).unwrap();
    let pk = PublicKey::from_slice(pubkey).unwrap();
    secp.verify_ecdsa(&Message::from_digest(sighash), &sig, &pk)
        .expect("self-produced signature verifies");

    // Already low-S, so normalizing is a no-op (consensus requires canonical S).
    let before = sig;
    sig.normalize_s();
    assert_eq!(before, sig, "signature is already low-S");
}

#[test]
fn check_owned_inputs_refuses_hostile_amounts() {
    let secp = Secp256k1::new();
    let m = master();
    let account = account_pub(&secp, &m);
    let key0 = m
        .account_key(&secp, 0)
        .unwrap()
        .address_key(&secp, BRANCH_EXTERNAL, 0)
        .unwrap();
    let script0 = p2pkh_script(&hash160(&key0.compressed_pubkey(&secp))).to_vec();
    let outputs = vec![OutputMeta {
        value: 90_000,
        version: 0,
        pk_script: foreign_script(0xee),
        is_change: false,
        branch: None,
        index: None,
    }];

    // Single amount above max supply.
    let mut bad = basic_request(script0.clone(), outputs.clone());
    bad.inputs[0].value_in = dcr_rs::airgap::MAX_ATOMS + 1;
    assert!(matches!(
        bad.check_owned_inputs(&secp, &account),
        Err(Error::InvalidRequest(_))
    ));

    // Two i64::MAX outputs wrap a naive i64 sum to negative, which would
    // sneak past a wrapping fee check; the exact-sum comparison plus the
    // per-amount cap must both refuse.
    let mut bad = basic_request(script0, outputs);
    bad.outputs = alloc_two_huge_outputs();
    assert!(matches!(
        bad.check_owned_inputs(&secp, &account),
        Err(Error::InvalidRequest(_))
    ));
    // The public totals saturate rather than wrapping negative.
    assert_eq!(bad.output_total(), i64::MAX);
}

fn alloc_two_huge_outputs() -> Vec<OutputMeta> {
    let huge = |tag| OutputMeta {
        value: i64::MAX,
        version: 0,
        pk_script: foreign_script(tag),
        is_change: false,
        branch: None,
        index: None,
    };
    vec![huge(0xaa), huge(0xbb)]
}

#[test]
fn sign_request_refuses_out_of_schema_paths() {
    let secp = Secp256k1::new();
    let m = master();
    let outputs = vec![OutputMeta {
        value: 90_000,
        version: 0,
        pk_script: foreign_script(0xee),
        is_change: false,
        branch: None,
        index: None,
    }];

    // Even without check_owned_inputs, the signer itself must refuse
    // non-wallet branches, hardened indices, and stake-tree inputs.
    let mut req = basic_request(foreign_script(0x11), outputs.clone());
    req.inputs[0].branch = 2;
    assert!(matches!(
        sign_request(&secp, &m, &req),
        Err(Error::InvalidRequest(_))
    ));

    let mut req = basic_request(foreign_script(0x11), outputs.clone());
    req.inputs[0].index = 0x8000_0000;
    assert!(matches!(
        sign_request(&secp, &m, &req),
        Err(Error::InvalidRequest(_))
    ));

    let mut req = basic_request(foreign_script(0x11), outputs);
    req.inputs[0].tree = 1;
    assert!(matches!(
        sign_request(&secp, &m, &req),
        Err(Error::InvalidRequest(_))
    ));
}

/// Wire fixtures lifted from the deployed KeyOS/Pulse interop: a 7-element
/// (pre-fingerprint) package must decode with `account_fp = None`, an
/// 8-element package must carry it, and encoding must stay byte-stable in
/// both directions (trailing `None` is trimmed, so old decoders keep working).
mod fp_compat {
    use super::*;

    /// The hardcoded version 1 fixtures this module used are gone: version 1 is
    /// refused outright now, so bytes declaring it can only ever assert
    /// `UnsupportedVersion`. That refusal is covered by
    /// [`refuses_version_one_packages`] below.
    ///
    /// What still matters here is the mechanism those fixtures exercised —
    /// minicbor omits trailing `None` fields, so a package without `account_fp`
    /// encodes one element shorter and must still decode. Version 2 leans on that
    /// same behaviour for `prev_tx_prefix`, `branch` and `index`, which is why it is worth
    /// pinning rather than assuming.
    fn with_fp(fp: Option<[u8; 4]>) -> SignRequest {
        let mut req = basic_request(
            foreign_script(0x11),
            vec![recipient(99_000, foreign_script(0xee))],
        );
        req.account_fp = fp;
        req
    }

    #[test]
    fn omitting_account_fp_shortens_the_array_and_still_decodes() {
        let without = encode_sign_request(&with_fp(None)).unwrap();
        let with = encode_sign_request(&with_fp(Some([1, 2, 3, 4]))).unwrap();

        // Trailing None is omitted entirely: 7 elements vs 8.
        assert_eq!(without[0], 0x87, "no fingerprint => 7-element array");
        assert_eq!(with[0], 0x88, "fingerprint present => 8-element array");

        assert_eq!(decode_sign_request(&without).unwrap().account_fp, None);
        assert_eq!(
            decode_sign_request(&with).unwrap().account_fp,
            Some([1, 2, 3, 4])
        );
    }

    #[test]
    fn both_forms_roundtrip_and_validate() {
        for fp in [None, Some([1u8, 2, 3, 4])] {
            let req = with_fp(fp);
            let bytes = encode_sign_request(&req).unwrap();
            let back = decode_sign_request(&bytes).unwrap();
            assert_eq!(back.account_fp, fp);
            back.validate().expect("fixture is economically valid");
            assert_eq!(
                hex::encode(encode_sign_request(&back).unwrap()),
                hex::encode(&bytes)
            );
        }
    }

    /// Version 1 must be refused, not silently downgraded to an unverified path.
    /// The sender picks the version, so accepting version 1 would let a hostile
    /// companion opt out of `prev_tx_prefix` verification entirely and reopen the
    /// amount-understatement attack.
    #[test]
    fn refuses_version_one_packages() {
        let mut req = with_fp(None);
        req.format_version = 1;
        let bytes = encode_sign_request(&req).unwrap();
        assert!(matches!(
            decode_sign_request(&bytes),
            Err(Error::UnsupportedVersion)
        ));
    }

    /// A device must not accept bytes it never looked at. `minicbor::decode`
    /// stops at the end of the top-level item, so without the position check in
    /// `decode_sign_request` every case below decodes as if the suffix were not
    /// there.
    #[test]
    fn refuses_trailing_bytes_after_the_package() {
        let bytes = encode_sign_request(&with_fp(None)).unwrap();
        decode_sign_request(&bytes).expect("the unpadded package decodes");

        // A second CBOR item (a transport concatenation bug) and dead padding
        // (a caller passing its whole scratch buffer) are the two real shapes.
        for suffix in [&[0xf6u8][..], &[0x00, 0x00, 0x00][..]] {
            let mut padded = bytes.clone();
            padded.extend_from_slice(suffix);
            assert!(matches!(
                decode_sign_request(&padded),
                Err(Error::InvalidRequest("trailing bytes after package"))
            ));
        }

        // What the check must NOT break: an unknown element INSIDE the array
        // still decodes, which is the forward compatibility `account_fp` relies
        // on. Splice the 8-element header to 9 and append the extra element.
        let mut longer = encode_sign_request(&with_fp(Some([1, 2, 3, 4]))).unwrap();
        assert_eq!(longer[0], 0x88);
        longer[0] = 0x89;
        longer.push(0xf6);
        assert_eq!(
            decode_sign_request(&longer).unwrap().account_fp,
            Some([1, 2, 3, 4])
        );
    }
}

#[test]
fn validate_refuses_duplicate_inputs_and_oversized_packages() {
    // Sized so that two 100_000 inputs leave a 1_000 fee. The absurd-fee ceiling
    // now rejects a package whose fee is a large share of its inputs, so a fixture
    // with an unrealistic fee would make these assertions pass for the wrong
    // reason — the duplicate-input check must be what fires, not the fee check.
    let outputs = vec![OutputMeta {
        value: 199_000,
        version: 0,
        pk_script: foreign_script(0xee),
        is_change: false,
        branch: None,
        index: None,
    }];

    // The same outpoint listed twice inflates the apparent input total and
    // understates the fee a reviewer sees — must refuse, and specifically for
    // that reason.
    let mut req = basic_request(foreign_script(0x11), outputs.clone());
    let dup = req.inputs[0].clone();
    req.inputs.push(dup);
    match req.validate() {
        Err(Error::InvalidRequest(msg)) => {
            assert!(
                msg.contains("same coin"),
                "must fail on the duplicate, not something else: {msg}"
            )
        }
        other => panic!("expected duplicate-input refusal, got {other:?}"),
    }
    assert!(matches!(
        sign_request(&Secp256k1::new(), &master(), &req),
        Err(Error::InvalidRequest(_))
    ));

    // Same prevout hash but a different index is a legitimate spend of two
    // outputs of one funding tx. The funding transaction must genuinely have two
    // outputs now, since verification checks prev_index against it.
    let script = foreign_script(0x11);
    let (prev_hash, prev_prefix) = funding_two_outputs(100_000, &script);
    let mut req = basic_request(script, outputs.clone());
    req.inputs[0].prev_hash = prev_hash;
    req.inputs[0].prev_tx_prefix = Some(prev_prefix.clone());
    let mut second = req.inputs[0].clone();
    second.prev_index = 1;
    req.inputs.push(second);
    req.validate().expect("distinct outpoints are fine");

    // More inputs than MAX_INPUTS: refused before any derivation work.
    let mut req = basic_request(foreign_script(0x11), outputs);
    let template = req.inputs[0].clone();
    req.inputs = (0..=dcr_rs::airgap::MAX_INPUTS as u32)
        .map(|i| {
            let mut input = template.clone();
            input.prev_index = i; // keep outpoints distinct
            input
        })
        .collect();
    assert!(matches!(req.validate(), Err(Error::InvalidRequest(_))));
}

#[test]
fn sign_request_refuses_prev_script_mismatch() {
    let secp = Secp256k1::new();
    let m = master();

    // prev_script claims a different address than the key at branch/index owns:
    // the anti-tamper tripwire must fire instead of signing.
    let req = basic_request(
        foreign_script(0x11), // not the script for m/44'/42'/0'/0/0
        vec![OutputMeta {
            value: 90_000,
            version: 0,
            pk_script: foreign_script(0xee),
            is_change: false,
            branch: None,
            index: None,
        }],
    );

    assert_eq!(sign_request(&secp, &m, &req), Err(Error::ScriptMismatch));
}

// ---------------------------------------------------------------------------
// Regression tests for the review pass. Each of these failed before the fix
// named in its doc comment.
// ---------------------------------------------------------------------------

/// `review_owned` must validate its own input.
///
/// It was the only entry point that did not, relying on a doc comment telling
/// callers to run `validate` first — and it is the one path whose entire job is
/// putting amounts in front of a human. On an unvalidated package its
/// `input_total - output_total` overflowed: inputs saturating to `i64::MAX` and
/// outputs to `i64::MIN` panicked in debug and, worse, silently wrapped in
/// release, so the fee on screen was arbitrary.
#[test]
fn review_owned_validates_its_own_input() {
    let secp = Secp256k1::new();
    let m = master();
    let account = account_pub(&secp, &m);

    let saturating_input = |tag: u8| InputMeta {
        prev_hash: [tag; 32],
        prev_index: 0,
        tree: 0,
        sequence: 0,
        value_in: i64::MAX,
        branch: BRANCH_EXTERNAL,
        index: 0,
        prev_script: Vec::new(),
        prev_tx_prefix: None,
    };
    let req = SignRequest {
        format_version: FORMAT_VERSION,
        tx_version: 1,
        account: 0,
        lock_time: 0,
        expiry: 0,
        inputs: vec![saturating_input(1), saturating_input(2)],
        outputs: vec![
            recipient(i64::MIN, foreign_script(0xaa)),
            recipient(i64::MIN, foreign_script(0xbb)),
        ],
        account_fp: None,
    };

    // Must be a clean refusal, not a panic and not a wrapped fee.
    assert!(
        matches!(
            req.review_owned(&secp, &account),
            Err(Error::InvalidRequest(_))
        ),
        "the display path must refuse a package whose math cannot be honest"
    );
}

/// `sign_request` must re-prove change ownership itself.
///
/// `validate` only checks that a change output *carries* a path in range, never
/// that the path derives to the script; that proof lived solely in
/// `review_owned`. So a caller that skipped the review step — which the signer
/// explicitly does not assume, hence its duplicated input checks — could be
/// walked into signing an attacker's address labelled as its own change.
#[test]
fn sign_request_reproves_change_ownership() {
    let secp = Secp256k1::new();
    let m = master();
    let acct = m.account_key(&secp, 0).unwrap();
    let input_key = acct.address_key(&secp, BRANCH_EXTERNAL, 0).unwrap();
    let input_script = p2pkh_script(&hash160(&input_key.compressed_pubkey(&secp))).to_vec();

    // An in-range path, but pointing at a script that is not ours.
    let req = basic_request(
        input_script,
        vec![change_at(90_000, foreign_script(0xcc), BRANCH_INTERNAL, 5)],
    );
    req.validate()
        .expect("structurally valid — validate cannot see the lie");
    assert_eq!(
        sign_request(&secp, &m, &req),
        Err(Error::ScriptMismatch),
        "the signer must not sign a foreign output labelled as change"
    );
}

/// The `FORMAT_VERSION` gate has to live in `validate`, not only in
/// `decode_sign_request`: a `SignRequest` can be built directly or decoded by
/// other means, and the whole reason version 1 is refused is that the *sender*
/// must not get to pick the weaker path.
#[test]
fn validate_enforces_the_format_version_gate() {
    let mut req = basic_request(
        foreign_script(0xaa),
        vec![recipient(90_000, foreign_script(0xbb))],
    );
    req.validate().expect("version 2 package is fine");

    for bad in [0, 1, FORMAT_VERSION + 1] {
        req.format_version = bad;
        assert_eq!(
            req.validate(),
            Err(Error::UnsupportedVersion),
            "validate must refuse format version {bad}"
        );
    }
}

/// `account_fp`, when present, is compared against the account key actually
/// supplied. It is a diagnostic — the `prev_script` re-derivation is what
/// protects funds — but it turns "wrong wallet open" into a specific error
/// instead of a late `ScriptMismatch` that reads like tampering.
#[test]
fn account_fp_mismatch_is_reported_as_such() {
    let secp = Secp256k1::new();
    let m = master();
    let account = account_pub(&secp, &m);
    let acct = m.account_key(&secp, 0).unwrap();
    let input_key = acct.address_key(&secp, BRANCH_EXTERNAL, 0).unwrap();
    let input_script = p2pkh_script(&hash160(&input_key.compressed_pubkey(&secp))).to_vec();

    let mut req = basic_request(input_script, vec![recipient(90_000, foreign_script(0xbb))]);

    // Absent: no check, everything proceeds.
    assert_eq!(req.check_account_fp(&account), Ok(()));

    // Correct: accepted.
    req.account_fp = Some(account.fingerprint());
    assert_eq!(req.check_account_fp(&account), Ok(()));
    assert!(req.review_owned(&secp, &account).is_ok());

    // Wrong: a specific error, and the review path surfaces it.
    req.account_fp = Some([0xde, 0xad, 0xbe, 0xef]);
    assert_eq!(req.check_account_fp(&account), Err(Error::AccountMismatch));
    assert!(matches!(
        req.review_owned(&secp, &account),
        Err(Error::AccountMismatch)
    ));
}

/// An oversized CBOR package is refused before minicbor allocates for it.
#[test]
fn decode_rejects_oversized_packages() {
    let huge = vec![0u8; dcr_rs::airgap::MAX_PACKAGE_BYTES + 1];
    assert!(matches!(
        decode_sign_request(&huge),
        Err(Error::InvalidRequest(_))
    ));
}

/// Byte-valued fields must encode as CBOR **byte strings**, not arrays of
/// integers.
///
/// This is the substance of format version 3, and it is worth asserting as a
/// property rather than leaving it to the opaque golden hex above. The obvious
/// way to ask minicbor for this — `#[b(..)]` — does not do it: `b` marks a field
/// as *borrowed* from the input and silently changes nothing for an owned type.
/// Only `#[cbor(n(..), with = "minicbor::bytes")]` works. A revert to either
/// `#[n(..)]` or `#[b(..)]` would still round-trip and still pass every other
/// test in this file, so the encoding is pinned directly.
#[test]
fn byte_fields_encode_as_cbor_byte_strings() {
    let script = p2pkh_script(&[0x9f; 20]).to_vec(); // 25 bytes, high bytes present
    let req = basic_request(script.clone(), vec![recipient(90_000, script)]);
    let bytes = encode_sign_request(&req).unwrap();

    // CBOR major type 2 (byte string), length 32 -> 0x58 0x20. Major type 4
    // (array), length 32 -> 0x98 0x20, which is what version 2 emitted.
    let has = |needle: &[u8]| bytes.windows(needle.len()).any(|w| w == needle);
    assert!(
        has(&[0x58, 0x20]),
        "prev_hash must be a bytes(32) header (0x5820)"
    );
    assert!(
        !has(&[0x98, 0x20]),
        "an array(32) header (0x9820) means the byte-string encoding regressed"
    );
    // A 25-byte script is bytes(25) -> 0x58 0x19; as an array it would be 0x98 0x19.
    assert!(has(&[0x58, 0x19]), "scripts must be bytes(25) (0x5819)");
    assert!(!has(&[0x98, 0x19]), "scripts must not be array(25)");

    // And the whole thing still round-trips.
    let back = decode_sign_request(&bytes).unwrap();
    assert_eq!(back.inputs[0].prev_hash, req.inputs[0].prev_hash);
    assert_eq!(back.outputs[0].pk_script, req.outputs[0].pk_script);

    // Sanity: with high bytes throughout, the int-array form would be far larger.
    // 32 + 25 + 25 bytes of payload cost ~82 bytes as byte strings.
    assert!(
        bytes.len() < 350,
        "unexpectedly large encoding ({} bytes)",
        bytes.len()
    );
}

/// `prev_tx_prefix` must be a PREFIX serialization. A full (prefix+witness)
/// transaction — which is what format version 2 carried — is refused rather than
/// tolerated, so a companion that was not updated fails loudly instead of
/// shipping ~3.5x the bytes for no added verification.
#[test]
fn prev_tx_prefix_refuses_a_full_serialization() {
    let script = p2pkh_script(&[0x31; 20]).to_vec();
    let value = 100_000;

    // The same funding transaction, both ways.
    let tx = MsgTx {
        version: 1,
        tx_in: vec![TxIn {
            previous_outpoint: OutPoint {
                hash: [0u8; 32],
                index: 0xffff_ffff,
                tree: 0,
            },
            sequence: 0xffff_ffff,
            value_in: value,
            block_height: 0,
            block_index: 0xffff_ffff,
            signature_script: vec![0x00],
        }],
        tx_out: vec![TxOut {
            value,
            version: 0,
            pk_script: script.clone(),
        }],
        lock_time: 0,
        expiry: 0,
    };

    let mut req = basic_request(
        script.clone(),
        vec![recipient(90_000, foreign_script(0xbb))],
    );
    req.inputs[0].prev_hash = tx.tx_hash();
    req.inputs[0].value_in = value;
    req.inputs[0].prev_script = script;

    // Prefix: accepted.
    req.inputs[0].prev_tx_prefix = Some(tx.serialize_prefix());
    req.verify_prev_txs()
        .expect("a prefix serialization verifies");

    // Full: refused, even though it hashes to the same txid.
    req.inputs[0].prev_tx_prefix = Some(tx.serialize_full());
    assert!(
        matches!(
            req.verify_prev_txs(),
            Err(Error::InvalidRequest(m)) if m.contains("unparseable")
        ),
        "a full serialization must be refused"
    );

    // The prefix really is the smaller half.
    assert!(tx.serialize_prefix().len() < tx.serialize_full().len());
}

/// `review_owned` must prove INPUT ownership, not just output ownership.
///
/// `verify_prev_txs` proves an input's amount is real; it says nothing about whose
/// coin it is. So a foreign input with a genuine funding transaction used to pass
/// review, and `input_total`/`fee` were sums over coins the device had not
/// established it controlled — inflating the total a user is shown and making an
/// outsized fee look proportionate to it. `sign_request` refused later, but a
/// firmware that reviews with dcr-rs and signs with its own code never saw that.
#[test]
fn review_owned_proves_input_ownership() {
    let secp = Secp256k1::new();
    let m = master();
    let account = account_pub(&secp, &m);
    let acct = m.account_key(&secp, 0).unwrap();

    // Input 0: genuinely ours.
    let own_key = acct.address_key(&secp, BRANCH_EXTERNAL, 0).unwrap();
    let own_script = p2pkh_script(&hash160(&own_key.compressed_pubkey(&secp))).to_vec();
    let (own_hash, own_prefix) = funding_for(100_000, &own_script);

    // Input 1: someone else's coin, with a REAL funding transaction, so
    // verify_prev_txs is perfectly happy with it.
    let foreign = p2pkh_script(&[0xcd; 20]).to_vec();
    let (foreign_hash, foreign_prefix) = funding_for(500_000, &foreign);

    let mk = |hash, script: Vec<u8>, prefix, value, index| InputMeta {
        prev_hash: hash,
        prev_index: 0,
        tree: 0,
        sequence: 0xffff_ffff,
        value_in: value,
        branch: BRANCH_EXTERNAL,
        index,
        prev_script: script,
        prev_tx_prefix: Some(prefix),
    };

    let req = SignRequest {
        format_version: FORMAT_VERSION,
        tx_version: 1,
        account: 0,
        lock_time: 0,
        expiry: 0,
        inputs: vec![
            mk(own_hash, own_script, own_prefix, 100_000, 0),
            mk(foreign_hash, foreign, foreign_prefix, 500_000, 1),
        ],
        outputs: vec![recipient(590_000, foreign_script(0xbb))],
        account_fp: None,
    };

    // Structurally fine, and the amounts genuinely check out against the funding
    // transactions — the lie is purely about ownership.
    req.validate()
        .expect("amounts verify; only ownership is false");

    assert!(
        matches!(
            req.review_owned(&secp, &account),
            Err(Error::ScriptMismatch)
        ),
        "the display path must refuse an input it cannot derive"
    );
    // The other two entry points agree.
    assert!(matches!(
        req.check_owned_inputs(&secp, &account),
        Err(Error::ScriptMismatch)
    ));
    assert_eq!(sign_request(&secp, &m, &req), Err(Error::ScriptMismatch));
}

/// The summary must report the transaction's timing fields, because they are
/// signed verbatim and no amount on the screen reveals them.
///
/// A companion can hand over a send whose addresses and amounts review as
/// completely ordinary while its lock time sits far above the current chain
/// height. dcrd calls such a transaction non-final and will not relay it, so the
/// send simply does not happen — nothing is stolen, but a review screen that
/// cannot say so is describing a transaction other than the one being signed.
///
/// The lowered sequence is on the SECOND input on purpose: finality is a property
/// of every input at once, so a check that looked only at the first would call
/// this transaction final.
#[test]
fn review_owned_reports_lock_time_expiry_and_nonfinal_sequence() {
    let secp = Secp256k1::new();
    let m = master();
    let acct = m.account_key(&secp, 0).unwrap();
    let account = account_pub(&secp, &m);
    let key0 = acct.address_key(&secp, BRANCH_EXTERNAL, 0).unwrap();
    let script0 = p2pkh_script(&hash160(&key0.compressed_pubkey(&secp))).to_vec();

    // Two of our own inputs from one funding transaction, 100_000 each, 190_000
    // to a stranger: an entirely ordinary send.
    let (prev_hash, prev_prefix) = funding_two_outputs(100_000, &script0);
    let mut plain = basic_request(script0, vec![recipient(190_000, foreign_script(0xee))]);
    plain.inputs[0].prev_hash = prev_hash;
    plain.inputs[0].prev_tx_prefix = Some(prev_prefix);
    let mut second = plain.inputs[0].clone();
    second.prev_index = 1;
    plain.inputs.push(second);

    let plain_summary = plain.review_owned(&secp, &account).unwrap();
    assert_eq!(plain_summary.lock_time, 0);
    assert_eq!(plain_summary.expiry, 0);
    assert!(
        !plain_summary.has_nonfinal_sequence,
        "every input sits at wire.MaxTxInSequenceNum"
    );

    // The same addresses and the same amounts, delayed: a lock time far above any
    // plausible current height, armed by one input dropped below the maximum.
    let mut delayed = plain.clone();
    delayed.lock_time = 9_000_000;
    delayed.expiry = 9_000_100;
    delayed.inputs[1].sequence = 0xffff_fffe;

    let summary = delayed.review_owned(&secp, &account).unwrap();
    assert_eq!(
        summary.recipients, plain_summary.recipients,
        "everything the old summary showed is byte-for-byte identical"
    );
    assert_eq!(summary.fee, plain_summary.fee);
    assert_eq!(summary.lock_time, 9_000_000);
    assert_eq!(summary.expiry, 9_000_100);
    assert!(
        summary.has_nonfinal_sequence,
        "one input below the maximum makes the whole transaction non-final"
    );

    // And the summary must describe the transaction that is actually SIGNED, not
    // merely echo the request struct back.
    let signed = sign_request(&secp, &m, &delayed).unwrap();
    let tx = MsgTx::parse_full(&signed).unwrap();
    assert_eq!(tx.lock_time, summary.lock_time);
    assert_eq!(tx.expiry, summary.expiry);
    assert_eq!(
        tx.tx_in.iter().any(|i| i.sequence != 0xffff_ffff),
        summary.has_nonfinal_sequence
    );
}

/// `sign_p2pkh_input` derives the published pubkey from the signing key itself, so
/// a signature made by one key can no longer be published alongside another key's
/// pubkey — a combination that produced a canonical, normal-length, completely
/// unspendable sigScript.
#[test]
fn signing_binds_the_key_to_the_script() {
    use dcr_rs::sign::sign_p2pkh_input;

    let secp = Secp256k1::new();
    let m = master();
    let acct = m.account_key(&secp, 0).unwrap();
    let key_a = acct.address_key(&secp, BRANCH_EXTERNAL, 0).unwrap();
    let key_b = acct.address_key(&secp, BRANCH_EXTERNAL, 1).unwrap();
    let script_a = p2pkh_script(&hash160(&key_a.compressed_pubkey(&secp))).to_vec();

    let tx = MsgTx {
        version: 1,
        tx_in: vec![TxIn {
            previous_outpoint: OutPoint {
                hash: [3u8; 32],
                index: 0,
                tree: 0,
            },
            sequence: 0xffff_ffff,
            value_in: 100_000,
            block_height: 0,
            block_index: 0xffff_ffff,
            signature_script: Vec::new(),
        }],
        tx_out: vec![TxOut {
            value: 90_000,
            version: 0,
            pk_script: foreign_script(0xaa),
        }],
        lock_time: 0,
        expiry: 0,
    };

    // The matching key signs, and the sigScript publishes exactly its own pubkey.
    let ss = sign_p2pkh_input(&secp, &tx, 0, &script_a, &key_a.secret).expect("matching key signs");
    let pk_len = ss[ss.len() - 34] as usize;
    assert_eq!(pk_len, 33);
    assert_eq!(
        &ss[ss.len() - 33..],
        &key_a.compressed_pubkey(&secp)[..],
        "the published pubkey must be the signing key's own"
    );

    // A different key for the same script is refused rather than producing a
    // plausible-looking, unspendable script.
    assert_eq!(
        sign_p2pkh_input(&secp, &tx, 0, &script_a, &key_b.secret),
        Err(Error::ScriptMismatch)
    );

    // Out-of-range input index still errors on the un-cached path.
    assert_eq!(
        sign_p2pkh_input(&secp, &tx, 9, &script_a, &key_a.secret),
        Err(Error::SigHashIndex)
    );
}

/// Pins the shared-funder ceiling documented on `MAX_PACKAGE_BYTES`.
///
/// `prev_tx_prefix` is per-input and nothing deduplicates it, so inputs spending
/// several outputs of one large transaction each carry a copy of it. The advertised
/// `MAX_INPUTS` is therefore unreachable for that shape. It fails closed, which is
/// why this is a documented limit rather than a bug, but it should not be able to
/// change silently.
#[test]
fn shared_funder_package_size_is_the_binding_limit() {
    use dcr_rs::airgap::{MAX_INPUTS, MAX_PACKAGE_BYTES};

    let script = p2pkh_script(&[0x5a; 20]).to_vec();
    // One funding transaction with many outputs, as a payout transaction has.
    let funder = MsgTx {
        version: 1,
        tx_in: vec![TxIn {
            previous_outpoint: OutPoint {
                hash: [1u8; 32],
                index: 0,
                tree: 0,
            },
            sequence: 0xffff_ffff,
            value_in: 1_000_000_000,
            block_height: 0,
            block_index: 0xffff_ffff,
            signature_script: vec![0x5a; 107],
        }],
        tx_out: (0..1000)
            .map(|_| TxOut {
                value: 1_000_000,
                version: 0,
                pk_script: script.clone(),
            })
            .collect(),
        lock_time: 0,
        expiry: 0,
    };
    let prefix = funder.serialize_prefix();
    let hash = funder.tx_hash();

    let package_for = |n: usize| {
        let req = SignRequest {
            format_version: FORMAT_VERSION,
            tx_version: 1,
            account: 0,
            lock_time: 0,
            expiry: 0,
            inputs: (0..n)
                .map(|i| InputMeta {
                    prev_hash: hash,
                    prev_index: i as u32,
                    tree: 0,
                    sequence: 0xffff_ffff,
                    value_in: 1_000_000,
                    branch: BRANCH_EXTERNAL,
                    index: i as u32,
                    prev_script: script.clone(),
                    prev_tx_prefix: Some(prefix.clone()),
                })
                .collect(),
            outputs: vec![recipient(1_000_000 * n as i64 - 20_000, script.clone())],
            account_fp: None,
        };
        encode_sign_request(&req).unwrap()
    };

    // A handful of inputs from a large funder is fine...
    let small = package_for(5);
    assert!(small.len() < MAX_PACKAGE_BYTES);
    assert!(decode_sign_request(&small).is_ok());

    // ...but nowhere near MAX_INPUTS (1000): each input repeats the whole 36 KB
    // prefix, so the size cap binds first by two orders of magnitude.
    assert_eq!(MAX_INPUTS, 1000);
    let large = package_for(20);
    assert!(
        large.len() > MAX_PACKAGE_BYTES,
        "20 inputs sharing a 1000-output funder should exceed the cap ({} B)",
        large.len()
    );
    // Fails closed, with the size error rather than anything unsafe.
    assert!(matches!(
        decode_sign_request(&large),
        Err(Error::InvalidRequest(m)) if m.contains("too large")
    ));
}
