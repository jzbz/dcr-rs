// SPDX-License-Identifier: ISC
//! Air-gapped interchange format between a watch-only Decred companion wallet
//! (online, builds the tx) and an offline signer.
//!
//! Decred has no PSBT, so this is a minimal CBOR package. The companion, as a
//! watch-only wallet, knows every input's prevout script, amount, and the
//! derivation path of the key that owns it — everything the signer needs. The
//! device independently recomputes addresses/amounts for on-screen review, so a
//! malicious or buggy companion cannot redirect funds without the user seeing it.
//!
//! Transport:
//!   * QR  → wrap [`encode_sign_request`] bytes in UR type `dcr-sign-request`;
//!     return `dcr-signed-tx` (the broadcast-ready full tx).
//!   * SD  → write the same bytes as `unsigned.dcrtx` / `signed.dcrtx`.
//!
//! The format is shared with the KeyOS and Keystone Decred signers, so one
//! companion implementation serves every device. This is format version 3;
//! bump [`FORMAT_VERSION`] on any breaking change.
//!
//! # Why version 3 exists
//!
//! Version 3 is version 2's security model in under a third of the bytes —
//! measured 3.5× smaller at any realistic input count. Nothing about what the
//! device verifies changed; only the encoding did.
//!
//! Two things were wasteful. First, every byte-valued field was declared
//! `#[n(..)]`, which makes minicbor emit a CBOR **array of integers** rather than
//! a byte string — so each byte ≥ 0x18 costs two bytes on the wire, very nearly
//! doubling the dominant payload (hashes, scripts, funding transactions). They now
//! carry `#[cbor(n(..), with = "minicbor::bytes")]` and encode as real byte
//! strings. Note that `#[b(..)]` is *not* the way to ask for this: in minicbor it
//! marks a field as borrowed from the input, and on an owned type it silently
//! changes nothing.
//!
//! Second, [`InputMeta::prev_tx_prefix`] used to carry the *full* funding
//! transaction. A Decred txid is `blake256` over the **prefix** serialization
//! alone, so the witness — signature scripts, which are the bulk of a
//! transaction — was transmitted and then ignored. Only the prefix is carried
//! now, which is around 40% of the bytes and verifies exactly as much.
//!
//! On a QR-transported package these compound. Measured over identical content,
//! with a typical 2-in/2-out P2PKH funding transaction per input:
//!
//! ```text
//! inputs      v2        v3     ratio    QR frames @400 B
//!      1    1007 B    331 B    3.04x     3 ->   1
//!      3    2756 B    823 B    3.35x     7 ->   3
//!     10    8868 B   2545 B    3.48x    23 ->   7
//!   1000  873228 B  247815 B   3.52x  2184 -> 620
//! ```
//!
//! Versions 1 and 2 are both REFUSED, for the reason spelled out below. Neither
//! shipped with a companion that emits it, so nothing in circulation breaks.
//!
//! # Why version 2 existed
//!
//! Decred's signature hash does not commit to input amounts (see
//! [`crate::sighash`]). In a version 1 package the only source for an input's
//! value is [`InputMeta::value_in`], which the companion simply asserts. A
//! hostile companion can therefore understate `value_in`, so the device shows a
//! small fee, and dcrd's mempool then *rewrites* the value from the utxo set
//! before computing the real fee (`internal/mempool/mempool.go`), paying the
//! difference to the miner. No device-side check on version 1 data can detect
//! this, because every number involved comes from the same untrusted source.
//!
//! Version 2 closes it by carrying the funding transaction for each input
//! ([`InputMeta::prev_tx_prefix`]) so the device can verify `value_in` and
//! `prev_script` against a hash it computes itself, and by carrying the
//! derivation path of change outputs ([`OutputMeta::branch`] /
//! [`OutputMeta::index`]) so ownership is proven rather than guessed by an
//! address scan.
//!
//! Version 1 packages are REFUSED outright. Accepting them would defeat the
//! purpose: the sender chooses the version, so a hostile companion would simply
//! send version 1 to reach the unverifiable path, leaving the amount attack
//! fully exploitable behind a warning the user has to notice. Verification is
//! worth only as much as the refusal of unverified packages.
//!
//! Nothing is lost by refusing: version 1 shipped with no companion that emits
//! it, so there are no such packages in circulation. The same goes for version 2,
//! which version 3 supersedes on encoding grounds alone.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use minicbor::{Decode, Encode};
use secp256k1::{All, Secp256k1};

use crate::address::{p2pkh_script, Address};
use crate::hashing::hash160;
use crate::hd::{ExtPrivKey, ExtPubKey, BRANCH_EXTERNAL, BRANCH_INTERNAL};
use crate::sighash::prefix_hash_all;
use crate::sign::sign_p2pkh_input_cached;
use crate::tx::{MsgTx, OutPoint, TxIn, TxOut, NULL_BLOCK_HEIGHT, NULL_BLOCK_INDEX};
use crate::Error;

/// Version of the CBOR package layout. This is the ONLY version accepted; see
/// the module docs for why accepting version 1 would reopen the amount attack.
pub const FORMAT_VERSION: u8 = 3;

/// Fees at or below this are always allowed regardless of proportion, so that
/// dust consolidation — where the fee is legitimately a large share of a small
/// total — still works. 0.001 DCR.
pub const FEE_ALWAYS_ALLOWED_ATOMS: i64 = 100_000;

/// Above [`FEE_ALWAYS_ALLOWED_ATOMS`], refuse a fee exceeding `1 / N` of the
/// declared input total. Catches a companion that asks the user to approve an
/// openly absurd fee.
///
/// This is NOT a defence against the version 1 amount-understatement described
/// in the module docs: there the declared fee is small and only becomes large
/// after dcrd substitutes the true input values. Only the
/// [`InputMeta::prev_tx_prefix`] verification addresses that.
pub const MAX_FEE_FRACTION_DIVISOR: i64 = 20;

/// One input to be signed, with the metadata only an online wallet has.
#[derive(Clone, Debug, Encode, Decode)]
pub struct InputMeta {
    /// Prevout transaction hash (internal byte order).
    #[cbor(n(0), with = "minicbor::bytes")]
    pub prev_hash: [u8; 32],
    /// Prevout output index.
    #[n(1)]
    pub prev_index: u32,
    /// Prevout tree (0 = regular, the only tree we sign).
    #[n(2)]
    pub tree: u8,
    /// Input sequence number.
    #[n(3)]
    pub sequence: u32,
    /// Value of the output being spent, in atoms.
    #[n(4)]
    pub value_in: i64,
    /// Account-relative path suffix `[branch, index]`; the device prepends
    /// `m/44'/coin'/account'`.
    #[n(5)]
    pub branch: u32,
    /// Address index below the branch.
    #[n(6)]
    pub index: u32,
    /// Prevout pkScript. For our keys the device re-derives and verifies this
    /// equals `p2pkh(hash160(pubkey))` before trusting it.
    #[cbor(n(7), with = "minicbor::bytes")]
    pub prev_script: Vec<u8>,
    /// REQUIRED: the **prefix** serialization (dcrd `TxSerializeNoWitness`) of the
    /// funding transaction that created this input's prevout.
    ///
    /// This is what makes [`InputMeta::value_in`] verifiable. The device computes
    /// `blake256` over these bytes — which is precisely how a Decred txid is
    /// defined — and requires the result to equal [`InputMeta::prev_hash`], then
    /// requires the referenced output's value and script to equal `value_in` and
    /// `prev_script`. Without it the amounts are unverifiable assertions; see the
    /// module docs.
    ///
    /// The prefix, not the full transaction: the witness carries signature scripts
    /// that the txid does not commit to and that say nothing about what the
    /// prevout paid, so transmitting them cost roughly 60% of these bytes for no
    /// verification value. Version 2 sent the full transaction. A full
    /// serialization is refused here, rather than tolerated, because
    /// [`MsgTx::parse_prefix`] rejects a serialization-type word that is not
    /// `TxSerializeNoWitness`.
    ///
    /// Typed `Option` only for wire mechanics and diagnostics, never as licence to
    /// omit it: minicbor omits a trailing `None`, and keeping the field optional
    /// lets a package that leaves it out fail in [`SignRequest::validate`] with a
    /// specific "input without prev_tx_prefix" error rather than an opaque CBOR
    /// decode failure. `validate` rejects `None` unconditionally.
    #[cbor(n(8), with = "minicbor::bytes")]
    pub prev_tx_prefix: Option<Vec<u8>>,
}

/// One output, for both the wire tx and on-device display.
#[derive(Clone, Debug, Encode, Decode)]
pub struct OutputMeta {
    /// Amount in atoms.
    #[n(0)]
    pub value: i64,
    /// Script version (0 for all standard scripts).
    #[n(1)]
    pub version: u16,
    /// The public key script.
    #[cbor(n(2), with = "minicbor::bytes")]
    pub pk_script: Vec<u8>,
    /// True if this output is change back to our own wallet. Advisory on its own —
    /// the device proves ownership itself (see [`SignRequest::review_owned`]).
    ///
    /// Must agree with the presence of [`OutputMeta::branch`]: a change output
    /// carries its path, a recipient does not. A package where the two disagree is
    /// malformed and refused, which is what removes the old ambiguity between
    /// "provably not ours" and "not found inside the scan window".
    #[n(3)]
    pub is_change: bool,
    /// REQUIRED at format version 2 for change outputs, absent otherwise: the
    /// branch of the key that owns this output.
    ///
    /// Lets the device prove ownership with one derivation instead of scanning a
    /// window of addresses guessed from the input indices. That scan is what
    /// misclassified change beyond the window as an external recipient.
    #[n(4)]
    pub branch: Option<u32>,
    /// Address index below [`OutputMeta::branch`]. Present exactly when
    /// `branch` is.
    #[n(5)]
    pub index: Option<u32>,
}

/// The unsigned-transaction package a companion hands the signer.
#[derive(Clone, Debug, Encode, Decode)]
pub struct SignRequest {
    /// Package layout version; must equal [`FORMAT_VERSION`].
    #[n(0)]
    pub format_version: u8,
    /// Transaction version for the assembled tx.
    #[n(1)]
    pub tx_version: u16,
    /// BIP44 account the inputs belong to.
    #[n(2)]
    pub account: u32,
    /// Transaction lock time.
    #[n(3)]
    pub lock_time: u32,
    /// Transaction expiry height (0 = none).
    #[n(4)]
    pub expiry: u32,
    /// Inputs to sign.
    #[n(5)]
    pub inputs: Vec<InputMeta>,
    /// Outputs of the transaction.
    #[n(6)]
    pub outputs: Vec<OutputMeta>,
    /// OPTIONAL (additive; the format stays v1 — 7-element packages decode
    /// with `None`): BIP32 fingerprint of the ACCOUNT key this request was
    /// built against (first 4 bytes of hash160 of the account's compressed
    /// pubkey). Lets a device detect "wrong wallet open" with a friendly
    /// message instead of a late [`Error::ScriptMismatch`]. Never required;
    /// never a security control — the prev_script re-derivation remains the
    /// fund protector.
    #[cbor(n(7), with = "minicbor::bytes")]
    pub account_fp: Option<[u8; 4]>,
}

/// CBOR-encode a sign request.
pub fn encode_sign_request(req: &SignRequest) -> Result<Vec<u8>, Error> {
    let mut buf = Vec::new();
    minicbor::encode(req, &mut buf).map_err(|_| Error::Encode)?;
    Ok(buf)
}

/// Largest CBOR package accepted by [`decode_sign_request`].
///
/// Decoding untrusted CBOR amplifies: skipping over an unexpected nested
/// structure allocates per item, so peak heap is a multiple of the input. This is
/// the backstop that keeps that multiple finite — nothing more. It is chosen to
/// sit above what [`MAX_INPUTS`] actually costs, so that the two limits do not
/// contradict each other: at format version 3 a 1000-input package carrying a
/// typical 2-in/2-out funding prefix per input measures ~248 KB, so 512 KiB
/// admits the largest package `MAX_INPUTS` permits with room to spare and
/// rejects everything beyond it. Version 2 needed four times as much.
///
/// A device with tight RAM should impose its own, much lower, limit before
/// calling [`decode_sign_request`] — neither QR transport nor a few hundred KB of
/// heap can handle a package anywhere near this size, and only the application
/// knows its real budget.
pub const MAX_PACKAGE_BYTES: usize = 512 * 1024;

/// Decode a sign request, enforcing the size and format-version gates.
///
/// Only [`FORMAT_VERSION`] is accepted. Version 1 packages are refused here
/// rather than downgraded to an unverified path, because the sender picks the
/// version and would otherwise choose the weaker one.
pub fn decode_sign_request(bytes: &[u8]) -> Result<SignRequest, Error> {
    if bytes.len() > MAX_PACKAGE_BYTES {
        return Err(Error::InvalidRequest("package too large"));
    }
    let req: SignRequest = minicbor::decode(bytes).map_err(|_| Error::Parse)?;
    if req.format_version != FORMAT_VERSION {
        return Err(Error::UnsupportedVersion);
    }
    Ok(req)
}

/// A human-reviewable summary the UI shows before the user approves signing.
///
/// Holds nothing secret — addresses and amounts that are about to go on a screen
/// anyway — so it is `Debug`.
#[derive(Clone, Debug)]
pub struct ReviewSummary {
    /// (address, amount) for every output the device does NOT own.
    pub recipients: Vec<(String, i64)>,
    /// (address, amount) for outputs the device re-derived as its own.
    pub change: Vec<(String, i64)>,
    /// Sum of all input amounts, in atoms.
    pub input_total: i64,
    /// Sum of all output amounts, in atoms.
    pub output_total: i64,
    /// `input_total - output_total`.
    pub fee: i64,
}
// NOTE: `flagged_mismatches` was removed with the address scan. It reported
// outputs the companion called change that the scan could not derive — a
// condition that no longer exists. An output is change only if a supplied path
// derives to its script, `validate` requires `is_change` to agree with that
// path's presence, and a path that fails to derive is a hard
// [`Error::ScriptMismatch`] rather than something to display. There is nothing
// left to warn about, so a device should drop the corresponding warning block
// instead of rendering a list that can never be non-empty.

/// Largest legal Decred amount (dcrd `dcrutil.MaxAmount`): 21M DCR in atoms.
/// Anything above this in a package is hostile or corrupt.
pub const MAX_ATOMS: i64 = 21_000_000 * crate::amount::ATOMS_PER_DCR;

/// Hard caps on package size. Far beyond anything a P2PKH send/receive wallet
/// builds, but low enough that a hostile package cannot make a small device
/// grind or allocate without bound.
pub const MAX_INPUTS: usize = 1_000;
/// See [`MAX_INPUTS`].
pub const MAX_OUTPUTS: usize = 1_000;

/// Sum amounts exactly in i128 (immune to i64 wrap-around from hostile
/// values), then report i64::MAX on overflow — callers compare totals, and a
/// saturated total can never masquerade as a valid balanced transaction once
/// per-amount MAX_ATOMS checks are in force.
fn total_atoms<'a>(vals: impl Iterator<Item = &'a i64>) -> i64 {
    let t: i128 = vals.map(|&v| v as i128).sum();
    t.clamp(i64::MIN as i128, i64::MAX as i128) as i64
}

/// Slot in a branch-key cache. `validate` already restricts branches to these
/// two, so a request can never widen the cache.
fn branch_slot(branch: u32) -> Result<usize, Error> {
    match branch {
        BRANCH_EXTERNAL => Ok(0),
        BRANCH_INTERNAL => Ok(1),
        _ => Err(Error::InvalidRequest("unknown derivation branch")),
    }
}

/// Caches the two branch keys below a watch-only account key.
///
/// Deriving `branch/index` from the account key for every input and every change
/// output repeats the `account -> branch` step every time. Holding those two
/// keys turns the work for N addresses from 2N CKD steps into N+2.
struct BranchPubCache<'a> {
    secp: &'a Secp256k1<All>,
    account: &'a ExtPubKey,
    branches: [Option<ExtPubKey>; 2],
}

impl<'a> BranchPubCache<'a> {
    fn new(secp: &'a Secp256k1<All>, account: &'a ExtPubKey) -> Self {
        BranchPubCache {
            secp,
            account,
            branches: [None, None],
        }
    }

    fn pubkey_at(&mut self, branch: u32, index: u32) -> Result<[u8; 33], Error> {
        let slot = branch_slot(branch)?;
        if self.branches[slot].is_none() {
            self.branches[slot] = Some(self.account.derive_child(self.secp, branch)?);
        }
        let branch_key = self.branches[slot].as_ref().expect("just populated");
        Ok(branch_key
            .derive_child(self.secp, index)?
            .compressed_pubkey())
    }

    /// The P2PKH script the key at `branch/index` pays to.
    fn script_at(&mut self, branch: u32, index: u32) -> Result<[u8; 25], Error> {
        Ok(p2pkh_script(&hash160(&self.pubkey_at(branch, index)?)))
    }
}

impl SignRequest {
    /// Sum of all input amounts, in atoms (saturating on hostile overflow).
    pub fn input_total(&self) -> i64 {
        total_atoms(self.inputs.iter().map(|i| &i.value_in))
    }

    /// Sum of all output amounts, in atoms (saturating on hostile overflow).
    pub fn output_total(&self) -> i64 {
        total_atoms(self.outputs.iter().map(|o| &o.value))
    }

    /// Verify every input's declared amount and script against the funding
    /// transaction supplied alongside it. This is the check that makes a fee
    /// figure trustworthy; see the module docs for why version 1 cannot have one.
    ///
    /// For each input: the funding transaction's prefix is parsed, its txid
    /// recomputed as `blake256` over those bytes (Decred's txid is a *single*
    /// BLAKE-256 over the prefix serialization, not a double hash of the whole
    /// transaction), and required to equal `prev_hash`. The referenced output must
    /// then exist and carry exactly the declared `value_in` and `prev_script`. A
    /// mismatch anywhere means the companion lied about what is being spent.
    ///
    /// Needs no key material, so a caller may run it before asking for a
    /// password.
    pub fn verify_prev_txs(&self) -> Result<(), Error> {
        for meta in &self.inputs {
            let raw = meta.prev_tx_prefix.as_ref().ok_or(Error::InvalidRequest(
                "format version 3 input without prev_tx_prefix",
            ))?;
            let funding = MsgTx::parse_prefix(raw)
                .map_err(|_| Error::InvalidRequest("unparseable prev_tx_prefix"))?;
            if funding.tx_hash() != meta.prev_hash {
                return Err(Error::InvalidRequest(
                    "prev_tx_prefix does not hash to the declared prevout",
                ));
            }
            let out = funding
                .tx_out
                .get(meta.prev_index as usize)
                .ok_or(Error::InvalidRequest(
                    "prev_index past end of prev_tx_prefix",
                ))?;
            if out.value != meta.value_in {
                return Err(Error::InvalidRequest(
                    "declared input amount does not match the funding output",
                ));
            }
            if out.pk_script != meta.prev_script {
                return Err(Error::InvalidRequest(
                    "declared input script does not match the funding output",
                ));
            }
        }
        Ok(())
    }

    /// Structural + economic sanity, needing no key material. REFUSES packages
    /// whose math cannot be honest: empty txs, oversized txs, out-of-range
    /// amounts, duplicate inputs (which inflate the apparent input total and
    /// understate the fee a reviewer sees), and outputs exceeding inputs
    /// (negative fee). The network would reject all of these too, but a signer
    /// must never even display them as if they were reviewable.
    pub fn validate(&self) -> Result<(), Error> {
        // The version gate lives here as well as in decode_sign_request, because
        // a SignRequest can also be constructed directly or decoded by other
        // means, and the whole point of refusing version 1 is that the *sender*
        // must not get to choose the weaker path. A gate only one entry point
        // enforces is a gate.
        if self.format_version != FORMAT_VERSION {
            return Err(Error::UnsupportedVersion);
        }
        if self.inputs.is_empty() || self.outputs.is_empty() {
            return Err(Error::InvalidRequest(
                "transaction has no inputs or outputs",
            ));
        }
        if self.inputs.len() > MAX_INPUTS || self.outputs.len() > MAX_OUTPUTS {
            return Err(Error::InvalidRequest("too many inputs or outputs"));
        }
        // Only version 1 transactions are standard on Decred, and DCP0008 caps
        // the version at 3 in consensus. Anything else assembles into a tx the
        // network will not mine, with nothing on screen to explain why.
        if self.tx_version != 1 {
            return Err(Error::InvalidRequest("unsupported transaction version"));
        }
        for i in &self.inputs {
            if i.value_in <= 0 {
                return Err(Error::InvalidRequest("non-positive input amount"));
            }
            if i.value_in > MAX_ATOMS {
                return Err(Error::InvalidRequest("input amount exceeds max supply"));
            }
            // These three were previously enforced only in check_owned_inputs and
            // in sign_request, leaving the display path free to derive and show an
            // address from a path this wallet never uses, and free to be driven
            // into a maxed-out ownership scan by a huge index. Enforcing them here
            // covers every entry point, since they all call validate() first.
            if i.branch != BRANCH_EXTERNAL && i.branch != BRANCH_INTERNAL {
                return Err(Error::InvalidRequest("unknown derivation branch"));
            }
            if i.index >= crate::hd::HARDENED {
                return Err(Error::InvalidRequest("hardened address index"));
            }
            if i.tree != 0 {
                return Err(Error::InvalidRequest(
                    "only regular-tree outputs can be spent",
                ));
            }
            if i.prev_tx_prefix.is_none() {
                return Err(Error::InvalidRequest("input without prev_tx_prefix"));
            }
        }
        for o in &self.outputs {
            if o.value < 0 {
                return Err(Error::InvalidRequest("negative output amount"));
            }
            if o.value > MAX_ATOMS {
                return Err(Error::InvalidRequest("output amount exceeds max supply"));
            }
            // Every standard Decred script is version 0. A higher version is
            // consensus-invalid under DCP0008 (ErrScriptVersionTooHigh), but it is
            // copied verbatim into the signed tx and ignored by address
            // classification, so without this check the device happily signs a
            // transaction that can never confirm.
            if o.version != 0 {
                return Err(Error::InvalidRequest("unsupported output script version"));
            }
            // A change output carries its path; a recipient does not. Requiring the
            // two to agree is what lets an ownership disagreement be a hard error
            // instead of the inconclusive flag the old address scan produced.
            if o.branch.is_some() != o.index.is_some() {
                return Err(Error::InvalidRequest(
                    "output branch and index must both be present or both absent",
                ));
            }
            if o.is_change != o.branch.is_some() {
                return Err(Error::InvalidRequest(
                    "change output must carry its derivation path",
                ));
            }
            if let (Some(branch), Some(index)) = (o.branch, o.index) {
                if branch != BRANCH_EXTERNAL && branch != BRANCH_INTERNAL {
                    return Err(Error::InvalidRequest("unknown output derivation branch"));
                }
                if index >= crate::hd::HARDENED {
                    return Err(Error::InvalidRequest("hardened output address index"));
                }
            }
        }
        // Exact i128 sums: hostile i64 values cannot wrap the totals (and the
        // per-amount caps above already bound each term).
        let input_total: i128 = self.inputs.iter().map(|i| i.value_in as i128).sum();
        let output_total: i128 = self.outputs.iter().map(|o| o.value as i128).sum();
        if input_total > MAX_ATOMS as i128 {
            return Err(Error::InvalidRequest("input total exceeds max supply"));
        }
        if input_total < output_total {
            return Err(Error::InvalidRequest(
                "outputs exceed inputs (negative fee)",
            ));
        }
        // Refuse an openly absurd fee. Now that prev_tx_prefix pins every input amount,
        // this operates on verified numbers rather than companion assertions, so it
        // is a real bound on what a mistaken or hostile companion can spend on
        // fees, not just a sanity check.
        let fee = input_total - output_total;
        if fee > FEE_ALWAYS_ALLOWED_ATOMS as i128
            && fee * MAX_FEE_FRACTION_DIVISOR as i128 > input_total
        {
            return Err(Error::InvalidRequest("fee is implausibly large"));
        }
        // The same coin listed twice inflates the apparent input total and
        // understates the fee shown for review. O(n²) is fine under MAX_INPUTS.
        for (a, i) in self.inputs.iter().enumerate() {
            for j in &self.inputs[a + 1..] {
                if i.prev_hash == j.prev_hash && i.prev_index == j.prev_index && i.tree == j.tree {
                    return Err(Error::InvalidRequest("same coin listed twice"));
                }
            }
        }
        // Verify the amounts against the funding transactions, LAST so that the
        // cheap structural checks above reject a hostile package before any parsing
        // or hashing work.
        //
        // This lives inside validate() deliberately, rather than being left for
        // callers to remember. Every entry point — the display path, the ownership
        // check, and the signer — already calls validate() first, so putting it
        // here means none of them can present or sign an unverified amount. A
        // verification that callers must opt into is one a caller will eventually
        // skip, and the display path skipping it would be just as damaging as the
        // signer doing so: the user would be approving numbers nobody checked.
        self.verify_prev_txs()
    }

    /// Compare the optional [`SignRequest::account_fp`] against the account key
    /// actually supplied. `Ok(())` when it matches or when the package carries
    /// none.
    ///
    /// A diagnostic, never a security control — the fingerprint comes from the
    /// same untrusted companion as everything else. Its value is that "wrong
    /// wallet open" reports [`Error::AccountMismatch`] instead of surfacing as a
    /// late [`Error::ScriptMismatch`], which reads like tampering.
    pub fn check_account_fp(&self, account: &ExtPubKey) -> Result<(), Error> {
        match self.account_fp {
            Some(fp) if fp != account.fingerprint() => Err(Error::AccountMismatch),
            _ => Ok(()),
        }
    }

    /// Prove that every output claiming to be ours really is: derive the key at
    /// the path the companion supplied and require the output's script to be
    /// exactly that key's P2PKH script.
    ///
    /// Shared by the review path and the signer so both enforce it identically.
    fn prove_change_outputs(
        &self,
        secp: &Secp256k1<All>,
        account: &ExtPubKey,
    ) -> Result<(), Error> {
        let mut cache = BranchPubCache::new(secp, account);
        for o in &self.outputs {
            if let (Some(branch), Some(index)) = (o.branch, o.index) {
                if o.pk_script != cache.script_at(branch, index)? {
                    return Err(Error::ScriptMismatch);
                }
            }
        }
        Ok(())
    }

    /// Trustless review: an output counts as change only when the device can
    /// PROVE it owns it, by deriving the key at the path the companion supplied
    /// and requiring it to produce exactly this output's script. Everything else
    /// is an external recipient and lands in the headline amount.
    ///
    /// This replaces the address scan earlier versions used. That scan derived a
    /// window of addresses guessed from the highest *input* index and applied it
    /// to both branches — but the external and internal branches advance
    /// independently, so change beyond the window was misfiled as a recipient and
    /// simultaneously flagged as evidence of a hostile companion, against the
    /// user's own address. Proving one path per output removes the guess, the
    /// false accusation, and the thousands of EC derivations a large index could
    /// provoke.
    ///
    /// The direction of failure is deliberately safe: a companion that omits the
    /// path for an output that really is ours gets it displayed as a recipient,
    /// over-stating what is being sent rather than hiding it. Claiming a path
    /// that does not derive to the script is a hard error, so a recipient can
    /// never be disguised as change.
    ///
    /// Runs [`SignRequest::validate`] itself, so the numbers it reports are the
    /// verified ones. It used to rely on the caller having done so; being the one
    /// path whose whole purpose is putting amounts in front of a human, it is the
    /// last place that should trust its input — an unvalidated package could drive
    /// the fee subtraction below to overflow.
    pub fn review_owned(
        &self,
        secp: &Secp256k1<All>,
        account: &ExtPubKey,
    ) -> Result<ReviewSummary, Error> {
        self.validate()?;
        self.check_account_fp(account)?;
        self.prove_change_outputs(secp, account)?;

        let display = |script: &[u8]| -> String {
            Address::from_script(script, account.network)
                .map(|a| a.encode())
                .unwrap_or_else(|| "<non-standard script>".to_string())
        };

        let mut recipients = Vec::new();
        let mut change = Vec::new();
        for o in &self.outputs {
            let addr = display(&o.pk_script);
            // Ownership was proven above; validate() guarantees `is_change`
            // agrees with the presence of the path, so the path alone classifies.
            if o.branch.is_some() {
                change.push((addr, o.value));
            } else {
                recipients.push((addr, o.value));
            }
        }

        // validate() bounds both totals by MAX_ATOMS and rejects
        // outputs > inputs, so this cannot overflow.
        let input_total = self.input_total();
        let output_total = self.output_total();
        Ok(ReviewSummary {
            recipients,
            change,
            input_total,
            output_total,
            fee: input_total - output_total,
        })
    }

    /// Verify (without touching the seed) that every input spends a key this
    /// wallet owns: the claimed `prev_script` must equal the P2PKH script of
    /// the pubkey derived at `branch/index` below the account key. Runs
    /// [`SignRequest::validate`] first, then enforces known branches, the
    /// regular tree, and non-hardened indices.
    pub fn check_owned_inputs(
        &self,
        secp: &Secp256k1<All>,
        account: &ExtPubKey,
    ) -> Result<(), Error> {
        self.validate()?;
        self.check_account_fp(account)?;
        let mut cache = BranchPubCache::new(secp, account);
        for meta in &self.inputs {
            if meta.branch != BRANCH_EXTERNAL && meta.branch != BRANCH_INTERNAL {
                return Err(Error::InvalidRequest("unknown derivation branch"));
            }
            if meta.index >= crate::hd::HARDENED {
                return Err(Error::InvalidRequest("hardened address index"));
            }
            if meta.tree != 0 {
                return Err(Error::InvalidRequest(
                    "only regular-tree outputs can be spent",
                ));
            }
            if meta.prev_script != cache.script_at(meta.branch, meta.index)? {
                return Err(Error::ScriptMismatch);
            }
        }
        self.prove_change_outputs(secp, account)
    }
}

/// End-to-end: turn a decoded [`SignRequest`] into a broadcast-ready Decred
/// tx, given the BIP32 master key.
///
/// For every input the device **re-derives** the owning key, recomputes its
/// P2PKH script, and refuses to sign if it does not match `prev_script` — so
/// the companion cannot trick the device into signing with the wrong key.
///
/// Takes an already-derived master [`ExtPrivKey`] rather than raw entropy, so
/// the application keeps ONE place that touches the seed. Every derived
/// intermediate is scrubbed on drop.
pub fn sign_request(
    secp: &Secp256k1<All>,
    master: &ExtPrivKey,
    req: &SignRequest,
) -> Result<Vec<u8>, Error> {
    // The signer re-validates on its own: it must refuse dishonest math even
    // if a caller skipped the review step.
    req.validate()?;
    let account = master.account_key(secp, req.account)?;
    let account_pub = account.neuter(secp);
    req.check_account_fp(&account_pub)?;
    // Re-prove change ownership here too. validate() only checks that a change
    // output *carries* a path in range, never that the path derives to the
    // script; that proof lived solely in review_owned, so a caller that skipped
    // the review could be walked into signing an attacker's address labelled as
    // its own change. Same reasoning as the duplicated input checks below.
    req.prove_change_outputs(secp, &account_pub)?;

    // Assemble the unsigned tx (sigScripts empty for sighash computation).
    let mut tx = MsgTx {
        version: req.tx_version,
        tx_in: req
            .inputs
            .iter()
            .map(|i| TxIn {
                previous_outpoint: OutPoint {
                    hash: i.prev_hash,
                    index: i.prev_index,
                    tree: i.tree,
                },
                sequence: i.sequence,
                value_in: i.value_in,
                block_height: NULL_BLOCK_HEIGHT,
                block_index: NULL_BLOCK_INDEX,
                signature_script: Vec::new(),
            })
            .collect(),
        tx_out: req
            .outputs
            .iter()
            .map(|o| TxOut {
                value: o.value,
                version: o.version,
                pk_script: o.pk_script.clone(),
            })
            .collect(),
        lock_time: req.lock_time,
        expiry: req.expiry,
    };

    // The prefix half of every SigHashAll sighash is the same for all inputs and
    // is unaffected by the signature scripts filled in below, so it is computed
    // once here. Recomputing it per input made signing O(N²) in the tx size.
    let prefix_hash = prefix_hash_all(&tx);

    // Branch keys, derived at most once each rather than per input.
    let mut branch_keys: [Option<ExtPrivKey>; 2] = [None, None];

    // Sign each input. The structural checks duplicate check_owned_inputs on
    // purpose: the signer must refuse out-of-schema derivation paths and
    // stake-tree inputs on its own, even if a caller skipped the review step.
    for (idx, meta) in req.inputs.iter().enumerate() {
        let slot = branch_slot(meta.branch)?;
        if meta.index >= crate::hd::HARDENED {
            return Err(Error::InvalidRequest("hardened address index"));
        }
        if meta.tree != 0 {
            return Err(Error::InvalidRequest(
                "only regular-tree outputs can be spent",
            ));
        }
        if branch_keys[slot].is_none() {
            branch_keys[slot] = Some(account.derive_child(secp, meta.branch)?);
        }
        let branch_key = branch_keys[slot].as_ref().expect("just populated");
        let key = branch_key.derive_child(secp, meta.index)?;
        let pubkey = key.compressed_pubkey(secp);
        let expected_script = p2pkh_script(&hash160(&pubkey));
        if meta.prev_script != expected_script {
            return Err(Error::ScriptMismatch);
        }
        let sig_script = sign_p2pkh_input_cached(
            secp,
            &tx,
            idx,
            &expected_script,
            &key.secret,
            &pubkey,
            &prefix_hash,
        )?;
        tx.tx_in[idx].signature_script = sig_script;
    }

    Ok(tx.serialize_full())
}
