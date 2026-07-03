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
//! companion implementation serves every device. This is format version 1;
//! bump [`FORMAT_VERSION`] on any breaking change.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use minicbor::{Decode, Encode};
use secp256k1::{All, Secp256k1};

use crate::address::{p2pkh_hash160, p2pkh_script, Address};
use crate::hashing::hash160;
use crate::hd::{ExtPrivKey, ExtPubKey, BRANCH_EXTERNAL, BRANCH_INTERNAL};
use crate::sign::sign_p2pkh_input;
use crate::tx::{MsgTx, OutPoint, TxIn, TxOut, NULL_BLOCK_HEIGHT, NULL_BLOCK_INDEX};
use crate::Error;

/// Version of the CBOR package layout this build speaks.
pub const FORMAT_VERSION: u8 = 1;

/// How many indices past the highest input index we scan per branch when
/// deciding whether an output pays one of our own keys.
const OWNERSHIP_GAP: u32 = 20;
/// Hard bound on the ownership scan so a hostile package cannot make the
/// device grind through thousands of EC derivations.
const OWNERSHIP_SCAN_MAX: u32 = 1000;

/// One input to be signed, with the metadata only an online wallet has.
#[derive(Clone, Debug, Encode, Decode)]
pub struct InputMeta {
    /// Prevout transaction hash (internal byte order).
    #[n(0)]
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
    #[n(7)]
    pub prev_script: Vec<u8>,
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
    #[n(2)]
    pub pk_script: Vec<u8>,
    /// True if this output is change back to our own wallet — advisory only;
    /// the device re-derives ownership itself (see [`SignRequest::review_owned`]).
    #[n(3)]
    pub is_change: bool,
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
    #[n(7)]
    pub account_fp: Option<[u8; 4]>,
}

/// CBOR-encode a sign request.
pub fn encode_sign_request(req: &SignRequest) -> Result<Vec<u8>, Error> {
    let mut buf = Vec::new();
    minicbor::encode(req, &mut buf).map_err(|_| Error::Encode)?;
    Ok(buf)
}

/// Decode a sign request, enforcing the format version gate.
pub fn decode_sign_request(bytes: &[u8]) -> Result<SignRequest, Error> {
    let req: SignRequest = minicbor::decode(bytes).map_err(|_| Error::Parse)?;
    if req.format_version != FORMAT_VERSION {
        return Err(Error::UnsupportedVersion);
    }
    Ok(req)
}

/// A human-reviewable summary the UI shows before the user approves signing.
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
    /// Outputs the companion claimed were change (`is_change = true`) but that
    /// the device CANNOT derive as its own. A correct watch-only wallet never
    /// does this, so each entry is evidence the companion is faulty or hostile
    /// — these MUST be surfaced loudly and block reflexive approval.
    pub flagged_mismatches: Vec<(String, i64)>,
}

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

impl SignRequest {
    /// Sum of all input amounts, in atoms (saturating on hostile overflow).
    pub fn input_total(&self) -> i64 {
        total_atoms(self.inputs.iter().map(|i| &i.value_in))
    }

    /// Sum of all output amounts, in atoms (saturating on hostile overflow).
    pub fn output_total(&self) -> i64 {
        total_atoms(self.outputs.iter().map(|o| &o.value))
    }

    fn scan_window(&self) -> u32 {
        let max_index = self.inputs.iter().map(|i| i.index).max().unwrap_or(0);
        max_index
            .saturating_add(OWNERSHIP_GAP)
            .min(OWNERSHIP_SCAN_MAX)
    }

    /// Structural + economic sanity, needing no key material. REFUSES packages
    /// whose math cannot be honest: empty txs, oversized txs, out-of-range
    /// amounts, duplicate inputs (which inflate the apparent input total and
    /// understate the fee a reviewer sees), and outputs exceeding inputs
    /// (negative fee). The network would reject all of these too, but a signer
    /// must never even display them as if they were reviewable.
    pub fn validate(&self) -> Result<(), Error> {
        if self.inputs.is_empty() || self.outputs.is_empty() {
            return Err(Error::InvalidRequest(
                "transaction has no inputs or outputs",
            ));
        }
        if self.inputs.len() > MAX_INPUTS || self.outputs.len() > MAX_OUTPUTS {
            return Err(Error::InvalidRequest("too many inputs or outputs"));
        }
        for i in &self.inputs {
            if i.value_in <= 0 {
                return Err(Error::InvalidRequest("non-positive input amount"));
            }
            if i.value_in > MAX_ATOMS {
                return Err(Error::InvalidRequest("input amount exceeds max supply"));
            }
        }
        for o in &self.outputs {
            if o.value < 0 {
                return Err(Error::InvalidRequest("negative output amount"));
            }
            if o.value > MAX_ATOMS {
                return Err(Error::InvalidRequest("output amount exceeds max supply"));
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
        // The same coin listed twice inflates the apparent input total and
        // understates the fee shown for review. O(n²) is fine under MAX_INPUTS.
        for (a, i) in self.inputs.iter().enumerate() {
            for j in &self.inputs[a + 1..] {
                if i.prev_hash == j.prev_hash && i.prev_index == j.prev_index && i.tree == j.tree {
                    return Err(Error::InvalidRequest("same coin listed twice"));
                }
            }
        }
        Ok(())
    }

    /// Trustless review: instead of believing the companion's `is_change`
    /// flag, the device RE-DERIVES its own addresses (public CKD below the
    /// account-level key) and decides for itself which outputs are change
    /// (pay one of our keys) and which are external recipients. This mirrors
    /// the input-side `prev_script` verification in
    /// [`SignRequest::check_owned_inputs`], so a malicious or buggy companion
    /// cannot hide a destination by mislabelling it as change.
    pub fn review_owned(
        &self,
        secp: &Secp256k1<All>,
        account: &ExtPubKey,
    ) -> Result<ReviewSummary, Error> {
        // Extract the P2PKH hash160 of every output up front (non-P2PKH can
        // never be one of our keys), then scan our own keys (external + change
        // branches; the window tracks the wallet's usage level via the highest
        // input index) comparing against those few hashes as each key is
        // derived. Memory stays O(outputs) instead of materializing the whole
        // ownership set — up to ~40 KB at the scan cap, which matters on
        // hardware wallets — and the scan stops early once every candidate
        // output is already known to be ours.
        let out_hashes: Vec<Option<[u8; 20]>> = self
            .outputs
            .iter()
            .map(|o| p2pkh_hash160(&o.pk_script))
            .collect();
        let mut owned_out = alloc::vec![false; self.outputs.len()];
        let mut unresolved = out_hashes.iter().filter(|h| h.is_some()).count();

        let window = self.scan_window();
        'scan: for branch in [BRANCH_EXTERNAL, BRANCH_INTERNAL] {
            let branch_key = account.derive_child(secp, branch)?;
            for index in 0..=window {
                if unresolved == 0 {
                    break 'scan;
                }
                let key = branch_key.derive_child(secp, index)?;
                let h = hash160(&key.compressed_pubkey());
                for (i, oh) in out_hashes.iter().enumerate() {
                    if !owned_out[i] && *oh == Some(h) {
                        owned_out[i] = true;
                        unresolved -= 1;
                    }
                }
            }
        }

        let display = |script: &[u8]| -> String {
            Address::from_script(script, account.network)
                .map(|a| a.encode())
                .unwrap_or_else(|| "<non-standard script>".to_string())
        };

        let mut recipients = Vec::new();
        let mut change = Vec::new();
        let mut flagged_mismatches = Vec::new();
        for (i, o) in self.outputs.iter().enumerate() {
            let addr = display(&o.pk_script);
            if owned_out[i] {
                change.push((addr, o.value));
            } else {
                recipients.push((addr.clone(), o.value));
                if o.is_change {
                    flagged_mismatches.push((addr, o.value));
                }
            }
        }

        let input_total = self.input_total();
        let output_total = self.output_total();
        Ok(ReviewSummary {
            recipients,
            change,
            input_total,
            output_total,
            fee: input_total - output_total,
            flagged_mismatches,
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
            let pubkey = account.pubkey_at(secp, meta.branch, meta.index)?;
            let expected = p2pkh_script(&hash160(&pubkey));
            if meta.prev_script != expected {
                return Err(Error::ScriptMismatch);
            }
        }
        Ok(())
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

    // Sign each input. The structural checks duplicate check_owned_inputs on
    // purpose: the signer must refuse out-of-schema derivation paths and
    // stake-tree inputs on its own, even if a caller skipped the review step.
    for (idx, meta) in req.inputs.iter().enumerate() {
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
        let key = account.address_key(secp, meta.branch, meta.index)?;
        let pubkey = key.compressed_pubkey(secp);
        let expected_script = p2pkh_script(&hash160(&pubkey));
        if meta.prev_script != expected_script {
            return Err(Error::ScriptMismatch);
        }
        let sig_script = sign_p2pkh_input(secp, &tx, idx, &expected_script, &key.secret, &pubkey)?;
        tx.tx_in[idx].signature_script = sig_script;
    }

    Ok(tx.serialize_full())
}
