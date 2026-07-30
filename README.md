# dcr-rs

[![CI](https://github.com/jzbz/dcr-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/jzbz/dcr-rs/actions/workflows/ci.yml)

Decred (DCR) primitives for Rust: BLAKE-256, addresses, BIP32 HD keys with
Decred serialization, the transaction wire format, the Decred signature hash,
and low-S ECDSA P2PKH signing. `no_std + alloc` friendly — the same crate runs
on a host wallet and on embedded signers.

Grown out of the Decred signing cores written for the
[KeyOS](https://github.com/Foundation-Devices/KeyOS) and [Keystone 3](https://github.com/KeystoneHQ/keystone3-firmware)
hardware-wallet firmwares, generalized to all four dcrd networks and both
private (signer) and public (watch-only) derivation.

## Scope

In scope — the consensus-critical byte formats a wallet or signer needs:

- **BLAKE-256** — the 14-round SHA-3 finalist Decred uses for *everything*
  (txids, sighashes, address hashes, base58 checksums). This is **not**
  BLAKE2/BLAKE3; no maintained crate implements it, so it is vendored and
  pinned by known-answer vectors generated from dcrd's own implementation.
- **Addresses** — P2PKH (ecdsa-secp256k1) and P2SH, encode/decode/classify,
  for mainnet, testnet3, simnet and regnet.
- **HD keys** — BIP32 with Decred's `dprv`/`dpub` (and `tprv`/`sprv`/`rprv`…)
  version bytes and double-BLAKE256 base58 checksum. Private CKD for signers,
  public CKD for watch-only companions, BIP39 seed expansion behind the
  `mnemonic` feature.
- **Transactions** — the dcrd `MsgTx` wire format (prefix ‖ witness),
  byte-exact serialize/parse, txids.
- **Signing** — the Decred signature hash (not Bitcoin's BIP143) and
  RFC6979/low-S ECDSA signature scripts for P2PKH inputs (SigHashAll).
- **Airgap format** (feature `airgap`) — the CBOR unsigned-tx package shared
  with the KeyOS and Keystone Decred signers, including the trustless review
  logic (the device re-derives ownership instead of trusting the companion).
  Format version 3: each input carries the *prefix* serialization of its funding
  transaction, so the device verifies the amount it displays against a txid it
  computes itself rather than trusting the companion's assertion.

Out of scope: networking/RPC, staking, mixing, and transaction-construction
policy (coin selection, fees).

Elliptic-curve math, HMAC/SHA/RIPEMD, BIP39 wordlists, base58 and CBOR are
delegated to audited crates ([`secp256k1`], [`sha2`], [`hmac`], [`ripemd`],
[`bip39`], [`bs58`], [`minicbor`]); this crate hand-rolls nothing that touches
curve math or standard KDFs.

[`secp256k1`]: https://crates.io/crates/secp256k1
[`sha2`]: https://crates.io/crates/sha2
[`hmac`]: https://crates.io/crates/hmac
[`ripemd`]: https://crates.io/crates/ripemd
[`bip39`]: https://crates.io/crates/bip39
[`bs58`]: https://crates.io/crates/bs58
[`minicbor`]: https://crates.io/crates/minicbor

## Usage

```toml
[dependencies]
dcr-rs = { git = "https://github.com/jzbz/dcr-rs" }
```

Addresses:

```rust
use dcr_rs::{Address, Network};

let addr = Address::decode("DsUZxxoHJSty8DCfwfartwTYbuhmVct7tJu").unwrap();
assert_eq!(addr.network, Network::Mainnet);
let script = addr.pk_script(); // 76a914…88ac
```

HD derivation, signer side (`m/44'/42'/0'` then `branch/index`):

```rust
use dcr_rs::{hd::ExtPrivKey, secp256k1::Secp256k1, Network, BRANCH_EXTERNAL};

let secp = Secp256k1::new();
let master = ExtPrivKey::from_phrase("abandon abandon … about", "", Network::Mainnet)?;
let account = master.account_key(&secp, 0)?;
println!("receive 0: {}", account.address_key(&secp, BRANCH_EXTERNAL, 0)?.p2pkh_address(&secp));
println!("export:    {}", account.neuter(&secp).to_base58()); // dpub…
```

Watch-only side (public CKD below an exported `dpub`):

```rust
use dcr_rs::{hd::ExtPubKey, secp256k1::Secp256k1, Address};

let secp = Secp256k1::new();
let account = ExtPubKey::from_base58("dpub…")?;
let pubkey = account.pubkey_at(&secp, 0, 5)?;
let addr = Address::from_pubkey(&pubkey, account.network);
```

Air-gapped signing (feature `airgap`):

```rust
use dcr_rs::{decode_sign_request, sign_request};

let req = decode_sign_request(&qr_payload)?;
req.check_owned_inputs(&secp, &account_pub)?;          // inputs really ours?
let review = req.review_owned(&secp, &account_pub)?;   // trustless UI summary
// review.recipients is the headline amount; review.change is proven ours.
// Anything the companion lied about is already an Err by this point.
show_and_confirm(&review);
let signed_tx = sign_request(&secp, &master, &req)?;   // broadcast-ready bytes
```

Every one of those three calls independently runs `validate()` — which verifies
each input's amount against the funding transaction the package carries — and
re-derives ownership from the device's own key. None of them trusts the previous
one having been called, so skipping a step weakens the UI, never the signing
guarantees.

## Feature flags

| feature    | default | effect                                                        |
|------------|---------|---------------------------------------------------------------|
| `std`      | yes     | std in dependencies + `std::error::Error` impl                |
| `mnemonic` | yes     | BIP39 (`ExtPrivKey::from_entropy` / `from_phrase`) via `bip39`|
| `airgap`   | yes     | CBOR sign-request package via `minicbor`                      |

With `default-features = false` the crate is `#![no_std]` and needs only
`alloc`; CI cross-checks `thumbv7em-none-eabihf`.

## Correctness

Every algorithm was written against dcrd source and is pinned by oracles that
the live network already validated:

- BLAKE-256 known-answer vectors generated from dcrd `crypto/blake256`,
  covering every padding path, plus incremental-vs-one-shot consistency at
  every split point.
- BIP32 chains (`dprv`/`dpub`, private and public CKD) from dcrd
  `hdkeychain/extendedkey_test.go`.
- Address vectors for mainnet/testnet/regnet from dcrd
  `txscript/stdaddr/address_test.go`; the simnet and remaining regnet rows are
  regression pins over address IDs read from dcrd `chaincfg`, not an independent
  oracle.
- A **real mainnet transaction** whose embedded signatures must verify against
  our recomputed sighash (`tests/onchain_sighash.rs`) — one wrong byte in the
  sighash or wire layout and this fails — plus its txid and a byte-exact
  serialize round-trip.
- Golden CBOR bytes pin the airgap format against layout drift, alongside
  property tests asserting the byte-string headers directly. For format version 1
  these came from the KeyOS `decred-core` encoder and were a genuine
  cross-implementation check; the version 3 bytes are generated by dcr-rs itself,
  so interop with KeyOS/Keystone is **unverified** until those encoders speak
  version 3.

```
cargo test --all-features
```

## Security notes

- Private key material is zeroized on drop: `ExtPrivKey` secrets and chain
  codes (including every intermediate along a derivation path), BIP32 HMAC
  outputs, BIP39 mnemonics and seeds, and the buffers used to serialize and
  parse `dprv` strings.
- `ExtPrivKey` deliberately implements neither `Debug` nor `Display`.
- Signatures are RFC6979-deterministic and low-S normalized.
- Seeds are bounds-checked (16–64 bytes, per BIP32/dcrd), airgap amounts are
  capped at max supply with exact (non-wrapping) fee arithmetic, and the tx
  parser rejects hostile counts/lengths before allocating.
- The airgap signer re-derives each input's key and refuses to sign when the
  claimed prevout script does not match (`Error::ScriptMismatch`), refuses
  out-of-schema derivation paths and stake-tree inputs on its own (even if the
  caller skipped review), and both the review path *and* the signer re-derive
  change ownership rather than trusting the companion's `is_change` flags.
- Every airgap entry point validates independently: none assumes a previous
  step ran, so no ordering mistake by a caller can reach the signing guarantees.
- Untrusted input is bounded before work is done on it: base58 strings are
  length-gated ahead of the quadratic decode, CBOR packages are capped
  (`airgap::MAX_PACKAGE_BYTES`), and the tx parser rejects hostile
  counts/lengths, non-canonical varints, and trailing bytes.
- `#![forbid(unsafe_code)]`.

**Build the consuming firmware with `overflow-checks = true`.** This crate uses
exact `i128` arithmetic for every amount total and caps each amount at max
supply, so it does not rely on overflow checks — but a release profile silently
wraps on any arithmetic slip, and on a signer a wrapped amount is a wrong number
on a screen a user is trusting. A library's own `[profile]` is ignored when it is
a dependency, so this is the application's call to make:

```toml
[profile.release]
overflow-checks = true
```

This library has **not** been independently audited. Use at your own risk.

## License

ISC, matching dcrd and the rest of the Decred ecosystem. See
[LICENSE](LICENSE).
