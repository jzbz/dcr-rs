# dcr-rs

[![CI](https://github.com/jzbz/dcr-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/jzbz/dcr-rs/actions/workflows/ci.yml)

Decred (DCR) primitives for Rust: BLAKE-256, addresses, BIP32 HD keys with
Decred serialization, the transaction wire format, the Decred signature hash,
and low-S ECDSA P2PKH signing. `no_std + alloc` friendly — the same crate runs
on a host wallet and on embedded signers.

Grown out of the Decred signing cores written for the
[Keystone 3](https://github.com/KeystoneHQ/keystone3-firmware) and KeyOS
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
assert!(review.flagged_mismatches.is_empty());         // companion lied? refuse
let signed_tx = sign_request(&secp, &master, &req)?;   // broadcast-ready bytes
```

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
  `txscript/stdaddr/address_test.go`.
- A **real mainnet transaction** whose embedded signatures must verify against
  our recomputed sighash (`tests/onchain_sighash.rs`) — one wrong byte in the
  sighash or wire layout and this fails.
- Golden CBOR bytes from the original KeyOS encoder pin the airgap format.

```
cargo test --all-features
```

## Security notes

- Private key material (`ExtPrivKey` secrets and chain codes, including every
  intermediate along a derivation path) is zeroized on drop.
- `ExtPrivKey` deliberately implements neither `Debug` nor `Display`.
- Signatures are RFC6979-deterministic and low-S normalized.
- The airgap signer re-derives each input's key and refuses to sign when the
  claimed prevout script does not match (`Error::ScriptMismatch`), and the
  review logic re-derives change ownership rather than trusting the
  companion's `is_change` flags.
- `#![forbid(unsafe_code)]`.

This library has **not** been independently audited. Use at your own risk.

## License

ISC, matching dcrd and the rest of the Decred ecosystem. See
[LICENSE](LICENSE).
