# Changelog

Notable changes per release. Dates are release dates; for versions before
0.6.0, which were never tagged, the date the version number was set.

This library has **not** been independently audited. See [SECURITY.md](SECURITY.md).

## Unreleased

Key hygiene. No API or behaviour change: derived keys, addresses and
serializations are byte-identical to 0.6.2.

- HMAC-SHA512 wipes its state on drop. The hashes move to the digest 0.11
  family (sha2 0.11, hmac 0.13, ripemd 0.2) with their `zeroize` features on.
  After finalization the HMAC's outer SHA-512 state holds the whole 64-byte
  output (the master secret or child tweak, and the chain code), and its inner
  state and block buffer hold the inner hash; 0.6.2 dropped all of it without
  clearing it. Those states, the block buffer and the MAC output are now
  overwritten when derivation drops them. Temporaries inside those crates' own
  functions, such as HMAC's padded key and inner hash and SHA-512's message
  schedule, are still not reached.
- digest 0.10 and generic-array leave the dependency tree. A dependent that
  still uses the 0.10 family elsewhere builds both. The MSRV stays 1.85, which
  is what the new crates declare; they allow MSRV bumps in patch releases, so a
  fresh resolve on 1.85 can pick up a patch release that needs a newer
  toolchain.
- `Cargo.lock` is refreshed to the latest semver-compatible versions.

## 0.6.2 — 2026-09-22

The first release published to crates.io. No API or behaviour change from
0.6.1.

- The README's install section leads with the crates.io version requirement
  and keeps the signed-tag git dependency as an alternative, and a new
  Versioning section states which changes take a minor release.
- `ExtPrivKey::to_base58` and `from_base58` document that a `dprv` round trip
  can change a key's hardened children.
- Adds SECURITY.md (reporting, threat model) and this changelog. The package
  ships an allow-listed file set: sources, tests and documentation only.
- Documentation corrections: signing with a cached prefix hash is still
  quadratic in the input count (the rustdoc said O(N)), and a `dprv` round
  trip changes hardened children only for a key that was stored stripped.
- LICENSE carries the Decred developers' notice, for the network version bytes
  and the test vectors taken from dcrd.
- `cargo doc` with warnings denied no longer fails on the crate's own links to
  feature-gated items when those features are off, as in a
  `--no-default-features` build of this repository. Dependents fetching the
  crate from git or a registry were unaffected, because Cargo caps a
  dependency's lints.
- CI packages the crate and builds its documentation with warnings denied.

## 0.6.1 — 2026-09-09

Key hygiene. No API or behaviour change.

- HMAC intermediates are wiped on every exit of `master_from_seed` and private
  child derivation, which abandoned them on early error returns, and on every
  path of `ExtPubKey::derive_child`, which never wiped them.
- `ExtPubKey::from_base58` wipes its decoded key slot. It holds a raw secret
  exactly when a private key is pasted where a public one belongs.

## 0.6.0 — 2026-08-25

**Breaking:** `ReviewSummary` gained public fields. It is deliberately not
`#[non_exhaustive]`, so code that destructures it stops compiling rather than
quietly hiding a new signed property.

- airgap: `ReviewSummary` reports `lock_time`, `expiry` and
  `has_nonfinal_sequence`. All three are signed and unconstrained by
  `validate`, and none previously reached the review screen. Informational;
  nothing refuses on them.
- airgap: `decode_sign_request` refuses trailing bytes after the package. A
  caller passing a fixed-size or zero-padded buffer rather than slicing to its
  transport's reported length now gets
  `InvalidRequest("trailing bytes after package")`.
- hd: a zero CKD tweak is rejected, matching dcrd. Unreachable in practice.
- airgap: funding transaction prefixes are hashed in place rather than
  re-serialized.
- `Cargo.lock` is tracked, and the MSRV (1.85) job builds against it.

## 0.5.0 — 2026-07-31

**Breaking:** derived keys change for some seeds.

- hd: the master key's leading zero bytes are never stripped, matching dcrd.
  Under 0.4.0 the account key for the roughly 1 seed in 256 whose master key
  begins with a zero byte matched neither dcrd variant.

## 0.4.0 — 2026-07-29

**Breaking:** airgap format version 3, and derived keys change for some seeds.

- airgap: format version 3 encodes byte-valued fields as CBOR byte strings and
  carries only each funding transaction's prefix (`prev_tx_prefix`): version
  2's checks in under a third of the bytes. Only version 3 is accepted.
- hd: hardened derivation follows dcrd's variant, which strips a derived
  private key's leading zero bytes before the next hardened HMAC.
  `derive_child`, `derive_path`, `account_key` and `address_key` use it;
  `derive_child_bip32_std` and `derive_path_bip32_std` keep strict BIP32.
  Before this, `m/44'/42'/0'` differed from dcrwallet and decrediton for about
  1 seed in 130.
- airgap: `review_owned` proves every input is the device's own before counting
  it. A foreign input with a genuine funding transaction previously inflated
  the displayed total.

## 0.3.0 — 2026-07-29

**Breaking:** airgap format version 2.

- airgap: each input carries its funding transaction, and the device checks
  the declared amount and script against a txid it computes. Decred's sighash
  does not commit to input amounts, so version 1's `value_in` was an
  unverifiable assertion. Version 1 is refused.
- airgap: change ownership is proven by deriving the supplied path.
  `ReviewSummary::flagged_mismatches` is removed; a mislabelled change output
  is an error.
- `review_owned` validates its own input, and `sign_request` re-proves change
  ownership rather than trusting a review it cannot see. `NULL_BLOCK_HEIGHT`
  matches dcrd (0). The transaction parser rejects non-canonical varints and
  trailing bytes. Signing hashes the prefix half of the sighash once per
  transaction instead of once per input; it stays quadratic in the input count,
  with a far smaller constant.
- `Address::from_pubkey` takes `[u8; 33]`; `Address::decode_for` checks the
  network.

## 0.2.0 — 2026-07-03

**Breaking:** `SignRequest` gained a public field, so code that builds it with
a struct literal stops compiling. The CBOR format is compatible both ways:
packages without `account_fp` decode with it as `None`.

- airgap: `SignRequest` gains the optional `account_fp`, and
  `SignRequest::validate` checks structure and amounts without key material.
- airgap: `check_owned_inputs` and `sign_request` now run `validate`, so both
  refuse empty or oversized packages, amounts outside max supply, a negative
  fee and duplicate outpoints. `check_owned_inputs` also refuses hardened
  address indices.

## 0.1.0 — 2026-07-02

Initial release.
