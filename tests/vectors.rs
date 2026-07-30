// SPDX-License-Identifier: ISC
//
//! Reference vectors lifted verbatim from dcrd source. These are the oracle:
//! if dcr-rs disagrees with any of them, dcr-rs is wrong, because these exact
//! strings/bytes are what the live network produced and validated.
//!
//! Sources (paths are within the dcrd repo):
//!   - hdkeychain/extendedkey_test.go   (BIP32 dprv/dpub chains, public CKD)
//!   - txscript/stdaddr/address_test.go (P2PKH/P2SH addresses + payScripts)
//!   - crypto/blake256                  (BLAKE-256 KATs)
//!
//! `cargo test --all-features` runs these on the host before anything ships.

use dcr_rs::address::{p2pkh_script, p2sh_script, Address, AddressKind};
use dcr_rs::blake256;
use dcr_rs::hd::{ExtPrivKey, ExtPubKey, BRANCH_EXTERNAL, HARDENED};
use dcr_rs::secp256k1::Secp256k1;
use dcr_rs::{Error, Network};

// ---------------------------------------------------------------------------
// BLAKE-256 — Decred's universal hash. NOT BLAKE2/BLAKE3.
// ---------------------------------------------------------------------------

#[test]
fn blake256_empty_kat() {
    // dcrd: blake256.Sum256("")
    let got = blake256::sum256(b"");
    assert_eq!(
        hex::encode(got),
        "716f6e863f744b9ac22c97ec7b76ea5f5908bc5b2f67c61510bfc4751384ea7a"
    );
}

#[test]
fn blake256_single_zero_kat() {
    // dcrd: blake256.Sum256(0x00)
    let got = blake256::sum256(&[0x00]);
    assert_eq!(
        hex::encode(got),
        "0ce8d4ef4dd7cd8d62dfded9d4edb0a774ae6a41929a74da23109e8f11139c87"
    );
}

// ---------------------------------------------------------------------------
// BIP32 over Decred version bytes. HMAC master key is "Bitcoin seed" for every
// coin; Decred differs only in the dprv/dpub version prefixes and the
// double-BLAKE256 base58 checksum. Chains from dcrd extendedkey_test.go
// TestBIP0032Vectors (test vector 1).
// ---------------------------------------------------------------------------

const BIP32_VEC1_SEED: &str = "000102030405060708090a0b0c0d0e0f";

/// (path, wantPriv, wantPub) — dcrd "test vector 1" chains.
const VEC1_CHAINS: &[(&[u32], &str, &str)] = &[
    (
        &[],
        "dprv3hCznBesA6jBtmoyVFPfyMSZ1qYZ3WdjdebquvkEfmRfxC9VFEFi2YDaJqHnx7uGe75eGSa3Mn3oHK11hBW7KZUrPxwbCPBmuCi1nwm182s",
        "dpubZ9169KDAEUnyoBhjjmT2VaEodr6pUTDoqCEAeqgbfr2JfkB88BbK77jbTYbcYXb2FVz7DKBdW4P618yd51MwF8DjKVopSbS7Lkgi6bowX5w",
    ),
    (
        &[HARDENED],
        "dprv3kUQDBztdyjKuwnaL3hfKYpT7W6X2huYH5d61YSWFBebSYwEBHAXJkCpQ7rvMAxPzKqxVCGLvBqWvGxXjAyMJsV1XwKkfnQCM9KctC8k8bk",
        "dpubZCGVaKZBiMo7pMgLaZm1qmchjWenTeVcUdFQkTNsFGFEA6xs4EW8PKiqYqP7HBAitt9Hw16VQkQ1tjsZQSHNWFc6bEK6bLqrbco24FzBTY4",
    ),
    (
        &[HARDENED, 1],
        "dprv3nRtCZ5VAoHW4RUwQgRafSNRPUDFrmsgyY71A5eoZceVfuyL9SbZe2rcbwDW2UwpkEniE4urffgbypegscNchPajWzy9QS4cRxF8QYXsZtq",
        "dpubZEDyZgdnFBMHxqNhfCUwBfAg1UmXHiTmB5jKtzbAZhF8PTzy2PwAicNdkg1CmW6TARxQeUbgC7nAQenJts4YoG3KMiqcjsjgeMvwLc43w6C",
    ),
    (
        &[HARDENED, 1, 2 | HARDENED],
        "dprv3pYtkZK168vgrU38gXkUSjHQ2LGpEUzQ9fXrR8fGUR59YviSnm6U82XjQYhpJEUPnVcC9bguJBQU5xVM4VFcDHu9BgScGPA6mQMH4bn5Cth",
        "dpubZGLz7gsJAWzUksvtw3opxx5eeLq5fRaUMDABA3bdUVfnGUk5fiS5Cc3kZGTjWtYr3jrEavQQnAF6jv2WCpZtFX4uFgifXqev6ED1TM9rTCB",
    ),
    (
        &[HARDENED, 1, 2 | HARDENED, 2],
        "dprv3r7zqYFjT3NiNzdnwGxGpYh6S1TJCp1zA6mSEGaqLBJFnCB94cRMp7YYLR49aTZHZ7ya1CXwQJ6rodKeU9NgQTxkPSK7pzgZRgjYkQ7rgJh",
        "dpubZHv6Cfp2XRSWHQXZBo1dLmVM421Zdkc4MePkyBXCLFttVkCmwZkxth4ZV9PzkFP3DtD5xcVq2CPSYpJMWMaoxu1ixz4GNZFVcE2xnHP6chJ",
    ),
    (
        &[HARDENED, 1, 2 | HARDENED, 2, 1000000000],
        "dprv3tJXnTDSb3uE6Euo6WvvhFKfBMNfxuJt5smqyPoHEoomoBMQyhYoQSKJAHWtWxmuqdUVb8q9J2NaTkF6rYm6XDrSotkJ55bM21fffa7VV97",
        "dpubZL6d9amjfRy1zeoZM2zHDU7uoMvwPqtxHRQAiJjeEtQQWjP3retQV1qKJyzUd6ZJNgbJGXjtc5pdoBcTTYTLoxQzvV9JJCzCjB2eCWpRf8T",
    ),
];

#[test]
fn bip32_vector1_priv_and_pub_chains() {
    let secp = Secp256k1::new();
    let seed = hex::decode(BIP32_VEC1_SEED).unwrap();
    let master = ExtPrivKey::master_from_seed(&seed, Network::Mainnet).unwrap();
    for (path, want_priv, want_pub) in VEC1_CHAINS {
        let key = master.derive_path(&secp, path).unwrap();
        assert_eq!(&key.to_base58(), want_priv, "priv at {path:?}");
        assert_eq!(&key.neuter(&secp).to_base58(), want_pub, "pub at {path:?}");
    }
}

#[test]
fn bip32_seed_length_bounds() {
    // dcrd hdkeychain: 16–64 bytes. Catching an entropy-for-seed mixup here
    // beats deriving a wallet nothing else can reproduce.
    assert!(ExtPrivKey::master_from_seed(&[0u8; 15], Network::Mainnet).is_err());
    assert!(ExtPrivKey::master_from_seed(&[0u8; 65], Network::Mainnet).is_err());
    assert!(ExtPrivKey::master_from_seed(&[7u8; 16], Network::Mainnet).is_ok());
    assert!(ExtPrivKey::master_from_seed(&[7u8; 64], Network::Mainnet).is_ok());
}

#[test]
fn bip32_serialization_roundtrip() {
    let secp = Secp256k1::new();
    let seed = hex::decode(BIP32_VEC1_SEED).unwrap();
    let master = ExtPrivKey::master_from_seed(&seed, Network::Mainnet).unwrap();
    let child = master.derive_path(&secp, &[HARDENED, 1]).unwrap();

    // dprv → parse → dprv must be the identity, preserving all metadata.
    let parsed = ExtPrivKey::from_base58(&child.to_base58()).unwrap();
    assert_eq!(parsed.to_base58(), child.to_base58());
    assert_eq!(parsed.network, Network::Mainnet);
    assert_eq!(parsed.depth, 2);
    assert_eq!(parsed.child_number, 1);

    // Same for the neutered form.
    let pubkey = child.neuter(&secp);
    let parsed = ExtPubKey::from_base58(&pubkey.to_base58()).unwrap();
    assert_eq!(parsed, pubkey);
}

#[test]
fn bip32_priv_pub_prefix_mixups_rejected() {
    let secp = Secp256k1::new();
    let seed = hex::decode(BIP32_VEC1_SEED).unwrap();
    let master = ExtPrivKey::master_from_seed(&seed, Network::Mainnet).unwrap();
    let dprv = master.to_base58();
    let dpub = master.neuter(&secp).to_base58();
    // (`.err()` because ExtPrivKey deliberately has no Debug impl.)
    assert_eq!(
        ExtPrivKey::from_base58(&dpub).err(),
        Some(Error::UnknownPrefix)
    );
    assert_eq!(
        ExtPubKey::from_base58(&dprv).unwrap_err(),
        Error::UnknownPrefix
    );
}

#[test]
fn bip32_testnet_simnet_version_bytes() {
    // Same key material, other networks: the serialized string must start with
    // the documented dcrd prefixes and roundtrip through parsing.
    let secp = Secp256k1::new();
    let seed = hex::decode(BIP32_VEC1_SEED).unwrap();
    for (net, priv_pfx, pub_pfx) in [
        (Network::Testnet, "tprv", "tpub"),
        (Network::Simnet, "sprv", "spub"),
        (Network::Regnet, "rprv", "rpub"),
    ] {
        let master = ExtPrivKey::master_from_seed(&seed, net).unwrap();
        let dprv = master.to_base58();
        let dpub = master.neuter(&secp).to_base58();
        assert!(dprv.starts_with(priv_pfx), "{net:?}: {dprv}");
        assert!(dpub.starts_with(pub_pfx), "{net:?}: {dpub}");
        assert_eq!(ExtPrivKey::from_base58(&dprv).unwrap().network, net);
        assert_eq!(ExtPubKey::from_base58(&dpub).unwrap().network, net);
    }
}

// ---------------------------------------------------------------------------
// Public CKD — dcrd extendedkey_test.go TestPublicDerivation. Parse a dpub,
// derive non-hardened children, compare serialized results.
// ---------------------------------------------------------------------------

const PUB_VEC1_MASTER: &str = "dpubZF8BRmciAzYoTjXZ3bbRWLVCwUKtTquact3Tr6ye77Rgmw76VyqMb9TB9KpfrvUYEM5d1Au4fQzE2BbtxRjwzGsqnWHmtQP9UV1kxZaqvb6";
const PUB_VEC2_MASTER: &str = "dpubZF4LSCdF9YKZfNzTVYhz4RBxsjYXqms8AQnMBHXZ8GUKoRSigG7kQnKiJt5pzk93Q8FxcdVBEkQZruSXduGtWnkwXzGnjbSovQ97dCxqaXc";

const PUB_CHAINS: &[(&str, &[u32], &str)] = &[
    (PUB_VEC1_MASTER, &[], PUB_VEC1_MASTER),
    (
        PUB_VEC1_MASTER,
        &[0],
        "dpubZHm6cmVU9pvfDCe3BY7iESzsEnV6xfi4DfoYvycnWLM9cryzKA84DqJ2CphYq6cfiEXgo9C3YLJA4ou81mavw9NDtNc3bLCWVqJz8Fx8qxB",
    ),
    (
        PUB_VEC1_MASTER,
        &[0, 1],
        "dpubZKtA6UTDuxeXV2PcYqoe68u7cgDhbTNbA4dUJoaAvfWzuCcRQCyG5S6dbpDZb2p3B5Y2XxLtD94Nemc8QRV4RspmvGwHvE2FZsfE5Pqpeor",
    ),
    (
        PUB_VEC1_MASTER,
        &[0, 1, 2],
        "dpubZMwLXm5dRVEJRvJHU8gNV7RwHeXMRRUnYFD4f6C8uNFfqksD1FCDARTwNPsQB3Pg4LuoKXkZbPnE6woUyedwNYVPvZToT5x4Kt6rs4GKa9c",
    ),
    (
        PUB_VEC1_MASTER,
        &[0, 1, 2, 2],
        "dpubZPfASfojwk6MhtAtkM6wPdQBr1ycVjoyqs3N51zR1keK6FcBhjBTtdW3Wn3kDLBZqgLnGozu8Gh3FV8GrFGpu3knmGVoF1Z6yGdqLU1Rz1S",
    ),
    (
        PUB_VEC1_MASTER,
        &[0, 1, 2, 2, 1000000000],
        "dpubZR5Pf8cbUGikESevygwydenBaTsgcvoYnRSi7tygu23PxmVEG4GeMQj54oHFoPyRdt7Pg4sMad56yprQszbNyZVewaNEhDkn112C3mqB1fd",
    ),
    (
        PUB_VEC2_MASTER,
        &[0, 2147483647],
        "dpubZJgFEUcAZawGaLZdFEX6FfQBQVgU4bUC5qvDERUTD5dfcB2AQPnJ1dKp1R2DrAzC36BznZG43317s2oBJv3PuaZmA6HqmwMu6vNna4Gfumf",
    ),
    (
        PUB_VEC2_MASTER,
        &[0, 2147483647, 1, 2147483646, 2],
        "dpubZRuRErXqhdJaZWD1AzXB6d5w2zw7UZ7ALxiS1gHbnQbVEohBzQzsVwGRzq97pmuE7ToA6DGn2QTH4DexxzdnMvkiYUpk8Nh2KEuYUM2RCeU",
    ),
];

#[test]
fn bip32_public_derivation_vectors() {
    let secp = Secp256k1::new();
    for (master, path, want) in PUB_CHAINS {
        let key = ExtPubKey::from_base58(master).unwrap();
        let derived = key.derive_path(&secp, path).unwrap();
        assert_eq!(&derived.to_base58(), want, "pub CKD at {path:?}");
    }
}

#[test]
fn bip32_public_hardened_derivation_rejected() {
    let secp = Secp256k1::new();
    let key = ExtPubKey::from_base58(PUB_VEC1_MASTER).unwrap();
    assert_eq!(
        key.derive_child(&secp, HARDENED).unwrap_err(),
        Error::HardenedFromPublic
    );
}

#[test]
fn bip32_priv_and_pub_derivation_agree() {
    // Deriving privately then neutering must equal neutering then deriving
    // publicly — the watch-only companion and the signer see the same keys.
    let secp = Secp256k1::new();
    let seed = hex::decode(BIP32_VEC1_SEED).unwrap();
    let master = ExtPrivKey::master_from_seed(&seed, Network::Mainnet).unwrap();
    let account = master.account_key(&secp, 0).unwrap();
    let account_pub = account.neuter(&secp);
    for branch in [0u32, 1] {
        for index in [0u32, 1, 7] {
            let via_priv = account.address_key(&secp, branch, index).unwrap();
            let via_pub = account_pub.pubkey_at(&secp, branch, index).unwrap();
            assert_eq!(via_priv.compressed_pubkey(&secp), via_pub);
            assert_eq!(
                via_priv.p2pkh_address(&secp),
                Address::from_pubkey(&via_pub, Network::Mainnet).encode()
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Addresses — dcrd txscript/stdaddr/address_test.go vectors (base58check with
// double-BLAKE256 checksum) and the canonical payScripts.
// ---------------------------------------------------------------------------

/// (hash160, network, kind, address) from dcrd address_test.go.
const ADDR_VECTORS: &[(&str, Network, AddressKind, &str)] = &[
    (
        "2789d58cfa0957d206f025c2af056fc8a77cebb0",
        Network::Mainnet,
        AddressKind::P2pkh,
        "DsUZxxoHJSty8DCfwfartwTYbuhmVct7tJu",
    ),
    (
        "229ebac30efd6a69eec9c1a48e048b7c975c25f2",
        Network::Mainnet,
        AddressKind::P2pkh,
        "DsU7xcg53nxaKLLcAUSKyRndjG78Z2VZnX9",
    ),
    (
        "f0b4e85100aee1a996f22915eb3c3f764d53779a",
        Network::Mainnet,
        AddressKind::P2sh,
        "DcuQKx8BES9wU7C6Q5VmLBjw436r27hayjS",
    ),
    (
        "c7da5095683436f4435fc4e7163dcafda1a2d007",
        Network::Mainnet,
        AddressKind::P2sh,
        "DcqgK4N4Ccucu2Sq4VDAdu4wH4LASLhzLVp",
    ),
    (
        "f15da1cb8d1bcb162c6ab446c95757a6e791c916",
        Network::Testnet,
        AddressKind::P2pkh,
        "Tso2MVTUeVrjHTBFedFhiyM7yVTbieqp91h",
    ),
    (
        "36c1ca10a8a6a4b5d4204ac970853979903aa284",
        Network::Testnet,
        AddressKind::P2sh,
        "TccWLgcquqvwrfBocq5mcK5kBiyw8MvyvCi",
    ),
    (
        "36c1ca10a8a6a4b5d4204ac970853979903aa284",
        Network::Regnet,
        AddressKind::P2sh,
        "RcKq28Eheeo2eJvWakqWWAr5pqCUWykwDHe",
    ),
    // The three remaining network/kind combinations had no vector at all, so the
    // round-trip test above passed for *any* value of their address IDs. The
    // constants themselves are verified against dcrd `chaincfg`
    // {simnet,regnet}params.go (Ss/Sc/Rs prefixes); these strings pin them so a
    // future edit to one byte cannot slip through unnoticed. Generated by
    // dcr-rs — a regression pin, not an independent oracle like the mainnet and
    // testnet rows above.
    (
        "f15da1cb8d1bcb162c6ab446c95757a6e791c916",
        Network::Simnet,
        AddressKind::P2pkh,
        "SsrMVhpZAFt17gmBB6qjq9HvgrpVtKtzUJM",
    ),
    (
        "36c1ca10a8a6a4b5d4204ac970853979903aa284",
        Network::Simnet,
        AddressKind::P2sh,
        "ScfqUtyvRbxDgtmj9JfoiV2Yu6LqJ57vVBM",
    ),
    (
        "f15da1cb8d1bcb162c6ab446c95757a6e791c916",
        Network::Regnet,
        AddressKind::P2pkh,
        "RsWM2w5LPJip56uxcZ1Scq7Tcbg97EfiwPA",
    ),
];

fn h160(s: &str) -> [u8; 20] {
    hex::decode(s).unwrap().try_into().unwrap()
}

#[test]
fn address_vectors_encode_and_decode() {
    for (hash_hex, network, kind, want) in ADDR_VECTORS {
        let addr = Address {
            network: *network,
            kind: *kind,
            hash: h160(hash_hex),
        };
        assert_eq!(&addr.encode(), want);
        assert_eq!(Address::decode(want).unwrap(), addr);
    }
}

#[test]
fn address_payscript_layouts() {
    // dcrd: P2PKH 76a914<hash>88ac, P2SH a914<hash>87.
    let pkh = h160("2789d58cfa0957d206f025c2af056fc8a77cebb0");
    assert_eq!(
        hex::encode(p2pkh_script(&pkh)),
        "76a9142789d58cfa0957d206f025c2af056fc8a77cebb088ac"
    );
    let sh = h160("f0b4e85100aee1a996f22915eb3c3f764d53779a");
    assert_eq!(
        hex::encode(p2sh_script(&sh)),
        "a914f0b4e85100aee1a996f22915eb3c3f764d53779a87"
    );

    // Script → address recovers the vector strings.
    let a = Address::from_script(&p2pkh_script(&pkh), Network::Mainnet).unwrap();
    assert_eq!(a.encode(), "DsUZxxoHJSty8DCfwfartwTYbuhmVct7tJu");
    let b = Address::from_script(&p2sh_script(&sh), Network::Mainnet).unwrap();
    assert_eq!(b.encode(), "DcuQKx8BES9wU7C6Q5VmLBjw436r27hayjS");
}

#[test]
fn address_decode_rejects_garbage() {
    // Flipped last char → checksum failure.
    assert_eq!(
        Address::decode("DsUZxxoHJSty8DCfwfartwTYbuhmVct7tJv").unwrap_err(),
        Error::BadChecksum
    );
    // 'l' is not in the base58 alphabet.
    assert_eq!(
        Address::decode("DsUZxxoHlSty8DCfwfartwTYbuhmVct7tJu").unwrap_err(),
        Error::Base58
    );
    assert_eq!(Address::decode("").unwrap_err(), Error::Parse);
}

// ---------------------------------------------------------------------------
// Regression tests for the review pass.
// ---------------------------------------------------------------------------

/// `address_key` must refuse a hardened branch or index.
///
/// It used to forward them to `derive_path`, which happily derived a hardened
/// child — a key the watch-only companion holding only the account `dpub` can
/// never reproduce, so the private and public halves of the wallet would silently
/// disagree about which address a path names.
#[test]
fn address_key_rejects_hardened_components() {
    let secp = Secp256k1::new();
    let seed = hex::decode(BIP32_VEC1_SEED).unwrap();
    let m = ExtPrivKey::master_from_seed(&seed, Network::Mainnet).unwrap();
    let acct = m.account_key(&secp, 0).unwrap();

    // (`.err()` because ExtPrivKey deliberately has no Debug impl.)
    for (branch, index) in [(0, HARDENED), (HARDENED, 0), (0, u32::MAX)] {
        assert_eq!(
            acct.address_key(&secp, branch, index).err(),
            Some(Error::HardenedIndex),
            "branch {branch:#x} index {index:#x}"
        );
    }

    // The non-hardened form still works, and agrees with the account dpub.
    let priv_key = acct.address_key(&secp, 0, 7).unwrap();
    let want = acct.neuter(&secp).pubkey_at(&secp, 0, 7).unwrap();
    assert_eq!(priv_key.compressed_pubkey(&secp), want);
}

/// `Address::decode` reports whichever network the prefix names, and
/// `pk_script` is network-blind, so a caller that already knows its network
/// should use `decode_for` and get a refusal rather than a valid payment script
/// for an address from another chain.
#[test]
fn decode_for_rejects_cross_network_addresses() {
    let hash = h160("f15da1cb8d1bcb162c6ab446c95757a6e791c916");
    for net in Network::ALL {
        let s = Address::p2pkh(hash, net).encode();
        // Matching network: accepted, and identical to plain decode.
        assert_eq!(
            Address::decode_for(&s, net).unwrap(),
            Address::decode(&s).unwrap()
        );
        // Every other network: refused.
        for other in Network::ALL.into_iter().filter(|n| *n != net) {
            assert_eq!(
                Address::decode_for(&s, other),
                Err(Error::UnknownPrefix),
                "{} must not decode as {}",
                s,
                other.name()
            );
        }
    }
}

/// Base58 decoding is quadratic in the input length, so both decoders
/// length-gate before doing any work. Without the gate a signer handed a long
/// string from a QR code stalls for seconds (128 KB) to minutes (1 MB).
#[test]
fn base58_decoders_reject_overlong_input() {
    let long = "D".repeat(dcr_rs::hashing::MAX_BASE58_LEN + 1);
    assert_eq!(Address::decode(&long), Err(Error::Parse));
    assert_eq!(ExtPrivKey::from_base58(&long).err(), Some(Error::Parse));
    assert_eq!(ExtPubKey::from_base58(&long), Err(Error::Parse));

    // Real keys and addresses are comfortably inside the bound.
    let secp = Secp256k1::new();
    let seed = hex::decode(BIP32_VEC1_SEED).unwrap();
    let m = ExtPrivKey::master_from_seed(&seed, Network::Mainnet).unwrap();
    assert!(m.to_base58().len() <= dcr_rs::hashing::MAX_BASE58_LEN);
    assert!(m.neuter(&secp).to_base58().len() <= dcr_rs::hashing::MAX_BASE58_LEN);
    assert!(m.p2pkh_address(&secp).len() <= dcr_rs::hashing::MAX_BASE58_LEN);
}

/// A wrong-length extended key or a bad checksum must still round-trip cleanly
/// through the parser's error paths, which now wipe the decoded buffer before
/// returning (it holds the raw secret for a `dprv`).
#[test]
fn ext_key_parse_error_paths() {
    let secp = Secp256k1::new();
    let seed = hex::decode(BIP32_VEC1_SEED).unwrap();
    let m = ExtPrivKey::master_from_seed(&seed, Network::Mainnet).unwrap();
    let good = m.to_base58();

    // Flip the last character to break the checksum.
    let mut chars: Vec<char> = good.chars().collect();
    let last = chars.len() - 1;
    chars[last] = if chars[last] == 'a' { 'b' } else { 'a' };
    let bad: String = chars.into_iter().collect();
    assert_eq!(
        ExtPrivKey::from_base58(&bad).err(),
        Some(Error::BadChecksum)
    );

    // Too short to be an 82-byte body.
    assert_eq!(ExtPrivKey::from_base58("dprv").err(), Some(Error::Parse));
    // Not base58 at all.
    assert!(matches!(
        ExtPrivKey::from_base58("dprv0OIl"),
        Err(Error::Base58) | Err(Error::Parse)
    ));

    // The good one still parses, on both halves.
    assert_eq!(ExtPrivKey::from_base58(&good).unwrap().to_base58(), good);
    let pubs = m.neuter(&secp).to_base58();
    assert_eq!(ExtPubKey::from_base58(&pubs).unwrap().to_base58(), pubs);
}

// ---------------------------------------------------------------------------
// Hardened derivation variant. THE discriminating vectors: dcrd's hdkeychain
// strips leading zero bytes from a child private key before feeding it into the
// next hardened HMAC, so its default `Child` diverges from strict BIP32
// (`ChildBIP32Std`) for any parent key with a leading zero byte.
//
// Every other BIP32 vector in this file uses seed 000102…0f, whose keys have no
// leading zeros, so they pass under BOTH variants and discriminate nothing. The
// two seeds below were chosen precisely because they do diverge, and every string
// was generated by running the local dcrd `hdkeychain` (v3) against both
// `Child` and `ChildBIP32Std` — so this is a real cross-implementation oracle,
// not a self-generated pin.
// ---------------------------------------------------------------------------

/// dcrd's own BIP32 test-vector-4 seed. `m/0'` has private key `00d948e9…`, so
/// `m/0'/1'` is where the variants part company.
const ZERO_LEAD_SEED_A: &str = "3ddd5602285899a946114506157c7997e5444528f3003f6134712147db19b678";

/// A seed whose `m/44'/42'` private key is `0043cf2d…`, so the divergence lands
/// squarely on the BIP44 account key every wallet uses.
const ZERO_LEAD_SEED_B: &str = "2fb78f0f7770720fa05952587c055866852c1e2f2cd7814e92e06d91b72af083";

#[test]
fn hardened_derivation_matches_dcrd_legacy_child() {
    let secp = Secp256k1::new();

    // (seed, path, dcrd Child, dcrd ChildBIP32Std)
    let cases: &[(&str, &[u32], &str, &str)] = &[
        (
            ZERO_LEAD_SEED_A,
            &[HARDENED, 1 | HARDENED],
            "dprv3mhK5vAEzovJTfnqwfzGTamym6yPPGEggq5fpQHrnXGyb22Doqew7Co7mCvYHe6nTCewnggesjM4LVJj8RFJ92ANtogs3NY7ev4YxSwf6ez",
            "dprv3mhK5vAEzovJUV5RycwKGbth8MYtoYL1aJTxN1T8PLmH6da6aMU8nYKQiC5Zj7mC7pH4G8xPxGZVR51FG9Ssptzx1c39A1JxADS6zDrsLPr",
        ),
        (
            ZERO_LEAD_SEED_B,
            &[44 | HARDENED, 42 | HARDENED, HARDENED],
            "dprv3o9RD4HnZWi2Ammh2RMH2yLR2oQzt8iHLk8eEhzP53xMffriXxWUpiFoJKQ927i6g1V1zraGeE1FKXxcuKXZg5WWUK6Nc3nVtdFBPHoStQ4",
            "dprv3o9RD4HnZWi2BfE3uRFunUsF9hiDyykGeDZfjr8McYm7pv2bTCYUfsnM6XmywQDTXrjcizDorH6YimQhaLBWgFWabQh59PuSxunuoZqAZQU",
        ),
    ];

    for (seed_hex, path, want_legacy, want_strict) in cases {
        let seed = hex::decode(seed_hex).unwrap();
        let m = ExtPrivKey::master_from_seed(&seed, Network::Mainnet).unwrap();

        assert_eq!(
            &m.derive_path(&secp, path).unwrap().to_base58(),
            want_legacy,
            "derive_path must match dcrd hdkeychain.Child (the dcrwallet default) at {path:?}"
        );
        assert_eq!(
            &m.derive_path_bip32_std(&secp, path).unwrap().to_base58(),
            want_strict,
            "derive_path_bip32_std must match dcrd hdkeychain.ChildBIP32Std at {path:?}"
        );
        assert_ne!(
            want_legacy, want_strict,
            "vector must actually discriminate the two variants"
        );
    }
}

/// A key whose leading zero byte is at the *end* of the path serializes the same
/// under both variants — the divergence only appears once that key is used as a
/// hardened parent. Pins that the zero is preserved in serialization (dcrd
/// zero-pads `dprv` to 32 bytes even when its stored key is shorter).
#[test]
fn leading_zero_key_serializes_identically_under_both_variants() {
    let secp = Secp256k1::new();
    let seed = hex::decode(ZERO_LEAD_SEED_A).unwrap();
    let m = ExtPrivKey::master_from_seed(&seed, Network::Mainnet).unwrap();

    // dcrd, both variants, m/0' (private key 00d948e9…):
    const WANT: &str = "dprv3jkqwzsd88yXqZJdSuLnfKqGPYzCVffataF79tcuPhdudeU3d1uUpvwn5Btmbai3BoVYhzbsEQ7tcH1XtEJ1BhzNSAtZfqv8BtSpdq5FEpj";
    assert_eq!(
        &m.derive_path(&secp, &[HARDENED]).unwrap().to_base58(),
        WANT
    );
    assert_eq!(
        &m.derive_path_bip32_std(&secp, &[HARDENED])
            .unwrap()
            .to_base58(),
        WANT
    );
}

/// The wallet-facing consequence: the BIP44 account key, its `dpub`, and the
/// first receive address must be the ones dcrwallet/decrediton derive.
#[test]
fn wallet_path_matches_dcrwallet_for_a_leading_zero_seed() {
    let secp = Secp256k1::new();
    let seed = hex::decode(ZERO_LEAD_SEED_B).unwrap();
    let m = ExtPrivKey::master_from_seed(&seed, Network::Mainnet).unwrap();

    let account = m.account_key(&secp, 0).unwrap();
    // dcrd Child path m/44'/42'/0', neutered:
    assert_eq!(
        account.neuter(&secp).to_base58(),
        "dpubZEwWaBr5dtmp5BfTGwQdZC8feoyGK5JMYHkxycvk58YzPDtMQur5uHmpT2CxorMxmQezrnzrb9Ki5Dq4cfStQtPrHc1eeFqHdKtnyy4pttK",
        "account_key must use the Decred variant, as dcrwallet does"
    );
    // m/44'/42'/0'/0/0 under dcrd Child:
    assert_eq!(
        account
            .address_key(&secp, BRANCH_EXTERNAL, 0)
            .unwrap()
            .p2pkh_address(&secp),
        "DsSYaeDjG6LYn1KJ85bNu1ousCu74scVVUC"
    );
    // The strict-BIP32 account key is a DIFFERENT wallet; pinned so the
    // divergence stays visible rather than becoming a silent regression.
    let strict = m
        .derive_path_bip32_std(&secp, &[44 | HARDENED, 42 | HARDENED, HARDENED])
        .unwrap();
    assert_eq!(
        strict
            .address_key(&secp, BRANCH_EXTERNAL, 0)
            .unwrap()
            .p2pkh_address(&secp),
        "DsgSmj1YRrxL2m4yPtkZmm5uZVP5Bis9Gbb"
    );

    // Public derivation below the account key is variant-independent: the same
    // dpub yields the same address either way.
    let via_pub = account
        .neuter(&secp)
        .pubkey_at(&secp, BRANCH_EXTERNAL, 0)
        .unwrap();
    assert_eq!(
        Address::from_pubkey(&via_pub, Network::Mainnet).encode(),
        "DsSYaeDjG6LYn1KJ85bNu1ousCu74scVVUC"
    );
}

// ---------------------------------------------------------------------------
// BIP39 seed expansion. Nothing pinned this path: `from_phrase` was called by no
// test at all, and `from_entropy` only as an unasserted key factory. It is the
// path every user exercises when restoring a wallet onto a signer, and its
// failure mode is silent — a wrong salt, iteration count, normalization, or a
// swapped (phrase, passphrase) argument order all still yield a valid-looking
// dprv and a valid-looking address, just for the wrong wallet.
//
// Oracle: the published BIP39 (Trezor) vectors. The expected seeds below were
// recomputed independently as
// PBKDF2-HMAC-SHA512(NFKD(phrase), NFKD("mnemonic"+passphrase), 2048, 64) and
// agree with the published values, so `master_from_seed(seed)` — already covered
// by the dcrd chains above — is the reference the mnemonic path must reproduce.
// ---------------------------------------------------------------------------

#[cfg(feature = "mnemonic")]
#[test]
fn bip39_mnemonic_expansion_matches_published_vectors() {
    // (entropy, phrase, passphrase, seed). Phrases derived from the official
    // English wordlist (entropy ‖ checksum, 11 bits per word) and seeds from
    // PBKDF2, both computed outside this crate.
    let cases: &[(&str, &str, &str, &str)] = &[
        (
            "00000000000000000000000000000000",
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "TREZOR",
            "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
        ),
        (
            "00000000000000000000000000000000",
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "",
            "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4",
        ),
        (
            "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
            "legal winner thank year wave sausage worth useful legal winner thank yellow",
            "TREZOR",
            "2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6fa457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607",
        ),
        (
            "ffffffffffffffffffffffffffffffff",
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
            "TREZOR",
            "ac27495480225222079d7be181583751e86f571027b0497b5b5d11218e0a8a13332572917f0f8e5a589620c6f15b11c61dee327651a14c34e18231052e48c069",
        ),
        // 24-word cases: the shape a hardware signer actually restores from.
        (
            "0000000000000000000000000000000000000000000000000000000000000000",
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
            "TREZOR",
            "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd3097170af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8",
        ),
        (
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
            "TREZOR",
            "dd48c104698c30cfe2b6142103248622fb7bb0ff692eebb00089b32d22484e1613912f0a5b694407be899ffd31ed3992c456cdf60f5d4564b8ba3f05a69890ad",
        ),
    ];

    for (entropy_hex, phrase, passphrase, seed_hex) in cases {
        let seed = hex::decode(seed_hex).unwrap();
        let want = ExtPrivKey::master_from_seed(&seed, Network::Mainnet)
            .unwrap()
            .to_base58();

        assert_eq!(
            ExtPrivKey::from_phrase(phrase, passphrase, Network::Mainnet)
                .unwrap()
                .to_base58(),
            want,
            "from_phrase must expand to the published BIP39 seed ({passphrase:?})"
        );
        assert_eq!(
            ExtPrivKey::from_entropy(
                &hex::decode(entropy_hex).unwrap(),
                passphrase,
                Network::Mainnet
            )
            .unwrap()
            .to_base58(),
            want,
            "from_entropy must agree with from_phrase for the same entropy"
        );
    }

    // The passphrase is not the mnemonic: swapping the arguments must not silently
    // produce a key (it is not a valid phrase).
    assert!(ExtPrivKey::from_phrase("TREZOR", cases[0].1, Network::Mainnet).is_err());
    // A checksum-invalid phrase is refused rather than expanded.
    assert!(ExtPrivKey::from_phrase(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon",
        "",
        Network::Mainnet
    )
    .is_err());
    // Distinct passphrases must give distinct wallets.
    let a = ExtPrivKey::from_phrase(cases[0].1, "", Network::Mainnet)
        .unwrap()
        .to_base58();
    let b = ExtPrivKey::from_phrase(cases[0].1, "TREZOR", Network::Mainnet)
        .unwrap()
        .to_base58();
    assert_ne!(a, b, "the passphrase must reach the KDF");
}
