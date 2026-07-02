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
use dcr_rs::hd::{ExtPrivKey, ExtPubKey, HARDENED};
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
