// SPDX-License-Identifier: ISC
//! Decred v0 addresses: P2PKH (ecdsa-secp256k1) and P2SH.
//!
//! dcrd `chaincfg` address IDs (see [`Network`]) with the double-BLAKE256
//! base58check from [`crate::hashing`]. Payment scripts per
//! `txscript/stdaddr`:
//!
//! * P2PKH: `DUP HASH160 <20> EQUALVERIFY CHECKSIG` (25 bytes)
//! * P2SH:  `HASH160 <20> EQUAL` (23 bytes)

use alloc::string::String;
use alloc::vec::Vec;

use crate::hashing::{check_decode, check_encode, hash160};
use crate::network::Network;
use crate::Error;

const OP_DUP: u8 = 0x76;
const OP_HASH160: u8 = 0xa9;
const OP_DATA_20: u8 = 0x14;
const OP_EQUALVERIFY: u8 = 0x88;
const OP_EQUAL: u8 = 0x87;
const OP_CHECKSIG: u8 = 0xac;

/// The script template an address pays to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AddressKind {
    /// Pay-to-pubkey-hash (ecdsa-secp256k1), `Ds…` on mainnet.
    P2pkh,
    /// Pay-to-script-hash, `Dc…` on mainnet.
    P2sh,
}

/// A parsed Decred address: network + kind + 20-byte hash.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Address {
    /// Which network's version bytes the address carries.
    pub network: Network,
    /// P2PKH or P2SH.
    pub kind: AddressKind,
    /// `hash160` of the pubkey (P2PKH) or redeem script (P2SH).
    pub hash: [u8; 20],
}

impl Address {
    /// P2PKH address for a 20-byte pubkey hash.
    pub fn p2pkh(hash: [u8; 20], network: Network) -> Self {
        Address {
            network,
            kind: AddressKind::P2pkh,
            hash,
        }
    }

    /// P2SH address for a 20-byte script hash.
    pub fn p2sh(hash: [u8; 20], network: Network) -> Self {
        Address {
            network,
            kind: AddressKind::P2sh,
            hash,
        }
    }

    /// P2PKH address for a serialized (compressed, 33-byte) public key.
    pub fn from_pubkey(pubkey: &[u8], network: Network) -> Self {
        Address::p2pkh(hash160(pubkey), network)
    }

    /// Classify a pkScript as one of the standard address templates.
    pub fn from_script(script: &[u8], network: Network) -> Option<Self> {
        if let Some(h) = p2pkh_hash160(script) {
            return Some(Address::p2pkh(h, network));
        }
        p2sh_hash160(script).map(|h| Address::p2sh(h, network))
    }

    /// Decode a base58check address string, detecting network and kind from
    /// the 2-byte version prefix.
    pub fn decode(s: &str) -> Result<Self, Error> {
        let (prefix, payload) = check_decode(s)?;
        // Identify the prefix first so e.g. a P2PK address (33-byte payload)
        // reports UnknownPrefix, not a length error.
        let kind = if let Some(network) = Network::from_p2pkh_id(prefix) {
            (network, AddressKind::P2pkh)
        } else if let Some(network) = Network::from_p2sh_id(prefix) {
            (network, AddressKind::P2sh)
        } else {
            return Err(Error::UnknownPrefix);
        };
        let hash: [u8; 20] = payload.as_slice().try_into().map_err(|_| Error::Parse)?;
        Ok(Address {
            network: kind.0,
            kind: kind.1,
            hash,
        })
    }

    /// The base58check address string.
    pub fn encode(&self) -> String {
        let prefix = match self.kind {
            AddressKind::P2pkh => self.network.p2pkh_addr_id(),
            AddressKind::P2sh => self.network.p2sh_addr_id(),
        };
        check_encode(&self.hash, prefix)
    }

    /// The pkScript paying this address.
    pub fn pk_script(&self) -> Vec<u8> {
        match self.kind {
            AddressKind::P2pkh => p2pkh_script(&self.hash).to_vec(),
            AddressKind::P2sh => p2sh_script(&self.hash).to_vec(),
        }
    }
}

impl core::fmt::Display for Address {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.encode())
    }
}

/// Build the 25-byte v0 P2PKH script for a 20-byte pubkey hash.
pub fn p2pkh_script(hash160: &[u8; 20]) -> [u8; 25] {
    let mut s = [0u8; 25];
    s[0] = OP_DUP;
    s[1] = OP_HASH160;
    s[2] = OP_DATA_20;
    s[3..23].copy_from_slice(hash160);
    s[23] = OP_EQUALVERIFY;
    s[24] = OP_CHECKSIG;
    s
}

/// Build the 23-byte v0 P2SH script for a 20-byte script hash.
pub fn p2sh_script(hash160: &[u8; 20]) -> [u8; 23] {
    let mut s = [0u8; 23];
    s[0] = OP_HASH160;
    s[1] = OP_DATA_20;
    s[2..22].copy_from_slice(hash160);
    s[22] = OP_EQUAL;
    s
}

/// Extract the 20-byte hash160 from a standard P2PKH script, if it is one.
pub fn p2pkh_hash160(script: &[u8]) -> Option<[u8; 20]> {
    if script.len() == 25
        && script[0] == OP_DUP
        && script[1] == OP_HASH160
        && script[2] == OP_DATA_20
        && script[23] == OP_EQUALVERIFY
        && script[24] == OP_CHECKSIG
    {
        let mut h = [0u8; 20];
        h.copy_from_slice(&script[3..23]);
        Some(h)
    } else {
        None
    }
}

/// Extract the 20-byte hash160 from a standard P2SH script, if it is one.
pub fn p2sh_hash160(script: &[u8]) -> Option<[u8; 20]> {
    if script.len() == 23
        && script[0] == OP_HASH160
        && script[1] == OP_DATA_20
        && script[22] == OP_EQUAL
    {
        let mut h = [0u8; 20];
        h.copy_from_slice(&script[2..22]);
        Some(h)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;
    use alloc::string::String;

    const HASH160: [u8; 20] = [
        0x27, 0x89, 0xd5, 0x8c, 0xfa, 0x09, 0x57, 0xd2, 0x06, 0xf0, 0x25, 0xc2, 0xaf, 0x05, 0x6f,
        0xc8, 0xa7, 0x7c, 0xeb, 0xb0,
    ];

    #[test]
    fn p2pkh_script_matches_dcrd() {
        // dcrd payScript: 76a914<hash160>88ac
        let s = p2pkh_script(&HASH160);
        let hex: String = s.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, "76a9142789d58cfa0957d206f025c2af056fc8a77cebb088ac");
    }

    #[test]
    fn decode_roundtrip_all_networks() {
        for net in Network::ALL {
            for addr in [Address::p2pkh(HASH160, net), Address::p2sh(HASH160, net)] {
                let s = addr.encode();
                assert_eq!(Address::decode(&s).unwrap(), addr, "{s}");
            }
        }
    }

    #[test]
    fn script_classification_roundtrip() {
        let a = Address::p2pkh(HASH160, Network::Mainnet);
        assert_eq!(
            Address::from_script(&a.pk_script(), Network::Mainnet),
            Some(a)
        );
        let b = Address::p2sh(HASH160, Network::Mainnet);
        assert_eq!(
            Address::from_script(&b.pk_script(), Network::Mainnet),
            Some(b)
        );
        assert_eq!(Address::from_script(&[0u8; 25], Network::Mainnet), None);
    }
}
