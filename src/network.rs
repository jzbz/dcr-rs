// SPDX-License-Identifier: ISC
//! Decred network parameters.
//!
//! Address and extended-key version bytes for the four dcrd networks, lifted
//! verbatim from dcrd `chaincfg/{mainnet,testnet,simnet,regnet}params.go`.
//! Only the identifiers this crate uses are carried; consensus parameters
//! (PoW limits, deployments, …) are out of scope.

/// A Decred network.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Network {
    /// Decred mainnet.
    Mainnet,
    /// Decred testnet (version 3).
    Testnet,
    /// Decred simulation network (private testing).
    Simnet,
    /// Decred regression network (dcrd `--regnet`).
    Regnet,
}

impl Network {
    /// Every supported network, in prefix-lookup order.
    pub const ALL: [Network; 4] = [
        Network::Mainnet,
        Network::Testnet,
        Network::Simnet,
        Network::Regnet,
    ];

    /// dcrd network name (`"mainnet"`, `"testnet3"`, …).
    pub const fn name(self) -> &'static str {
        match self {
            Network::Mainnet => "mainnet",
            Network::Testnet => "testnet3",
            Network::Simnet => "simnet",
            Network::Regnet => "regnet",
        }
    }

    /// Pay-to-pubkey-hash (ecdsa-secp256k1) address ID: `Ds`/`Ts`/`Ss`/`Rs`.
    pub const fn p2pkh_addr_id(self) -> [u8; 2] {
        match self {
            Network::Mainnet => [0x07, 0x3f],
            Network::Testnet => [0x0f, 0x21],
            Network::Simnet => [0x0e, 0x91],
            Network::Regnet => [0x0e, 0x00],
        }
    }

    /// Pay-to-script-hash address ID: `Dc`/`Tc`/`Sc`/`Rc`.
    pub const fn p2sh_addr_id(self) -> [u8; 2] {
        match self {
            Network::Mainnet => [0x07, 0x1a],
            Network::Testnet => [0x0e, 0xfc],
            Network::Simnet => [0x0e, 0x6c],
            Network::Regnet => [0x0d, 0xdb],
        }
    }

    /// BIP32 extended private key version: `dprv`/`tprv`/`sprv`/`rprv`.
    pub const fn hd_priv_id(self) -> [u8; 4] {
        match self {
            Network::Mainnet => [0x02, 0xfd, 0xa4, 0xe8],
            Network::Testnet => [0x04, 0x35, 0x83, 0x97],
            Network::Simnet => [0x04, 0x20, 0xb9, 0x03],
            Network::Regnet => [0xea, 0xb4, 0x04, 0x48],
        }
    }

    /// BIP32 extended public key version: `dpub`/`tpub`/`spub`/`rpub`.
    pub const fn hd_pub_id(self) -> [u8; 4] {
        match self {
            Network::Mainnet => [0x02, 0xfd, 0xa9, 0x26],
            Network::Testnet => [0x04, 0x35, 0x87, 0xd1],
            Network::Simnet => [0x04, 0x20, 0xbd, 0x3d],
            Network::Regnet => [0xea, 0xb4, 0xf9, 0x87],
        }
    }

    /// SLIP-0044 coin type used at `m/44'/coin'` (42 on mainnet, 1 — the
    /// shared testnet type — everywhere else).
    pub const fn slip44(self) -> u32 {
        match self {
            Network::Mainnet => 42,
            Network::Testnet | Network::Simnet | Network::Regnet => 1,
        }
    }

    /// Network whose P2PKH address ID equals `id`, if any.
    pub fn from_p2pkh_id(id: [u8; 2]) -> Option<Network> {
        Network::ALL.into_iter().find(|n| n.p2pkh_addr_id() == id)
    }

    /// Network whose P2SH address ID equals `id`, if any.
    pub fn from_p2sh_id(id: [u8; 2]) -> Option<Network> {
        Network::ALL.into_iter().find(|n| n.p2sh_addr_id() == id)
    }

    /// Network whose extended-private-key version equals `id`, if any.
    pub fn from_hd_priv_id(id: [u8; 4]) -> Option<Network> {
        Network::ALL.into_iter().find(|n| n.hd_priv_id() == id)
    }

    /// Network whose extended-public-key version equals `id`, if any.
    pub fn from_hd_pub_id(id: [u8; 4]) -> Option<Network> {
        Network::ALL.into_iter().find(|n| n.hd_pub_id() == id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_lookup_is_unambiguous() {
        for net in Network::ALL {
            assert_eq!(Network::from_p2pkh_id(net.p2pkh_addr_id()), Some(net));
            assert_eq!(Network::from_p2sh_id(net.p2sh_addr_id()), Some(net));
            assert_eq!(Network::from_hd_priv_id(net.hd_priv_id()), Some(net));
            assert_eq!(Network::from_hd_pub_id(net.hd_pub_id()), Some(net));
        }
    }
}
