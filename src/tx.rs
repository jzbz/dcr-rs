// SPDX-License-Identifier: ISC
//! Decred transaction wire format (`wire/msgtx.go`).
//!
//! A Decred tx serializes as two concatenated parts:
//!   * **prefix** (TxSerializeNoWitness): version, inputs (outpoint+sequence),
//!     outputs, locktime, expiry.
//!   * **witness** (TxSerializeOnlyWitness): per-input valueIn, blockHeight,
//!     blockIndex, signatureScript.
//!
//! The serialized version word is `version | (serType << 16)` little-endian.
//! NOTE: the *sighash* uses a different witness layout — see [`crate::sighash`].

use alloc::vec::Vec;

use crate::Error;

/// Serialization type word for a full (prefix + witness) transaction.
pub const SER_FULL: u16 = 0;
/// Serialization type word for the prefix alone.
pub const SER_NO_WITNESS: u16 = 1;
/// Serialization type word for the witness alone.
pub const SER_ONLY_WITNESS: u16 = 2;

/// Sentinel for "unknown" witness block height (matches dcrd null values).
pub const NULL_BLOCK_HEIGHT: u32 = 0xffff_ffff;
/// Sentinel for "unknown" witness block index (matches dcrd null values).
pub const NULL_BLOCK_INDEX: u32 = 0xffff_ffff;

/// Reference to a previous transaction output.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutPoint {
    /// Transaction hash (internal byte order).
    pub hash: [u8; 32],
    /// Output index within that transaction.
    pub index: u32,
    /// Tree the output lives in: 0 = regular, 1 = stake.
    pub tree: u8,
}

/// A transaction input, including its witness fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxIn {
    /// The output being spent.
    pub previous_outpoint: OutPoint,
    /// Input sequence number.
    pub sequence: u32,
    /// Witness: value of the output being spent, in atoms.
    pub value_in: i64,
    /// Witness: block height of the prevout ([`NULL_BLOCK_HEIGHT`] if unknown).
    pub block_height: u32,
    /// Witness: block index of the prevout ([`NULL_BLOCK_INDEX`] if unknown).
    pub block_index: u32,
    /// Witness: the signature script satisfying the prevout script.
    pub signature_script: Vec<u8>,
}

/// A transaction output.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxOut {
    /// Amount in atoms.
    pub value: i64,
    /// Script version (0 for all standard scripts).
    pub version: u16,
    /// The public key script.
    pub pk_script: Vec<u8>,
}

/// A Decred transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MsgTx {
    /// Transaction version.
    pub version: u16,
    /// Inputs.
    pub tx_in: Vec<TxIn>,
    /// Outputs.
    pub tx_out: Vec<TxOut>,
    /// Lock time.
    pub lock_time: u32,
    /// Expiry height (0 = no expiry).
    pub expiry: u32,
}

// ---- varint (compact size), dcrd-compatible ----

/// Append a dcrd-compatible compact-size varint.
pub fn put_varint(out: &mut Vec<u8>, val: u64) {
    if val < 0xfd {
        out.push(val as u8);
    } else if val <= 0xffff {
        out.push(0xfd);
        out.extend_from_slice(&(val as u16).to_le_bytes());
    } else if val <= 0xffff_ffff {
        out.push(0xfe);
        out.extend_from_slice(&(val as u32).to_le_bytes());
    } else {
        out.push(0xff);
        out.extend_from_slice(&val.to_le_bytes());
    }
}

fn read_varint(buf: &[u8], pos: &mut usize) -> Result<u64, Error> {
    let first = *buf.get(*pos).ok_or(Error::Parse)?;
    *pos += 1;
    let v = match first {
        0xff => {
            let b = buf.get(*pos..*pos + 8).ok_or(Error::Parse)?;
            *pos += 8;
            u64::from_le_bytes(b.try_into().unwrap())
        }
        0xfe => {
            let b = buf.get(*pos..*pos + 4).ok_or(Error::Parse)?;
            *pos += 4;
            u32::from_le_bytes(b.try_into().unwrap()) as u64
        }
        0xfd => {
            let b = buf.get(*pos..*pos + 2).ok_or(Error::Parse)?;
            *pos += 2;
            u16::from_le_bytes(b.try_into().unwrap()) as u64
        }
        n => n as u64,
    };
    Ok(v)
}

/// Read an item count, rejecting any value that could not possibly fit in the
/// remaining bytes (each item needs at least `min_item_size` bytes). This
/// bounds `Vec::with_capacity` so a hostile count varint cannot force a huge
/// allocation before per-item reads would fail anyway.
fn read_count(buf: &[u8], pos: &mut usize, min_item_size: usize) -> Result<usize, Error> {
    let v = read_varint(buf, pos)?;
    let remaining = buf.len().saturating_sub(*pos) as u64;
    if v > remaining / (min_item_size as u64) {
        return Err(Error::Parse);
    }
    Ok(v as usize)
}

/// Read a length-prefixed byte string, checking the declared length against
/// the remaining buffer as u64 first (a `as usize` cast of a hostile 64-bit
/// length would silently truncate on 32-bit targets).
fn read_var_bytes<'a>(buf: &'a [u8], pos: &mut usize) -> Result<&'a [u8], Error> {
    let n = read_varint(buf, pos)?;
    if n > buf.len().saturating_sub(*pos) as u64 {
        return Err(Error::Parse);
    }
    read_bytes(buf, pos, n as usize)
}

fn read_bytes<'a>(buf: &'a [u8], pos: &mut usize, n: usize) -> Result<&'a [u8], Error> {
    let s = buf.get(*pos..*pos + n).ok_or(Error::Parse)?;
    *pos += n;
    Ok(s)
}

fn read_u32(buf: &[u8], pos: &mut usize) -> Result<u32, Error> {
    Ok(u32::from_le_bytes(
        read_bytes(buf, pos, 4)?.try_into().unwrap(),
    ))
}
fn read_u16(buf: &[u8], pos: &mut usize) -> Result<u16, Error> {
    Ok(u16::from_le_bytes(
        read_bytes(buf, pos, 2)?.try_into().unwrap(),
    ))
}
fn read_i64(buf: &[u8], pos: &mut usize) -> Result<i64, Error> {
    Ok(i64::from_le_bytes(
        read_bytes(buf, pos, 8)?.try_into().unwrap(),
    ))
}

impl MsgTx {
    fn ser_version(&self, ser_type: u16) -> u32 {
        (self.version as u32) | ((ser_type as u32) << 16)
    }

    fn write_prefix_body(&self, o: &mut Vec<u8>) {
        put_varint(o, self.tx_in.len() as u64);
        for ti in &self.tx_in {
            o.extend_from_slice(&ti.previous_outpoint.hash);
            o.extend_from_slice(&ti.previous_outpoint.index.to_le_bytes());
            o.push(ti.previous_outpoint.tree);
            o.extend_from_slice(&ti.sequence.to_le_bytes());
        }
        put_varint(o, self.tx_out.len() as u64);
        for to in &self.tx_out {
            o.extend_from_slice(&(to.value as u64).to_le_bytes());
            o.extend_from_slice(&to.version.to_le_bytes());
            put_varint(o, to.pk_script.len() as u64);
            o.extend_from_slice(&to.pk_script);
        }
        o.extend_from_slice(&self.lock_time.to_le_bytes());
        o.extend_from_slice(&self.expiry.to_le_bytes());
    }

    fn write_witness_body(&self, o: &mut Vec<u8>) {
        put_varint(o, self.tx_in.len() as u64);
        for ti in &self.tx_in {
            o.extend_from_slice(&(ti.value_in as u64).to_le_bytes());
            o.extend_from_slice(&ti.block_height.to_le_bytes());
            o.extend_from_slice(&ti.block_index.to_le_bytes());
            put_varint(o, ti.signature_script.len() as u64);
            o.extend_from_slice(&ti.signature_script);
        }
    }

    /// Prefix serialization (TxSerializeNoWitness).
    pub fn serialize_prefix(&self) -> Vec<u8> {
        let mut o = Vec::new();
        o.extend_from_slice(&self.ser_version(SER_NO_WITNESS).to_le_bytes());
        self.write_prefix_body(&mut o);
        o
    }

    /// Witness serialization (TxSerializeOnlyWitness) — the real broadcast
    /// witness (valueIn/height/index/sigScript), NOT the sighash witness.
    pub fn serialize_witness(&self) -> Vec<u8> {
        let mut o = Vec::new();
        o.extend_from_slice(&self.ser_version(SER_ONLY_WITNESS).to_le_bytes());
        self.write_witness_body(&mut o);
        o
    }

    /// Full serialization (prefix ‖ witness) — the bytes a wallet broadcasts.
    pub fn serialize_full(&self) -> Vec<u8> {
        let mut o = Vec::new();
        o.extend_from_slice(&self.ser_version(SER_FULL).to_le_bytes());
        self.write_prefix_body(&mut o);
        self.write_witness_body(&mut o);
        o
    }

    /// TxHash (txid) = blake256 of the prefix serialization, in internal byte
    /// order. Reverse it for the display/RPC form.
    pub fn tx_hash(&self) -> [u8; 32] {
        crate::blake256::sum256(&self.serialize_prefix())
    }

    /// Parse a full (prefix+witness) Decred transaction.
    pub fn parse_full(buf: &[u8]) -> Result<MsgTx, Error> {
        let mut pos = 0usize;
        let ver_word = read_u32(buf, &mut pos)?;
        let version = (ver_word & 0xffff) as u16;
        let ser_type = ((ver_word >> 16) & 0xffff) as u16;
        if ser_type != SER_FULL {
            return Err(Error::Parse);
        }

        // Minimum sizes: prefix input 41 B, output 11 B, witness input 17 B.
        let n_in = read_count(buf, &mut pos, 41)?;
        let mut inputs: Vec<(OutPoint, u32)> = Vec::with_capacity(n_in);
        for _ in 0..n_in {
            let mut hash = [0u8; 32];
            hash.copy_from_slice(read_bytes(buf, &mut pos, 32)?);
            let index = read_u32(buf, &mut pos)?;
            let tree = *read_bytes(buf, &mut pos, 1)?.first().unwrap();
            let sequence = read_u32(buf, &mut pos)?;
            inputs.push((OutPoint { hash, index, tree }, sequence));
        }

        let n_out = read_count(buf, &mut pos, 11)?;
        let mut tx_out = Vec::with_capacity(n_out);
        for _ in 0..n_out {
            let value = read_i64(buf, &mut pos)?;
            let version = read_u16(buf, &mut pos)?;
            let pk_script = read_var_bytes(buf, &mut pos)?.to_vec();
            tx_out.push(TxOut {
                value,
                version,
                pk_script,
            });
        }

        let lock_time = read_u32(buf, &mut pos)?;
        let expiry = read_u32(buf, &mut pos)?;

        // Witness.
        let n_wit = read_count(buf, &mut pos, 17)?;
        if n_wit != n_in {
            return Err(Error::Parse);
        }
        let mut tx_in = Vec::with_capacity(n_in);
        for (outpoint, sequence) in inputs {
            let value_in = read_i64(buf, &mut pos)?;
            let block_height = read_u32(buf, &mut pos)?;
            let block_index = read_u32(buf, &mut pos)?;
            let signature_script = read_var_bytes(buf, &mut pos)?.to_vec();
            tx_in.push(TxIn {
                previous_outpoint: outpoint,
                sequence,
                value_in,
                block_height,
                block_index,
                signature_script,
            });
        }

        Ok(MsgTx {
            version,
            tx_in,
            tx_out,
            lock_time,
            expiry,
        })
    }
}
