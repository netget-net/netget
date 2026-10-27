//! The Bitcoin structures the Template Distribution and Job Declaration roles build and check,
//! written here rather than borrowed for the same reason the rest of this directory is: SRI's
//! applications serialise transactions with rust-bitcoin, so a NetGet that did too would agree
//! with them by construction. What is here is the consensus serialisation of a transaction
//! (with and without its witness), txid and wtxid, the merkle path a template carries and the
//! root it folds to, the BIP 141 witness commitment, BIP 34's height push, compact targets,
//! the block subsidy, and a parser for what a peer sends that refuses anything it cannot fully
//! account for.
//!
//! Transactions the model writes are structured, never bytes: inputs name an outpoint by txid
//! and index and carry the value they spend (so fees are known without a UTXO set), and
//! outputs either pay `OP_TRUE` — the anyone-can-spend script a regtest chain can spend with an
//! empty scriptSig — or carry an `OP_RETURN` text. Those two are enough to build blocks a real
//! node accepts, and neither asks the model to spell a script.
use super::wire::sha256d;
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value};

/// Inputs and outputs one model-written transaction may have.
pub const MAX_TX_INPUTS: usize = 16;
pub const MAX_TX_OUTPUTS: usize = 16;
/// Transactions one model-written template or declared job may carry.
pub const MAX_MODEL_TXS: usize = 64;
/// An `OP_RETURN` text, in bytes (Bitcoin Core's default relay limit for the data).
pub const MAX_OP_RETURN: usize = 80;
/// The most a value field may say: 21 million BTC.
pub const MAX_MONEY: u64 = 21_000_000 * 100_000_000;
/// Inputs, outputs or witness items a parsed transaction may declare. Each is bounded again by
/// the bytes the message can still hold, so this only stops arithmetic on absurd counts.
pub const MAX_PARSE_ITEMS: u64 = 100_000;
/// BIP 141's witness commitment header: OP_RETURN, push 36, 0xaa21a9ed.
pub const WITNESS_COMMITMENT_HEADER: [u8; 6] = [0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
/// The largest block weight there is.
pub const MAX_BLOCK_WEIGHT: u64 = 4_000_000;
/// A coinbase scriptSig is 2 to 100 bytes (bad-cb-length).
pub const MAX_COINBASE_SCRIPT_SIG: usize = 100;
/// sv2-spec §7: NewTemplate's coinbase_prefix is at most 8 bytes.
pub const MAX_COINBASE_PREFIX: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxIn {
    /// The spent transaction's id, in internal byte order.
    pub prev_txid: [u8; 32],
    pub vout: u32,
    pub script_sig: Vec<u8>,
    pub sequence: u32,
    pub witness: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxOut {
    pub value: u64,
    pub script: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tx {
    pub version: u32,
    pub inputs: Vec<TxIn>,
    pub outputs: Vec<TxOut>,
    pub locktime: u32,
}

pub fn write_varint(out: &mut Vec<u8>, n: u64) {
    match n {
        0..=0xfc => out.push(n as u8),
        0xfd..=0xffff => {
            out.push(0xfd);
            out.extend_from_slice(&(n as u16).to_le_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(0xfe);
            out.extend_from_slice(&(n as u32).to_le_bytes());
        }
        _ => {
            out.push(0xff);
            out.extend_from_slice(&n.to_le_bytes());
        }
    }
}

/// Reads consensus-encoded data, refusing anything that runs past the end.
pub struct Cursor<'a> {
    buf: &'a [u8],
    pub pos: usize,
}

impl<'a> Cursor<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        ensure!(
            self.remaining() >= n,
            "transaction ends {} bytes into a {n}-byte field",
            self.remaining()
        );
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into()?))
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into()?))
    }
    /// A CompactSize, which must be minimally encoded (as Bitcoin Core requires).
    pub fn varint(&mut self) -> Result<u64> {
        let n = match self.u8()? {
            0xfd => {
                let v = u64::from(u16::from_le_bytes(self.take(2)?.try_into()?));
                ensure!(v >= 0xfd, "non-canonical CompactSize");
                v
            }
            0xfe => {
                let v = u64::from(self.u32()?);
                ensure!(v > 0xffff, "non-canonical CompactSize");
                v
            }
            0xff => {
                let v = self.u64()?;
                ensure!(v > 0xffff_ffff, "non-canonical CompactSize");
                v
            }
            b => u64::from(b),
        };
        Ok(n)
    }
    /// A count of items each at least `min` bytes long, checked against what is left.
    fn count(&mut self, min: usize, what: &str) -> Result<usize> {
        let n = self.varint()?;
        ensure!(
            n <= MAX_PARSE_ITEMS && (n as usize).saturating_mul(min) <= self.remaining(),
            "{what} count {n} is more than the {} bytes left can hold",
            self.remaining()
        );
        Ok(n as usize)
    }
    fn bytes(&mut self) -> Result<Vec<u8>> {
        let n = self.count(1, "byte")?;
        Ok(self.take(n)?.to_vec())
    }
    pub fn txout(&mut self) -> Result<TxOut> {
        let value = self.u64()?;
        ensure!(value <= MAX_MONEY, "output value {value} is above 21M BTC");
        Ok(TxOut {
            value,
            script: self.bytes()?,
        })
    }
}

impl Tx {
    pub fn has_witness(&self) -> bool {
        self.inputs.iter().any(|i| !i.witness.is_empty())
    }

    pub fn serialize(&self, with_witness: bool) -> Vec<u8> {
        let witness = with_witness && self.has_witness();
        let mut out = Vec::new();
        out.extend_from_slice(&self.version.to_le_bytes());
        if witness {
            out.extend_from_slice(&[0x00, 0x01]);
        }
        write_varint(&mut out, self.inputs.len() as u64);
        for i in &self.inputs {
            out.extend_from_slice(&i.prev_txid);
            out.extend_from_slice(&i.vout.to_le_bytes());
            write_varint(&mut out, i.script_sig.len() as u64);
            out.extend_from_slice(&i.script_sig);
            out.extend_from_slice(&i.sequence.to_le_bytes());
        }
        write_varint(&mut out, self.outputs.len() as u64);
        for o in &self.outputs {
            write_txout(&mut out, o);
        }
        if witness {
            for i in &self.inputs {
                write_varint(&mut out, i.witness.len() as u64);
                for item in &i.witness {
                    write_varint(&mut out, item.len() as u64);
                    out.extend_from_slice(item);
                }
            }
        }
        out.extend_from_slice(&self.locktime.to_le_bytes());
        out
    }

    pub fn txid(&self) -> [u8; 32] {
        sha256d(&self.serialize(false))
    }

    pub fn wtxid(&self) -> [u8; 32] {
        sha256d(&self.serialize(true))
    }

    /// BIP 141 weight: non-witness bytes count four times, witness bytes once.
    pub fn weight(&self) -> u64 {
        let base = self.serialize(false).len() as u64;
        let total = self.serialize(true).len() as u64;
        base * 3 + total
    }

    pub fn is_coinbase(&self) -> bool {
        self.inputs.len() == 1
            && self.inputs[0].prev_txid == [0u8; 32]
            && self.inputs[0].vout == u32::MAX
    }

    /// Parse one transaction that must fill `bytes` exactly.
    pub fn parse(bytes: &[u8]) -> Result<Tx> {
        let mut c = Cursor::new(bytes);
        let tx = Self::read(&mut c)?;
        ensure!(
            c.remaining() == 0,
            "{} bytes after the transaction",
            c.remaining()
        );
        Ok(tx)
    }

    pub fn read(c: &mut Cursor) -> Result<Tx> {
        let version = c.u32()?;
        let mut segwit = false;
        let mut n_in = c.count(41, "input")?;
        if n_in == 0 {
            // BIP 144: a zero input count is the marker, and the flag must be 1.
            ensure!(c.u8()? == 1, "segwit marker without the flag 1");
            segwit = true;
            n_in = c.count(41, "input")?;
            ensure!(n_in > 0, "a transaction with no inputs");
        }
        let mut inputs = Vec::with_capacity(n_in);
        for _ in 0..n_in {
            let prev_txid: [u8; 32] = c.take(32)?.try_into()?;
            let vout = c.u32()?;
            let script_sig = c.bytes()?;
            let sequence = c.u32()?;
            inputs.push(TxIn {
                prev_txid,
                vout,
                script_sig,
                sequence,
                witness: Vec::new(),
            });
        }
        let n_out = c.count(9, "output")?;
        let mut outputs = Vec::with_capacity(n_out);
        for _ in 0..n_out {
            outputs.push(c.txout()?);
        }
        if segwit {
            for input in &mut inputs {
                let n = c.count(1, "witness item")?;
                let mut items = Vec::with_capacity(n);
                for _ in 0..n {
                    items.push(c.bytes()?);
                }
                input.witness = items;
            }
            ensure!(
                inputs.iter().any(|i| !i.witness.is_empty()),
                "a segwit serialisation with no witness data"
            );
        }
        let locktime = c.u32()?;
        Ok(Tx {
            version,
            inputs,
            outputs,
            locktime,
        })
    }
}

pub fn write_txout(out: &mut Vec<u8>, o: &TxOut) {
    out.extend_from_slice(&o.value.to_le_bytes());
    write_varint(out, o.script.len() as u64);
    out.extend_from_slice(&o.script);
}

/// Outputs concatenated with no count, as NewTemplate's coinbase_tx_outputs carries them.
pub fn outputs_bytes(outputs: &[TxOut]) -> Vec<u8> {
    let mut out = Vec::new();
    for o in outputs {
        write_txout(&mut out, o);
    }
    out
}

/// A consensus output vector: CompactSize count, then the outputs (AllocateMiningJobToken.Success).
pub fn output_vector_bytes(outputs: &[TxOut]) -> Vec<u8> {
    let mut out = Vec::new();
    write_varint(&mut out, outputs.len() as u64);
    out.extend_from_slice(&outputs_bytes(outputs));
    out
}

/// Parse a consensus output vector that must fill `bytes`, at most `max` outputs.
pub fn parse_output_vector(bytes: &[u8], max: usize) -> Result<Vec<TxOut>> {
    let mut c = Cursor::new(bytes);
    let n = c.count(9, "output")?;
    ensure!(n <= max, "{n} outputs, at most {max} accepted");
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        out.push(c.txout()?);
    }
    ensure!(
        c.remaining() == 0,
        "{} bytes after the outputs",
        c.remaining()
    );
    Ok(out)
}

/// The merkle root of a full list of leaves (Bitcoin's: an odd level repeats its last hash).
pub fn merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return [0u8; 32];
    }
    let mut level = leaves.to_vec();
    while level.len() > 1 {
        level = level
            .chunks(2)
            .map(|pair| {
                let right = pair.get(1).unwrap_or(&pair[0]);
                sha256d(&[&pair[0][..], &right[..]].concat())
            })
            .collect();
    }
    level[0]
}

/// The merkle path (deepest first) of the coinbase — leaf 0, whose hash is not known yet —
/// in a block whose other transactions have these txids.
pub fn coinbase_merkle_path(txids: &[[u8; 32]]) -> Vec<[u8; 32]> {
    let mut level: Vec<Option<[u8; 32]>> = std::iter::once(None)
        .chain(txids.iter().copied().map(Some))
        .collect();
    let mut path = Vec::new();
    while level.len() > 1 {
        // Leaf 0's sibling at this level is entry 1, which is never the unknown coinbase side.
        path.push(level[1].expect("only entry 0 is unknown"));
        level = level
            .chunks(2)
            .enumerate()
            .map(|(i, pair)| {
                if i == 0 {
                    return None;
                }
                let left = pair[0].expect("only entry 0 is unknown");
                let right = pair.get(1).copied().flatten().unwrap_or(left);
                Some(sha256d(&[&left[..], &right[..]].concat()))
            })
            .collect();
    }
    path
}

/// Fold a coinbase txid up a merkle path to the root.
pub fn fold_path(coinbase_txid: [u8; 32], path: &[[u8; 32]]) -> [u8; 32] {
    path.iter().fold(coinbase_txid, |acc, sibling| {
        sha256d(&[&acc[..], &sibling[..]].concat())
    })
}

/// BIP 141's commitment output for the given non-coinbase wtxids and the coinbase's 32-byte
/// witness reserved value.
pub fn witness_commitment(wtxids: &[[u8; 32]], reserved: &[u8; 32]) -> TxOut {
    let leaves: Vec<[u8; 32]> = std::iter::once([0u8; 32])
        .chain(wtxids.iter().copied())
        .collect();
    let root = merkle_root(&leaves);
    let commitment = sha256d(&[&root[..], &reserved[..]].concat());
    let mut script = WITNESS_COMMITMENT_HEADER.to_vec();
    script.extend_from_slice(&commitment);
    TxOut { value: 0, script }
}

/// The last output that carries a witness commitment, as BIP 141 locates it.
pub fn find_witness_commitment(outputs: &[TxOut]) -> Option<&TxOut> {
    outputs
        .iter()
        .rev()
        .find(|o| o.script.len() >= 38 && o.script[..6] == WITNESS_COMMITMENT_HEADER)
}

/// `CScript() << height` as Bitcoin Core's BIP 34 check writes it: OP_0, OP_1..OP_16, or a
/// minimal little-endian number push.
pub fn bip34_height_script(height: u32) -> Vec<u8> {
    match height {
        0 => vec![0x00],
        1..=16 => vec![0x50 + height as u8],
        _ => {
            let mut n = height.to_le_bytes().to_vec();
            while n.len() > 1 && n[n.len() - 1] == 0 {
                n.pop();
            }
            if n[n.len() - 1] & 0x80 != 0 {
                n.push(0);
            }
            let mut out = vec![n.len() as u8];
            out.extend_from_slice(&n);
            out
        }
    }
}

/// The height a coinbase scriptSig commits to, if it starts with a BIP 34 push.
pub fn bip34_height(script_sig: &[u8]) -> Option<u32> {
    let first = *script_sig.first()?;
    match first {
        0x00 => Some(0),
        0x51..=0x60 => Some(u32::from(first - 0x50)),
        1..=4 => {
            let n = script_sig.get(1..1 + usize::from(first))?;
            if n.last()? & 0x80 != 0 {
                return None;
            }
            let mut b = [0u8; 4];
            b[..n.len()].copy_from_slice(n);
            let h = u32::from_le_bytes(b);
            (bip34_height_script(h) == script_sig[..1 + n.len()]).then_some(h)
        }
        _ => None,
    }
}

/// The chains a template can be for: their proof-of-work limit and halving interval.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    Mainnet,
    Testnet4,
    Signet,
    Regtest,
}

impl Network {
    pub fn parse(s: &str) -> Result<Self> {
        Ok(match s {
            "mainnet" | "main" | "bitcoin" => Network::Mainnet,
            "testnet4" => Network::Testnet4,
            "signet" => Network::Signet,
            "regtest" => Network::Regtest,
            other => bail!("network must be mainnet, testnet4, signet or regtest, not {other:?}"),
        })
    }
    pub fn name(self) -> &'static str {
        match self {
            Network::Mainnet => "mainnet",
            Network::Testnet4 => "testnet4",
            Network::Signet => "signet",
            Network::Regtest => "regtest",
        }
    }
    /// The easiest target the chain allows, in compact form.
    pub fn pow_limit_bits(self) -> u32 {
        match self {
            Network::Mainnet | Network::Testnet4 => 0x1d00_ffff,
            Network::Signet => 0x1e03_77ae,
            Network::Regtest => 0x207f_ffff,
        }
    }
    pub fn halving_interval(self) -> u32 {
        match self {
            Network::Regtest => 150,
            _ => 210_000,
        }
    }
    /// The new coins a block at `height` may claim.
    pub fn subsidy(self, height: u32) -> u64 {
        let halvings = height / self.halving_interval();
        if halvings >= 64 {
            0
        } else {
            (50 * 100_000_000u64) >> halvings
        }
    }
}

/// A compact target (nBits) as a little-endian 256-bit number. Negative, overflowing and zero
/// targets are refused, as Bitcoin Core's `DeriveTarget` refuses them.
pub fn compact_to_target(bits: u32) -> Result<[u8; 32]> {
    let exponent = (bits >> 24) as usize;
    let mantissa = bits & 0x007f_ffff;
    ensure!(
        bits & 0x0080_0000 == 0 || mantissa == 0,
        "nbits {bits:08x} is negative"
    );
    ensure!(mantissa != 0, "nbits {bits:08x} is a zero target");
    let mut out = [0u8; 32];
    let m = mantissa.to_le_bytes();
    if exponent <= 3 {
        let v = mantissa >> (8 * (3 - exponent));
        ensure!(v != 0, "nbits {bits:08x} is a zero target");
        out[..4].copy_from_slice(&v.to_le_bytes());
        return Ok(out);
    }
    for (i, b) in m[..3].iter().enumerate() {
        let at = exponent - 3 + i;
        if *b != 0 {
            ensure!(at < 32, "nbits {bits:08x} overflows 256 bits");
            out[at] = *b;
        }
    }
    Ok(out)
}

/// Whether `bits` is a target the network allows: valid, and no easier than its limit.
pub fn check_bits(network: Network, bits: u32) -> Result<[u8; 32]> {
    let target = compact_to_target(bits)?;
    let limit = compact_to_target(network.pow_limit_bits())?;
    ensure!(
        super::wire::meets(&target, &limit),
        "nbits {bits:08x} is easier than {}'s limit {:08x}",
        network.name(),
        network.pow_limit_bits()
    );
    Ok(target)
}

/// What a script is, for events: the model sees the kind, never the bytes.
pub fn script_type(script: &[u8]) -> &'static str {
    match script {
        [0x51] => "op_true",
        [0x6a, ..] => "op_return",
        [0x76, 0xa9, 0x14, .., 0x88, 0xac] if script.len() == 25 => "p2pkh",
        [0xa9, 0x14, .., 0x87] if script.len() == 23 => "p2sh",
        [0x00, 0x14, ..] if script.len() == 22 => "p2wpkh",
        [0x00, 0x20, ..] if script.len() == 34 => "p2wsh",
        [0x51, 0x20, ..] if script.len() == 34 => "p2tr",
        _ => "nonstandard",
    }
}

/// The text an `OP_RETURN` carries in its first push, as printable text.
pub fn op_return_text(script: &[u8]) -> Option<String> {
    let (&op, rest) = script.split_first()?;
    if op != 0x6a {
        return None;
    }
    let (&len, data) = rest.split_first()?;
    let data = match len {
        1..=75 => data.get(..usize::from(len))?,
        0x4c => data.get(1..1 + usize::from(*data.first()?))?,
        _ => return None,
    };
    Some(super::wire::text(data))
}

/// An output as events describe it.
pub fn describe_output(o: &TxOut) -> Value {
    let mut v = json!({"value_sats": o.value, "script_type": script_type(&o.script)});
    if o.script.len() >= 38 && o.script[..6] == WITNESS_COMMITMENT_HEADER {
        v["script_type"] = json!("witness_commitment");
    } else if let Some(text) = op_return_text(&o.script) {
        v["op_return"] = json!(text);
    }
    v
}

/// The output script a model-written output names: `{"pay_to": "op_true"}` or
/// `{"op_return": "text"}`.
pub fn output_script(spec: &Value) -> Result<Vec<u8>> {
    if let Some(text) = spec.get("op_return").filter(|v| !v.is_null()) {
        let text = text.as_str().context("op_return must be text")?;
        ensure!(
            text.len() <= MAX_OP_RETURN,
            "op_return text must be at most {MAX_OP_RETURN} bytes"
        );
        let mut script = vec![0x6a];
        if text.len() <= 75 {
            script.push(text.len() as u8);
        } else {
            script.extend_from_slice(&[0x4c, text.len() as u8]);
        }
        script.extend_from_slice(text.as_bytes());
        return Ok(script);
    }
    match spec["pay_to"].as_str().unwrap_or("op_true") {
        "op_true" => Ok(vec![0x51]),
        other => bail!("pay_to must be op_true (or give op_return text), not {other:?}"),
    }
}

/// A hash written as RPC shows it (byte-reversed hex) to internal order.
pub fn parse_txid(s: &str) -> Result<[u8; 32]> {
    let mut b: [u8; 32] = hex::decode(s)
        .ok()
        .and_then(|v| v.try_into().ok())
        .with_context(|| format!("{s:?} is not 64 hex digits"))?;
    b.reverse();
    Ok(b)
}

/// One model-written transaction and the fee it pays.
pub fn tx_from_json(v: &Value) -> Result<(Tx, u64)> {
    let inputs = v["inputs"].as_array().context("inputs must be a list")?;
    let outputs = v["outputs"].as_array().context("outputs must be a list")?;
    ensure!(
        (1..=MAX_TX_INPUTS).contains(&inputs.len()),
        "a transaction has 1 to {MAX_TX_INPUTS} inputs"
    );
    ensure!(
        (1..=MAX_TX_OUTPUTS).contains(&outputs.len()),
        "a transaction has 1 to {MAX_TX_OUTPUTS} outputs"
    );
    let mut value_in = 0u64;
    let mut tx_inputs = Vec::new();
    for i in inputs {
        let txid = parse_txid(i["txid"].as_str().context("each input needs a txid")?)?;
        let vout = i["vout"].as_u64().context("each input needs a vout")?;
        ensure!(vout < u64::from(u32::MAX), "vout must be below 2^32-1");
        let value = i["value_sats"]
            .as_u64()
            .context("each input needs value_sats, the value of the output it spends")?;
        ensure!(value <= MAX_MONEY, "an input's value_sats is above 21M BTC");
        value_in += value;
        tx_inputs.push(TxIn {
            prev_txid: txid,
            vout: vout as u32,
            script_sig: Vec::new(),
            sequence: u32::MAX,
            witness: Vec::new(),
        });
    }
    let mut value_out = 0u64;
    let mut tx_outputs = Vec::new();
    for o in outputs {
        let value = o["value_sats"]
            .as_u64()
            .context("each output needs value_sats")?;
        ensure!(
            value <= MAX_MONEY,
            "an output's value_sats is above 21M BTC"
        );
        value_out += value;
        tx_outputs.push(TxOut {
            value,
            script: output_script(o)?,
        });
    }
    ensure!(
        value_out <= value_in,
        "outputs ({value_out} sats) spend more than the inputs ({value_in} sats)"
    );
    let locktime = v["locktime"].as_u64().unwrap_or(0);
    ensure!(locktime <= u64::from(u32::MAX), "locktime must fit 32 bits");
    Ok((
        Tx {
            version: 2,
            inputs: tx_inputs,
            outputs: tx_outputs,
            locktime: locktime as u32,
        },
        value_in - value_out,
    ))
}

/// A model-written transaction list, bounded, with the fees it pays in total.
pub fn txs_from_json(v: &Value) -> Result<(Vec<Tx>, u64)> {
    let Some(list) = v.as_array() else {
        if v.is_null() {
            return Ok((Vec::new(), 0));
        }
        bail!("transactions must be a list");
    };
    ensure!(
        list.len() <= MAX_MODEL_TXS,
        "at most {MAX_MODEL_TXS} transactions"
    );
    let mut txs = Vec::new();
    let mut fees = 0u64;
    for t in list {
        let (tx, fee) = tx_from_json(t)?;
        fees += fee;
        txs.push(tx);
    }
    Ok((txs, fees))
}

/// A block: the 80-byte header, then every transaction with its witness.
pub fn block_bytes(header: &[u8; 80], coinbase: &[u8], txs: &[Tx]) -> Vec<u8> {
    let mut out = header.to_vec();
    write_varint(&mut out, 1 + txs.len() as u64);
    out.extend_from_slice(coinbase);
    for t in txs {
        out.extend_from_slice(&t.serialize(true));
    }
    out
}
