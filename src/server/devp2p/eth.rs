//! The messages: the devp2p base protocol (Hello, Disconnect, Ping, Pong) and the `eth`
//! subprotocol at versions 68 and 69, plus the pieces they are made of — block headers as
//! structured JSON and their hashes, fork identifiers (EIP-2124), enode URLs, transactions.
//!
//! Message codes on the wire: the base protocol owns 0x00–0x0f; capabilities follow in
//! alphabetical order, each taking as many codes as it defines. NetGet offers only `eth`, so a
//! matched `eth` always starts at 0x10.
use super::crypto;
use super::rlp::{self, Rlp};
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Map, Value};

/// Base protocol version sent in Hello; 5 turns on Snappy compression.
pub const BASE_VERSION: u64 = 5;
/// The largest Hello accepted (go-ethereum's `baseProtocolMaxMsgSize`).
pub const MAX_HELLO_BYTES: usize = 2048;
/// The most capabilities a Hello may list.
pub const MAX_CAPS: usize = 64;
/// The longest client id kept from a Hello, in characters.
pub const MAX_CLIENT_ID_CHARS: usize = 256;
/// `eth` versions NetGet speaks, newest first.
pub const ETH_VERSIONS: [u64; 2] = [69, 68];
/// Where `eth` codes start.
pub const ETH_OFFSET: u64 = 0x10;

pub mod code {
    pub const HELLO: u64 = 0x00;
    pub const DISCONNECT: u64 = 0x01;
    pub const PING: u64 = 0x02;
    pub const PONG: u64 = 0x03;
    // eth, relative to ETH_OFFSET
    pub const STATUS: u64 = 0x00;
    pub const NEW_BLOCK_HASHES: u64 = 0x01;
    pub const TRANSACTIONS: u64 = 0x02;
    pub const GET_BLOCK_HEADERS: u64 = 0x03;
    pub const BLOCK_HEADERS: u64 = 0x04;
    pub const GET_BLOCK_BODIES: u64 = 0x05;
    pub const BLOCK_BODIES: u64 = 0x06;
    pub const NEW_BLOCK: u64 = 0x07;
    pub const NEW_POOLED_TRANSACTION_HASHES: u64 = 0x08;
    pub const GET_POOLED_TRANSACTIONS: u64 = 0x09;
    pub const POOLED_TRANSACTIONS: u64 = 0x0a;
    pub const GET_RECEIPTS: u64 = 0x0f;
    pub const RECEIPTS: u64 = 0x10;
    pub const BLOCK_RANGE_UPDATE: u64 = 0x11;
}

/// How many codes `eth/<version>` takes.
pub fn eth_length(version: u64) -> u64 {
    if version >= 69 {
        0x12
    } else {
        0x11
    }
}

/// Disconnect reasons (devp2p spec), by code.
pub const DISCONNECT_REASONS: &[(u64, &str)] = &[
    (0x00, "requested"),
    (0x01, "tcp_error"),
    (0x02, "breach_of_protocol"),
    (0x03, "useless_peer"),
    (0x04, "too_many_peers"),
    (0x05, "already_connected"),
    (0x06, "incompatible_version"),
    (0x07, "invalid_identity"),
    (0x08, "client_quitting"),
    (0x09, "unexpected_identity"),
    (0x0a, "connected_to_self"),
    (0x0b, "timeout"),
    (0x10, "subprotocol_error"),
];

pub fn reason_name(code: u64) -> String {
    DISCONNECT_REASONS
        .iter()
        .find(|(c, _)| *c == code)
        .map(|(_, n)| n.to_string())
        .unwrap_or_else(|| format!("unknown_{code:#04x}"))
}

pub fn reason_code(name: &str) -> Result<u64> {
    DISCONNECT_REASONS
        .iter()
        .find(|(_, n)| *n == name)
        .map(|(c, _)| *c)
        .with_context(|| {
            format!(
                "unknown disconnect reason {name:?}; one of {}",
                DISCONNECT_REASONS
                    .iter()
                    .map(|(_, n)| *n)
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        })
}

/// `rlp([reason])`, as go-ethereum writes it.
pub fn encode_disconnect(reason: u64) -> Vec<u8> {
    Rlp::List(vec![Rlp::uint(reason)]).encode()
}

/// A Disconnect payload's reason. Peers write `[reason]`, a bare integer, or nothing.
pub fn decode_disconnect(payload: &[u8]) -> u64 {
    match rlp::decode(payload) {
        Ok(Rlp::List(l)) => l.first().and_then(|r| r.as_u64().ok()).unwrap_or(0),
        Ok(item) => item.as_u64().unwrap_or(0),
        Err(_) => 0,
    }
}

/// The empty list Ping and Pong carry.
pub fn empty_payload() -> Vec<u8> {
    Rlp::empty_list().encode()
}

/// The base protocol's Hello.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hello {
    pub version: u64,
    pub client_id: String,
    pub caps: Vec<(String, u64)>,
    pub listen_port: u64,
    pub id: [u8; 64],
}

impl Hello {
    pub fn ours(client_id: &str, listen_port: u16, id: [u8; 64]) -> Hello {
        Hello {
            version: BASE_VERSION,
            client_id: client_id.to_string(),
            caps: ETH_VERSIONS
                .iter()
                .map(|v| ("eth".to_string(), *v))
                .collect(),
            listen_port: u64::from(listen_port),
            id,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        Rlp::List(vec![
            Rlp::uint(self.version),
            Rlp::string(&self.client_id),
            Rlp::List(
                self.caps
                    .iter()
                    .map(|(n, v)| Rlp::List(vec![Rlp::string(n), Rlp::uint(*v)]))
                    .collect(),
            ),
            Rlp::uint(self.listen_port),
            Rlp::bytes(&self.id),
        ])
        .encode()
    }

    /// Decode a peer's Hello. The client id is reduced to a printable token; capabilities past
    /// [`MAX_CAPS`] are refused.
    pub fn decode(payload: &[u8]) -> Result<Hello> {
        ensure!(
            payload.len() <= MAX_HELLO_BYTES,
            "Hello of {} bytes is above {MAX_HELLO_BYTES}",
            payload.len()
        );
        let item = rlp::decode(payload).context("Hello is not RLP")?;
        let l = item.as_list().context("Hello")?;
        ensure!(l.len() >= 5, "Hello has {} fields, not 5", l.len());
        let caps_l = l[2].as_list().context("Hello capabilities")?;
        ensure!(
            caps_l.len() <= MAX_CAPS,
            "Hello lists {} capabilities, above {MAX_CAPS}",
            caps_l.len()
        );
        let mut caps = Vec::new();
        for c in caps_l {
            let c = c.as_list().context("capability")?;
            ensure!(c.len() >= 2, "capability without a version");
            let name = crate::utils::sanitize::token(
                &String::from_utf8_lossy(c[0].as_bytes().context("capability name")?),
                32,
            );
            caps.push((name, c[1].as_u64().context("capability version")?));
        }
        Ok(Hello {
            version: l[0].as_u64().context("Hello version")?,
            client_id: crate::utils::sanitize::token(
                &String::from_utf8_lossy(l[1].as_bytes().context("client id")?),
                MAX_CLIENT_ID_CHARS,
            ),
            caps,
            listen_port: l[3].as_u64().context("listen port")?,
            id: l[4].as_fixed().context("Hello node id")?,
        })
    }

    /// The highest `eth` version both sides speak.
    pub fn shared_eth(&self) -> Option<u64> {
        ETH_VERSIONS
            .iter()
            .copied()
            .find(|v| self.caps.iter().any(|(n, cv)| n == "eth" && cv == v))
    }

    pub fn caps_strings(&self) -> Vec<String> {
        self.caps.iter().map(|(n, v)| format!("{n}/{v}")).collect()
    }
}

// ---------------------------------------------------------------------------------------
// Hex and numbers as the model writes them
// ---------------------------------------------------------------------------------------

pub fn hex0x(b: &[u8]) -> String {
    format!("0x{}", hex::encode(b))
}

/// Bytes from a `0x`-prefixed (or bare) hex string.
pub fn parse_hex(v: &Value, what: &str) -> Result<Vec<u8>> {
    let s = v
        .as_str()
        .with_context(|| format!("{what} is a hex string"))?;
    let s = s.strip_prefix("0x").unwrap_or(s);
    let s = if s.len() % 2 == 1 {
        format!("0{s}")
    } else {
        s.to_string()
    };
    hex::decode(&s).with_context(|| format!("{what} is not hex"))
}

pub fn parse_fixed<const N: usize>(v: &Value, what: &str) -> Result<[u8; N]> {
    let b = parse_hex(v, what)?;
    b.as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("{what} is {} bytes, not {N}", b.len()))
}

/// An unsigned integer: a JSON number, a `0x` hex string, or a decimal string.
pub fn parse_u64(v: &Value, what: &str) -> Result<u64> {
    if let Some(n) = v.as_u64() {
        return Ok(n);
    }
    let s = v.as_str().with_context(|| format!("{what} is a number"))?;
    if let Some(h) = s.strip_prefix("0x") {
        ensure!(!h.is_empty(), "{what} is an empty hex number");
        return u64::from_str_radix(h, 16)
            .with_context(|| format!("{what} is not a 64-bit number"));
    }
    s.parse::<u64>()
        .with_context(|| format!("{what} is not a 64-bit number"))
}

/// An unsigned big integer (up to 256 bits) as minimal big-endian bytes.
pub fn parse_big(v: &Value, what: &str) -> Result<Vec<u8>> {
    if let Some(n) = v.as_u64() {
        return Ok(Rlp::uint(n).as_bytes()?.to_vec());
    }
    let s = v.as_str().with_context(|| format!("{what} is a number"))?;
    let bytes = if s.starts_with("0x") {
        parse_hex(v, what)?
    } else {
        decimal_to_be(s).with_context(|| format!("{what} is not a number"))?
    };
    let start = bytes.iter().position(|b| *b != 0).unwrap_or(bytes.len());
    ensure!(bytes.len() - start <= 32, "{what} is above 256 bits");
    Ok(bytes[start..].to_vec())
}

fn decimal_to_be(s: &str) -> Result<Vec<u8>> {
    ensure!(
        !s.is_empty() && s.len() <= 80 && s.bytes().all(|b| b.is_ascii_digit()),
        "not a decimal number"
    );
    let mut out: Vec<u8> = vec![0];
    for d in s.bytes() {
        let mut carry = u32::from(d - b'0');
        for byte in out.iter_mut().rev() {
            let v = u32::from(*byte) * 10 + carry;
            *byte = (v & 0xff) as u8;
            carry = v >> 8;
        }
        while carry > 0 {
            out.insert(0, (carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    Ok(out)
}

/// A big integer for the model: a JSON number when it fits in 64 bits, hex otherwise.
pub fn big_json(be: &[u8]) -> Value {
    if be.len() <= 8 {
        json!(be.iter().fold(0u64, |n, d| (n << 8) | u64::from(*d)))
    } else {
        json!(hex0x(be))
    }
}

// ---------------------------------------------------------------------------------------
// Block headers
// ---------------------------------------------------------------------------------------

#[derive(Clone, Copy)]
enum Kind {
    Hash,
    Address,
    Bloom,
    Big,
    U64,
    Bytes,
    Nonce,
}

/// Header fields in RLP order, by their JSON-RPC names. Everything from `baseFeePerGas` on is
/// optional and must be contiguous: a later field present means every earlier one is.
const HEADER_FIELDS: &[(&str, Kind)] = &[
    ("parentHash", Kind::Hash),
    ("sha3Uncles", Kind::Hash),
    ("miner", Kind::Address),
    ("stateRoot", Kind::Hash),
    ("transactionsRoot", Kind::Hash),
    ("receiptsRoot", Kind::Hash),
    ("logsBloom", Kind::Bloom),
    ("difficulty", Kind::Big),
    ("number", Kind::U64),
    ("gasLimit", Kind::U64),
    ("gasUsed", Kind::U64),
    ("timestamp", Kind::U64),
    ("extraData", Kind::Bytes),
    ("mixHash", Kind::Hash),
    ("nonce", Kind::Nonce),
    ("baseFeePerGas", Kind::Big),
    ("withdrawalsRoot", Kind::Hash),
    ("blobGasUsed", Kind::U64),
    ("excessBlobGas", Kind::U64),
    ("parentBeaconBlockRoot", Kind::Hash),
    ("requestsHash", Kind::Hash),
    ("blockAccessListHash", Kind::Hash),
    ("slotNumber", Kind::U64),
];
const REQUIRED_HEADER_FIELDS: usize = 15;
/// Block keys `eth_getBlockByNumber` returns that are not header fields; accepted and ignored
/// (except `hash`, which is checked).
const NON_HEADER_BLOCK_KEYS: &[&str] = &[
    "hash",
    "size",
    "transactions",
    "uncles",
    "totalDifficulty",
    "withdrawals",
    "blockAccessList",
];
/// `extraData` is at most 32 bytes on mainnet; a little room for other chains.
pub const MAX_EXTRA_DATA: usize = 1024;

fn field_rlp(v: &Value, name: &str, kind: Kind) -> Result<Rlp> {
    Ok(match kind {
        Kind::Hash => Rlp::bytes(&parse_fixed::<32>(v, name)?),
        Kind::Address => Rlp::bytes(&parse_fixed::<20>(v, name)?),
        Kind::Bloom => Rlp::bytes(&parse_fixed::<256>(v, name)?),
        Kind::Nonce => Rlp::bytes(&parse_fixed::<8>(v, name)?),
        Kind::Big => Rlp::big_uint(&parse_big(v, name)?),
        Kind::U64 => Rlp::uint(parse_u64(v, name)?),
        Kind::Bytes => {
            let b = parse_hex(v, name)?;
            ensure!(
                b.len() <= MAX_EXTRA_DATA,
                "{name} is above {MAX_EXTRA_DATA} bytes"
            );
            Rlp::bytes(&b)
        }
    })
}

fn field_json(item: &Rlp, name: &str, kind: Kind) -> Result<Value> {
    Ok(match kind {
        Kind::Hash => json!(hex0x(&item.as_fixed::<32>().context(name.to_string())?)),
        Kind::Address => json!(hex0x(&item.as_fixed::<20>().context(name.to_string())?)),
        Kind::Bloom => json!(hex0x(&item.as_fixed::<256>().context(name.to_string())?)),
        Kind::Nonce => json!(hex0x(&item.as_fixed::<8>().context(name.to_string())?)),
        Kind::Big => big_json(item.as_big_uint().context(name.to_string())?),
        Kind::U64 => json!(item.as_u64().context(name.to_string())?),
        Kind::Bytes => {
            let b = item.as_bytes().context(name.to_string())?;
            ensure!(
                b.len() <= MAX_EXTRA_DATA,
                "{name} is above {MAX_EXTRA_DATA} bytes"
            );
            json!(hex0x(b))
        }
    })
}

/// Build a header from JSON fields named as `eth_getBlockByNumber` names them. When the JSON
/// carries a `hash`, it must be the hash of the header these fields make.
pub fn header_from_json(v: &Value) -> Result<Rlp> {
    let obj = v.as_object().context("a header is an object of fields")?;
    for k in obj.keys() {
        ensure!(
            HEADER_FIELDS.iter().any(|(n, _)| n == k)
                || NON_HEADER_BLOCK_KEYS.contains(&k.as_str()),
            "{k:?} is not a block header field"
        );
    }
    let mut items = Vec::new();
    let mut ended = None;
    for (i, (name, kind)) in HEADER_FIELDS.iter().enumerate() {
        match obj.get(*name).filter(|v| !v.is_null()) {
            Some(value) => {
                if let Some(missing) = ended {
                    bail!("{name} is present but {missing} before it is not; header fields after baseFeePerGas are added in order");
                }
                items.push(field_rlp(value, name, *kind)?);
            }
            None if i < REQUIRED_HEADER_FIELDS => bail!("header field {name} is required"),
            None => {
                ended.get_or_insert(*name);
            }
        }
    }
    let header = Rlp::List(items);
    if let Some(claimed) = obj.get("hash").filter(|v| !v.is_null()) {
        let claimed = parse_fixed::<32>(claimed, "hash")?;
        let actual = header_hash(&header);
        ensure!(
            claimed == actual,
            "the header's hash is {}, not the {} it claims",
            hex0x(&actual),
            hex0x(&claimed)
        );
    }
    Ok(header)
}

/// keccak-256 of the header's RLP: the block hash.
pub fn header_hash(header: &Rlp) -> [u8; 32] {
    crypto::keccak256(&[&header.encode()])
}

fn header_fields(header: &Rlp) -> Result<&[Rlp]> {
    let l = header.as_list().context("a header is a list")?;
    ensure!(
        (REQUIRED_HEADER_FIELDS..=HEADER_FIELDS.len()).contains(&l.len()),
        "a header has {} fields, not {REQUIRED_HEADER_FIELDS} to {}",
        l.len(),
        HEADER_FIELDS.len()
    );
    Ok(l)
}

pub fn header_number(header: &Rlp) -> Result<u64> {
    header_fields(header)?[8].as_u64().context("header number")
}

pub fn header_parent(header: &Rlp) -> Result<[u8; 32]> {
    header_fields(header)?[0]
        .as_fixed()
        .context("header parentHash")
}

/// A header as JSON, with its computed `hash`.
pub fn header_to_json(header: &Rlp) -> Result<Value> {
    let l = header_fields(header)?;
    let mut m = Map::new();
    m.insert("hash".into(), json!(hex0x(&header_hash(header))));
    for (item, (name, kind)) in l.iter().zip(HEADER_FIELDS) {
        m.insert((*name).into(), field_json(item, name, *kind)?);
    }
    Ok(Value::Object(m))
}

// ---------------------------------------------------------------------------------------
// Transactions and bodies
// ---------------------------------------------------------------------------------------

/// The largest single transaction accepted from the model.
pub const MAX_TRANSACTION_BYTES: usize = 128 * 1024;

/// A signed transaction from its canonical encoding (`0x`-hex, as `eth_getRawTransactionByHash`
/// returns it): how it is embedded in a list (a legacy transaction is the RLP list itself, a
/// typed one is its EIP-2718 envelope as a byte string) and its hash.
pub fn transaction_from_hex(v: &Value) -> Result<(Rlp, [u8; 32])> {
    let raw = parse_hex(v, "transaction")?;
    ensure!(!raw.is_empty(), "a transaction is not empty");
    ensure!(
        raw.len() <= MAX_TRANSACTION_BYTES,
        "a transaction is at most {MAX_TRANSACTION_BYTES} bytes"
    );
    let hash = crypto::keccak256(&[&raw]);
    if raw[0] >= 0xc0 {
        let item = rlp::decode(&raw).context("legacy transaction")?;
        item.as_list().context("legacy transaction")?;
        Ok((item, hash))
    } else {
        ensure!(
            raw[0] <= 0x7f,
            "transaction type byte {:#04x} is not EIP-2718",
            raw[0]
        );
        let inner = rlp::decode(&raw[1..]).context("typed transaction payload")?;
        inner.as_list().context("typed transaction payload")?;
        Ok((Rlp::Bytes(raw), hash))
    }
}

/// How a transaction in a list is reported: its hash, type and size.
pub fn transaction_json(item: &Rlp) -> Result<Value> {
    let (raw, kind) = match item {
        Rlp::List(_) => (item.encode(), 0u64),
        Rlp::Bytes(b) => {
            ensure!(
                b.first().is_some_and(|t| *t <= 0x7f),
                "typed transaction without a type byte"
            );
            (b.clone(), u64::from(b[0]))
        }
    };
    Ok(json!({"hash": hex0x(&crypto::keccak256(&[&raw])), "type": kind, "size": raw.len()}))
}

fn withdrawal_from_json(v: &Value) -> Result<Rlp> {
    Ok(Rlp::List(vec![
        Rlp::uint(parse_u64(&v["index"], "withdrawal index")?),
        Rlp::uint(parse_u64(
            &v["validatorIndex"],
            "withdrawal validatorIndex",
        )?),
        Rlp::bytes(&parse_fixed::<20>(&v["address"], "withdrawal address")?),
        Rlp::uint(parse_u64(&v["amount"], "withdrawal amount")?),
    ]))
}

fn withdrawal_json(item: &Rlp) -> Result<Value> {
    let l = item.as_list().context("withdrawal")?;
    ensure!(l.len() == 4, "a withdrawal has 4 fields");
    Ok(json!({
        "index": l[0].as_u64()?,
        "validatorIndex": l[1].as_u64()?,
        "address": hex0x(&l[2].as_fixed::<20>()?),
        "amount": l[3].as_u64()?,
    }))
}

/// The most transactions, uncles or withdrawals one body may carry.
pub const MAX_BODY_ITEMS: usize = 4096;

/// A block body from `{transactions: ["0x…"], uncles: [header], withdrawals: [..] | absent}`.
pub fn body_from_json(v: &Value) -> Result<Rlp> {
    let list = |k: &str| -> Result<Vec<Value>> {
        match v.get(k) {
            None | Some(Value::Null) => Ok(Vec::new()),
            Some(Value::Array(a)) => {
                ensure!(
                    a.len() <= MAX_BODY_ITEMS,
                    "{k} holds more than {MAX_BODY_ITEMS}"
                );
                Ok(a.clone())
            }
            Some(_) => bail!("{k} is an array"),
        }
    };
    let mut txs = Vec::new();
    for t in list("transactions")? {
        txs.push(transaction_from_hex(&t)?.0);
    }
    let mut uncles = Vec::new();
    for u in list("uncles")? {
        uncles.push(header_from_json(&u)?);
    }
    let mut fields = vec![Rlp::List(txs), Rlp::List(uncles)];
    if v.get("withdrawals").is_some_and(|w| !w.is_null()) {
        let mut ws = Vec::new();
        for w in list("withdrawals")? {
            ws.push(withdrawal_from_json(&w)?);
        }
        fields.push(Rlp::List(ws));
    }
    Ok(Rlp::List(fields))
}

pub fn body_json(item: &Rlp) -> Result<Value> {
    let l = item.as_list().context("block body")?;
    ensure!((2..=3).contains(&l.len()), "a block body has 2 or 3 fields");
    let txs = l[0]
        .as_list()?
        .iter()
        .map(transaction_json)
        .collect::<Result<Vec<_>>>()?;
    let uncles = l[1]
        .as_list()?
        .iter()
        .map(header_to_json)
        .collect::<Result<Vec<_>>>()?;
    let mut out = json!({"transactions": txs, "uncles": uncles, "uncles_hash": hex0x(&crypto::keccak256(&[&l[1].encode()]))});
    if let Some(w) = l.get(2) {
        out["withdrawals"] = json!(w
            .as_list()?
            .iter()
            .map(withdrawal_json)
            .collect::<Result<Vec<_>>>()?);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------------------
// Fork identifiers (EIP-2124)
// ---------------------------------------------------------------------------------------

/// Continue a CRC-32 (IEEE) over `data`, as Go's `crc32.Update`.
pub fn crc32_update(crc: u32, data: &[u8]) -> u32 {
    let mut c = !crc;
    for b in data {
        c ^= u32::from(*b);
        for _ in 0..8 {
            c = if c & 1 != 0 {
                (c >> 1) ^ 0xedb8_8320
            } else {
                c >> 1
            };
        }
    }
    !c
}

/// The fork hash of a chain with this genesis that has passed these forks (block numbers or
/// timestamps, in activation order; zeros — forks active at genesis — are skipped).
pub fn fork_hash(genesis: &[u8; 32], passed: &[u64]) -> [u8; 4] {
    let mut h = crc32_update(0, genesis);
    let mut last = 0;
    for f in passed {
        if *f == 0 || *f == last {
            continue;
        }
        last = *f;
        h = crc32_update(h, &f.to_be_bytes());
    }
    h.to_be_bytes()
}

// ---------------------------------------------------------------------------------------
// eth messages
// ---------------------------------------------------------------------------------------

/// An `eth` Status at version 68 or 69.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Status {
    pub version: u64,
    pub network_id: u64,
    pub genesis: [u8; 32],
    pub fork_hash: [u8; 4],
    pub fork_next: u64,
    /// eth/68: total difficulty (minimal big-endian) and head hash.
    pub total_difficulty: Vec<u8>,
    pub head: [u8; 32],
    /// eth/69: the block range this node serves.
    pub earliest_block: u64,
    pub latest_block: u64,
    pub latest_block_hash: [u8; 32],
}

impl Status {
    pub fn encode(&self) -> Vec<u8> {
        let fork = Rlp::List(vec![Rlp::bytes(&self.fork_hash), Rlp::uint(self.fork_next)]);
        let fields = if self.version >= 69 {
            vec![
                Rlp::uint(self.version),
                Rlp::uint(self.network_id),
                Rlp::bytes(&self.genesis),
                fork,
                Rlp::uint(self.earliest_block),
                Rlp::uint(self.latest_block),
                Rlp::bytes(&self.latest_block_hash),
            ]
        } else {
            vec![
                Rlp::uint(self.version),
                Rlp::uint(self.network_id),
                Rlp::big_uint(&self.total_difficulty),
                Rlp::bytes(&self.head),
                Rlp::bytes(&self.genesis),
                fork,
            ]
        };
        Rlp::List(fields).encode()
    }

    /// Decode a Status sent on a session that negotiated `version`.
    pub fn decode(payload: &[u8], version: u64) -> Result<Status> {
        let item = rlp::decode(payload).context("Status is not RLP")?;
        let l = item.as_list().context("Status")?;
        ensure!(!l.is_empty(), "Status is empty");
        let sent = l[0].as_u64().context("Status version")?;
        ensure!(
            sent == version,
            "Status says eth/{sent} on a session that negotiated eth/{version}"
        );
        let fork = |f: &Rlp| -> Result<([u8; 4], u64)> {
            let f = f.as_list().context("fork id")?;
            ensure!(f.len() >= 2, "fork id has {} fields", f.len());
            Ok((
                f[0].as_fixed().context("fork hash")?,
                f[1].as_u64().context("fork next")?,
            ))
        };
        let mut s = Status {
            version,
            network_id: 0,
            genesis: [0; 32],
            fork_hash: [0; 4],
            fork_next: 0,
            total_difficulty: Vec::new(),
            head: [0; 32],
            earliest_block: 0,
            latest_block: 0,
            latest_block_hash: [0; 32],
        };
        if version >= 69 {
            ensure!(l.len() >= 7, "eth/69 Status has {} fields, not 7", l.len());
            s.network_id = l[1].as_u64().context("network id")?;
            s.genesis = l[2].as_fixed().context("genesis hash")?;
            (s.fork_hash, s.fork_next) = fork(&l[3])?;
            s.earliest_block = l[4].as_u64().context("earliest block")?;
            s.latest_block = l[5].as_u64().context("latest block")?;
            s.latest_block_hash = l[6].as_fixed().context("latest block hash")?;
        } else {
            ensure!(l.len() >= 6, "eth/68 Status has {} fields, not 6", l.len());
            s.network_id = l[1].as_u64().context("network id")?;
            s.total_difficulty = l[2].as_big_uint().context("total difficulty")?.to_vec();
            s.head = l[3].as_fixed().context("head hash")?;
            s.genesis = l[4].as_fixed().context("genesis hash")?;
            (s.fork_hash, s.fork_next) = fork(&l[5])?;
        }
        Ok(s)
    }

    pub fn to_json(&self) -> Value {
        let mut v = json!({
            "version": self.version,
            "network_id": self.network_id,
            "genesis_hash": hex0x(&self.genesis),
            "fork_hash": hex0x(&self.fork_hash),
            "fork_next": self.fork_next,
        });
        if self.version >= 69 {
            v["earliest_block"] = json!(self.earliest_block);
            v["latest_block"] = json!(self.latest_block);
            v["latest_block_hash"] = json!(hex0x(&self.latest_block_hash));
        } else {
            v["total_difficulty"] = big_json(&self.total_difficulty);
            v["head_hash"] = json!(hex0x(&self.head));
        }
        v
    }
}

/// Where a header request starts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    Number(u64),
    Hash([u8; 32]),
}

impl Origin {
    pub fn to_json(self) -> Value {
        match self {
            Origin::Number(n) => json!(n),
            Origin::Hash(h) => json!(hex0x(&h)),
        }
    }

    /// A block number (number or decimal string) or a `0x` 32-byte hash.
    pub fn from_json(v: &Value) -> Result<Origin> {
        if let Some(s) = v.as_str() {
            if s.starts_with("0x") && s.len() == 66 {
                return Ok(Origin::Hash(parse_fixed(v, "origin")?));
            }
        }
        Ok(Origin::Number(parse_u64(v, "origin").context(
            "origin is a block number or a 0x-prefixed 32-byte block hash",
        )?))
    }
}

/// GetBlockHeaders.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderRequest {
    pub origin: Origin,
    pub amount: u64,
    pub skip: u64,
    pub reverse: bool,
}

impl HeaderRequest {
    pub fn encode(&self, request_id: u64) -> Vec<u8> {
        let origin = match self.origin {
            Origin::Number(n) => Rlp::uint(n),
            Origin::Hash(h) => Rlp::bytes(&h),
        };
        Rlp::List(vec![
            Rlp::uint(request_id),
            Rlp::List(vec![
                origin,
                Rlp::uint(self.amount),
                Rlp::uint(self.skip),
                Rlp::uint(u64::from(self.reverse)),
            ]),
        ])
        .encode()
    }

    pub fn decode(payload: &[u8]) -> Result<(u64, HeaderRequest)> {
        let item = rlp::decode(payload).context("GetBlockHeaders is not RLP")?;
        let l = item.as_list()?;
        ensure!(l.len() == 2, "GetBlockHeaders has {} fields", l.len());
        let q = l[1].as_list()?;
        ensure!(q.len() == 4, "a header query has {} fields", q.len());
        let origin_bytes = q[0].as_bytes().context("origin")?;
        let origin = if origin_bytes.len() == 32 {
            Origin::Hash(q[0].as_fixed()?)
        } else {
            Origin::Number(q[0].as_u64().context("origin number")?)
        };
        Ok((
            l[0].as_u64().context("request id")?,
            HeaderRequest {
                origin,
                amount: q[1].as_u64().context("amount")?,
                skip: q[2].as_u64().context("skip")?,
                reverse: q[3].as_bool().context("reverse")?,
            },
        ))
    }

    pub fn to_json(&self) -> Value {
        json!({"origin": self.origin.to_json(), "amount": self.amount, "skip": self.skip, "reverse": self.reverse})
    }

    /// The block number at position `i` of an answer whose first header is `first`, or None
    /// when it would pass block zero or overflow.
    pub fn number_at(&self, first: u64, i: u64) -> Option<u64> {
        let step = self.skip.checked_add(1)?.checked_mul(i)?;
        if self.reverse {
            first.checked_sub(step)
        } else {
            first.checked_add(step)
        }
    }
}

/// `[request_id, [items…]]`.
pub fn encode_response(request_id: u64, items: Vec<Rlp>) -> Vec<u8> {
    Rlp::List(vec![Rlp::uint(request_id), Rlp::List(items)]).encode()
}

/// `[request_id, [items…]]`, at most `max` items.
pub fn decode_response(payload: &[u8], max: usize, what: &str) -> Result<(u64, Vec<Rlp>)> {
    let item = rlp::decode(payload).with_context(|| format!("{what} is not RLP"))?;
    let mut l = match item {
        Rlp::List(l) => l,
        Rlp::Bytes(_) => bail!("{what} is not a list"),
    };
    ensure!(l.len() == 2, "{what} has {} fields", l.len());
    let items = match l.pop() {
        Some(Rlp::List(items)) => items,
        _ => bail!("{what}'s second field is not a list"),
    };
    ensure!(
        items.len() <= max,
        "{what} carries {} items, above {max}",
        items.len()
    );
    Ok((l[0].as_u64().context("request id")?, items))
}

/// `[request_id, [hash…]]` (GetBlockBodies, GetPooledTransactions, GetReceipts).
pub fn decode_hash_request(payload: &[u8], max: usize, what: &str) -> Result<(u64, Vec<[u8; 32]>)> {
    let (id, items) = decode_response(payload, max, what)?;
    let hashes = items
        .iter()
        .map(|h| h.as_fixed::<32>())
        .collect::<Result<Vec<_>>>()
        .with_context(|| format!("{what} hash"))?;
    Ok((id, hashes))
}

pub fn encode_hash_request(request_id: u64, hashes: &[[u8; 32]]) -> Vec<u8> {
    encode_response(request_id, hashes.iter().map(|h| Rlp::bytes(h)).collect())
}

/// NewPooledTransactionHashes (eth/68+): `[types, [sizes…], [hashes…]]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Announcement {
    pub types: Vec<u8>,
    pub sizes: Vec<u64>,
    pub hashes: Vec<[u8; 32]>,
}

impl Announcement {
    pub fn decode(payload: &[u8], max: usize) -> Result<Announcement> {
        let item = rlp::decode(payload).context("NewPooledTransactionHashes is not RLP")?;
        let l = item.as_list()?;
        ensure!(
            l.len() >= 3,
            "NewPooledTransactionHashes has {} fields",
            l.len()
        );
        let types = l[0].as_bytes().context("types")?.to_vec();
        let sizes = l[1]
            .as_list()?
            .iter()
            .map(Rlp::as_u64)
            .collect::<Result<Vec<_>>>()
            .context("sizes")?;
        let hashes = l[2]
            .as_list()?
            .iter()
            .map(|h| h.as_fixed::<32>())
            .collect::<Result<Vec<_>>>()
            .context("hashes")?;
        ensure!(
            types.len() == sizes.len() && sizes.len() == hashes.len(),
            "NewPooledTransactionHashes lists {} types, {} sizes and {} hashes",
            types.len(),
            sizes.len(),
            hashes.len()
        );
        ensure!(
            hashes.len() <= max,
            "{} hashes announced, above {max}",
            hashes.len()
        );
        Ok(Announcement {
            types,
            sizes,
            hashes,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        Rlp::List(vec![
            Rlp::bytes(&self.types),
            Rlp::List(self.sizes.iter().map(|s| Rlp::uint(*s)).collect()),
            Rlp::List(self.hashes.iter().map(|h| Rlp::bytes(h)).collect()),
        ])
        .encode()
    }
}

/// BlockRangeUpdate (eth/69): `[earliest, latest, latest_hash]`.
pub fn decode_block_range(payload: &[u8]) -> Result<(u64, u64, [u8; 32])> {
    let item = rlp::decode(payload).context("BlockRangeUpdate is not RLP")?;
    let l = item.as_list()?;
    ensure!(l.len() >= 3, "BlockRangeUpdate has {} fields", l.len());
    let (earliest, latest) = (l[0].as_u64()?, l[1].as_u64()?);
    ensure!(
        earliest <= latest,
        "BlockRangeUpdate's earliest is after its latest"
    );
    Ok((earliest, latest, l[2].as_fixed()?))
}

// ---------------------------------------------------------------------------------------
// enode URLs
// ---------------------------------------------------------------------------------------

/// `enode://<128 hex>@<host>:<port>` (a `?discport=` query is ignored).
pub fn parse_enode(s: &str) -> Result<([u8; 64], String)> {
    let rest = s
        .trim()
        .strip_prefix("enode://")
        .context("a devp2p peer is named by its enode URL: enode://<node id>@<host>:<port>")?;
    let (id_hex, addr) = rest
        .split_once('@')
        .context("the enode URL has no @host:port")?;
    let id = hex::decode(id_hex).context("the enode node id is not hex")?;
    let id: [u8; 64] = id
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("the enode node id is {} bytes, not 64", id.len()))?;
    crypto::public_from_id(&id)?;
    let addr = addr
        .split('?')
        .next()
        .unwrap_or_default()
        .trim_end_matches('/');
    ensure!(
        addr.rsplit_once(':')
            .is_some_and(|(h, p)| !h.is_empty() && p.parse::<u16>().is_ok()),
        "the enode URL names no port"
    );
    Ok((id, addr.to_string()))
}

pub fn format_enode(id: &[u8; 64], addr: std::net::SocketAddr) -> String {
    format!("enode://{}@{}", hex::encode(id), addr)
}
