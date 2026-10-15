//! RESP3: the `HELLO` negotiation and the reply types RESP2 does not have.
//!
//! A connection starts in RESP2. `HELLO 3` (answered here, in Rust: it is protocol negotiation,
//! not data) switches it to RESP3 for the rest of its life, and `HELLO 2` switches it back.
//! From then on the reply verbs encode for the connection's version, the way Redis itself
//! does: the RESP3-only types are downgraded on a RESP2 connection (a map becomes a flat
//! array, a set an array, a double or big number a bulk string, a boolean the integer 1 or 0,
//! a verbatim string its text), and a push is refused there, because RESP2 has no
//! out-of-band frame.
//!
//! Requests are RESP2 arrays in both versions, so the decoder does not change.
use anyhow::{bail, ensure, Context, Result};
use serde_json::Value;

/// How deep a model-authored RESP3 aggregate may nest.
pub const MAX_REPLY_DEPTH: usize = 32;

/// What `HELLO` asked for.
#[derive(Debug, Default, PartialEq)]
pub struct Hello {
    pub protover: Option<u8>,
    pub auth: Option<(String, String)>,
    pub setname: Option<String>,
}

/// Parse a `HELLO [protover [AUTH username password] [SETNAME clientname]]` command's
/// arguments (the command name excluded). `Err` carries the RESP error to send.
pub fn parse_hello(args: &[String]) -> std::result::Result<Hello, String> {
    let mut hello = Hello::default();
    let mut rest = args;
    if let Some(first) = rest.first() {
        let v: i64 = first
            .parse()
            .map_err(|_| "ERR Protocol version is not an integer or out of range".to_string())?;
        if v != 2 && v != 3 {
            return Err("NOPROTO unsupported protocol version".into());
        }
        hello.protover = Some(v as u8);
        rest = &rest[1..];
    }
    while let Some(opt) = rest.first() {
        if opt.eq_ignore_ascii_case("AUTH") && rest.len() >= 3 {
            hello.auth = Some((rest[1].clone(), rest[2].clone()));
            rest = &rest[3..];
        } else if opt.eq_ignore_ascii_case("SETNAME") && rest.len() >= 2 {
            hello.setname = Some(rest[1].clone());
            rest = &rest[2..];
        } else {
            return Err(format!("ERR Syntax error in HELLO option '{opt}'"));
        }
    }
    Ok(hello)
}

/// The server properties `HELLO` answers with: a map in RESP3, a flat array in RESP2. `mode`
/// is `standalone`, or `cluster` for a server started with `cluster_nodes`.
pub fn hello_reply(proto: u8, connection_id: u64, mode: &str) -> Vec<u8> {
    let fields: Vec<(&str, Value)> = vec![
        ("server", Value::from("redis")),
        ("version", Value::from(REPORTED_VERSION)),
        ("proto", Value::from(proto)),
        ("id", Value::from(connection_id)),
        ("mode", Value::from(mode)),
        ("role", Value::from("master")),
        ("modules", Value::Array(vec![])),
    ];
    let mut out = Vec::new();
    if proto == 3 {
        out.extend_from_slice(format!("%{}\r\n", fields.len()).as_bytes());
    } else {
        out.extend_from_slice(format!("*{}\r\n", fields.len() * 2).as_bytes());
    }
    for (k, v) in fields {
        out.extend_from_slice(&super::actions::encode_bulk_string(k.as_bytes()));
        match v {
            Value::String(s) => {
                out.extend_from_slice(&super::actions::encode_bulk_string(s.as_bytes()))
            }
            Value::Number(n) => {
                out.extend_from_slice(&super::actions::encode_integer(n.as_i64().unwrap_or(0)))
            }
            _ => out.extend_from_slice(b"*0\r\n"),
        }
    }
    out
}

/// The Redis version `HELLO` reports. Clients gate features on it; 7.4 is the release whose
/// RESP3 behaviour this follows.
pub const REPORTED_VERSION: &str = "7.4.0";

/// A null: `_` in RESP3, a nil bulk string in RESP2.
pub fn null(proto: u8) -> Vec<u8> {
    if proto == 3 {
        b"_\r\n".to_vec()
    } else {
        super::actions::encode_null()
    }
}

/// A double's RESP3 text: `inf`, `-inf`, `nan`, or the number as JSON writes it.
fn double_text(v: &Value) -> Result<String> {
    match v {
        Value::Number(n) => {
            let f = n.as_f64().context("not a number")?;
            Ok(if f.fract() == 0.0 && f.abs() < 1e15 {
                format!("{f:.0}")
            } else {
                n.to_string()
            })
        }
        Value::String(s) if matches!(s.as_str(), "inf" | "-inf" | "nan") => Ok(s.clone()),
        Value::String(s) => {
            let f: f64 = s.parse().context("value is a number, inf, -inf or nan")?;
            ensure!(f.is_finite(), "value is a number, inf, -inf or nan");
            Ok(s.clone())
        }
        _ => bail!("value is a number, inf, -inf or nan"),
    }
}

pub fn double(v: &Value, proto: u8) -> Result<Vec<u8>> {
    let text = double_text(v)?;
    Ok(if proto == 3 {
        format!(",{text}\r\n").into_bytes()
    } else {
        super::actions::encode_bulk_string(text.as_bytes())
    })
}

pub fn boolean(b: bool, proto: u8) -> Vec<u8> {
    if proto == 3 {
        if b {
            b"#t\r\n".to_vec()
        } else {
            b"#f\r\n".to_vec()
        }
    } else {
        super::actions::encode_integer(i64::from(b))
    }
}

pub fn big_number(digits: &str, proto: u8) -> Result<Vec<u8>> {
    let body = digits.strip_prefix('-').unwrap_or(digits);
    ensure!(
        !body.is_empty() && body.len() <= 4096 && body.bytes().all(|b| b.is_ascii_digit()),
        "value is a decimal integer, optionally negative"
    );
    Ok(if proto == 3 {
        format!("({digits}\r\n").into_bytes()
    } else {
        super::actions::encode_bulk_string(digits.as_bytes())
    })
}

pub fn verbatim(format: &str, text: &str, proto: u8) -> Result<Vec<u8>> {
    ensure!(
        format.len() == 3 && format.bytes().all(|b| b.is_ascii_alphanumeric()),
        "format is three letters, such as txt or mkd"
    );
    Ok(if proto == 3 {
        let body = format!("{format}:{text}");
        let mut out = format!("={}\r\n", body.len()).into_bytes();
        out.extend_from_slice(body.as_bytes());
        out.extend_from_slice(b"\r\n");
        out
    } else {
        super::actions::encode_bulk_string(text.as_bytes())
    })
}

/// One element of a RESP3 aggregate, from JSON: a string is a bulk string, an integer a RESP
/// integer, a fraction a double, a boolean a boolean, null a null, an array an array and an
/// object a map.
pub fn value(v: &Value, depth: usize) -> Result<Vec<u8>> {
    ensure!(
        depth <= MAX_REPLY_DEPTH,
        "the reply nests deeper than {MAX_REPLY_DEPTH} levels"
    );
    Ok(match v {
        Value::String(s) => super::actions::encode_bulk_string(s.as_bytes()),
        Value::Number(n) => match n.as_i64() {
            Some(i) => super::actions::encode_integer(i),
            None => double(v, 3)?,
        },
        Value::Bool(b) => boolean(*b, 3),
        Value::Null => null(3),
        Value::Array(items) => aggregate(b'*', items, depth)?,
        Value::Object(map) => {
            let mut out = format!("%{}\r\n", map.len()).into_bytes();
            for (k, v) in map {
                out.extend_from_slice(&super::actions::encode_bulk_string(k.as_bytes()));
                out.extend_from_slice(&value(v, depth + 1)?);
            }
            out
        }
    })
}

fn aggregate(kind: u8, items: &[Value], depth: usize) -> Result<Vec<u8>> {
    let mut out = vec![kind];
    out.extend_from_slice(format!("{}\r\n", items.len()).as_bytes());
    for item in items {
        out.extend_from_slice(&value(item, depth + 1)?);
    }
    Ok(out)
}

/// A map's entries, in order: a JSON object, or `[[key, value], …]` where order matters.
pub fn entries(v: &Value) -> Result<Vec<(Value, Value)>> {
    match v {
        Value::Object(map) => Ok(map
            .iter()
            .map(|(k, v)| (Value::String(k.clone()), v.clone()))
            .collect()),
        Value::Array(pairs) => pairs
            .iter()
            .map(|p| match p.as_array().map(Vec::as_slice) {
                Some([k, v]) => Ok((k.clone(), v.clone())),
                _ => bail!("each entry is a [key, value] pair"),
            })
            .collect(),
        _ => bail!("entries is an object or an array of [key, value] pairs"),
    }
}

/// A map: `%` in RESP3, a flat key-value array in RESP2 (elements as `redis_array` encodes them).
pub fn map(entries: &[(Value, Value)], proto: u8) -> Result<Vec<u8>> {
    if proto == 3 {
        let mut out = format!("%{}\r\n", entries.len()).into_bytes();
        for (k, v) in entries {
            out.extend_from_slice(&value(k, 1)?);
            out.extend_from_slice(&value(v, 1)?);
        }
        Ok(out)
    } else {
        let flat: Vec<Value> = entries
            .iter()
            .flat_map(|(k, v)| [k.clone(), v.clone()])
            .collect();
        Ok(super::actions::encode_array(&flat))
    }
}

/// A set: `~` in RESP3, an array in RESP2.
pub fn set(items: &[Value], proto: u8) -> Result<Vec<u8>> {
    if proto == 3 {
        aggregate(b'~', items, 0)
    } else {
        Ok(super::actions::encode_array(items))
    }
}

/// An array: nested aggregates and RESP3 scalars in RESP3; `redis_array`'s RESP2 rules otherwise.
pub fn array(items: &[Value], proto: u8) -> Result<Vec<u8>> {
    if proto == 3 {
        aggregate(b'*', items, 0)
    } else {
        Ok(super::actions::encode_array(items))
    }
}

/// An out-of-band push (`>`), RESP3 only.
pub fn push(items: &[Value], proto: u8) -> Result<Vec<u8>> {
    ensure!(
        proto == 3,
        "this connection speaks RESP2, which has no push frame; a client must send HELLO 3 first"
    );
    ensure!(
        !items.is_empty(),
        "a push names its kind as its first element"
    );
    aggregate(b'>', items, 0)
}
