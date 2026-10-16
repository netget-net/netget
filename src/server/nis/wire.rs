//! NIS (YP) version 2, ONC RPC program 100004: the XDR of every procedure's arguments and
//! results, the `ypresp_all` stream, and the rendering of the model's structured map entries
//! into the canonical lines NIS clients parse (`name:passwd:uid:gid:gecos:home:shell`, …).
//!
//! The RPC layer — call and reply headers, AUTH_NONE/AUTH_SYS, TCP record marking — is the
//! portmapper's (`crate::server::sunrpc::wire`), shared by both roles. Every length a peer
//! announces is bounded before use, by the limits `yp.x` itself declares.
use crate::server::sunrpc::wire::{Reader, Writer};
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value};
use std::net::IpAddr;

pub const PROGRAM: u32 = 100_004;
pub const VERSION: u32 = 2;
/// `ypbind`, which clients ask for a server (not served; named so the docs can point at it).
pub const YPBIND_PROGRAM: u32 = 100_007;

/// `yp.x`: a key or a value is at most this long.
pub const YPMAXRECORD: usize = 1024;
/// `yp.x`: a domain name is at most this long.
pub const YPMAXDOMAIN: usize = 64;
/// `yp.x`: a map name is at most this long.
pub const YPMAXMAP: usize = 64;
/// `yp.x`: a master server's name is at most this long.
pub const YPMAXPEER: usize = 64;

/// One inbound call (a TCP record or a UDP datagram). The largest a YP call can be is a
/// MATCH: the RPC header with two 400-byte auth bodies, a domain, a map and a 1024-byte key —
/// under 2 KiB. Anything announcing more is refused from its header.
pub const MAX_CALL: usize = 8 * 1024;
/// Fragments one inbound TCP record may be split into.
pub const MAX_CALL_FRAGMENTS: usize = 8;
/// Entries one map may have, as the model enumerates it and as a client accepts it.
pub const MAX_ENTRIES: usize = 10_000;
/// Maps one MAPLIST may name.
pub const MAX_MAPS: usize = 256;
/// The largest reply NetGet writes (an ALL of a large map) or a client accepts. 10 000
/// entries of 1 KiB keys and values could reach ~20 MiB; a reply that would pass this is
/// refused whole (YP_YPERR) rather than cut short, since a truncated map reads as complete.
pub const MAX_REPLY: usize = 4 * 1024 * 1024;
/// Fragments one reply record is written in, and the most a client accepts.
pub const REPLY_FRAGMENT: usize = 64 * 1024;
pub const MAX_REPLY_FRAGMENTS: usize = 1024;
/// The largest reply that fits one UDP datagram.
pub const MAX_UDP_REPLY: usize = 65_000;

/// `ypstat`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stat {
    True,
    NoMore,
    False,
    NoMap,
    NoDom,
    NoKey,
    BadOp,
    BadDb,
    YpErr,
    BadArgs,
    Vers,
}

impl Stat {
    pub fn code(self) -> i32 {
        match self {
            Stat::True => 1,
            Stat::NoMore => 2,
            Stat::False => 0,
            Stat::NoMap => -1,
            Stat::NoDom => -2,
            Stat::NoKey => -3,
            Stat::BadOp => -4,
            Stat::BadDb => -5,
            Stat::YpErr => -6,
            Stat::BadArgs => -7,
            Stat::Vers => -8,
        }
    }
    pub fn from_code(c: i32) -> Option<Self> {
        Some(match c {
            1 => Stat::True,
            2 => Stat::NoMore,
            0 => Stat::False,
            -1 => Stat::NoMap,
            -2 => Stat::NoDom,
            -3 => Stat::NoKey,
            -4 => Stat::BadOp,
            -5 => Stat::BadDb,
            -6 => Stat::YpErr,
            -7 => Stat::BadArgs,
            -8 => Stat::Vers,
            _ => return None,
        })
    }
    pub fn name(self) -> &'static str {
        match self {
            Stat::True => "YP_TRUE",
            Stat::NoMore => "YP_NOMORE",
            Stat::False => "YP_FALSE",
            Stat::NoMap => "YP_NOMAP",
            Stat::NoDom => "YP_NODOM",
            Stat::NoKey => "YP_NOKEY",
            Stat::BadOp => "YP_BADOP",
            Stat::BadDb => "YP_BADDB",
            Stat::YpErr => "YP_YPERR",
            Stat::BadArgs => "YP_BADARGS",
            Stat::Vers => "YP_VERS",
        }
    }
    /// The model's name for a refusal (`nis_error {status}`).
    pub fn from_model(s: &str) -> Option<Self> {
        Some(match s {
            "no_map" => Stat::NoMap,
            "no_domain" => Stat::NoDom,
            "no_key" => Stat::NoKey,
            "bad_args" => Stat::BadArgs,
            "bad_database" => Stat::BadDb,
            "error" => Stat::YpErr,
            _ => return None,
        })
    }
    pub const MODEL_NAMES: &'static [&'static str] = &[
        "no_map",
        "no_domain",
        "no_key",
        "bad_args",
        "bad_database",
        "error",
    ];
}

fn stat_of(code: u32) -> Result<Stat> {
    Stat::from_code(code as i32).with_context(|| format!("ypstat {}", code as i32))
}

/// YP procedures (version 2).
pub mod proc_ {
    pub const NULL: u32 = 0;
    pub const DOMAIN: u32 = 1;
    pub const DOMAIN_NONACK: u32 = 2;
    pub const MATCH: u32 = 3;
    pub const FIRST: u32 = 4;
    pub const NEXT: u32 = 5;
    pub const XFR: u32 = 6;
    pub const CLEAR: u32 = 7;
    pub const ALL: u32 = 8;
    pub const MASTER: u32 = 9;
    pub const ORDER: u32 = 10;
    pub const MAPLIST: u32 = 11;
}

/// A decoded YP call.
#[derive(Debug, Clone, PartialEq)]
pub enum Request {
    Null,
    Clear,
    Xfr,
    Domain {
        domain: String,
        nonack: bool,
    },
    Match {
        domain: String,
        map: String,
        key: String,
    },
    First {
        domain: String,
        map: String,
    },
    Next {
        domain: String,
        map: String,
        key: String,
    },
    All {
        domain: String,
        map: String,
    },
    Master {
        domain: String,
        map: String,
    },
    Order {
        domain: String,
        map: String,
    },
    Maplist {
        domain: String,
    },
}

impl Request {
    pub fn name(&self) -> &'static str {
        match self {
            Request::Null => "null",
            Request::Clear => "clear",
            Request::Xfr => "xfr",
            Request::Domain { nonack: false, .. } => "domain",
            Request::Domain { nonack: true, .. } => "domain_nonack",
            Request::Match { .. } => "match",
            Request::First { .. } => "first",
            Request::Next { .. } => "next",
            Request::All { .. } => "all",
            Request::Master { .. } => "master",
            Request::Order { .. } => "order",
            Request::Maplist { .. } => "maplist",
        }
    }
}

/// Why a call cannot be answered as asked.
#[derive(Debug, PartialEq)]
pub enum Refusal {
    /// The XDR does not decode (a string past its `yp.x` bound included): GARBAGE_ARGS.
    Garbage,
    /// It decodes, but a name is empty or unusable (control characters, a `/`, not UTF-8):
    /// the procedure's own YP_BADARGS.
    BadArgs,
    /// Not a version-2 procedure: PROC_UNAVAIL.
    NoProc,
}

fn xdr_text(r: &mut Reader, max: usize) -> std::result::Result<Vec<u8>, Refusal> {
    r.opaque(max)
        .map(<[u8]>::to_vec)
        .map_err(|_| Refusal::Garbage)
}

/// A domain or map name: printable UTF-8 with no `/` (ypserv joins them into a path, and
/// refuses the same).
fn name(b: Vec<u8>) -> std::result::Result<String, Refusal> {
    let s = String::from_utf8(b).map_err(|_| Refusal::BadArgs)?;
    if s.is_empty()
        || s.contains('/')
        || s.starts_with('.')
        || crate::utils::sanitize::has_controls(&s)
        || s.chars().any(char::is_whitespace)
    {
        return Err(Refusal::BadArgs);
    }
    Ok(s)
}

/// A key: non-empty UTF-8 text without control characters. NIS keys are text in every map
/// a client looks up; anything else is a malformed request rather than data.
fn key(b: Vec<u8>) -> std::result::Result<String, Refusal> {
    let s = String::from_utf8(b).map_err(|_| Refusal::BadArgs)?;
    if s.is_empty() || crate::utils::sanitize::has_controls(&s) {
        return Err(Refusal::BadArgs);
    }
    Ok(s)
}

/// Decode one version-2 call's arguments. Trailing bytes are tolerated, as XDR decoders do.
pub fn parse_request(procedure: u32, args: &[u8]) -> std::result::Result<Request, Refusal> {
    let mut r = Reader::new(args);
    let domain = |r: &mut Reader| xdr_text(r, YPMAXDOMAIN);
    let map = |r: &mut Reader| xdr_text(r, YPMAXMAP);
    let keydat = |r: &mut Reader| xdr_text(r, YPMAXRECORD);
    // Decode every field first (GARBAGE_ARGS), then judge the names (YP_BADARGS), so an
    // over-long key is a decode error even when the domain is also unusable.
    Ok(match procedure {
        proc_::NULL => Request::Null,
        proc_::CLEAR => Request::Clear,
        proc_::XFR => Request::Xfr,
        proc_::DOMAIN | proc_::DOMAIN_NONACK | proc_::MAPLIST => {
            let d = domain(&mut r)?;
            let d = name(d)?;
            match procedure {
                proc_::MAPLIST => Request::Maplist { domain: d },
                p => Request::Domain {
                    domain: d,
                    nonack: p == proc_::DOMAIN_NONACK,
                },
            }
        }
        proc_::MATCH | proc_::NEXT => {
            let (d, m, k) = (domain(&mut r)?, map(&mut r)?, keydat(&mut r)?);
            let (domain, map, key) = (name(d)?, name(m)?, key(k)?);
            if procedure == proc_::MATCH {
                Request::Match { domain, map, key }
            } else {
                Request::Next { domain, map, key }
            }
        }
        proc_::FIRST | proc_::ALL | proc_::MASTER | proc_::ORDER => {
            let (d, m) = (domain(&mut r)?, map(&mut r)?);
            let (domain, map) = (name(d)?, name(m)?);
            match procedure {
                proc_::FIRST => Request::First { domain, map },
                proc_::ALL => Request::All { domain, map },
                proc_::MASTER => Request::Master { domain, map },
                _ => Request::Order { domain, map },
            }
        }
        _ => return Err(Refusal::NoProc),
    })
}

// ---------------------------------------------------------------------------------------
// Results, as the server writes them.

fn w_stat(w: &mut Writer, s: Stat) {
    w.u32(s.code() as u32);
}

/// `ypresp_val {stat, val}`.
pub fn resp_val(stat: Stat, val: &str) -> Vec<u8> {
    let mut w = Writer::default();
    w_stat(&mut w, stat);
    w.opaque(val.as_bytes());
    w.0
}

/// `ypresp_key_val {stat, val, key}` — value before key, as `yp.x` has it on the wire.
pub fn resp_key_val(stat: Stat, key: &str, val: &str) -> Vec<u8> {
    let mut w = Writer::default();
    w_stat(&mut w, stat);
    w.opaque(val.as_bytes()).opaque(key.as_bytes());
    w.0
}

/// The `ypresp_all` stream: one `{more: TRUE, ypresp_key_val}` per entry with YP_TRUE, then
/// `{more: FALSE}`. A failure is a single `{more: TRUE, stat}` with an empty value and key,
/// then `{more: FALSE}` — the shape Linux ypserv 4.2 writes for YP_NOMAP and YP_NODOM.
pub fn resp_all(result: std::result::Result<&[(String, String)], Stat>) -> Vec<u8> {
    let mut w = Writer::default();
    match result {
        Ok(entries) => {
            for (k, v) in entries {
                w.u32(1);
                w_stat(&mut w, Stat::True);
                w.opaque(v.as_bytes()).opaque(k.as_bytes());
            }
        }
        Err(stat) => {
            w.u32(1);
            w_stat(&mut w, stat);
            w.opaque(b"").opaque(b"");
        }
    }
    w.u32(0);
    w.0
}

/// `ypresp_master {stat, peer}`.
pub fn resp_master(stat: Stat, peer: &str) -> Vec<u8> {
    let mut w = Writer::default();
    w_stat(&mut w, stat);
    w.string(peer);
    w.0
}

/// `ypresp_order {stat, ordernum}`.
pub fn resp_order(stat: Stat, order: u32) -> Vec<u8> {
    let mut w = Writer::default();
    w_stat(&mut w, stat);
    w.u32(order);
    w.0
}

/// `ypresp_maplist {stat, ypmaplist *maps}`: a linked list of map names.
pub fn resp_maplist(stat: Stat, maps: &[String]) -> Vec<u8> {
    let mut w = Writer::default();
    w_stat(&mut w, stat);
    for m in maps {
        w.u32(1).string(m);
    }
    w.u32(0);
    w.0
}

pub fn resp_bool(b: bool) -> Vec<u8> {
    let mut w = Writer::default();
    w.u32(u32::from(b));
    w.0
}

/// TCP record marking for a reply that may be large: fragments of at most
/// [`REPLY_FRAGMENT`] bytes, the last one flagged.
pub fn record_fragments(msg: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(msg.len() + 4 * (msg.len() / REPLY_FRAGMENT + 1));
    let mut chunks = msg.chunks(REPLY_FRAGMENT).peekable();
    if chunks.peek().is_none() {
        out.extend_from_slice(&0x8000_0000u32.to_be_bytes());
    }
    while let Some(c) = chunks.next() {
        let last = if chunks.peek().is_none() {
            0x8000_0000
        } else {
            0
        };
        out.extend_from_slice(&(last | c.len() as u32).to_be_bytes());
        out.extend_from_slice(c);
    }
    out
}

// ---------------------------------------------------------------------------------------
// Map entries: the model's structured fields, rendered into canonical lines.

/// How a map's values are laid out, from its name.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum MapKind {
    /// passwd.byname, passwd.byuid: `name:password:uid:gid:gecos:home:shell`
    Passwd,
    /// group.byname, group.bygid: `name:password:gid:member,member`
    Group,
    /// hosts.byname, hosts.byaddr: `address<TAB>name alias …`
    Hosts,
    /// netgroup: `(host,user,domain) (…) othergroup`
    Netgroup,
    /// Anything else: the model gives `key` and `value` as text.
    Generic,
}

pub fn map_kind(map: &str) -> MapKind {
    match map {
        "passwd.byname" | "passwd.byuid" => MapKind::Passwd,
        "group.byname" | "group.bygid" => MapKind::Group,
        "hosts.byname" | "hosts.byaddr" => MapKind::Hosts,
        "netgroup" => MapKind::Netgroup,
        _ => MapKind::Generic,
    }
}

/// Text the model wrote into one field of a line: no control characters (they would split
/// or forge lines) and none of the line's own separators, which would shift every field
/// after it — a `:` in a gecos makes the home directory the shell. Refused, never rewritten.
fn field(e: &Value, k: &str, separators: &[char], default: Option<&str>) -> Result<String> {
    let s = match &e[k] {
        Value::String(s) => s.clone(),
        Value::Null => default
            .map(str::to_string)
            .with_context(|| format!("{k} is required"))?,
        other => bail!("{k} must be text, not {other}"),
    };
    ensure!(
        !crate::utils::sanitize::has_controls(&s),
        "{k} has a control character"
    );
    if let Some(c) = s.chars().find(|c| separators.contains(c)) {
        bail!("{k} contains {c:?}, which separates the line's fields");
    }
    Ok(s)
}

fn number(e: &Value, k: &str) -> Result<u32> {
    let n = match &e[k] {
        Value::Number(n) => n.as_u64(),
        Value::String(s) => s.parse().ok(),
        _ => None,
    }
    .with_context(|| format!("{k} must be a non-negative number"))?;
    u32::try_from(n).with_context(|| format!("{k} is a 32-bit number"))
}

fn nonempty(s: String, k: &str) -> Result<String> {
    ensure!(!s.is_empty(), "{k} must not be empty");
    Ok(s)
}

/// One model entry as the (key, value) pairs it contributes to `map`. A hosts entry is one
/// pair per name in hosts.byname, as makedbm builds it.
pub fn entry_pairs(map: &str, e: &Value) -> Result<Vec<(String, String)>> {
    ensure!(e.is_object(), "each entry is an object");
    let pairs = if !e["value"].is_null() {
        // Raw text, for any map: the model spells the whole line.
        vec![(
            nonempty(field(e, "key", &[], None)?, "key")?,
            field(e, "value", &[], None)?,
        )]
    } else {
        match map_kind(map) {
            MapKind::Passwd => {
                let colon = &[':'];
                let name = nonempty(field(e, "name", colon, None)?, "name")?;
                let uid = number(e, "uid")?;
                let line = format!(
                    "{name}:{}:{uid}:{}:{}:{}:{}",
                    field(e, "password", colon, Some("x"))?,
                    number(e, "gid")?,
                    field(e, "gecos", colon, Some(""))?,
                    field(e, "home", colon, None)?,
                    field(e, "shell", colon, None)?,
                );
                let key = if map == "passwd.byuid" {
                    uid.to_string()
                } else {
                    name
                };
                vec![(key, line)]
            }
            MapKind::Group => {
                let colon = &[':'];
                let name = nonempty(field(e, "name", colon, None)?, "name")?;
                let gid = number(e, "gid")?;
                let members = match &e["members"] {
                    Value::Null => Vec::new(),
                    Value::Array(a) => a
                        .iter()
                        .map(|m| {
                            let m = m.as_str().context("members are user names")?;
                            ensure!(
                                !m.is_empty()
                                    && !m.contains([':', ',', ' '])
                                    && !crate::utils::sanitize::has_controls(m),
                                "member {m:?} is not a user name"
                            );
                            Ok(m.to_string())
                        })
                        .collect::<Result<_>>()?,
                    _ => bail!("members must be an array of user names"),
                };
                let line = format!(
                    "{name}:{}:{gid}:{}",
                    field(e, "password", colon, Some("x"))?,
                    members.join(",")
                );
                let key = if map == "group.bygid" {
                    gid.to_string()
                } else {
                    name
                };
                vec![(key, line)]
            }
            MapKind::Hosts => {
                let address: IpAddr = field(e, "address", &[], None)?
                    .parse()
                    .context("address must be an IPv4 or IPv6 address")?;
                let names: Vec<String> = e["names"]
                    .as_array()
                    .context("names must be an array of host names")?
                    .iter()
                    .map(|n| {
                        let n = n.as_str().context("names are text")?;
                        ensure!(
                            !n.is_empty()
                                && !n.chars().any(char::is_whitespace)
                                && !crate::utils::sanitize::has_controls(n),
                            "{n:?} is not a host name"
                        );
                        Ok(n.to_string())
                    })
                    .collect::<Result<_>>()?;
                ensure!(!names.is_empty(), "a host has at least one name");
                let line = format!("{address}\t{}", names.join(" "));
                if map == "hosts.byaddr" {
                    vec![(address.to_string(), line)]
                } else {
                    names.into_iter().map(|n| (n, line.clone())).collect()
                }
            }
            MapKind::Netgroup => {
                let name = nonempty(field(e, "name", &[' ', '(', ')', ','], None)?, "name")?;
                let members = e["members"]
                    .as_array()
                    .context("members must be an array")?
                    .iter()
                    .map(|m| {
                        if let Some(group) = m.as_str() {
                            ensure!(
                                !group.is_empty()
                                    && !group.contains([' ', '(', ')', ','])
                                    && !crate::utils::sanitize::has_controls(group),
                                "{group:?} is not a netgroup name"
                            );
                            return Ok(group.to_string());
                        }
                        let sep = &[' ', '(', ')', ','];
                        Ok(format!(
                            "({},{},{})",
                            field(m, "host", sep, Some(""))?,
                            field(m, "user", sep, Some(""))?,
                            field(m, "domain", sep, Some(""))?
                        ))
                    })
                    .collect::<Result<Vec<_>>>()?;
                vec![(name, members.join(" "))]
            }
            MapKind::Generic => {
                bail!("{map} has no structured form here: give each entry as {{key, value}} text")
            }
        }
    };
    for (k, v) in &pairs {
        ensure!(
            k.len() <= YPMAXRECORD && v.len() <= YPMAXRECORD,
            "a key or value longer than YPMAXRECORD ({YPMAXRECORD} bytes)"
        );
    }
    Ok(pairs)
}

/// Every pair of a map, in the model's order, the first entry for a key winning.
pub fn map_pairs(map: &str, entries: &[Value]) -> Result<Vec<(String, String)>> {
    ensure!(
        entries.len() <= MAX_ENTRIES,
        "at most {MAX_ENTRIES} entries in a map"
    );
    let mut out: Vec<(String, String)> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for e in entries {
        for (k, v) in entry_pairs(map, e)? {
            if seen.insert(k.clone()) {
                out.push((k, v));
            }
        }
    }
    ensure!(
        out.len() <= MAX_ENTRIES,
        "at most {MAX_ENTRIES} keys in a map"
    );
    Ok(out)
}

/// A map or domain name the model gave (MAPLIST, MASTER).
pub fn model_name(s: &str, max: usize, what: &str) -> Result<String> {
    ensure!(!s.is_empty() && s.len() <= max, "a {what} is 1-{max} bytes");
    ensure!(
        !s.contains('/')
            && !crate::utils::sanitize::has_controls(s)
            && !s.chars().any(char::is_whitespace),
        "{what} {s:?} has a space, a / or a control character"
    );
    Ok(s.to_string())
}

// ---------------------------------------------------------------------------------------
// Calls and results as the client sees them.

pub fn req_domain(domain: &str) -> Vec<u8> {
    let mut w = Writer::default();
    w.string(domain);
    w.0
}

pub fn req_nokey(domain: &str, map: &str) -> Vec<u8> {
    let mut w = Writer::default();
    w.string(domain).string(map);
    w.0
}

pub fn req_key(domain: &str, map: &str, key: &str) -> Vec<u8> {
    let mut w = Writer::default();
    w.string(domain).string(map).opaque(key.as_bytes());
    w.0
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

pub fn read_bool(body: &[u8]) -> Result<bool> {
    Reader::new(body).bool()
}

pub fn read_resp_val(body: &[u8]) -> Result<(Stat, String)> {
    let mut r = Reader::new(body);
    let stat = stat_of(r.u32()?)?;
    Ok((stat, text(r.opaque(YPMAXRECORD)?)))
}

/// `ypresp_key_val`: (stat, key, value).
pub fn read_resp_key_val(body: &[u8]) -> Result<(Stat, String, String)> {
    let mut r = Reader::new(body);
    let stat = stat_of(r.u32()?)?;
    let val = text(r.opaque(YPMAXRECORD)?);
    let key = text(r.opaque(YPMAXRECORD)?);
    Ok((stat, key, val))
}

/// The `ypresp_all` stream: every YP_TRUE entry, and the status it ended with — YP_NOMORE
/// for `{more: FALSE}` or a YP_NOMORE entry (both mean "complete"), otherwise the error.
/// Iterative, and capped at [`MAX_ENTRIES`].
pub fn read_resp_all(body: &[u8]) -> Result<(Vec<(String, String)>, Stat)> {
    let mut r = Reader::new(body);
    let mut out = Vec::new();
    loop {
        if !r.bool()? {
            return Ok((out, Stat::NoMore));
        }
        let stat = stat_of(r.u32()?)?;
        let val = text(r.opaque(YPMAXRECORD)?);
        let key = text(r.opaque(YPMAXRECORD)?);
        if stat != Stat::True {
            return Ok((out, stat));
        }
        ensure!(
            out.len() < MAX_ENTRIES,
            "more than {MAX_ENTRIES} entries in one ALL"
        );
        out.push((key, val));
    }
}

pub fn read_resp_master(body: &[u8]) -> Result<(Stat, String)> {
    let mut r = Reader::new(body);
    let stat = stat_of(r.u32()?)?;
    Ok((stat, text(r.opaque(YPMAXPEER)?)))
}

pub fn read_resp_order(body: &[u8]) -> Result<(Stat, u32)> {
    let mut r = Reader::new(body);
    let stat = stat_of(r.u32()?)?;
    Ok((stat, r.u32()?))
}

/// `ypresp_maplist`: iterative over the linked list, capped at [`MAX_MAPS`].
pub fn read_resp_maplist(body: &[u8]) -> Result<(Stat, Vec<String>)> {
    let mut r = Reader::new(body);
    let stat = stat_of(r.u32()?)?;
    let mut maps = Vec::new();
    while r.bool()? {
        ensure!(maps.len() < MAX_MAPS, "more than {MAX_MAPS} maps");
        maps.push(text(r.opaque(YPMAXMAP)?));
    }
    Ok((stat, maps))
}

/// A value line as a handler reads it: the line itself (control characters replaced by
/// spaces), and for the four structured map kinds its fields.
pub fn entry_json(map: &str, key: &str, value: &str) -> Value {
    let value = crate::utils::sanitize::line_field(value);
    let key = crate::utils::sanitize::line_field(key);
    let fields = match map_kind(map) {
        MapKind::Passwd => {
            let f: Vec<&str> = value.split(':').collect();
            (f.len() == 7).then(|| {
                json!({"name": f[0], "password": f[1], "uid": f[2].parse::<u64>().ok(),
                       "gid": f[3].parse::<u64>().ok(), "gecos": f[4], "home": f[5], "shell": f[6]})
            })
        }
        MapKind::Group => {
            let f: Vec<&str> = value.split(':').collect();
            (f.len() == 4).then(|| {
                let members: Vec<&str> = f[3].split(',').filter(|m| !m.is_empty()).collect();
                json!({"name": f[0], "password": f[1], "gid": f[2].parse::<u64>().ok(), "members": members})
            })
        }
        MapKind::Hosts => {
            let mut words = value.split_whitespace();
            words
                .next()
                .map(|address| json!({"address": address, "names": words.collect::<Vec<_>>()}))
        }
        MapKind::Netgroup => Some(json!({"members": value.split_whitespace().collect::<Vec<_>>()})),
        MapKind::Generic => None,
    };
    let mut v = json!({"key": key, "value": value});
    if let Some(f) = fields {
        v["fields"] = f;
    }
    v
}
