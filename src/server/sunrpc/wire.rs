//! ONC RPC (RFC 5531) and the portmapper/rpcbind programs (RFC 1833), shared by both roles:
//! XDR, call and reply messages, TCP record marking, and the PMAP v2 / RPCBIND v3-v4
//! argument and result bodies. Every length the peer announces is bounded before use.
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value};
use std::net::{IpAddr, SocketAddr};

pub const PORT: u16 = 111;
pub const PROGRAM: u32 = 100_000;
/// The portmapper versions spoken: PMAP 2, RPCBIND 3 and 4.
pub const LOW_VERSION: u32 = 2;
pub const HIGH_VERSION: u32 = 4;
/// One RPC message (a whole TCP record, or a UDP datagram) is at most this long. Nothing
/// a portmapper exchanges comes near it; a DUMP of 1000 mappings is about 60 KiB.
pub const MAX_RECORD: usize = 256 * 1024;
/// Fragments one TCP record may be split into.
pub const MAX_FRAGMENTS: usize = 64;
/// XDR strings (netids, universal addresses, owners) are at most this long.
pub const MAX_STRING: usize = 1024;
/// Credential and verifier bodies are at most 400 bytes (RFC 5531 §8.2).
pub const MAX_AUTH: usize = 400;
/// Mappings one answer may carry.
pub const MAX_MAPPINGS: usize = 1000;

pub const IPPROTO_TCP: u32 = 6;
pub const IPPROTO_UDP: u32 = 17;

/// Well-known program numbers, so the handler sees a name beside the number.
pub fn program_name(p: u32) -> Option<&'static str> {
    Some(match p {
        100_000 => "portmapper",
        100_003 => "nfs",
        100_005 => "mountd",
        100_011 => "rquotad",
        100_021 => "nlockmgr",
        100_024 => "status",
        100_227 => "nfs_acl",
        100_004 => "ypserv",
        100_007 => "ypbind",
        150_001 => "pcnfsd",
        _ => return None,
    })
}

pub struct Reader<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(b: &'a [u8]) -> Self {
        Self { b, pos: 0 }
    }
    pub fn u32(&mut self) -> Result<u32> {
        let v = self
            .b
            .get(self.pos..self.pos + 4)
            .context("XDR value runs past the message")?;
        self.pos += 4;
        Ok(u32::from_be_bytes([v[0], v[1], v[2], v[3]]))
    }
    pub fn opaque(&mut self, max: usize) -> Result<&'a [u8]> {
        let n = self.u32()? as usize;
        ensure!(n <= max, "XDR opaque of {n} bytes; the limit is {max}");
        let padded = n + (4 - n % 4) % 4;
        let v = self
            .b
            .get(self.pos..self.pos + n)
            .context("XDR opaque runs past the message")?;
        ensure!(self.pos + padded <= self.b.len(), "XDR padding missing");
        self.pos += padded;
        Ok(v)
    }
    pub fn string(&mut self) -> Result<String> {
        let b = self.opaque(MAX_STRING)?;
        String::from_utf8(b.to_vec()).context("XDR string is not UTF-8")
    }
    pub fn bool(&mut self) -> Result<bool> {
        match self.u32()? {
            0 => Ok(false),
            1 => Ok(true),
            v => bail!("XDR bool must be 0 or 1, not {v}"),
        }
    }
    pub fn rest(&self) -> &'a [u8] {
        &self.b[self.pos..]
    }
    pub fn done(&self) -> bool {
        self.pos == self.b.len()
    }
}

#[derive(Default)]
pub struct Writer(pub Vec<u8>);

impl Writer {
    pub fn u32(&mut self, v: u32) -> &mut Self {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }
    pub fn opaque(&mut self, b: &[u8]) -> &mut Self {
        self.u32(b.len() as u32);
        self.0.extend_from_slice(b);
        self.0
            .extend(std::iter::repeat_n(0u8, (4 - b.len() % 4) % 4));
        self
    }
    pub fn string(&mut self, s: &str) -> &mut Self {
        self.opaque(s.as_bytes())
    }
}

/// An RPC credential, as the handler is shown it.
pub fn credential_json(flavor: u32, body: &[u8]) -> Value {
    match flavor {
        0 => json!({"flavor": "none"}),
        1 => {
            // AUTH_SYS: stamp, machine name, uid, gid, gids.
            let mut r = Reader::new(body);
            let parsed = (|| -> Result<Value> {
                let stamp = r.u32()?;
                let machine = String::from_utf8_lossy(r.opaque(255)?).into_owned();
                let uid = r.u32()?;
                let gid = r.u32()?;
                let n = r.u32()? as usize;
                ensure!(n <= 16, "too many gids");
                let gids = (0..n).map(|_| r.u32()).collect::<Result<Vec<_>>>()?;
                Ok(
                    json!({"flavor": "sys", "stamp": stamp, "machine": machine, "uid": uid, "gid": gid, "gids": gids}),
                )
            })();
            parsed.unwrap_or_else(|_| json!({"flavor": "sys", "malformed": true}))
        }
        f => json!({"flavor": f}),
    }
}

pub struct Call<'a> {
    pub xid: u32,
    pub rpc_version: u32,
    pub program: u32,
    pub version: u32,
    pub procedure: u32,
    pub cred_flavor: u32,
    pub cred: &'a [u8],
    pub args: &'a [u8],
}

/// A message that is a call; `Ok(None)` for a reply (which a server ignores).
pub fn parse_call(b: &[u8]) -> Result<Option<Call<'_>>> {
    let mut r = Reader::new(b);
    let xid = r.u32()?;
    if r.u32()? != 0 {
        return Ok(None);
    }
    let rpc_version = r.u32()?;
    let program = r.u32()?;
    let version = r.u32()?;
    let procedure = r.u32()?;
    let cred_flavor = r.u32()?;
    let cred = r.opaque(MAX_AUTH)?;
    let _verf_flavor = r.u32()?;
    let _verf = r.opaque(MAX_AUTH)?;
    Ok(Some(Call {
        xid,
        rpc_version,
        program,
        version,
        procedure,
        cred_flavor,
        cred,
        args: r.rest(),
    }))
}

/// Just the xid, for answering a call too malformed to parse.
pub fn xid_of(b: &[u8]) -> Option<u32> {
    b.get(..4)
        .map(|x| u32::from_be_bytes([x[0], x[1], x[2], x[3]]))
}

/// What an accepted call came to.
pub enum Accepted {
    Success(Vec<u8>),
    ProgUnavail,
    ProgMismatch(u32, u32),
    ProcUnavail,
    GarbageArgs,
    SystemErr,
}

pub fn accepted_reply(xid: u32, a: &Accepted) -> Vec<u8> {
    let mut w = Writer::default();
    w.u32(xid).u32(1).u32(0); // REPLY, MSG_ACCEPTED
    w.u32(0).u32(0); // verifier AUTH_NONE
    match a {
        Accepted::Success(body) => {
            w.u32(0);
            w.0.extend_from_slice(body);
        }
        Accepted::ProgUnavail => {
            w.u32(1);
        }
        Accepted::ProgMismatch(lo, hi) => {
            w.u32(2).u32(*lo).u32(*hi);
        }
        Accepted::ProcUnavail => {
            w.u32(3);
        }
        Accepted::GarbageArgs => {
            w.u32(4);
        }
        Accepted::SystemErr => {
            w.u32(5);
        }
    }
    w.0
}

/// MSG_DENIED / RPC_MISMATCH: this server speaks RPC version 2 only.
pub fn rpc_mismatch_reply(xid: u32) -> Vec<u8> {
    let mut w = Writer::default();
    w.u32(xid).u32(1).u32(1).u32(0).u32(2).u32(2);
    w.0
}

pub fn call_message(xid: u32, version: u32, procedure: u32, args: &[u8]) -> Vec<u8> {
    call_message_to(xid, PROGRAM, version, procedure, args)
}

/// An AUTH_NONE call to any program; [`call_message`] is the portmapper's.
pub fn call_message_to(
    xid: u32,
    program: u32,
    version: u32,
    procedure: u32,
    args: &[u8],
) -> Vec<u8> {
    let mut w = Writer::default();
    w.u32(xid)
        .u32(0)
        .u32(2)
        .u32(program)
        .u32(version)
        .u32(procedure);
    w.u32(0).u32(0).u32(0).u32(0); // AUTH_NONE credential and verifier
    w.0.extend_from_slice(args);
    w.0
}

/// A reply as the client reads it: its xid and either the result body or why there is none.
pub fn parse_reply(b: &[u8]) -> Result<(u32, std::result::Result<Vec<u8>, String>)> {
    let mut r = Reader::new(b);
    let xid = r.u32()?;
    ensure!(r.u32()? == 1, "not a reply");
    match r.u32()? {
        0 => {
            r.u32()?;
            r.opaque(MAX_AUTH)?;
            let stat = r.u32()?;
            Ok((
                xid,
                match stat {
                    0 => Ok(r.rest().to_vec()),
                    1 => Err("PROG_UNAVAIL".into()),
                    2 => Err(format!(
                        "PROG_MISMATCH (versions {}-{})",
                        r.u32()?,
                        r.u32()?
                    )),
                    3 => Err("PROC_UNAVAIL".into()),
                    4 => Err("GARBAGE_ARGS".into()),
                    5 => Err("SYSTEM_ERR".into()),
                    s => Err(format!("accept_stat {s}")),
                },
            ))
        }
        1 => {
            let why = match r.u32()? {
                0 => format!("RPC_MISMATCH (versions {}-{})", r.u32()?, r.u32()?),
                _ => format!("AUTH_ERROR {}", r.u32()?),
            };
            Ok((xid, Err(why)))
        }
        s => bail!("reply_stat {s}"),
    }
}

/// TCP record marking: one fragment, last-fragment bit set.
pub fn record(msg: &[u8]) -> Vec<u8> {
    let mut out = (0x8000_0000u32 | msg.len() as u32).to_be_bytes().to_vec();
    out.extend_from_slice(msg);
    out
}

/// Read one record, refusing before reading past the bounds.
pub async fn read_record<R: tokio::io::AsyncRead + Unpin>(r: &mut R) -> Result<Option<Vec<u8>>> {
    read_record_bounded(r, MAX_RECORD, MAX_FRAGMENTS).await
}

/// Read one record of at most `max_record` bytes in at most `max_fragments` fragments. Each
/// fragment's announced length is checked against the bound before anything is read or
/// allocated for it. Other ONC RPC programs (NIS) read through this with bounds of their own.
pub async fn read_record_bounded<R: tokio::io::AsyncRead + Unpin>(
    r: &mut R,
    max_record: usize,
    max_fragments: usize,
) -> Result<Option<Vec<u8>>> {
    use tokio::io::AsyncReadExt;
    let mut out = Vec::new();
    for i in 0..max_fragments {
        let mut h = [0u8; 4];
        match r.read_exact(&mut h).await {
            Ok(_) => {}
            Err(e) if i == 0 && e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e.into()),
        }
        let h = u32::from_be_bytes(h);
        let len = (h & 0x7fff_ffff) as usize;
        ensure!(
            out.len() + len <= max_record,
            "record of more than {max_record} bytes announced"
        );
        let start = out.len();
        out.resize(start + len, 0);
        r.read_exact(&mut out[start..]).await?;
        if h & 0x8000_0000 != 0 {
            return Ok(Some(out));
        }
    }
    bail!("record split into more than {max_fragments} fragments")
}

// ---------------------------------------------------------------------------------------
// Mappings, the portmapper's one kind of data.

#[derive(Clone, Debug, PartialEq)]
pub struct Mapping {
    pub program: u32,
    pub version: u32,
    /// tcp, udp, tcp6 or udp6.
    pub netid: String,
    pub port: u16,
    pub owner: String,
}

pub fn netid_of(protocol: u32) -> Option<&'static str> {
    match protocol {
        IPPROTO_TCP => Some("tcp"),
        IPPROTO_UDP => Some("udp"),
        _ => None,
    }
}

pub fn protocol_of(netid: &str) -> Option<u32> {
    match netid {
        "tcp" | "tcp6" => Some(IPPROTO_TCP),
        "udp" | "udp6" => Some(IPPROTO_UDP),
        _ => None,
    }
}

/// A universal address: `h1.h2.h3.h4.p1.p2`, or an IPv6 address and `.p1.p2`.
pub fn uaddr(ip: IpAddr, port: u16) -> String {
    format!("{ip}.{}.{}", port >> 8, port & 0xff)
}

pub fn parse_uaddr(s: &str) -> Result<SocketAddr> {
    let mut parts = s.rsplitn(3, '.');
    let lo: u16 = parts.next().context("empty universal address")?.parse()?;
    let hi: u16 = parts
        .next()
        .context("universal address has no port")?
        .parse()?;
    let ip: IpAddr = parts
        .next()
        .context("universal address has no host")?
        .parse()?;
    ensure!(
        hi < 256 && lo < 256,
        "universal address port bytes out of range"
    );
    Ok(SocketAddr::new(ip, hi << 8 | lo))
}

/// A mapping as the handler writes it: `{program, version, protocol, port, owner?}` with
/// protocol one of tcp/udp/tcp6/udp6.
pub fn mapping_from_json(v: &Value) -> Result<Mapping> {
    let num = |k: &str| -> Result<u64> {
        v[k].as_u64()
            .with_context(|| format!("{k} must be a number"))
    };
    let program = num("program")?;
    let version = num("version")?;
    let port = num("port")?;
    ensure!(
        program <= u64::from(u32::MAX) && version <= u64::from(u32::MAX),
        "program and version are 32-bit"
    );
    ensure!(port <= 65535, "port must be 0-65535");
    let netid = v["protocol"].as_str().unwrap_or("tcp").to_string();
    ensure!(
        protocol_of(&netid).is_some(),
        "protocol must be tcp, udp, tcp6 or udp6"
    );
    Ok(Mapping {
        program: program as u32,
        version: version as u32,
        netid,
        port: port as u16,
        owner: v["owner"]
            .as_str()
            .unwrap_or("netget")
            .chars()
            .take(64)
            .collect(),
    })
}

pub fn mapping_json(m: &Mapping) -> Value {
    json!({"program": m.program, "program_name": program_name(m.program), "version": m.version,
           "protocol": m.netid, "port": m.port, "owner": m.owner})
}

/// PMAP v2 `pmap` (prog, vers, prot, port).
pub fn read_pmap(r: &mut Reader) -> Result<(u32, u32, u32, u32)> {
    Ok((r.u32()?, r.u32()?, r.u32()?, r.u32()?))
}

pub fn write_pmap(w: &mut Writer, m: &Mapping) {
    let prot = protocol_of(&m.netid).unwrap_or(IPPROTO_TCP);
    w.u32(m.program)
        .u32(m.version)
        .u32(prot)
        .u32(u32::from(m.port));
}

/// RPCBIND `rpcb` (prog, vers, netid, addr, owner).
pub struct Rpcb {
    pub program: u32,
    pub version: u32,
    pub netid: String,
    pub addr: String,
    pub owner: String,
}

pub fn read_rpcb(r: &mut Reader) -> Result<Rpcb> {
    Ok(Rpcb {
        program: r.u32()?,
        version: r.u32()?,
        netid: r.string()?,
        addr: r.string()?,
        owner: r.string()?,
    })
}

pub fn write_rpcb(w: &mut Writer, b: &Rpcb) {
    w.u32(b.program).u32(b.version);
    w.string(&b.netid).string(&b.addr).string(&b.owner);
}

/// The host part of a universal address for a mapping, as a client reaching `local` sees it.
pub fn host_for(netid: &str, local: IpAddr) -> IpAddr {
    match (netid.ends_with('6'), local) {
        (true, IpAddr::V4(_)) => IpAddr::from(std::net::Ipv6Addr::LOCALHOST),
        (false, IpAddr::V6(v6)) => v6
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::from([127, 0, 0, 1])),
        _ => local,
    }
}

/// PMAP v2 DUMP result: the linked list of mappings (only tcp and udp have a v2 form).
pub fn pmaplist(ms: &[Mapping]) -> Vec<u8> {
    let mut w = Writer::default();
    for m in ms.iter().filter(|m| m.netid == "tcp" || m.netid == "udp") {
        w.u32(1);
        write_pmap(&mut w, m);
    }
    w.u32(0);
    w.0
}

/// RPCBIND DUMP result.
pub fn rpcblist(ms: &[Mapping], local: IpAddr) -> Vec<u8> {
    let mut w = Writer::default();
    for m in ms {
        w.u32(1);
        write_rpcb(
            &mut w,
            &Rpcb {
                program: m.program,
                version: m.version,
                netid: m.netid.clone(),
                addr: uaddr(host_for(&m.netid, local), m.port),
                owner: m.owner.clone(),
            },
        );
    }
    w.u32(0);
    w.0
}

/// RPCBIND v4 GETADDRLIST result: one `rpcb_entry` per mapping.
pub fn entry_list(ms: &[Mapping], local: IpAddr) -> Vec<u8> {
    let mut w = Writer::default();
    for m in ms {
        let tcp = m.netid.starts_with("tcp");
        w.u32(1);
        w.string(&uaddr(host_for(&m.netid, local), m.port));
        w.string(&m.netid);
        w.u32(if tcp { 3 } else { 1 }); // NC_TPI_COTS_ORD / NC_TPI_CLTS
        w.string(if m.netid.ends_with('6') {
            "inet6"
        } else {
            "inet"
        });
        w.string(if tcp { "tcp" } else { "udp" });
    }
    w.u32(0);
    w.0
}

/// Read a PMAP v2 DUMP result.
pub fn read_pmaplist(b: &[u8]) -> Result<Vec<Mapping>> {
    let mut r = Reader::new(b);
    let mut out = Vec::new();
    while r.bool()? {
        ensure!(
            out.len() < MAX_MAPPINGS,
            "more than {MAX_MAPPINGS} mappings"
        );
        let (program, version, prot, port) = read_pmap(&mut r)?;
        out.push(Mapping {
            program,
            version,
            netid: netid_of(prot).unwrap_or("unknown").to_string(),
            port: port as u16,
            owner: String::new(),
        });
    }
    Ok(out)
}

/// Read an RPCBIND DUMP result.
pub fn read_rpcblist(b: &[u8]) -> Result<Vec<Value>> {
    let mut r = Reader::new(b);
    let mut out = Vec::new();
    while r.bool()? {
        ensure!(
            out.len() < MAX_MAPPINGS,
            "more than {MAX_MAPPINGS} mappings"
        );
        let e = read_rpcb(&mut r)?;
        let port = parse_uaddr(&e.addr).map(|a| a.port()).ok();
        out.push(json!({"program": e.program, "program_name": program_name(e.program), "version": e.version,
                        "netid": e.netid, "address": e.addr, "port": port, "owner": e.owner}));
    }
    Ok(out)
}
