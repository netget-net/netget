//! DRDA in the requesting role: the Db2 client's codec.
//!
//! Rust owns everything below the SQL: DSS framing (request chains, correlators, continuation
//! segments), DDM objects and their extended lengths, the EBCDIC (CCSID 37) DDM character
//! strings, the package name every SQL command names, and the FD:OCA structures replies carry
//! (SQLCA, SQLDA, the query answer set descriptor and its rows). The model chooses statements
//! and reads decoded results; it never sees or writes a byte of this.
//!
//! Every length a server declares is checked against what it sent and against a bound of
//! ours before anything is allocated for it: a DSS and its continuations ([`MAX_DSS_BYTES`]),
//! a whole reply chain ([`MAX_REPLY_BYTES`], [`MAX_REPLY_DSS`]), objects per DSS
//! ([`MAX_OBJECTS_PER_DSS`]), columns ([`MAX_COLUMNS`]), rows ([`MAX_ROWS_LIMIT`]) and the
//! bytes of one answer set ([`MAX_RESULT_BYTES`]). None of the decoders recurses.
//!
//! The layouts follow DRDA (The Open Group, Volume 1) at SQLAM level 7, cross-checked against
//! Apache Derby's network server and client (`org.apache.derby.impl.drda`,
//! `org.apache.derby.client.net`), which is also the server the tests drive.

use anyhow::{anyhow, bail, ensure, Result};
use serde_json::{json, Map, Value};

use crate::server::db2::drda::{ascii_byte_to_ebcdic, ebcdic_byte_to_ascii};

/// DDM code points this client sends or reads.
pub mod cp {
    // Commands
    pub const EXCSAT: u16 = 0x1041;
    pub const ACCSEC: u16 = 0x106D;
    pub const SECCHK: u16 = 0x106E;
    pub const ACCRDB: u16 = 0x2001;
    pub const CLSQRY: u16 = 0x2005;
    pub const CNTQRY: u16 = 0x2006;
    pub const EXCSQLIMM: u16 = 0x200A;
    pub const OPNQRY: u16 = 0x200C;
    pub const PRPSQLSTT: u16 = 0x200D;
    pub const RDBCMM: u16 = 0x200E;
    pub const RDBRLLBCK: u16 = 0x200F;
    // Command data and reply data objects
    pub const SQLSTT: u16 = 0x2414;
    pub const SQLCARD: u16 = 0x2408;
    pub const SQLDARD: u16 = 0x2411;
    pub const QRYDSC: u16 = 0x241A;
    pub const QRYDTA: u16 = 0x241B;
    pub const EXTDTA: u16 = 0x146C;
    pub const EXCSATRD: u16 = 0x1443;
    pub const ACCSECRD: u16 = 0x14AC;
    pub const TYPDEFNAM: u16 = 0x002F;
    pub const TYPDEFOVR: u16 = 0x0035;
    /// Derby's piggy-backed session data: isolation level and current schema.
    pub const PBSD: u16 = 0xC000;
    // Reply messages
    pub const SECCHKRM: u16 = 0x1219;
    pub const ACCRDBRM: u16 = 0x2201;
    pub const MGRLVLRM: u16 = 0x1210;
    pub const AGNPRMRM: u16 = 0x1232;
    pub const PRCCNVRM: u16 = 0x1245;
    pub const SYNTAXRM: u16 = 0x124C;
    pub const CMDNSPRM: u16 = 0x1250;
    pub const PRMNSPRM: u16 = 0x1251;
    pub const VALNSPRM: u16 = 0x1252;
    pub const OBJNSPRM: u16 = 0x1253;
    pub const CMDCHKRM: u16 = 0x1254;
    pub const QRYNOPRM: u16 = 0x2202;
    pub const RDBNACRM: u16 = 0x2204;
    pub const OPNQRYRM: u16 = 0x2205;
    pub const ENDQRYRM: u16 = 0x220B;
    pub const ENDUOWRM: u16 = 0x220C;
    pub const ABNUOWRM: u16 = 0x220D;
    pub const DTAMCHRM: u16 = 0x220E;
    pub const QRYPOPRM: u16 = 0x220F;
    pub const RDBNFNRM: u16 = 0x2211;
    pub const OPNQFLRM: u16 = 0x2212;
    pub const SQLERRRM: u16 = 0x2213;
    pub const RDBUPDRM: u16 = 0x2218;
    pub const RSLSETRM: u16 = 0x2219;
    pub const RDBAFLRM: u16 = 0x221A;
    pub const CMMRQSRM: u16 = 0x2225;
    pub const RDBATHRM: u16 = 0x22CB;
    // Parameters
    pub const EXTNAM: u16 = 0x115E;
    pub const SRVCLSNM: u16 = 0x1147;
    pub const SRVNAM: u16 = 0x116D;
    pub const SRVRLSLV: u16 = 0x115A;
    pub const MGRLVLLS: u16 = 0x1404;
    pub const SECMEC: u16 = 0x11A2;
    pub const SECCHKCD: u16 = 0x11A4;
    pub const SVRCOD: u16 = 0x1149;
    pub const SYNERRCD: u16 = 0x114A;
    pub const CODPNT: u16 = 0x000C;
    pub const RDBNAM: u16 = 0x2110;
    pub const USRID: u16 = 0x11A0;
    pub const PASSWORD: u16 = 0x11A1;
    pub const PRDID: u16 = 0x112E;
    pub const RDBACCCL: u16 = 0x210F;
    pub const CRRTKN: u16 = 0x2135;
    pub const CCSIDSBC: u16 = 0x119C;
    pub const CCSIDDBC: u16 = 0x119D;
    pub const CCSIDMBC: u16 = 0x119E;
    pub const PKGNAMCSN: u16 = 0x2113;
    pub const RDBCMTOK: u16 = 0x2105;
    pub const RTNSQLDA: u16 = 0x2116;
    pub const TYPSQLDA: u16 = 0x2146;
    pub const QRYBLKSZ: u16 = 0x2114;
    pub const QRYCLSIMP: u16 = 0x215D;
    pub const QRYINSID: u16 = 0x215B;
    pub const UOWDSP: u16 = 0x2115;
    // Managers named in MGRLVLLS
    pub const AGENT: u16 = 0x1403;
    pub const SECMGR: u16 = 0x1440;
    pub const SQLAM: u16 = 0x2407;
    pub const RDB: u16 = 0x240F;
}

/// DSS types (low nibble of the format byte).
pub const DSS_RQSDSS: u8 = 0x01;
pub const DSS_RPYDSS: u8 = 0x02;
pub const DSS_OBJDSS: u8 = 0x03;
/// Format flags: another DSS follows in this chain / it carries the same correlator.
const DSS_CHAINED: u8 = 0x40;
const DSS_SAME_CORRELATOR: u8 = 0x10;
/// The largest DSS segment the 15-bit length can describe.
const MAX_SEGMENT: usize = 0x7FFF;

/// SQLAM level whose FD:OCA layouts this codec reads. A server below it is refused.
pub const SQLAM_LEVEL: u16 = 7;
/// USRIDPWD: user id and password, sent in the clear.
pub const SECMEC_USRIDPWD: u16 = 3;
/// USRIDONL: user id only, for a connection with no password.
pub const SECMEC_USRIDONL: u16 = 4;
/// The data representation this client declares for what it sends: big-endian integers,
/// and through TYPDEFOVR, UTF-8 single-byte and mixed characters.
pub const OUR_TYPDEFNAM: &str = "QTDSQLASC";
pub const CCSID_UTF8: u16 = 1208;
pub const CCSID_UTF16: u16 = 1200;
/// The dynamic-SQL package every statement names: collection NULLID, package SYSLH200 (large,
/// with hold, isolation 2 = cursor stability), consistency token SYSLVL01, section 1. These are
/// the names IBM's JDBC driver binds; Derby reads isolation and holdability out of them.
pub const PKG_COLLECTION: &str = "NULLID";
pub const PKG_ID: &str = "SYSLH200";
pub const PKG_TOKEN: &[u8; 8] = b"SYSLVL01";
pub const PKG_SECTION: u16 = 1;

/// One reassembled DSS (all its continuation segments joined) may be at most this large.
pub const MAX_DSS_BYTES: usize = 8 * 1024 * 1024;
/// One reply chain — every DSS answering one command — may be at most this large.
pub const MAX_REPLY_BYTES: usize = 16 * 1024 * 1024;
/// One reply chain may hold at most this many DSSes.
pub const MAX_REPLY_DSS: usize = 4096;
/// One DSS may hold at most this many DDM objects.
pub const MAX_OBJECTS_PER_DSS: usize = 256;
/// A described result may have at most this many columns (Db2's own limit is 1012).
pub const MAX_COLUMNS: usize = 1024;
/// The most rows one `execute_query` may deliver, whatever `max_rows` asks for.
pub const MAX_ROWS_LIMIT: usize = 1000;
/// Rows delivered when `max_rows` is not given.
pub const DEFAULT_MAX_ROWS: usize = 100;
/// The query block size asked for in OPNQRY and CNTQRY.
pub const QUERY_BLOCK_SIZE: u32 = 32767;
/// The answer-set bytes (QRYDTA) one query may accumulate before it is refused.
pub const MAX_RESULT_BYTES: usize = 8 * 1024 * 1024;
/// CNTQRY round trips one query may take.
pub const MAX_CONTINUES: usize = 512;
/// The longest statement sent (Db2's own statement limit is 2 MiB).
pub const MAX_SQL_BYTES: usize = 2 * 1024 * 1024;
/// User id and password are DDM strings of at most 255 bytes.
pub const MAX_CREDENTIAL_BYTES: usize = 255;
/// A relational database name, with any connection attributes, is at most 255 bytes here.
pub const MAX_RDBNAM_BYTES: usize = 255;
/// RDBNAM, RDB collection and package id are padded with blanks to 18 bytes.
const NAME_PAD: usize = 18;
/// Character fields in an answer row: the longest fixed field this client will copy.
const MAX_FIXED_FIELD: usize = 32767;
/// Packed decimal: DRDA allows at most 31 digits.
const MAX_DECIMAL_PRECISION: usize = 31;

// ============================================================================
// DDM character strings (CCSID 37)
// ============================================================================

/// Encode a DDM character string in CCSID 37, refusing any character it cannot carry rather
/// than substituting one: a user id or password that arrived altered would be a different
/// credential.
pub fn ebcdic(s: &str, what: &str) -> Result<Vec<u8>> {
    s.chars()
        .map(|c| {
            let b = u8::try_from(c as u32)
                .ok()
                .filter(|b| (0x20..0x7F).contains(b));
            match b {
                Some(b) => Ok(ascii_byte_to_ebcdic(b)),
                None => bail!(
                    "{what} holds {c:?}, which DDM's EBCDIC strings (CCSID 37) cannot carry; \
                     only printable ASCII is sent"
                ),
            }
        })
        .collect()
}

/// Decode a DDM character string from CCSID 37, trailing blanks dropped.
pub fn from_ebcdic(bytes: &[u8]) -> String {
    let s: String = bytes
        .iter()
        .map(|&b| ebcdic_byte_to_ascii(b) as char)
        .collect();
    s.trim_end().to_string()
}

fn padded(mut v: Vec<u8>, len: usize) -> Vec<u8> {
    while v.len() < len {
        v.push(0x40); // EBCDIC blank
    }
    v
}

// ============================================================================
// Encoding requests
// ============================================================================

/// `length | codepoint | data`, with an extended length when `data` does not fit 15 bits.
pub fn object(codepoint: u16, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + 8);
    if data.len() + 4 <= MAX_SEGMENT {
        out.extend_from_slice(&((data.len() + 4) as u16).to_be_bytes());
        out.extend_from_slice(&codepoint.to_be_bytes());
    } else {
        // 0x8008: the high bit says "extended", and 8 - 4 = four bytes of length follow the
        // code point, counting the data only.
        out.extend_from_slice(&0x8008u16.to_be_bytes());
        out.extend_from_slice(&codepoint.to_be_bytes());
        out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    }
    out.extend_from_slice(data);
    out
}

/// Several parameters inside one object.
fn collection(codepoint: u16, params: &[Vec<u8>]) -> Vec<u8> {
    object(codepoint, &params.concat())
}

/// Wrap `payload` in a DSS, splitting it into continuation segments when it is longer than one
/// segment can say.
pub fn dss(
    dss_type: u8,
    correlator: u16,
    chained: bool,
    same_correlator: bool,
    payload: &[u8],
) -> Vec<u8> {
    let mut format = dss_type & 0x0F;
    if chained {
        format |= DSS_CHAINED;
        if same_correlator {
            format |= DSS_SAME_CORRELATOR;
        }
    }
    let mut out = Vec::with_capacity(payload.len() + 16);
    let first = payload.len().min(MAX_SEGMENT - 6);
    let continued = first < payload.len();
    let len = if continued {
        0xFFFF
    } else {
        (first + 6) as u16
    };
    out.extend_from_slice(&len.to_be_bytes());
    out.push(0xD0);
    out.push(format);
    out.extend_from_slice(&correlator.to_be_bytes());
    out.extend_from_slice(&payload[..first]);
    let mut rest = &payload[first..];
    while !rest.is_empty() {
        let take = rest.len().min(MAX_SEGMENT - 2);
        let more = take < rest.len();
        let header = if more { 0xFFFF } else { (take + 2) as u16 };
        out.extend_from_slice(&header.to_be_bytes());
        out.extend_from_slice(&rest[..take]);
        rest = &rest[take..];
    }
    out
}

/// One command: its DSSes, all under one correlator, chained to each other.
pub fn command(correlator: u16, parts: &[(u8, Vec<u8>)]) -> Vec<u8> {
    let mut out = Vec::new();
    for (i, (dss_type, payload)) in parts.iter().enumerate() {
        let last = i + 1 == parts.len();
        out.extend(dss(*dss_type, correlator, !last, !last, payload));
    }
    out
}

/// The package, consistency token and section every SQL command names. When the database name
/// is longer than 18 bytes the extended form (each name preceded by its length) is used.
#[derive(Clone, Debug)]
pub struct Package {
    rdbnam: Vec<u8>,
}

impl Package {
    pub fn new(rdbnam: &str) -> Result<Self> {
        Ok(Self {
            rdbnam: rdb_name(rdbnam)?,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let collection = padded(
            ebcdic(PKG_COLLECTION, "collection").unwrap_or_default(),
            NAME_PAD,
        );
        let package = padded(ebcdic(PKG_ID, "package").unwrap_or_default(), NAME_PAD);
        let mut data = Vec::with_capacity(80);
        if self.rdbnam.len() == NAME_PAD {
            data.extend_from_slice(&self.rdbnam);
            data.extend_from_slice(&collection);
            data.extend_from_slice(&package);
        } else {
            for part in [&self.rdbnam, &collection, &package] {
                data.extend_from_slice(&(part.len() as u16).to_be_bytes());
                data.extend_from_slice(part);
            }
        }
        data.extend_from_slice(&ebcdic_bytes(PKG_TOKEN));
        data.extend_from_slice(&PKG_SECTION.to_be_bytes());
        object(cp::PKGNAMCSN, &data)
    }
}

fn ebcdic_bytes(b: &[u8]) -> Vec<u8> {
    b.iter().map(|&c| ascii_byte_to_ebcdic(c)).collect()
}

/// RDBNAM as DDM wants it: CCSID 37, at least 18 bytes (blank-padded), at most
/// [`MAX_RDBNAM_BYTES`].
pub fn rdb_name(name: &str) -> Result<Vec<u8>> {
    ensure!(!name.trim().is_empty(), "the database name is empty");
    ensure!(
        name.len() <= MAX_RDBNAM_BYTES,
        "the database name is {} bytes; at most {MAX_RDBNAM_BYTES} are sent",
        name.len()
    );
    Ok(padded(ebcdic(name, "the database name")?, NAME_PAD))
}

fn credential(value: &str, what: &str) -> Result<Vec<u8>> {
    ensure!(
        value.len() <= MAX_CREDENTIAL_BYTES,
        "{what} is {} bytes; DDM carries at most {MAX_CREDENTIAL_BYTES}",
        value.len()
    );
    ebcdic(value, what)
}

/// EXCSAT: who we are and the manager levels we speak.
pub fn excsat(product_id: &str) -> Result<Vec<u8>> {
    let mut mgr = Vec::new();
    for (m, level) in [
        (cp::AGENT, 7u16),
        (cp::SQLAM, SQLAM_LEVEL),
        (cp::RDB, 7),
        (cp::SECMGR, 7),
    ] {
        mgr.extend_from_slice(&m.to_be_bytes());
        mgr.extend_from_slice(&level.to_be_bytes());
    }
    Ok(collection(
        cp::EXCSAT,
        &[
            object(cp::EXTNAM, &ebcdic("netget-db2-client", "EXTNAM")?),
            object(cp::SRVNAM, &ebcdic("netget", "SRVNAM")?),
            object(cp::SRVRLSLV, &ebcdic(product_id, "product_id")?),
            object(cp::MGRLVLLS, &mgr),
            object(cp::SRVCLSNM, &ebcdic("QNETGET/RUST", "SRVCLSNM")?),
        ],
    ))
}

pub fn accsec(secmec: u16, rdbnam: &str) -> Result<Vec<u8>> {
    Ok(collection(
        cp::ACCSEC,
        &[
            object(cp::SECMEC, &secmec.to_be_bytes()),
            object(cp::RDBNAM, &rdb_name(rdbnam)?),
        ],
    ))
}

pub fn secchk(secmec: u16, rdbnam: &str, user: &str, password: Option<&str>) -> Result<Vec<u8>> {
    ensure!(!user.is_empty(), "a user id is required");
    let mut params = vec![
        object(cp::SECMEC, &secmec.to_be_bytes()),
        object(cp::RDBNAM, &rdb_name(rdbnam)?),
        object(cp::USRID, &credential(user, "the user id")?),
    ];
    if let Some(p) = password {
        params.push(object(cp::PASSWORD, &credential(p, "the password")?));
    }
    Ok(collection(cp::SECCHK, &params))
}

/// ACCRDB: open the database, declaring our data representation and product.
pub fn accrdb(rdbnam: &str, product_id: &str, crrtkn: &[u8]) -> Result<Vec<u8>> {
    ensure!(
        product_id.len() == 8 && product_id.is_ascii(),
        "product_id must be 8 ASCII characters (pppvvrrm), got {product_id:?}"
    );
    let ccsid = |c: u16, v: u16| object(c, &v.to_be_bytes());
    let ovr = [
        ccsid(cp::CCSIDSBC, CCSID_UTF8),
        ccsid(cp::CCSIDDBC, CCSID_UTF16),
        ccsid(cp::CCSIDMBC, CCSID_UTF8),
    ]
    .concat();
    Ok(collection(
        cp::ACCRDB,
        &[
            object(cp::RDBNAM, &rdb_name(rdbnam)?),
            object(cp::RDBACCCL, &cp::SQLAM.to_be_bytes()),
            object(cp::PRDID, &ebcdic(product_id, "product_id")?),
            object(cp::TYPDEFNAM, &ebcdic(OUR_TYPDEFNAM, "TYPDEFNAM")?),
            object(cp::CRRTKN, crrtkn),
            object(cp::TYPDEFOVR, &ovr),
        ],
    ))
}

/// The correlation token DRDA asks a TCP/IP requester for: its IPv4 address as eight hex
/// digits whose first is shifted into G..P, a dot, its port as four hex digits, then six
/// bytes that make this connection's token unique.
pub fn correlation_token(local: std::net::SocketAddr, unique: [u8; 6]) -> Vec<u8> {
    let ip = match local.ip() {
        std::net::IpAddr::V4(v4) => u32::from(v4),
        std::net::IpAddr::V6(v6) => v6.to_ipv4_mapped().map(u32::from).unwrap_or(0x7F00_0001),
    };
    let mut text = format!("{ip:08X}");
    let first = text.as_bytes()[0];
    let shifted =
        (b'G' + u8::from_str_radix(&(first as char).to_string(), 16).unwrap_or(0)) as char;
    text.replace_range(0..1, &shifted.to_string());
    text.push('.');
    text.push_str(&format!("{:04X}", local.port()));
    let mut out = ebcdic_bytes(text.as_bytes());
    out.extend_from_slice(&unique);
    out
}

/// SQLSTT: a nullable mixed-character LOB (null indicator, 4-byte length, UTF-8 text) then a
/// null single-byte string.
pub fn sqlstt(sql: &str) -> Result<Vec<u8>> {
    ensure!(!sql.trim().is_empty(), "the statement is empty");
    ensure!(
        sql.len() <= MAX_SQL_BYTES,
        "the statement is {} bytes; at most {MAX_SQL_BYTES} are sent",
        sql.len()
    );
    let mut data = Vec::with_capacity(sql.len() + 6);
    data.push(0x00);
    data.extend_from_slice(&(sql.len() as u32).to_be_bytes());
    data.extend_from_slice(sql.as_bytes());
    data.push(0xFF);
    Ok(object(cp::SQLSTT, &data))
}

/// EXCSQLIMM + SQLSTT: run a statement that returns no rows.
pub fn excsqlimm(pkg: &Package, sql: &str) -> Result<Vec<(u8, Vec<u8>)>> {
    Ok(vec![
        (
            DSS_RQSDSS,
            collection(
                cp::EXCSQLIMM,
                &[pkg.encode(), object(cp::RDBCMTOK, &[0xF1])],
            ),
        ),
        (DSS_OBJDSS, sqlstt(sql)?),
    ])
}

/// PRPSQLSTT + SQLSTT: prepare a query and have its output described (extended SQLDA).
pub fn prpsqlstt(pkg: &Package, sql: &str) -> Result<Vec<(u8, Vec<u8>)>> {
    Ok(vec![
        (
            DSS_RQSDSS,
            collection(
                cp::PRPSQLSTT,
                &[
                    pkg.encode(),
                    object(cp::RTNSQLDA, &[0xF1]),
                    object(cp::TYPSQLDA, &[0x04]),
                ],
            ),
        ),
        (DSS_OBJDSS, sqlstt(sql)?),
    ])
}

/// OPNQRY: open the prepared query; the server closes it itself at end of data.
pub fn opnqry(pkg: &Package) -> Vec<(u8, Vec<u8>)> {
    vec![(
        DSS_RQSDSS,
        collection(
            cp::OPNQRY,
            &[
                pkg.encode(),
                object(cp::QRYBLKSZ, &QUERY_BLOCK_SIZE.to_be_bytes()),
                object(cp::QRYCLSIMP, &[0x01]),
            ],
        ),
    )]
}

pub fn cntqry(pkg: &Package, qryinsid: &[u8]) -> Vec<(u8, Vec<u8>)> {
    vec![(
        DSS_RQSDSS,
        collection(
            cp::CNTQRY,
            &[
                pkg.encode(),
                object(cp::QRYBLKSZ, &QUERY_BLOCK_SIZE.to_be_bytes()),
                object(cp::QRYINSID, qryinsid),
            ],
        ),
    )]
}

pub fn clsqry(pkg: &Package, qryinsid: &[u8]) -> Vec<(u8, Vec<u8>)> {
    vec![(
        DSS_RQSDSS,
        collection(cp::CLSQRY, &[pkg.encode(), object(cp::QRYINSID, qryinsid)]),
    )]
}

pub fn rdbcmm() -> Vec<(u8, Vec<u8>)> {
    vec![(DSS_RQSDSS, object(cp::RDBCMM, &[]))]
}

pub fn rdbrllbck() -> Vec<(u8, Vec<u8>)> {
    vec![(DSS_RQSDSS, object(cp::RDBRLLBCK, &[]))]
}

// ============================================================================
// Reading replies: DSS, objects, parameters
// ============================================================================

/// One reply DSS with its continuation segments joined.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dss {
    pub dss_type: u8,
    pub chained: bool,
    pub correlator: u16,
    pub payload: Vec<u8>,
}

/// Take one complete DSS off the front of `buf`. `Ok(None)` means more bytes are needed; an
/// error means the stream is not DRDA, or declares more than [`MAX_DSS_BYTES`].
pub fn take_dss(buf: &mut Vec<u8>) -> Result<Option<Dss>> {
    if buf.len() < 6 {
        return Ok(None);
    }
    let raw = u16::from_be_bytes([buf[0], buf[1]]);
    ensure!(
        buf[2] == 0xD0,
        "not a DSS: byte 2 is 0x{:02X}, where DRDA puts 0xD0",
        buf[2]
    );
    let format = buf[3];
    let correlator = u16::from_be_bytes([buf[4], buf[5]]);
    let mut more = raw & 0x8000 != 0;
    let first = if more { MAX_SEGMENT } else { raw as usize };
    ensure!(
        first >= 10,
        "a DSS declares {first} bytes, fewer than its own headers"
    );
    // Walk the segment headers that have arrived, refusing a chain that declares too much
    // before waiting for any of it.
    let mut ranges = vec![(6usize, first)];
    let mut pos = first;
    let mut total = first - 6;
    while more {
        if buf.len() < pos + 2 {
            return Ok(None);
        }
        let header = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        more = header & 0x8000 != 0;
        let len = if more { MAX_SEGMENT } else { header as usize };
        ensure!(len > 2, "a DSS continuation declares {len} bytes");
        total += len - 2;
        ensure!(
            total <= MAX_DSS_BYTES,
            "a DSS continues past {MAX_DSS_BYTES} bytes; refused"
        );
        ranges.push((pos + 2, pos + len));
        pos += len;
    }
    if buf.len() < pos {
        return Ok(None);
    }
    let mut payload = Vec::with_capacity(total);
    for (start, end) in ranges {
        payload.extend_from_slice(&buf[start..end]);
    }
    buf.drain(..pos);
    Ok(Some(Dss {
        dss_type: format & 0x0F,
        chained: format & DSS_CHAINED != 0,
        correlator,
        payload,
    }))
}

/// One DDM object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Object {
    pub codepoint: u16,
    pub data: Vec<u8>,
}

/// The objects in one DSS, in order. Extended lengths are honoured; a length running past the
/// DSS is an error.
pub fn objects(payload: &[u8]) -> Result<Vec<Object>> {
    let mut out = Vec::new();
    let mut pos = 0;
    while pos < payload.len() {
        ensure!(
            out.len() < MAX_OBJECTS_PER_DSS,
            "a DSS holds more than {MAX_OBJECTS_PER_DSS} objects; refused"
        );
        let (codepoint, data, used) = one_object(&payload[pos..])?;
        out.push(Object {
            codepoint,
            data: data.to_vec(),
        });
        pos += used;
    }
    Ok(out)
}

/// `(codepoint, data, bytes used)` for the object at the front of `b`.
fn one_object(b: &[u8]) -> Result<(u16, &[u8], usize)> {
    ensure!(
        b.len() >= 4,
        "a DDM object is cut short ({} bytes)",
        b.len()
    );
    let ll = u16::from_be_bytes([b[0], b[1]]);
    let codepoint = u16::from_be_bytes([b[2], b[3]]);
    if ll & 0x8000 == 0 {
        let len = ll as usize;
        ensure!(
            len >= 4 && len <= b.len(),
            "DDM object 0x{codepoint:04X} declares {len} bytes where {} remain",
            b.len()
        );
        return Ok((codepoint, &b[4..len], len));
    }
    let ext = (ll & 0x7FFF) as usize;
    ensure!(
        matches!(ext, 4 | 8 | 10 | 12),
        "DDM object 0x{codepoint:04X} has an extended length field of {ext} bytes"
    );
    let n = ext - 4;
    if n == 0 {
        // Layer-B streaming: the object runs to the end of the DSS.
        return Ok((codepoint, &b[4..], b.len()));
    }
    ensure!(
        b.len() >= 4 + n,
        "DDM object 0x{codepoint:04X} is cut short"
    );
    let mut len: u64 = 0;
    for &byte in &b[4..4 + n] {
        len = (len << 8) | byte as u64;
    }
    let end = (4 + n) as u64 + len;
    ensure!(
        end <= b.len() as u64,
        "DDM object 0x{codepoint:04X} declares {len} bytes where {} remain",
        b.len() - 4 - n
    );
    Ok((codepoint, &b[4 + n..end as usize], end as usize))
}

/// The parameters inside an object's data.
pub fn params(data: &[u8]) -> Result<Vec<(u16, &[u8])>> {
    let mut out = Vec::new();
    let mut pos = 0;
    while pos < data.len() {
        ensure!(
            out.len() < MAX_OBJECTS_PER_DSS,
            "an object holds more than {MAX_OBJECTS_PER_DSS} parameters; refused"
        );
        let (cp, value, used) = one_object(&data[pos..])?;
        out.push((cp, value));
        pos += used;
    }
    Ok(out)
}

pub fn param(data: &[u8], codepoint: u16) -> Result<Option<&[u8]>> {
    Ok(params(data)?
        .into_iter()
        .find(|(cp, _)| *cp == codepoint)
        .map(|(_, v)| v))
}

/// SVRCOD of a reply message, 0 when absent.
pub fn severity(data: &[u8]) -> Result<u16> {
    Ok(match param(data, cp::SVRCOD)? {
        Some([a, b]) => u16::from_be_bytes([*a, *b]),
        Some(other) => bail!("SVRCOD is {} bytes, not 2", other.len()),
        None => 0,
    })
}

/// The name of a reply message or reply data object, for errors and logs.
pub fn name_of(codepoint: u16) -> String {
    let n = match codepoint {
        cp::SECCHKRM => "SECCHKRM (security check)",
        cp::ACCRDBRM => "ACCRDBRM (access RDB)",
        cp::MGRLVLRM => "MGRLVLRM (manager level conflict)",
        cp::AGNPRMRM => "AGNPRMRM (permanent agent error)",
        cp::PRCCNVRM => "PRCCNVRM (conversational protocol error)",
        cp::SYNTAXRM => "SYNTAXRM (data stream syntax error)",
        cp::CMDNSPRM => "CMDNSPRM (command not supported)",
        cp::PRMNSPRM => "PRMNSPRM (parameter not supported)",
        cp::VALNSPRM => "VALNSPRM (parameter value not supported)",
        cp::OBJNSPRM => "OBJNSPRM (object not supported)",
        cp::CMDCHKRM => "CMDCHKRM (command check)",
        cp::QRYNOPRM => "QRYNOPRM (query not open)",
        cp::RDBNACRM => "RDBNACRM (RDB not accessed)",
        cp::OPNQRYRM => "OPNQRYRM (open query complete)",
        cp::ENDQRYRM => "ENDQRYRM (end of query)",
        cp::ENDUOWRM => "ENDUOWRM (end of unit of work)",
        cp::ABNUOWRM => "ABNUOWRM (abnormal end of unit of work)",
        cp::DTAMCHRM => "DTAMCHRM (data descriptor mismatch)",
        cp::QRYPOPRM => "QRYPOPRM (query previously opened)",
        cp::RDBNFNRM => "RDBNFNRM (RDB not found)",
        cp::OPNQFLRM => "OPNQFLRM (open query failure)",
        cp::SQLERRRM => "SQLERRRM (SQL error condition)",
        cp::RDBUPDRM => "RDBUPDRM (RDB updated)",
        cp::RSLSETRM => "RSLSETRM (result set)",
        cp::RDBAFLRM => "RDBAFLRM (RDB access failed)",
        cp::CMMRQSRM => "CMMRQSRM (commitment request)",
        cp::RDBATHRM => "RDBATHRM (not authorized to RDB)",
        cp::SQLCARD => "SQLCARD",
        cp::SQLDARD => "SQLDARD",
        cp::QRYDSC => "QRYDSC",
        cp::QRYDTA => "QRYDTA",
        cp::EXTDTA => "EXTDTA",
        _ => return format!("0x{codepoint:04X}"),
    };
    n.to_string()
}

/// What SECCHKCD says, in words.
pub fn secchkcd_meaning(code: u8) -> &'static str {
    match code {
        0x00 => "accepted",
        0x01 => "security mechanism not supported",
        0x0E => "password expired",
        0x0F => "password invalid",
        0x10 => "password missing",
        0x12 => "user id missing",
        0x13 => "user id invalid",
        0x14 => "user id revoked",
        0x15 => "new password invalid",
        0x0A => "local security service non-retryable error",
        0x0B => "SECTKN missing or invalid",
        _ => "refused",
    }
}

// ============================================================================
// The server's data representation
// ============================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Endian {
    Big,
    Little,
}

/// How the server represents FD:OCA data: byte order from its TYPDEFNAM, character sets from
/// its TYPDEFOVR.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Repr {
    pub typdefnam: String,
    pub endian: Endian,
    /// S/390 hexadecimal floating point: not decoded.
    pub hex_float: bool,
    pub sbc: u16,
    pub mbc: u16,
    pub dbc: u16,
}

impl Default for Repr {
    fn default() -> Self {
        Self::named(OUR_TYPDEFNAM)
    }
}

impl Repr {
    pub fn named(typdefnam: &str) -> Self {
        let endian = match typdefnam {
            "QTDSQLX86" | "QTDSQLVAX" => Endian::Little,
            _ => Endian::Big,
        };
        Self {
            typdefnam: typdefnam.to_string(),
            endian,
            hex_float: typdefnam == "QTDSQL370",
            sbc: CCSID_UTF8,
            mbc: CCSID_UTF8,
            dbc: CCSID_UTF16,
        }
    }

    /// Apply a TYPDEFNAM object (its value in DDM characters).
    pub fn set_name(&mut self, raw: &[u8]) -> Result<()> {
        let mut name = from_ebcdic(raw);
        if !name.starts_with("QTDSQL") && raw.is_ascii() {
            // A server that negotiated nothing still sometimes answers in ASCII.
            name = String::from_utf8_lossy(raw).trim_end().to_string();
        }
        ensure!(
            matches!(
                name.as_str(),
                "QTDSQL370" | "QTDSQL400" | "QTDSQLX86" | "QTDSQLASC" | "QTDSQLVAX" | "QTDSQLJVM"
            ),
            "the server names data representation {name:?}, which this client does not know"
        );
        let keep = (self.sbc, self.mbc, self.dbc);
        *self = Self::named(&name);
        (self.sbc, self.mbc, self.dbc) = keep;
        Ok(())
    }

    /// Apply a TYPDEFOVR object.
    pub fn set_overrides(&mut self, data: &[u8]) -> Result<()> {
        for (code, value) in params(data)? {
            let ccsid = match value {
                [a, b] => u16::from_be_bytes([*a, *b]),
                [0, 0, a, b] => u16::from_be_bytes([*a, *b]),
                _ => bail!("a CCSID override is {} bytes", value.len()),
            };
            match code {
                cp::CCSIDSBC => self.sbc = ccsid,
                cp::CCSIDMBC => self.mbc = ccsid,
                cp::CCSIDDBC => self.dbc = ccsid,
                _ => {}
            }
        }
        Ok(())
    }
}

/// Decode character data in `ccsid`.
pub fn decode_text(bytes: &[u8], ccsid: u16) -> Result<String> {
    Ok(match ccsid {
        0 | CCSID_UTF8 => String::from_utf8_lossy(bytes).into_owned(),
        1200 | 13488 | 17584 => {
            ensure!(bytes.len().is_multiple_of(2), "UTF-16 data of odd length");
            let units: Vec<u16> = bytes
                .chunks_exact(2)
                .map(|c| u16::from_be_bytes([c[0], c[1]]))
                .collect();
            String::from_utf16_lossy(&units)
        }
        37 | 500 | 1047 | 1140 => bytes
            .iter()
            .map(|&b| ebcdic_byte_to_ascii(b) as char)
            .collect(),
        367 | 437 | 819 | 850 | 923 | 1252 => bytes.iter().map(|&b| b as char).collect(),
        other => bail!("character data in CCSID {other}, which this client does not decode"),
    })
}

// ============================================================================
// FD:OCA reader
// ============================================================================

/// Why a read stopped.
#[derive(Debug)]
pub enum Short {
    /// The bytes ran out: for answer-set rows, more may come with the next query block.
    Incomplete,
    /// The bytes are wrong.
    Bad(anyhow::Error),
}

impl From<anyhow::Error> for Short {
    fn from(e: anyhow::Error) -> Self {
        Short::Bad(e)
    }
}

type R<T> = std::result::Result<T, Short>;

fn finish<T>(r: R<T>, what: &str) -> Result<T> {
    match r {
        Ok(v) => Ok(v),
        Err(Short::Incomplete) => Err(anyhow!("{what} is cut short")),
        Err(Short::Bad(e)) => Err(e),
    }
}

struct Reader<'a> {
    b: &'a [u8],
    pos: usize,
    repr: &'a Repr,
}

impl<'a> Reader<'a> {
    fn new(b: &'a [u8], repr: &'a Repr) -> Self {
        Self { b, pos: 0, repr }
    }
    fn take(&mut self, n: usize) -> R<&'a [u8]> {
        if self.b.len() - self.pos < n {
            return Err(Short::Incomplete);
        }
        let s = &self.b[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
    fn u8(&mut self) -> R<u8> {
        Ok(self.take(1)?[0])
    }
    fn fixed<const N: usize>(&mut self) -> R<[u8; N]> {
        let mut a: [u8; N] = self.take(N)?.try_into().map_err(|_| Short::Incomplete)?;
        if self.repr.endian == Endian::Little {
            a.reverse();
        }
        Ok(a)
    }
    fn i16(&mut self) -> R<i16> {
        Ok(i16::from_be_bytes(self.fixed()?))
    }
    fn u16(&mut self) -> R<u16> {
        Ok(u16::from_be_bytes(self.fixed()?))
    }
    fn i32(&mut self) -> R<i32> {
        Ok(i32::from_be_bytes(self.fixed()?))
    }
    fn i64(&mut self) -> R<i64> {
        Ok(i64::from_be_bytes(self.fixed()?))
    }
    /// A length-prefixed string (VCS or VCM), undecoded.
    fn vc_raw(&mut self) -> R<&'a [u8]> {
        let n = self.u16()? as usize;
        self.take(n)
    }
    /// A length-prefixed string (VCS or VCM).
    fn vc(&mut self, ccsid: u16) -> R<String> {
        let raw = self.vc_raw()?;
        Ok(decode_text(raw, ccsid)?)
    }
    /// VCM then VCS, of which at most one is non-empty.
    fn vcm_or_vcs(&mut self) -> R<String> {
        let m = self.vc(self.repr.mbc)?;
        let s = self.vc(self.repr.sbc)?;
        Ok(if m.is_empty() { s } else { m })
    }
}

// ============================================================================
// SQLCA
// ============================================================================

/// An SQL communications area: what a statement did.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Sqlca {
    pub sqlcode: i32,
    pub sqlstate: String,
    pub errproc: String,
    pub errd: [i32; 6],
    pub warnings: String,
    /// SQLERRMC split on its 0xFF / 0x14 separators.
    pub tokens: Vec<String>,
}

impl Sqlca {
    /// Rows a statement inserted, updated or deleted (SQLERRD3).
    pub fn row_count(&self) -> i32 {
        self.errd[2]
    }

    pub fn to_json(&self) -> Value {
        json!({
            "sqlcode": self.sqlcode,
            "sqlstate": self.sqlstate,
            "message_tokens": self.tokens,
        })
    }
}

fn read_sqlca(r: &mut Reader<'_>) -> R<Option<Sqlca>> {
    if r.u8()? & 0x80 != 0 {
        return Ok(None);
    }
    let sbc = r.repr.sbc;
    let sqlcode = r.i32()?;
    let sqlstate = decode_text(r.take(5)?, sbc)?;
    let errproc = decode_text(r.take(8)?, sbc)?.trim_end().to_string();
    let mut ca = Sqlca {
        sqlcode,
        sqlstate,
        errproc,
        ..Default::default()
    };
    if r.u8()? & 0x80 == 0 {
        for d in ca.errd.iter_mut() {
            *d = r.i32()?;
        }
        ca.warnings = decode_text(r.take(11)?, sbc)?.trim().to_string();
        let _rdbname = r.vc(sbc)?;
        // SQLERRMC: mixed, else single-byte. Its tokens are separated by 0xFF (Db2) or 0x14
        // (Derby), split before decoding so a separator never becomes a replacement character.
        let mixed = r.vc_raw()?;
        let single = r.vc_raw()?;
        let (msg, ccsid) = if mixed.is_empty() {
            (single, sbc)
        } else {
            (mixed, r.repr.mbc)
        };
        for token in msg.split(|b| *b == 0x14 || *b == 0xFF) {
            let t = crate::utils::sanitize::line_field(&decode_text(token, ccsid)?);
            if !t.trim().is_empty() {
                ca.tokens.push(t.trim().to_string());
            }
        }
    }
    if r.u8()? & 0x80 == 0 {
        return Err(Short::Bad(anyhow!(
            "the SQLCA carries a diagnostics group (SQLDIAGGRP), which this client does not \
             decode"
        )));
    }
    Ok(Some(ca))
}

/// SQLCARD: one SQLCA, or none when the statement succeeded without comment.
pub fn parse_sqlcard(data: &[u8], repr: &Repr) -> Result<Option<Sqlca>> {
    let mut r = Reader::new(data, repr);
    let ca = finish(read_sqlca(&mut r), "the SQLCARD")?;
    Ok(ca)
}

// ============================================================================
// SQLDARD: column descriptions
// ============================================================================

/// One described output column.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Column {
    pub name: String,
    pub sql_type: i16,
    pub nullable: bool,
    pub precision: i16,
    pub scale: i16,
    pub length: i64,
    pub ccsid: u16,
}

impl Column {
    pub fn type_name(&self) -> String {
        let base = self.sql_type & !1;
        match base {
            384 => "DATE".into(),
            388 => "TIME".into(),
            392 => "TIMESTAMP".into(),
            404 => "BLOB".into(),
            408 => "CLOB".into(),
            412 => "DBCLOB".into(),
            448 => format!("VARCHAR({})", self.length),
            452 => format!("CHAR({})", self.length),
            456 => "LONG VARCHAR".into(),
            464 => format!("VARGRAPHIC({})", self.length),
            468 => format!("GRAPHIC({})", self.length),
            480 if self.length == 4 => "REAL".into(),
            480 => "DOUBLE".into(),
            484 => format!("DECIMAL({},{})", self.precision, self.scale),
            492 => "BIGINT".into(),
            496 => "INTEGER".into(),
            500 => "SMALLINT".into(),
            908 => format!("VARBINARY({})", self.length),
            912 => format!("BINARY({})", self.length),
            996 => "DECFLOAT".into(),
            2436 => "BOOLEAN".into(),
            other => format!("SQLTYPE {other}"),
        }
    }

    pub fn to_json(&self) -> Value {
        json!({
            "name": self.name,
            "type": self.type_name(),
            "nullable": self.nullable,
        })
    }
}

/// Derby's own SQLTYPE for a Java user-defined type, whose SQLUDTGRP it writes without a null
/// indicator.
const DERBY_UDT: i16 = 2000;

/// SQLDARD: the statement's SQLCA, then its described columns.
pub fn parse_sqldard(data: &[u8], repr: &Repr) -> Result<(Option<Sqlca>, Vec<Column>)> {
    finish(read_sqldard(data, repr), "the SQLDARD")
}

fn read_sqldard(data: &[u8], repr: &Repr) -> R<(Option<Sqlca>, Vec<Column>)> {
    let mut r = Reader::new(data, repr);
    let ca = read_sqlca(&mut r)?;
    // SQLDHGRP
    if r.u8()? & 0x80 == 0 {
        for _ in 0..6 {
            r.i16()?;
        }
        r.vc(repr.sbc)?;
        r.vcm_or_vcs()?;
    }
    let n = r.i16()?;
    if n < 0 || n as usize > MAX_COLUMNS {
        return Err(Short::Bad(anyhow!(
            "the SQLDA describes {n} columns; at most {MAX_COLUMNS} are read"
        )));
    }
    let mut columns = Vec::with_capacity(n as usize);
    for i in 0..n as usize {
        let precision = r.i16()?;
        let scale = r.i16()?;
        let length = r.i64()?;
        let sql_type = r.i16()?;
        // SQLCCSID is always big-endian.
        let c = r.take(2)?;
        let ccsid = u16::from_be_bytes([c[0], c[1]]);
        let mut name = String::new();
        // SQLDOPTGRP
        if r.u8()? & 0x80 == 0 {
            r.i16()?;
            name = r.vcm_or_vcs()?;
            r.vcm_or_vcs()?; // label
            r.vcm_or_vcs()?; // comments
                             // SQLUDTGRP
            if sql_type & !1 == DERBY_UDT {
                r.vcm_or_vcs()?;
                r.vcm_or_vcs()?;
            } else if r.u8()? & 0x80 == 0 {
                return Err(Short::Bad(anyhow!(
                    "column {} carries a user-defined type group, which this client does not \
                     decode",
                    i + 1
                )));
            }
            // SQLDXGRP
            if r.u8()? & 0x80 == 0 {
                for _ in 0..4 {
                    r.i16()?;
                }
                r.vc(repr.sbc)?;
                for _ in 0..4 {
                    r.vcm_or_vcs()?;
                }
            }
        }
        columns.push(Column {
            name: crate::utils::sanitize::line_field(&name),
            sql_type,
            nullable: sql_type & 1 == 1,
            precision,
            scale,
            length,
            ccsid,
        });
    }
    Ok((ca, columns))
}

// ============================================================================
// QRYDSC: the answer-set row layout
// ============================================================================

/// One field of an answer-set row: its DRDA type (odd = nullable) and length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Field {
    pub drda_type: u8,
    pub length: u16,
    /// A CCSID an SDA override gave this field.
    pub ccsid: Option<u16>,
}

/// Parse the FD:OCA triplets of a QRYDSC (or several, concatenated) into the row layout.
pub fn parse_qrydsc(data: &[u8]) -> Result<Vec<Field>> {
    let mut fields: Vec<Field> = Vec::new();
    let mut overrides: Vec<(u8, u8, u16)> = Vec::new(); // (lid, drda type, ccsid)
    let mut mdd_protocol_type: Option<u8> = None;
    let mut saw_gda = false;
    let mut pos = 0;
    while pos < data.len() {
        ensure!(pos + 3 <= data.len(), "a QRYDSC triplet is cut short");
        let ll = data[pos] as usize;
        let kind = data[pos + 1];
        let id = data[pos + 2];
        ensure!(
            ll >= 3 && pos + ll <= data.len(),
            "a QRYDSC triplet declares {ll} bytes where {} remain",
            data.len() - pos
        );
        let body = &data[pos + 3..pos + ll];
        match kind {
            // MDD: which DRDA type the next SDA redefines.
            0x78 => {
                ensure!(ll == 7, "an MDD triplet is {ll} bytes, not 7");
                mdd_protocol_type = Some(body[3]);
            }
            // SDA: a redefinition of a type, with its CCSID.
            0x70 => {
                ensure!(ll == 12, "an SDA triplet is {ll} bytes, not 12");
                let ccsid = u32::from_be_bytes([body[1], body[2], body[3], body[4]]);
                let protocol = mdd_protocol_type.take().unwrap_or(id);
                overrides.push((id, protocol, ccsid.min(u16::MAX as u32) as u16));
            }
            // NGDA (the row group) and CPT (its continuation): (type, length) per field.
            0x76 | 0x7F => {
                ensure!(
                    kind == 0x7F || id == 0xD0,
                    "the row group triplet has id 0x{id:02X}, not 0xD0"
                );
                ensure!(
                    kind == 0x76 || saw_gda,
                    "a continuation triplet precedes its group"
                );
                saw_gda = true;
                ensure!(
                    body.len().is_multiple_of(3),
                    "a group triplet's entries are not 3 bytes each"
                );
                for e in body.chunks_exact(3) {
                    ensure!(
                        fields.len() < MAX_COLUMNS,
                        "the answer set has more than {MAX_COLUMNS} columns; refused"
                    );
                    let length = u16::from_be_bytes([e[1], e[2]]);
                    let (drda_type, ccsid) = match overrides.iter().find(|o| o.0 == e[0]) {
                        Some(&(_, protocol, ccsid)) => (protocol, Some(ccsid)),
                        None => (e[0], None),
                    };
                    fields.push(Field {
                        drda_type,
                        length,
                        ccsid,
                    });
                }
            }
            // RLO: the row is an SQLCA and the row group; the answer set is rows.
            0x71 => ensure!(
                (id == 0xE0 && ll == 9) || (id == 0xF0 && ll == 6),
                "unexpected row layout triplet (id 0x{id:02X}, {ll} bytes)"
            ),
            other => bail!("QRYDSC triplet type 0x{other:02X} is not one this client reads"),
        }
        pos += ll;
    }
    ensure!(saw_gda, "the QRYDSC describes no row group");
    Ok(fields)
}

// ============================================================================
// QRYDTA: answer-set rows
// ============================================================================

/// One row's worth of an answer set.
#[derive(Debug, Clone, PartialEq)]
pub enum RowItem {
    /// A row, with the warning SQLCA the server attached to it, if any.
    Row(Vec<Value>, Option<Sqlca>),
    /// End of data (SQLCODE +100).
    End(Sqlca),
    /// The query failed part-way.
    Failed(Sqlca),
    /// A row position that carries no data (a delete hole).
    Empty,
}

/// Decode the row at the front of `buf`. `Ok(None)`: the row continues in the next query block.
pub fn decode_row(buf: &[u8], fields: &[Field], repr: &Repr) -> Result<Option<(RowItem, usize)>> {
    let mut r = Reader::new(buf, repr);
    match read_row(&mut r, fields) {
        Ok(item) => Ok(Some((item, r.pos))),
        Err(Short::Incomplete) => Ok(None),
        Err(Short::Bad(e)) => Err(e),
    }
}

fn read_row(r: &mut Reader<'_>, fields: &[Field]) -> R<RowItem> {
    let ca = read_sqlca(r)?;
    let da = r.u8()?;
    if let Some(ca) = &ca {
        if ca.sqlcode < 0 {
            return Ok(RowItem::Failed(ca.clone()));
        }
        if ca.sqlcode == 100 {
            return Ok(RowItem::End(ca.clone()));
        }
    }
    if da & 0x80 != 0 {
        return Ok(RowItem::Empty);
    }
    let mut values = Vec::with_capacity(fields.len());
    for (i, f) in fields.iter().enumerate() {
        values.push(read_field(r, f, i + 1)?);
    }
    Ok(RowItem::Row(values, ca))
}

fn read_field(r: &mut Reader<'_>, f: &Field, column: usize) -> R<Value> {
    if f.drda_type & 1 == 1 && r.u8()? & 0x80 != 0 {
        return Ok(Value::Null);
    }
    let len = f.length as usize;
    let repr = r.repr;
    let sbc = f.ccsid.unwrap_or(repr.sbc);
    let mbc = f.ccsid.unwrap_or(repr.mbc);
    let dbc = f.ccsid.unwrap_or(repr.dbc);
    let fixed_len = |want: usize| -> R<()> {
        if len != want {
            return Err(Short::Bad(anyhow!(
                "column {column}: DRDA type 0x{:02X} described with length {len}, not {want}",
                f.drda_type
            )));
        }
        Ok(())
    };
    let base = f.drda_type & !1;
    Ok(match base {
        0x02 => {
            fixed_len(4)?;
            json!(r.i32()?)
        }
        0x04 => {
            fixed_len(2)?;
            json!(r.i16()?)
        }
        0x06 => {
            fixed_len(1)?;
            json!(r.u8()? as i8)
        }
        0x16 => {
            fixed_len(8)?;
            json!(r.i64()?)
        }
        0x0A | 0x0C if repr.hex_float => {
            return Err(Short::Bad(anyhow!(
                "column {column} is a hexadecimal (S/390) float, which this client does not \
                 decode"
            )))
        }
        0x0A => {
            fixed_len(8)?;
            float(f64::from_bits(r.i64()? as u64))
        }
        0x0C => {
            fixed_len(4)?;
            float(f32::from_bits(r.i32()? as u32) as f64)
        }
        0x0E => decimal(r, f.length, column)?,
        0x20 | 0x22 | 0x24 | 0x30 => text_fixed(r, len, sbc)?,
        0x3C => text_fixed(r, len, mbc)?,
        0x36 => text_fixed(r, len * 2, dbc)?,
        0x32 | 0x34 => text_var(r, len, sbc, 1, column)?,
        0x3E | 0x40 => text_var(r, len, mbc, 1, column)?,
        0x38 | 0x3A => text_var(r, len, dbc, 2, column)?,
        0x46 | 0x48 => {
            let n = r.u8()? as usize;
            json!(decode_text(
                r.take(n)?,
                if base == 0x46 { sbc } else { mbc }
            )?)
        }
        0x26 => {
            r.take(len)?;
            json!({ "binary_length": len })
        }
        0x28 | 0x2A | 0x1E => {
            let n = r.u16()? as usize;
            r.take(n)?;
            json!({ "binary_length": n })
        }
        0x44 => {
            let n = r.u8()? as usize;
            r.take(n)?;
            json!({ "binary_length": n })
        }
        0xBE => {
            fixed_len(1)?;
            json!(r.u8()? != 0)
        }
        other => {
            return Err(Short::Bad(anyhow!(
                "column {column} has DRDA type 0x{other:02X}{}, which this client does not \
                 decode (LOBs, locators, XML, DECFLOAT and user-defined types are not read)",
                if f.drda_type & 1 == 1 {
                    " (nullable)"
                } else {
                    ""
                }
            )))
        }
    })
}

fn float(v: f64) -> Value {
    serde_json::Number::from_f64(v)
        .map(Value::Number)
        .unwrap_or_else(|| json!(v.to_string()))
}

fn text_fixed(r: &mut Reader<'_>, len: usize, ccsid: u16) -> R<Value> {
    if len > MAX_FIXED_FIELD {
        return Err(Short::Bad(anyhow!(
            "a fixed character field of {len} bytes; at most {MAX_FIXED_FIELD} are read"
        )));
    }
    Ok(json!(decode_text(r.take(len)?, ccsid)?))
}

fn text_var(r: &mut Reader<'_>, max: usize, ccsid: u16, unit: usize, column: usize) -> R<Value> {
    let n = r.u16()? as usize;
    if n > max {
        return Err(Short::Bad(anyhow!(
            "column {column}: a value of {n} characters in a column described as at most {max}"
        )));
    }
    Ok(json!(decode_text(r.take(n * unit)?, ccsid)?))
}

/// Packed decimal: `precision/2 + 1` bytes of BCD digits, the last nibble the sign. The value
/// is delivered as a string so no digit is lost to a float.
fn decimal(r: &mut Reader<'_>, length: u16, column: usize) -> R<Value> {
    let precision = (length >> 8) as usize;
    let scale = (length & 0xFF) as usize;
    if precision == 0 || precision > MAX_DECIMAL_PRECISION || scale > precision {
        return Err(Short::Bad(anyhow!(
            "column {column}: DECIMAL({precision},{scale}) is not a packed decimal DRDA allows"
        )));
    }
    let bytes = r.take(precision / 2 + 1)?;
    let mut digits = String::with_capacity(precision + 1);
    for (i, &b) in bytes.iter().enumerate() {
        let hi = b >> 4;
        let lo = b & 0x0F;
        let last = i + 1 == bytes.len();
        for (n, d) in [(0, hi), (1, lo)] {
            if last && n == 1 {
                break;
            }
            if d > 9 {
                return Err(Short::Bad(anyhow!(
                    "column {column}: packed decimal digit 0x{d:X}"
                )));
            }
            digits.push((b'0' + d) as char);
        }
    }
    let sign = bytes.last().map(|b| b & 0x0F).unwrap_or(0x0C);
    let negative = match sign {
        0x0B | 0x0D => true,
        0x0A | 0x0C | 0x0E | 0x0F => false,
        s => {
            return Err(Short::Bad(anyhow!(
                "column {column}: packed decimal sign nibble 0x{s:X}"
            )))
        }
    };
    // An even precision has one pad digit at the front.
    let digits = &digits[digits.len() - precision..];
    let (int, frac) = digits.split_at(precision - scale);
    let int = int.trim_start_matches('0');
    let mut out = String::new();
    if negative && digits.bytes().any(|d| d != b'0') {
        out.push('-');
    }
    out.push_str(if int.is_empty() { "0" } else { int });
    if scale > 0 {
        out.push('.');
        out.push_str(frac);
    }
    Ok(json!(out))
}

/// Pair decoded values with column names into one JSON object per row. Names a statement
/// repeats get `#2`, `#3`, ...; an unnamed column is `COLn`.
pub fn row_object(columns: &[Column], values: Vec<Value>) -> Value {
    let mut obj = Map::new();
    for (i, v) in values.into_iter().enumerate() {
        let base = columns
            .get(i)
            .map(|c| c.name.clone())
            .filter(|n| !n.is_empty())
            .unwrap_or_else(|| format!("COL{}", i + 1));
        let mut key = base.clone();
        let mut n = 2;
        while obj.contains_key(&key) {
            key = format!("{base}#{n}");
            n += 1;
        }
        obj.insert(key, v);
    }
    Value::Object(obj)
}
