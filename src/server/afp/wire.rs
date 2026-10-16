//! AFP 3.x command encoding: requests, replies, bitmaps, names, paths and dates.
//!
//! Every byte NetGet's AFP server reads or writes, and every byte its client writes or reads,
//! goes through here. Nothing in this file touches a socket, so all of the peer-controlled
//! parsing is fuzzed directly (`fuzz/fuzz_targets/afp_dsi.rs`).
//!
//! The layouts follow Apple's *Apple Filing Protocol Programming Guide* (AFP 3.4) and were
//! checked against what netatalk 4.6 sends and accepts (`etc/afpd/{status,volume,file,
//! directory,enumerate,fork,auth}.c`): where the two differ, netatalk is what every client in
//! use was written against.
//!
//! - **Bitmaps.** A reply's parameters appear in bit order, each fixed width; a name is a
//!   2-byte offset (from the start of the parameter block) to a Pascal string (long name,
//!   MacRoman, at most 31 bytes) or to `hint(4) length(2) bytes` (UTF-8 name, AFP 3), and the
//!   UTF-8 name's offset is followed by 4 reserved bytes. Names are appended after the fixed
//!   part, long name first. An unknown bit is `kFPBitmapErr`.
//! - **Dates** are seconds since 2000-01-01 00:00:00 UTC, signed 32-bit; `0x80000000` is
//!   "never".
//! - **Paths** are a type byte (1 short, 2 long, 3 UTF-8) and a name whose elements are
//!   separated by NUL bytes; each NUL after the first of a run ascends one directory.
use anyhow::{anyhow, bail, ensure, Result};
use unicode_normalization::UnicodeNormalization;

/// AFP command codes.
pub mod cmd {
    pub const BYTE_RANGE_LOCK: u8 = 1;
    pub const CLOSE_VOL: u8 = 2;
    pub const CLOSE_DIR: u8 = 3;
    pub const CLOSE_FORK: u8 = 4;
    pub const COPY_FILE: u8 = 5;
    pub const CREATE_DIR: u8 = 6;
    pub const CREATE_FILE: u8 = 7;
    pub const DELETE: u8 = 8;
    pub const ENUMERATE: u8 = 9;
    pub const FLUSH: u8 = 10;
    pub const FLUSH_FORK: u8 = 11;
    pub const GET_FORK_PARMS: u8 = 14;
    pub const GET_SRVR_INFO: u8 = 15;
    pub const GET_SRVR_PARMS: u8 = 16;
    pub const GET_VOL_PARMS: u8 = 17;
    pub const LOGIN: u8 = 18;
    pub const LOGIN_CONT: u8 = 19;
    pub const LOGOUT: u8 = 20;
    pub const MAP_ID: u8 = 21;
    pub const MAP_NAME: u8 = 22;
    pub const MOVE_AND_RENAME: u8 = 23;
    pub const OPEN_VOL: u8 = 24;
    pub const OPEN_DIR: u8 = 25;
    pub const OPEN_FORK: u8 = 26;
    pub const READ: u8 = 27;
    pub const RENAME: u8 = 28;
    pub const SET_DIR_PARMS: u8 = 29;
    pub const SET_FILE_PARMS: u8 = 30;
    pub const SET_FORK_PARMS: u8 = 31;
    pub const SET_VOL_PARMS: u8 = 32;
    pub const WRITE: u8 = 33;
    pub const GET_FILE_DIR_PARMS: u8 = 34;
    pub const SET_FILE_DIR_PARMS: u8 = 35;
    pub const CHANGE_PASSWORD: u8 = 36;
    pub const GET_USER_INFO: u8 = 37;
    pub const GET_SRVR_MSG: u8 = 38;
    pub const CREATE_ID: u8 = 39;
    pub const DELETE_ID: u8 = 40;
    pub const RESOLVE_ID: u8 = 41;
    pub const EXCHANGE_FILES: u8 = 42;
    pub const CAT_SEARCH: u8 = 43;
    pub const OPEN_DT: u8 = 48;
    pub const CLOSE_DT: u8 = 49;
    pub const GET_ICON: u8 = 51;
    pub const GET_ICON_INFO: u8 = 52;
    pub const ADD_APPL: u8 = 53;
    pub const REMOVE_APPL: u8 = 54;
    pub const GET_APPL: u8 = 55;
    pub const ADD_COMMENT: u8 = 56;
    pub const REMOVE_COMMENT: u8 = 57;
    pub const GET_COMMENT: u8 = 58;
    pub const BYTE_RANGE_LOCK_EXT: u8 = 59;
    pub const READ_EXT: u8 = 60;
    pub const WRITE_EXT: u8 = 61;
    pub const GET_AUTH_METHODS: u8 = 62;
    pub const LOGIN_EXT: u8 = 63;
    pub const GET_SESSION_TOKEN: u8 = 64;
    pub const DISCONNECT_OLD_SESSION: u8 = 65;
    pub const ENUMERATE_EXT: u8 = 66;
    pub const CAT_SEARCH_EXT: u8 = 67;
    pub const ENUMERATE_EXT2: u8 = 68;
    pub const GET_EXT_ATTR: u8 = 69;
    pub const SET_EXT_ATTR: u8 = 70;
    pub const REMOVE_EXT_ATTR: u8 = 71;
    pub const LIST_EXT_ATTRS: u8 = 72;
    pub const GET_ACL: u8 = 73;
    pub const SET_ACL: u8 = 74;
    pub const ACCESS: u8 = 75;
    pub const SPOTLIGHT_RPC: u8 = 76;
    pub const SYNC_DIR: u8 = 78;
    pub const SYNC_FORK: u8 = 79;
    pub const ZZZZZ: u8 = 122;
    pub const ADD_ICON: u8 = 192;
}

pub fn command_name(c: u8) -> &'static str {
    use cmd::*;
    match c {
        BYTE_RANGE_LOCK => "FPByteRangeLock",
        CLOSE_VOL => "FPCloseVol",
        CLOSE_DIR => "FPCloseDir",
        CLOSE_FORK => "FPCloseFork",
        COPY_FILE => "FPCopyFile",
        CREATE_DIR => "FPCreateDir",
        CREATE_FILE => "FPCreateFile",
        DELETE => "FPDelete",
        ENUMERATE => "FPEnumerate",
        FLUSH => "FPFlush",
        FLUSH_FORK => "FPFlushFork",
        GET_FORK_PARMS => "FPGetForkParms",
        GET_SRVR_INFO => "FPGetSrvrInfo",
        GET_SRVR_PARMS => "FPGetSrvrParms",
        GET_VOL_PARMS => "FPGetVolParms",
        LOGIN => "FPLogin",
        LOGIN_CONT => "FPLoginCont",
        LOGOUT => "FPLogout",
        MAP_ID => "FPMapID",
        MAP_NAME => "FPMapName",
        MOVE_AND_RENAME => "FPMoveAndRename",
        OPEN_VOL => "FPOpenVol",
        OPEN_DIR => "FPOpenDir",
        OPEN_FORK => "FPOpenFork",
        READ => "FPRead",
        RENAME => "FPRename",
        SET_DIR_PARMS => "FPSetDirParms",
        SET_FILE_PARMS => "FPSetFileParms",
        SET_FORK_PARMS => "FPSetForkParms",
        SET_VOL_PARMS => "FPSetVolParms",
        WRITE => "FPWrite",
        GET_FILE_DIR_PARMS => "FPGetFileDirParms",
        SET_FILE_DIR_PARMS => "FPSetFileDirParms",
        CHANGE_PASSWORD => "FPChangePassword",
        GET_USER_INFO => "FPGetUserInfo",
        GET_SRVR_MSG => "FPGetSrvrMsg",
        CREATE_ID => "FPCreateID",
        DELETE_ID => "FPDeleteID",
        RESOLVE_ID => "FPResolveID",
        EXCHANGE_FILES => "FPExchangeFiles",
        CAT_SEARCH => "FPCatSearch",
        OPEN_DT => "FPOpenDT",
        CLOSE_DT => "FPCloseDT",
        GET_ICON => "FPGetIcon",
        GET_ICON_INFO => "FPGetIconInfo",
        ADD_APPL => "FPAddAPPL",
        REMOVE_APPL => "FPRemoveAPPL",
        GET_APPL => "FPGetAPPL",
        ADD_COMMENT => "FPAddComment",
        REMOVE_COMMENT => "FPRemoveComment",
        GET_COMMENT => "FPGetComment",
        BYTE_RANGE_LOCK_EXT => "FPByteRangeLockExt",
        READ_EXT => "FPReadExt",
        WRITE_EXT => "FPWriteExt",
        GET_AUTH_METHODS => "FPGetAuthMethods",
        LOGIN_EXT => "FPLoginExt",
        GET_SESSION_TOKEN => "FPGetSessionToken",
        DISCONNECT_OLD_SESSION => "FPDisconnectOldSession",
        ENUMERATE_EXT => "FPEnumerateExt",
        CAT_SEARCH_EXT => "FPCatSearchExt",
        ENUMERATE_EXT2 => "FPEnumerateExt2",
        GET_EXT_ATTR => "FPGetExtAttr",
        SET_EXT_ATTR => "FPSetExtAttr",
        REMOVE_EXT_ATTR => "FPRemoveExtAttr",
        LIST_EXT_ATTRS => "FPListExtAttrs",
        GET_ACL => "FPGetACL",
        SET_ACL => "FPSetACL",
        ACCESS => "FPAccess",
        SPOTLIGHT_RPC => "FPSpotlightRPC",
        SYNC_DIR => "FPSyncDir",
        SYNC_FORK => "FPSyncFork",
        ZZZZZ => "FPZzzzz",
        ADD_ICON => "FPAddIcon",
        _ => "unknown AFP command",
    }
}

/// AFP result codes.
pub mod err {
    pub const NO_ERR: i32 = 0;
    pub const ACCESS_DENIED: i32 = -5000;
    pub const AUTH_CONTINUE: i32 = -5001;
    pub const BAD_UAM: i32 = -5002;
    pub const BAD_VERS_NUM: i32 = -5003;
    pub const BITMAP_ERR: i32 = -5004;
    pub const CANT_MOVE: i32 = -5005;
    pub const DENY_CONFLICT: i32 = -5006;
    pub const DIR_NOT_EMPTY: i32 = -5007;
    pub const DISK_FULL: i32 = -5008;
    pub const EOF_ERR: i32 = -5009;
    pub const FILE_BUSY: i32 = -5010;
    pub const FLAT_VOL: i32 = -5011;
    pub const ITEM_NOT_FOUND: i32 = -5012;
    pub const LOCK_ERR: i32 = -5013;
    pub const MISC_ERR: i32 = -5014;
    pub const NO_MORE_LOCKS: i32 = -5015;
    pub const NO_SERVER: i32 = -5016;
    pub const OBJECT_EXISTS: i32 = -5017;
    pub const OBJECT_NOT_FOUND: i32 = -5018;
    pub const PARAM_ERR: i32 = -5019;
    pub const RANGE_NOT_LOCKED: i32 = -5020;
    pub const RANGE_OVERLAP: i32 = -5021;
    pub const SESS_CLOSED: i32 = -5022;
    pub const USER_NOT_AUTH: i32 = -5023;
    pub const CALL_NOT_SUPPORTED: i32 = -5024;
    pub const OBJECT_TYPE_ERR: i32 = -5025;
    pub const TOO_MANY_FILES_OPEN: i32 = -5026;
    pub const SERVER_GOING_DOWN: i32 = -5027;
    pub const CANT_RENAME: i32 = -5028;
    pub const DIR_NOT_FOUND: i32 = -5029;
    pub const ICON_TYPE_ERROR: i32 = -5030;
    pub const VOL_LOCKED: i32 = -5031;
    pub const OBJECT_LOCKED: i32 = -5032;
    pub const ID_NOT_FOUND: i32 = -5034;
    pub const DISK_QUOTA_EXCEEDED: i32 = -5047;
}

pub fn error_name(code: i32) -> &'static str {
    use err::*;
    match code {
        NO_ERR => "kFPNoErr",
        ACCESS_DENIED => "kFPAccessDenied",
        AUTH_CONTINUE => "kFPAuthContinue",
        BAD_UAM => "kFPBadUAM",
        BAD_VERS_NUM => "kFPBadVersNum",
        BITMAP_ERR => "kFPBitmapErr",
        CANT_MOVE => "kFPCantMove",
        DENY_CONFLICT => "kFPDenyConflict",
        DIR_NOT_EMPTY => "kFPDirNotEmpty",
        DISK_FULL => "kFPDiskFull",
        EOF_ERR => "kFPEOFErr",
        FILE_BUSY => "kFPFileBusy",
        FLAT_VOL => "kFPFlatVol",
        ITEM_NOT_FOUND => "kFPItemNotFound",
        LOCK_ERR => "kFPLockErr",
        MISC_ERR => "kFPMiscErr",
        NO_MORE_LOCKS => "kFPNoMoreLocks",
        NO_SERVER => "kFPNoServer",
        OBJECT_EXISTS => "kFPObjectExists",
        OBJECT_NOT_FOUND => "kFPObjectNotFound",
        PARAM_ERR => "kFPParamErr",
        RANGE_NOT_LOCKED => "kFPRangeNotLocked",
        RANGE_OVERLAP => "kFPRangeOverlap",
        SESS_CLOSED => "kFPSessClosed",
        USER_NOT_AUTH => "kFPUserNotAuth",
        CALL_NOT_SUPPORTED => "kFPCallNotSupported",
        OBJECT_TYPE_ERR => "kFPObjectTypeErr",
        TOO_MANY_FILES_OPEN => "kFPTooManyFilesOpen",
        SERVER_GOING_DOWN => "kFPServerGoingDown",
        CANT_RENAME => "kFPCantRename",
        DIR_NOT_FOUND => "kFPDirNotFound",
        ICON_TYPE_ERROR => "kFPIconTypeError",
        VOL_LOCKED => "kFPVolLocked",
        OBJECT_LOCKED => "kFPObjectLocked",
        ID_NOT_FOUND => "kFPIDNotFound",
        DISK_QUOTA_EXCEEDED => "kFPDiskQuotaExceeded",
        _ => "unknown AFP error",
    }
}

/// UAM names as they appear on the wire.
pub mod uam {
    pub const NO_USER_AUTHENT: &str = "No User Authent";
    pub const CLEARTXT_PASSWRD: &str = "Cleartxt Passwrd";
    pub const DHX2: &str = "DHX2";
    pub const DHCAST128: &str = "DHCAST128";
}

/// The cleartext UAM's password field: eight bytes, NUL padded.
pub const PASSWORD_LEN: usize = 8;

/// AFP versions NetGet's server speaks, oldest first.
pub const AFP_VERSIONS: &[&str] = &["AFPX03", "AFP3.1", "AFP3.2", "AFP3.3", "AFP3.4"];

/// Server flags in FPGetSrvrInfo.
pub mod srvr_flag {
    pub const COPY_FILE: u16 = 0x0001;
    pub const CHANGEABLE_PASSWORDS: u16 = 0x0002;
    pub const NO_PASSWORD_SAVING: u16 = 0x0004;
    pub const SERVER_MESSAGES: u16 = 0x0008;
    pub const SERVER_SIGNATURE: u16 = 0x0010;
    pub const TCP_IP: u16 = 0x0020;
    pub const SERVER_NOTIFICATIONS: u16 = 0x0040;
    pub const RECONNECT: u16 = 0x0080;
    pub const DIRECTORY_SERVICES: u16 = 0x0100;
    pub const UTF8_SERVER_NAME: u16 = 0x0200;
    pub const UUIDS: u16 = 0x0400;
    pub const EXT_SLEEP: u16 = 0x0800;
    pub const SUPER_CLIENT: u16 = 0x8000;
}

/// Volume parameter bits.
pub mod vol_bit {
    pub const ATTRIBUTES: u16 = 1 << 0;
    pub const SIGNATURE: u16 = 1 << 1;
    pub const CREATE_DATE: u16 = 1 << 2;
    pub const MOD_DATE: u16 = 1 << 3;
    pub const BACKUP_DATE: u16 = 1 << 4;
    pub const VOLUME_ID: u16 = 1 << 5;
    pub const BYTES_FREE: u16 = 1 << 6;
    pub const BYTES_TOTAL: u16 = 1 << 7;
    pub const NAME: u16 = 1 << 8;
    pub const EXT_BYTES_FREE: u16 = 1 << 9;
    pub const EXT_BYTES_TOTAL: u16 = 1 << 10;
    pub const BLOCK_SIZE: u16 = 1 << 11;
    /// Every bit NetGet encodes.
    pub const ALL: u16 = 0x0FFF;
}

/// Volume attribute bits.
pub mod vol_attr {
    pub const READ_ONLY: u16 = 1 << 0;
    pub const HAS_VOLUME_PASSWORD: u16 = 1 << 1;
    pub const SUPPORTS_FILE_IDS: u16 = 1 << 2;
    pub const SUPPORTS_CAT_SEARCH: u16 = 1 << 3;
    pub const SUPPORTS_UNIX_PRIVS: u16 = 1 << 5;
    pub const SUPPORTS_UTF8_NAMES: u16 = 1 << 6;
    pub const NO_NETWORK_USER_IDS: u16 = 1 << 7;
}

/// A fixed-directory-ID volume (the only kind AFP 3 knows).
pub const VOLUME_SIGNATURE_FIXED: u16 = 2;

/// File parameter bits.
pub mod file_bit {
    pub const ATTRIBUTES: u16 = 1 << 0;
    pub const PARENT_DIR_ID: u16 = 1 << 1;
    pub const CREATE_DATE: u16 = 1 << 2;
    pub const MOD_DATE: u16 = 1 << 3;
    pub const BACKUP_DATE: u16 = 1 << 4;
    pub const FINDER_INFO: u16 = 1 << 5;
    pub const LONG_NAME: u16 = 1 << 6;
    pub const SHORT_NAME: u16 = 1 << 7;
    pub const NODE_ID: u16 = 1 << 8;
    pub const DATA_FORK_LEN: u16 = 1 << 9;
    pub const RSRC_FORK_LEN: u16 = 1 << 10;
    pub const EXT_DATA_FORK_LEN: u16 = 1 << 11;
    pub const LAUNCH_LIMIT: u16 = 1 << 12;
    pub const UTF8_NAME: u16 = 1 << 13;
    pub const EXT_RSRC_FORK_LEN: u16 = 1 << 14;
    pub const UNIX_PRIVS: u16 = 1 << 15;
    /// Every bit NetGet encodes (launch limit is obsolete and refused, as netatalk does).
    pub const SUPPORTED: u16 = 0xFFFF & !LAUNCH_LIMIT;
}

/// Directory parameter bits.
pub mod dir_bit {
    pub const ATTRIBUTES: u16 = 1 << 0;
    pub const PARENT_DIR_ID: u16 = 1 << 1;
    pub const CREATE_DATE: u16 = 1 << 2;
    pub const MOD_DATE: u16 = 1 << 3;
    pub const BACKUP_DATE: u16 = 1 << 4;
    pub const FINDER_INFO: u16 = 1 << 5;
    pub const LONG_NAME: u16 = 1 << 6;
    pub const SHORT_NAME: u16 = 1 << 7;
    pub const NODE_ID: u16 = 1 << 8;
    pub const OFFSPRING_COUNT: u16 = 1 << 9;
    pub const OWNER_ID: u16 = 1 << 10;
    pub const GROUP_ID: u16 = 1 << 11;
    pub const ACCESS_RIGHTS: u16 = 1 << 12;
    pub const UTF8_NAME: u16 = 1 << 13;
    pub const UNIX_PRIVS: u16 = 1 << 15;
    pub const SUPPORTED: u16 = 0xBFFF;
}

/// File and directory attribute bits.
pub mod attr {
    pub const INVISIBLE: u16 = 1 << 0;
    pub const WRITE_INHIBIT: u16 = 1 << 5;
    pub const RENAME_INHIBIT: u16 = 1 << 7;
    pub const DELETE_INHIBIT: u16 = 1 << 8;
}

/// Access-right bits, one byte each for user, world, group and owner.
pub mod access {
    pub const SEARCH: u8 = 1 << 0;
    pub const READ: u8 = 1 << 1;
    pub const WRITE: u8 = 1 << 2;
    /// In the user byte: the user owns the item.
    pub const USER_IS_OWNER: u8 = 1 << 7;
}

/// FPOpenFork access mode bits.
pub mod open_mode {
    pub const READ: u16 = 1 << 0;
    pub const WRITE: u16 = 1 << 1;
    pub const DENY_READ: u16 = 1 << 4;
    pub const DENY_WRITE: u16 = 1 << 5;
}

/// The directory ID of a volume's root, and of the root's (nonexistent) parent.
pub const ROOT_DID: u32 = 2;
pub const ROOT_PARENT_DID: u32 = 1;
/// The lowest CNID an ordinary file or directory may have.
pub const FIRST_CNID: u32 = 17;

/// The FileDir flag in enumerate entries and FPGetFileDirParms replies.
pub const IS_DIR: u8 = 0x80;

/// The text encoding hint NetGet sends with UTF-8 names (kTextEncodingUTF8 with the
/// decomposition variant, as nmap and Mac OS X send).
pub const UTF8_HINT: u32 = 0x0800_0103;

/// The longest name element NetGet reads or writes, in bytes (netatalk's
/// `UTF8FILELEN_EARLY`).
pub const MAX_NAME_BYTES: usize = 255;
/// A long (MacRoman) name: at most 31 bytes (HFS).
pub const MAX_LONG_NAME: usize = 31;
/// A volume's MacRoman name: at most 27 bytes.
pub const MAX_VOLUME_NAME: usize = 27;
/// The most elements one AFP path may have.
pub const MAX_PATH_ELEMENTS: usize = 64;
/// The most volumes one FPGetSrvrParms reply lists.
pub const MAX_VOLUMES: usize = 64;
/// The most entries one enumerate reply carries, whatever the client asked for.
pub const MAX_ENUMERATE_ENTRIES: usize = 1024;

// ---------------------------------------------------------------------------------------------
// Dates
// ---------------------------------------------------------------------------------------------

/// "Never": the date AFP uses for a backup that never happened.
pub const DATE_NEVER: i32 = i32::MIN;
/// Seconds from the Unix epoch to the AFP epoch (2000-01-01T00:00:00Z).
pub const AFP_EPOCH_UNIX: i64 = 946_684_800;

pub fn date_from_unix(secs: i64) -> i32 {
    (secs - AFP_EPOCH_UNIX).clamp(i32::MIN as i64 + 1, i32::MAX as i64) as i32
}

/// The current time as an AFP date.
pub fn now() -> i32 {
    let secs = crate::utils::clock::SystemTime::now()
        .duration_since(crate::utils::clock::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(AFP_EPOCH_UNIX);
    date_from_unix(secs)
}

pub fn date_to_unix(d: i32) -> Option<i64> {
    (d != DATE_NEVER).then_some(d as i64 + AFP_EPOCH_UNIX)
}

/// An RFC 3339 / ISO 8601 timestamp ("2026-10-01T12:00:00Z", or a bare "2026-10-01").
pub fn date_from_text(s: &str) -> Result<i32> {
    let s = s.trim();
    if let Ok(t) = chrono::DateTime::parse_from_rfc3339(s) {
        return Ok(date_from_unix(t.timestamp()));
    }
    if let Ok(t) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S") {
        return Ok(date_from_unix(t.and_utc().timestamp()));
    }
    if let Ok(t) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M") {
        return Ok(date_from_unix(t.and_utc().timestamp()));
    }
    if let Ok(d) = chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d") {
        return Ok(date_from_unix(
            d.and_hms_opt(0, 0, 0)
                .map(|t| t.and_utc().timestamp())
                .unwrap_or(0),
        ));
    }
    bail!("{s:?} is not a date (use RFC 3339, e.g. \"2026-10-01T12:00:00Z\")")
}

pub fn date_to_text(d: i32) -> Option<String> {
    let unix = date_to_unix(d)?;
    chrono::DateTime::from_timestamp(unix, 0).map(|t| t.format("%Y-%m-%dT%H:%M:%SZ").to_string())
}

// ---------------------------------------------------------------------------------------------
// Names
// ---------------------------------------------------------------------------------------------

/// `s` in MacRoman, at most `max` bytes; a character MacRoman lacks becomes `?`.
pub fn mac_roman_encode(s: &str, max: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len().min(max));
    let mut buf = [0u8; 4];
    for ch in s.nfc() {
        if out.len() >= max {
            break;
        }
        if ch.is_ascii() {
            out.push(ch as u8);
            continue;
        }
        let (bytes, _, errors) = encoding_rs::MACINTOSH.encode(ch.encode_utf8(&mut buf));
        if errors || bytes.len() != 1 {
            out.push(b'?');
        } else {
            out.push(bytes[0]);
        }
    }
    out
}

pub fn mac_roman_decode(b: &[u8]) -> String {
    let (s, _) = encoding_rs::MACINTOSH.decode_without_bom_handling(b);
    s.into_owned()
}

/// The decomposed form AFP 3 sends UTF-8 names in.
pub fn to_wire_utf8(s: &str) -> String {
    s.nfd().collect()
}

/// The composed form names are compared and shown in.
pub fn normalize(s: &str) -> String {
    s.nfc().collect()
}

/// Whether `name` is something NetGet will put in a listing: non-empty, at most
/// [`MAX_NAME_BYTES`], no NUL (the path separator), no `/` (the separator the model's paths
/// use), and not `.` or `..`.
pub fn check_name(name: &str) -> Result<()> {
    ensure!(!name.is_empty(), "a name cannot be empty");
    ensure!(
        name.len() <= MAX_NAME_BYTES,
        "{name:?} is {} bytes; AFP names are at most {MAX_NAME_BYTES}",
        name.len()
    );
    ensure!(
        !name.contains('\0') && !name.contains('/'),
        "{name:?} contains NUL or '/'"
    );
    ensure!(name != "." && name != "..", "{name:?} is not a name");
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// A bounded reader
// ---------------------------------------------------------------------------------------------

/// Why a request could not be read: the AFP code to answer with and what was wrong.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    pub code: i32,
    pub message: String,
}

impl ParseError {
    pub fn param(message: impl Into<String>) -> Self {
        Self {
            code: err::PARAM_ERR,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.message, error_name(self.code))
    }
}

impl std::error::Error for ParseError {}

type PResult<T> = std::result::Result<T, ParseError>;

/// A cursor over a command block. Offsets are from the start of the block, which is what
/// AFP's "pad to an even boundary" is relative to.
pub struct Reader<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(b: &'a [u8]) -> Self {
        Self { b, pos: 0 }
    }
    pub fn pos(&self) -> usize {
        self.pos
    }
    pub fn remaining(&self) -> usize {
        self.b.len().saturating_sub(self.pos)
    }
    pub fn rest(&self) -> &'a [u8] {
        &self.b[self.pos.min(self.b.len())..]
    }
    pub fn take(&mut self, n: usize, what: &str) -> PResult<&'a [u8]> {
        if self.remaining() < n {
            return Err(ParseError::param(format!(
                "{what}: needs {n} bytes at offset {}, {} left",
                self.pos,
                self.remaining()
            )));
        }
        let s = &self.b[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
    pub fn u8(&mut self, what: &str) -> PResult<u8> {
        Ok(self.take(1, what)?[0])
    }
    pub fn u16(&mut self, what: &str) -> PResult<u16> {
        let s = self.take(2, what)?;
        Ok(u16::from_be_bytes([s[0], s[1]]))
    }
    pub fn u32(&mut self, what: &str) -> PResult<u32> {
        let s = self.take(4, what)?;
        Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
    }
    pub fn u64(&mut self, what: &str) -> PResult<u64> {
        let s = self.take(8, what)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(s);
        Ok(u64::from_be_bytes(a))
    }
    pub fn skip(&mut self, n: usize, what: &str) -> PResult<()> {
        self.take(n, what).map(|_| ())
    }
    /// Skip one pad byte if the cursor is at an odd offset and a byte remains.
    pub fn pad_even(&mut self) {
        if self.pos % 2 == 1 && self.remaining() > 0 {
            self.pos += 1;
        }
    }
    /// A Pascal string's bytes.
    pub fn pascal(&mut self, what: &str) -> PResult<&'a [u8]> {
        let n = self.u8(what)? as usize;
        self.take(n, what)
    }
    /// A Pascal string read as ASCII/MacRoman text.
    pub fn pascal_text(&mut self, what: &str) -> PResult<String> {
        Ok(mac_roman_decode(self.pascal(what)?))
    }
    /// An AFP path: type byte and name, split into elements.
    pub fn path(&mut self) -> PResult<AfpPath> {
        let kind = self.u8("path type")?;
        let raw: Vec<u8> = match kind {
            1 | 2 => self.pascal("path name")?.to_vec(),
            3 => {
                let _hint = self.u32("UTF-8 path text encoding hint")?;
                let n = self.u16("UTF-8 path length")? as usize;
                self.take(n, "UTF-8 path name")?.to_vec()
            }
            other => {
                return Err(ParseError::param(format!(
                    "path type {other} is not 1 (short), 2 (long) or 3 (UTF-8)"
                )))
            }
        };
        AfpPath::from_wire(kind, &raw)
    }
}

// ---------------------------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------------------------

/// One element of an AFP path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathElement {
    Name(String),
    /// Ascend to the parent (an extra NUL separator).
    Parent,
}

/// An AFP path relative to some directory: what its NUL-separated name says to walk.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AfpPath {
    /// 1 short name, 2 long name (MacRoman), 3 UTF-8.
    pub kind: u8,
    pub elements: Vec<PathElement>,
}

impl AfpPath {
    /// The empty path: the directory itself.
    pub fn here() -> Self {
        Self {
            kind: 3,
            elements: Vec::new(),
        }
    }

    pub fn names<S: AsRef<str>>(names: &[S]) -> Self {
        Self {
            kind: 3,
            elements: names
                .iter()
                .map(|n| PathElement::Name(n.as_ref().to_string()))
                .collect(),
        }
    }

    /// Split a path's bytes into elements. A run of `n` NULs is a separator plus `n - 1`
    /// ascents; a leading or trailing NUL is a separator with nothing on its other side.
    pub fn from_wire(kind: u8, raw: &[u8]) -> PResult<AfpPath> {
        let mut elements = Vec::new();
        let mut i = 0usize;
        let push = |elements: &mut Vec<PathElement>, e: PathElement| -> PResult<()> {
            if elements.len() >= MAX_PATH_ELEMENTS {
                return Err(ParseError::param(format!(
                    "the path has more than {MAX_PATH_ELEMENTS} elements"
                )));
            }
            elements.push(e);
            Ok(())
        };
        while i < raw.len() {
            if raw[i] == 0 {
                i += 1;
                while i < raw.len() && raw[i] == 0 {
                    push(&mut elements, PathElement::Parent)?;
                    i += 1;
                }
                continue;
            }
            let start = i;
            while i < raw.len() && raw[i] != 0 {
                i += 1;
            }
            let bytes = &raw[start..i];
            if bytes.len() > MAX_NAME_BYTES {
                return Err(ParseError::param(format!(
                    "a path element of {} bytes exceeds {MAX_NAME_BYTES}",
                    bytes.len()
                )));
            }
            let name = if kind == 3 {
                normalize(&String::from_utf8_lossy(bytes))
            } else {
                normalize(&mac_roman_decode(bytes))
            };
            push(&mut elements, PathElement::Name(name))?;
        }
        Ok(AfpPath { kind, elements })
    }

    /// The path's bytes as a client sends them: type 3 (UTF-8, decomposed) or type 2.
    pub fn encode(&self) -> Vec<u8> {
        let mut raw = Vec::new();
        for (i, e) in self.elements.iter().enumerate() {
            match e {
                PathElement::Name(n) => {
                    if i > 0 && matches!(self.elements[i - 1], PathElement::Name(_)) {
                        raw.push(0);
                    }
                    if self.kind == 3 {
                        raw.extend_from_slice(to_wire_utf8(n).as_bytes());
                    } else {
                        raw.extend(mac_roman_encode(n, MAX_NAME_BYTES));
                    }
                }
                PathElement::Parent => {
                    if i == 0 || !matches!(self.elements[i - 1], PathElement::Parent) {
                        raw.push(0);
                    }
                    raw.push(0);
                }
            }
        }
        let mut out = vec![self.kind];
        if self.kind == 3 {
            out.extend_from_slice(&UTF8_HINT.to_be_bytes());
            out.extend_from_slice(&(raw.len().min(u16::MAX as usize) as u16).to_be_bytes());
        } else {
            out.push(raw.len().min(255) as u8);
        }
        out.extend_from_slice(&raw[..raw.len().min(u16::MAX as usize)]);
        out
    }

    /// The path for logs: elements joined with '/', ascents as "..".
    pub fn display(&self) -> String {
        self.elements
            .iter()
            .map(|e| match e {
                PathElement::Name(n) => n.as_str(),
                PathElement::Parent => "..",
            })
            .collect::<Vec<_>>()
            .join("/")
    }
}

// ---------------------------------------------------------------------------------------------
// Requests
// ---------------------------------------------------------------------------------------------

/// The flavours of enumerate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnumerateKind {
    /// FPEnumerate: 1-byte entry lengths, 2-byte counts.
    Classic,
    /// FPEnumerateExt: 2-byte entry lengths.
    Ext,
    /// FPEnumerateExt2: 2-byte entry lengths, 4-byte start index and reply size.
    Ext2,
}

impl EnumerateKind {
    pub fn command(self) -> u8 {
        match self {
            EnumerateKind::Classic => cmd::ENUMERATE,
            EnumerateKind::Ext => cmd::ENUMERATE_EXT,
            EnumerateKind::Ext2 => cmd::ENUMERATE_EXT2,
        }
    }
    /// The bytes before an entry's parameters: length (1 or 2), flag, and for Ext a pad.
    pub fn entry_header(self) -> usize {
        match self {
            EnumerateKind::Classic => 2,
            _ => 4,
        }
    }
    pub fn max_entry_len(self) -> usize {
        match self {
            EnumerateKind::Classic => u8::MAX as usize,
            _ => u16::MAX as usize,
        }
    }
}

/// A login, whichever command and UAM carried it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Login {
    /// FPLoginExt rather than FPLogin.
    pub ext: bool,
    pub version: String,
    pub uam: String,
    /// The user name the UAM carried (cleartext, and FPLoginExt always).
    pub user: Option<String>,
    /// The cleartext UAM's password, NUL padding removed.
    pub password: Option<Vec<u8>>,
}

/// One parsed AFP request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    GetSrvrInfo,
    Login(Login),
    LoginCont,
    Logout,
    GetSrvrParms,
    OpenVol {
        bitmap: u16,
        name: String,
        has_password: bool,
    },
    CloseVol {
        vol: u16,
    },
    GetVolParms {
        vol: u16,
        bitmap: u16,
    },
    GetFileDirParms {
        vol: u16,
        dir: u32,
        file_bitmap: u16,
        dir_bitmap: u16,
        path: AfpPath,
    },
    Enumerate {
        kind: EnumerateKind,
        vol: u16,
        dir: u32,
        file_bitmap: u16,
        dir_bitmap: u16,
        req_count: u16,
        start_index: u32,
        max_reply: u32,
        path: AfpPath,
    },
    OpenFork {
        resource: bool,
        vol: u16,
        dir: u32,
        bitmap: u16,
        mode: u16,
        path: AfpPath,
    },
    Read {
        ext: bool,
        fork: u16,
        offset: u64,
        count: u64,
    },
    Write {
        ext: bool,
        from_end: bool,
        fork: u16,
        offset: u64,
        count: u64,
    },
    GetForkParms {
        fork: u16,
        bitmap: u16,
    },
    SetForkParms {
        fork: u16,
        bitmap: u16,
        length: u64,
    },
    FlushFork {
        fork: u16,
    },
    Flush {
        vol: u16,
    },
    CloseFork {
        fork: u16,
    },
    CreateFile {
        hard: bool,
        vol: u16,
        dir: u32,
        path: AfpPath,
    },
    CreateDir {
        vol: u16,
        dir: u32,
        path: AfpPath,
    },
    Delete {
        vol: u16,
        dir: u32,
        path: AfpPath,
    },
    ResolveId {
        vol: u16,
        id: u32,
        bitmap: u16,
    },
    GetUserInfo {
        this_user: bool,
        user_id: u32,
        bitmap: u16,
    },
    /// Anything NetGet does not implement: answered kFPCallNotSupported.
    Unsupported {
        code: u8,
    },
}

impl Request {
    pub fn name(&self) -> &'static str {
        match self {
            Request::GetSrvrInfo => "FPGetSrvrInfo",
            Request::Login(l) if l.ext => "FPLoginExt",
            Request::Login(_) => "FPLogin",
            Request::LoginCont => "FPLoginCont",
            Request::Logout => "FPLogout",
            Request::GetSrvrParms => "FPGetSrvrParms",
            Request::OpenVol { .. } => "FPOpenVol",
            Request::CloseVol { .. } => "FPCloseVol",
            Request::GetVolParms { .. } => "FPGetVolParms",
            Request::GetFileDirParms { .. } => "FPGetFileDirParms",
            Request::Enumerate { kind, .. } => command_name(kind.command()),
            Request::OpenFork { .. } => "FPOpenFork",
            Request::Read { ext: true, .. } => "FPReadExt",
            Request::Read { .. } => "FPRead",
            Request::Write { ext: true, .. } => "FPWriteExt",
            Request::Write { .. } => "FPWrite",
            Request::GetForkParms { .. } => "FPGetForkParms",
            Request::SetForkParms { .. } => "FPSetForkParms",
            Request::FlushFork { .. } => "FPFlushFork",
            Request::Flush { .. } => "FPFlush",
            Request::CloseFork { .. } => "FPCloseFork",
            Request::CreateFile { .. } => "FPCreateFile",
            Request::CreateDir { .. } => "FPCreateDir",
            Request::Delete { .. } => "FPDelete",
            Request::ResolveId { .. } => "FPResolveID",
            Request::GetUserInfo { .. } => "FPGetUserInfo",
            Request::Unsupported { code } => command_name(*code),
        }
    }
}

fn parse_login(r: &mut Reader<'_>, ext: bool) -> PResult<Login> {
    if ext {
        r.skip(1, "FPLoginExt pad")?;
        r.skip(2, "FPLoginExt flags")?;
    }
    let version = r.pascal_text("AFP version")?;
    let uam = r.pascal_text("UAM name")?;
    let mut user = None;
    if ext {
        let kind = r.u8("user name type")?;
        user = Some(match kind {
            3 => {
                let n = r.u16("user name length")? as usize;
                normalize(&String::from_utf8_lossy(r.take(n, "user name")?))
            }
            1 | 2 => r.pascal_text("user name")?,
            other => {
                return Err(ParseError::param(format!(
                    "user name type {other} is not 1, 2 or 3"
                )))
            }
        });
        let kind = r.u8("directory service name type")?;
        match kind {
            3 => {
                let n = r.u16("directory service name length")? as usize;
                r.skip(n, "directory service name")?;
            }
            1 | 2 => {
                r.pascal("directory service name")?;
            }
            other => {
                return Err(ParseError::param(format!(
                    "directory service name type {other} is not 1, 2 or 3"
                )))
            }
        }
        r.pad_even();
    }
    let mut password = None;
    if uam == uam::CLEARTXT_PASSWRD {
        if !ext {
            user = Some(r.pascal_text("user name")?);
            r.pad_even();
        }
        let p = r.take(PASSWORD_LEN, "cleartext password")?;
        let end = p.iter().position(|b| *b == 0).unwrap_or(PASSWORD_LEN);
        password = Some(p[..end].to_vec());
    }
    Ok(Login {
        ext,
        version,
        uam,
        user,
        password,
    })
}

/// Parse an AFP command block. `Ok(Request::Unsupported)` for a command NetGet does not
/// implement; `Err` for one it does whose parameters are short or malformed.
pub fn parse_request(block: &[u8]) -> PResult<Request> {
    let mut r = Reader::new(block);
    let code = r.u8("AFP command")?;
    use cmd::*;
    Ok(match code {
        GET_SRVR_INFO => Request::GetSrvrInfo,
        LOGIN => Request::Login(parse_login(&mut r, false)?),
        LOGIN_EXT => Request::Login(parse_login(&mut r, true)?),
        LOGIN_CONT => Request::LoginCont,
        LOGOUT => Request::Logout,
        GET_SRVR_PARMS => Request::GetSrvrParms,
        OPEN_VOL => {
            r.skip(1, "pad")?;
            let bitmap = r.u16("volume bitmap")?;
            let name = r.pascal_text("volume name")?;
            r.pad_even();
            Request::OpenVol {
                bitmap,
                name: normalize(&name),
                has_password: r.remaining() >= PASSWORD_LEN,
            }
        }
        CLOSE_VOL => {
            r.skip(1, "pad")?;
            Request::CloseVol {
                vol: r.u16("volume ID")?,
            }
        }
        GET_VOL_PARMS => {
            r.skip(1, "pad")?;
            Request::GetVolParms {
                vol: r.u16("volume ID")?,
                bitmap: r.u16("volume bitmap")?,
            }
        }
        GET_FILE_DIR_PARMS => {
            r.skip(1, "pad")?;
            Request::GetFileDirParms {
                vol: r.u16("volume ID")?,
                dir: r.u32("directory ID")?,
                file_bitmap: r.u16("file bitmap")?,
                dir_bitmap: r.u16("directory bitmap")?,
                path: r.path()?,
            }
        }
        ENUMERATE | ENUMERATE_EXT | ENUMERATE_EXT2 => {
            let kind = match code {
                ENUMERATE => EnumerateKind::Classic,
                ENUMERATE_EXT => EnumerateKind::Ext,
                _ => EnumerateKind::Ext2,
            };
            r.skip(1, "pad")?;
            let vol = r.u16("volume ID")?;
            let dir = r.u32("directory ID")?;
            let file_bitmap = r.u16("file bitmap")?;
            let dir_bitmap = r.u16("directory bitmap")?;
            let req_count = r.u16("request count")?;
            let (start_index, max_reply) = if kind == EnumerateKind::Ext2 {
                (r.u32("start index")?, r.u32("max reply size")?)
            } else {
                (
                    r.u16("start index")? as u32,
                    r.u16("max reply size")? as u32,
                )
            };
            Request::Enumerate {
                kind,
                vol,
                dir,
                file_bitmap,
                dir_bitmap,
                req_count,
                start_index,
                max_reply,
                path: r.path()?,
            }
        }
        OPEN_FORK => {
            let flag = r.u8("fork flag")?;
            Request::OpenFork {
                resource: flag & 0x80 != 0,
                vol: r.u16("volume ID")?,
                dir: r.u32("directory ID")?,
                bitmap: r.u16("file bitmap")?,
                mode: r.u16("access mode")?,
                path: r.path()?,
            }
        }
        READ => {
            r.skip(1, "pad")?;
            let fork = r.u16("fork")?;
            let offset = r.u32("offset")? as i32;
            let count = r.u32("count")? as i32;
            if offset < 0 || count < 0 {
                return Err(ParseError::param("FPRead with a negative offset or count"));
            }
            Request::Read {
                ext: false,
                fork,
                offset: offset as u64,
                count: count as u64,
            }
        }
        READ_EXT => {
            r.skip(1, "pad")?;
            let fork = r.u16("fork")?;
            let offset = r.u64("offset")? as i64;
            let count = r.u64("count")? as i64;
            if offset < 0 || count < 0 {
                return Err(ParseError::param(
                    "FPReadExt with a negative offset or count",
                ));
            }
            Request::Read {
                ext: true,
                fork,
                offset: offset as u64,
                count: count as u64,
            }
        }
        WRITE | WRITE_EXT => {
            let ext = code == WRITE_EXT;
            let flag = r.u8("write flag")?;
            let fork = r.u16("fork")?;
            let (offset, count) = if ext {
                (r.u64("offset")? as i64, r.u64("count")? as i64)
            } else {
                (
                    r.u32("offset")? as i32 as i64,
                    r.u32("count")? as i32 as i64,
                )
            };
            let from_end = flag & 0x80 != 0;
            if count < 0 || (!from_end && offset < 0) {
                return Err(ParseError::param("a write with a negative offset or count"));
            }
            Request::Write {
                ext,
                from_end,
                fork,
                offset: offset as u64,
                count: count as u64,
            }
        }
        GET_FORK_PARMS => {
            r.skip(1, "pad")?;
            Request::GetForkParms {
                fork: r.u16("fork")?,
                bitmap: r.u16("file bitmap")?,
            }
        }
        SET_FORK_PARMS => {
            r.skip(1, "pad")?;
            let fork = r.u16("fork")?;
            let bitmap = r.u16("file bitmap")?;
            let length =
                if bitmap & (file_bit::EXT_DATA_FORK_LEN | file_bit::EXT_RSRC_FORK_LEN) != 0 {
                    r.u64("fork length")?
                } else {
                    r.u32("fork length")? as u64
                };
            Request::SetForkParms {
                fork,
                bitmap,
                length,
            }
        }
        FLUSH_FORK => {
            r.skip(1, "pad")?;
            Request::FlushFork {
                fork: r.u16("fork")?,
            }
        }
        FLUSH => {
            r.skip(1, "pad")?;
            Request::Flush {
                vol: r.u16("volume ID")?,
            }
        }
        CLOSE_FORK => {
            r.skip(1, "pad")?;
            Request::CloseFork {
                fork: r.u16("fork")?,
            }
        }
        CREATE_FILE => {
            let flag = r.u8("create flag")?;
            Request::CreateFile {
                hard: flag & 0x80 != 0,
                vol: r.u16("volume ID")?,
                dir: r.u32("directory ID")?,
                path: r.path()?,
            }
        }
        CREATE_DIR => {
            r.skip(1, "pad")?;
            Request::CreateDir {
                vol: r.u16("volume ID")?,
                dir: r.u32("directory ID")?,
                path: r.path()?,
            }
        }
        DELETE => {
            r.skip(1, "pad")?;
            Request::Delete {
                vol: r.u16("volume ID")?,
                dir: r.u32("directory ID")?,
                path: r.path()?,
            }
        }
        RESOLVE_ID => {
            r.skip(1, "pad")?;
            Request::ResolveId {
                vol: r.u16("volume ID")?,
                id: r.u32("file ID")?,
                bitmap: r.u16("file bitmap")?,
            }
        }
        GET_USER_INFO => {
            let flags = r.u8("flags")?;
            Request::GetUserInfo {
                this_user: flags & 0x01 != 0,
                user_id: r.u32("user ID")?,
                bitmap: r.u16("bitmap")?,
            }
        }
        other => Request::Unsupported { code: other },
    })
}

// ---------------------------------------------------------------------------------------------
// Request encoding (the client's side)
// ---------------------------------------------------------------------------------------------

fn pascal(out: &mut Vec<u8>, s: &[u8]) {
    let n = s.len().min(255);
    out.push(n as u8);
    out.extend_from_slice(&s[..n]);
}

fn pad_to_even(out: &mut Vec<u8>) {
    if out.len() % 2 == 1 {
        out.push(0);
    }
}

/// The command block for `req`. A write's data is sent after it in the same DSIWrite.
pub fn encode_request(req: &Request) -> Vec<u8> {
    use cmd::*;
    let mut o = Vec::new();
    match req {
        Request::GetSrvrInfo => o.extend_from_slice(&[GET_SRVR_INFO, 0]),
        Request::Login(l) => {
            if l.ext {
                o.extend_from_slice(&[LOGIN_EXT, 0, 0, 0]);
            } else {
                o.push(LOGIN);
            }
            pascal(&mut o, l.version.as_bytes());
            pascal(&mut o, l.uam.as_bytes());
            let user = l.user.clone().unwrap_or_default();
            if l.ext {
                o.push(3);
                let u = to_wire_utf8(&user);
                o.extend_from_slice(&(u.len().min(255) as u16).to_be_bytes());
                o.extend_from_slice(&u.as_bytes()[..u.len().min(255)]);
                o.push(3);
                o.extend_from_slice(&[0, 0]);
                pad_to_even(&mut o);
            } else if l.password.is_some() {
                pascal(&mut o, &mac_roman_encode(&user, 255));
                pad_to_even(&mut o);
            }
            if let Some(p) = &l.password {
                let mut pw = [0u8; PASSWORD_LEN];
                let n = p.len().min(PASSWORD_LEN);
                pw[..n].copy_from_slice(&p[..n]);
                o.extend_from_slice(&pw);
            }
        }
        Request::LoginCont => o.extend_from_slice(&[LOGIN_CONT, 0]),
        Request::Logout => o.extend_from_slice(&[LOGOUT, 0]),
        Request::GetSrvrParms => o.extend_from_slice(&[GET_SRVR_PARMS, 0]),
        Request::OpenVol { bitmap, name, .. } => {
            o.extend_from_slice(&[OPEN_VOL, 0]);
            o.extend_from_slice(&bitmap.to_be_bytes());
            pascal(&mut o, &mac_roman_encode(name, MAX_NAME_BYTES));
        }
        Request::CloseVol { vol } => {
            o.extend_from_slice(&[CLOSE_VOL, 0]);
            o.extend_from_slice(&vol.to_be_bytes());
        }
        Request::GetVolParms { vol, bitmap } => {
            o.extend_from_slice(&[GET_VOL_PARMS, 0]);
            o.extend_from_slice(&vol.to_be_bytes());
            o.extend_from_slice(&bitmap.to_be_bytes());
        }
        Request::GetFileDirParms {
            vol,
            dir,
            file_bitmap,
            dir_bitmap,
            path,
        } => {
            o.extend_from_slice(&[GET_FILE_DIR_PARMS, 0]);
            o.extend_from_slice(&vol.to_be_bytes());
            o.extend_from_slice(&dir.to_be_bytes());
            o.extend_from_slice(&file_bitmap.to_be_bytes());
            o.extend_from_slice(&dir_bitmap.to_be_bytes());
            o.extend(path.encode());
        }
        Request::Enumerate {
            kind,
            vol,
            dir,
            file_bitmap,
            dir_bitmap,
            req_count,
            start_index,
            max_reply,
            path,
        } => {
            o.extend_from_slice(&[kind.command(), 0]);
            o.extend_from_slice(&vol.to_be_bytes());
            o.extend_from_slice(&dir.to_be_bytes());
            o.extend_from_slice(&file_bitmap.to_be_bytes());
            o.extend_from_slice(&dir_bitmap.to_be_bytes());
            o.extend_from_slice(&req_count.to_be_bytes());
            if *kind == EnumerateKind::Ext2 {
                o.extend_from_slice(&start_index.to_be_bytes());
                o.extend_from_slice(&max_reply.to_be_bytes());
            } else {
                o.extend_from_slice(&(*start_index as u16).to_be_bytes());
                o.extend_from_slice(&(*max_reply as u16).to_be_bytes());
            }
            o.extend(path.encode());
        }
        Request::OpenFork {
            resource,
            vol,
            dir,
            bitmap,
            mode,
            path,
        } => {
            o.extend_from_slice(&[OPEN_FORK, if *resource { 0x80 } else { 0 }]);
            o.extend_from_slice(&vol.to_be_bytes());
            o.extend_from_slice(&dir.to_be_bytes());
            o.extend_from_slice(&bitmap.to_be_bytes());
            o.extend_from_slice(&mode.to_be_bytes());
            o.extend(path.encode());
        }
        Request::Read {
            ext,
            fork,
            offset,
            count,
        } => {
            if *ext {
                o.extend_from_slice(&[READ_EXT, 0]);
                o.extend_from_slice(&fork.to_be_bytes());
                o.extend_from_slice(&offset.to_be_bytes());
                o.extend_from_slice(&count.to_be_bytes());
            } else {
                o.extend_from_slice(&[READ, 0]);
                o.extend_from_slice(&fork.to_be_bytes());
                o.extend_from_slice(&(*offset as u32).to_be_bytes());
                o.extend_from_slice(&(*count as u32).to_be_bytes());
                o.extend_from_slice(&[0, 0]);
            }
        }
        Request::Write {
            ext,
            from_end,
            fork,
            offset,
            count,
        } => {
            o.push(if *ext { WRITE_EXT } else { WRITE });
            o.push(if *from_end { 0x80 } else { 0 });
            o.extend_from_slice(&fork.to_be_bytes());
            if *ext {
                o.extend_from_slice(&offset.to_be_bytes());
                o.extend_from_slice(&count.to_be_bytes());
            } else {
                o.extend_from_slice(&(*offset as u32).to_be_bytes());
                o.extend_from_slice(&(*count as u32).to_be_bytes());
            }
        }
        Request::GetForkParms { fork, bitmap } => {
            o.extend_from_slice(&[GET_FORK_PARMS, 0]);
            o.extend_from_slice(&fork.to_be_bytes());
            o.extend_from_slice(&bitmap.to_be_bytes());
        }
        Request::SetForkParms {
            fork,
            bitmap,
            length,
        } => {
            o.extend_from_slice(&[SET_FORK_PARMS, 0]);
            o.extend_from_slice(&fork.to_be_bytes());
            o.extend_from_slice(&bitmap.to_be_bytes());
            if bitmap & (file_bit::EXT_DATA_FORK_LEN | file_bit::EXT_RSRC_FORK_LEN) != 0 {
                o.extend_from_slice(&length.to_be_bytes());
            } else {
                o.extend_from_slice(&(*length as u32).to_be_bytes());
            }
        }
        Request::FlushFork { fork } => {
            o.extend_from_slice(&[FLUSH_FORK, 0]);
            o.extend_from_slice(&fork.to_be_bytes());
        }
        Request::Flush { vol } => {
            o.extend_from_slice(&[FLUSH, 0]);
            o.extend_from_slice(&vol.to_be_bytes());
        }
        Request::CloseFork { fork } => {
            o.extend_from_slice(&[CLOSE_FORK, 0]);
            o.extend_from_slice(&fork.to_be_bytes());
        }
        Request::CreateFile {
            hard,
            vol,
            dir,
            path,
        } => {
            o.extend_from_slice(&[CREATE_FILE, if *hard { 0x80 } else { 0 }]);
            o.extend_from_slice(&vol.to_be_bytes());
            o.extend_from_slice(&dir.to_be_bytes());
            o.extend(path.encode());
        }
        Request::CreateDir { vol, dir, path } => {
            o.extend_from_slice(&[CREATE_DIR, 0]);
            o.extend_from_slice(&vol.to_be_bytes());
            o.extend_from_slice(&dir.to_be_bytes());
            o.extend(path.encode());
        }
        Request::Delete { vol, dir, path } => {
            o.extend_from_slice(&[DELETE, 0]);
            o.extend_from_slice(&vol.to_be_bytes());
            o.extend_from_slice(&dir.to_be_bytes());
            o.extend(path.encode());
        }
        Request::ResolveId { vol, id, bitmap } => {
            o.extend_from_slice(&[RESOLVE_ID, 0]);
            o.extend_from_slice(&vol.to_be_bytes());
            o.extend_from_slice(&id.to_be_bytes());
            o.extend_from_slice(&bitmap.to_be_bytes());
        }
        Request::GetUserInfo {
            this_user,
            user_id,
            bitmap,
        } => {
            o.extend_from_slice(&[GET_USER_INFO, u8::from(*this_user)]);
            o.extend_from_slice(&user_id.to_be_bytes());
            o.extend_from_slice(&bitmap.to_be_bytes());
        }
        Request::Unsupported { code } => o.extend_from_slice(&[*code, 0]),
    }
    o
}

// ---------------------------------------------------------------------------------------------
// FPGetSrvrInfo (the DSIGetStatus reply)
// ---------------------------------------------------------------------------------------------

/// What a server says about itself before anyone logs in.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ServerInfo {
    pub machine_type: String,
    pub versions: Vec<String>,
    pub uams: Vec<String>,
    pub flags: u16,
    pub server_name: String,
    pub signature: Option<[u8; 16]>,
    /// `(tag, bytes)`: 1 IPv4, 2 IPv4 + port, 4 DNS name, 6 IPv6, 7 IPv6 + port.
    pub addresses: Vec<(u8, Vec<u8>)>,
    pub utf8_server_name: Option<String>,
}

impl ServerInfo {
    /// The addresses as text ("127.0.0.1:548", "host.example").
    pub fn address_strings(&self) -> Vec<String> {
        self.addresses
            .iter()
            .map(|(tag, b)| match (tag, b.len()) {
                (1, 4) => std::net::Ipv4Addr::new(b[0], b[1], b[2], b[3]).to_string(),
                (2, 6) => format!(
                    "{}:{}",
                    std::net::Ipv4Addr::new(b[0], b[1], b[2], b[3]),
                    u16::from_be_bytes([b[4], b[5]])
                ),
                (4, _) | (5, _) => String::from_utf8_lossy(b).into_owned(),
                (6, 16) => {
                    let mut a = [0u8; 16];
                    a.copy_from_slice(b);
                    std::net::Ipv6Addr::from(a).to_string()
                }
                (7, 18) => {
                    let mut a = [0u8; 16];
                    a.copy_from_slice(&b[..16]);
                    format!(
                        "[{}]:{}",
                        std::net::Ipv6Addr::from(a),
                        u16::from_be_bytes([b[16], b[17]])
                    )
                }
                _ => format!("tag {tag}: {}", hex::encode(b)),
            })
            .collect()
    }
}

/// The FPGetSrvrInfo reply block, laid out as netatalk lays it out: the four leading offsets
/// and flags, the server name padded to even, the four offsets AFP 3 added (signature,
/// network addresses, directory names, UTF-8 server name), then the data they point at.
pub fn encode_server_info(info: &ServerInfo) -> Vec<u8> {
    let mut o = vec![0u8; 10];
    o[8..10].copy_from_slice(&info.flags.to_be_bytes());
    pascal(&mut o, &mac_roman_encode(&info.server_name, MAX_LONG_NAME));
    pad_to_even(&mut o);
    let post = o.len();
    o.extend_from_slice(&[0u8; 8]);
    let set = |o: &mut Vec<u8>, at: usize| {
        let v = o.len() as u16;
        o[at..at + 2].copy_from_slice(&v.to_be_bytes());
    };
    set(&mut o, 0);
    pascal(&mut o, &mac_roman_encode(&info.machine_type, 16));
    set(&mut o, 2);
    o.push(info.versions.len().min(255) as u8);
    for v in info.versions.iter().take(255) {
        pascal(&mut o, v.as_bytes());
    }
    set(&mut o, 4);
    o.push(info.uams.len().min(255) as u8);
    for u in info.uams.iter().take(255) {
        pascal(&mut o, u.as_bytes());
    }
    // Volume icon offset (6) stays 0: no icon.
    if let Some(sig) = info.signature {
        set(&mut o, post);
        o.extend_from_slice(&sig);
    }
    set(&mut o, post + 2);
    o.push(info.addresses.len().min(255) as u8);
    for (tag, b) in info.addresses.iter().take(255) {
        let n = b.len().min(253);
        o.push((n + 2) as u8);
        o.push(*tag);
        o.extend_from_slice(&b[..n]);
    }
    set(&mut o, post + 4);
    o.push(0); // no directory names
    if let Some(name) = &info.utf8_server_name {
        set(&mut o, post + 6);
        let n = to_wire_utf8(name);
        let n = &n.as_bytes()[..n.len().min(255)];
        o.extend_from_slice(&(n.len() as u16).to_be_bytes());
        o.extend_from_slice(n);
    }
    o
}

fn at(b: &[u8], offset: u16, what: &str) -> Result<usize> {
    let o = offset as usize;
    ensure!(
        o < b.len(),
        "{what} offset {o} is past the end of a {}-byte reply",
        b.len()
    );
    Ok(o)
}

fn pascal_at(b: &[u8], pos: usize, what: &str) -> Result<(String, usize)> {
    let n = *b
        .get(pos)
        .ok_or_else(|| anyhow!("{what}: no length byte"))? as usize;
    let s = b
        .get(pos + 1..pos + 1 + n)
        .ok_or_else(|| anyhow!("{what}: {n} bytes past the end"))?;
    Ok((mac_roman_decode(s), pos + 1 + n))
}

fn be16(b: &[u8], pos: usize, what: &str) -> Result<u16> {
    let s = b
        .get(pos..pos + 2)
        .ok_or_else(|| anyhow!("{what}: cut short at {pos}"))?;
    Ok(u16::from_be_bytes([s[0], s[1]]))
}

fn be32(b: &[u8], pos: usize, what: &str) -> Result<u32> {
    let s = b
        .get(pos..pos + 4)
        .ok_or_else(|| anyhow!("{what}: cut short at {pos}"))?;
    Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}

fn be64(b: &[u8], pos: usize, what: &str) -> Result<u64> {
    let s = b
        .get(pos..pos + 8)
        .ok_or_else(|| anyhow!("{what}: cut short at {pos}"))?;
    let mut a = [0u8; 8];
    a.copy_from_slice(s);
    Ok(u64::from_be_bytes(a))
}

pub fn decode_server_info(b: &[u8]) -> Result<ServerInfo> {
    let machine_off = be16(b, 0, "machine type offset")?;
    let versions_off = be16(b, 2, "versions offset")?;
    let uams_off = be16(b, 4, "UAMs offset")?;
    let flags = be16(b, 8, "flags")?;
    let (server_name, end) = pascal_at(b, 10, "server name")?;
    let post = end + (end % 2);
    let (machine_type, _) = pascal_at(b, at(b, machine_off, "machine type")?, "machine type")?;
    let list = |off: u16, what: &str| -> Result<Vec<String>> {
        let mut pos = at(b, off, what)?;
        let n = b[pos] as usize;
        pos += 1;
        let mut v = Vec::with_capacity(n);
        for _ in 0..n {
            let (s, next) = pascal_at(b, pos, what)?;
            v.push(s);
            pos = next;
        }
        Ok(v)
    };
    let versions = list(versions_off, "AFP versions")?;
    let uams = list(uams_off, "UAMs")?;
    let mut info = ServerInfo {
        machine_type,
        versions,
        uams,
        flags,
        server_name,
        ..Default::default()
    };
    // The AFP 3 offsets exist only when the flags say so, and only as far as the block goes.
    if flags & srvr_flag::SERVER_SIGNATURE != 0 {
        if let Ok(off) = be16(b, post, "signature offset") {
            if off != 0 {
                let p = at(b, off, "signature")?;
                let s = b
                    .get(p..p + 16)
                    .ok_or_else(|| anyhow!("signature cut short"))?;
                let mut sig = [0u8; 16];
                sig.copy_from_slice(s);
                info.signature = Some(sig);
            }
        }
    }
    if flags & srvr_flag::TCP_IP != 0 {
        if let Ok(off) = be16(b, post + 2, "network address offset") {
            if off != 0 {
                let mut p = at(b, off, "network addresses")?;
                let n = b[p] as usize;
                p += 1;
                for _ in 0..n {
                    let len = *b.get(p).ok_or_else(|| anyhow!("address cut short"))? as usize;
                    ensure!(len >= 2, "a network address entry of length {len}");
                    let tag = *b.get(p + 1).ok_or_else(|| anyhow!("address cut short"))?;
                    let data = b
                        .get(p + 2..p + len)
                        .ok_or_else(|| anyhow!("address data cut short"))?;
                    info.addresses.push((tag, data.to_vec()));
                    p += len;
                }
            }
        }
    }
    if flags & srvr_flag::UTF8_SERVER_NAME != 0 {
        if let Ok(off) = be16(b, post + 6, "UTF-8 server name offset") {
            if off != 0 {
                let p = at(b, off, "UTF-8 server name")?;
                let n = be16(b, p, "UTF-8 server name length")? as usize;
                let s = b
                    .get(p + 2..p + 2 + n)
                    .ok_or_else(|| anyhow!("UTF-8 server name cut short"))?;
                info.utf8_server_name = Some(normalize(&String::from_utf8_lossy(s)));
            }
        }
    }
    Ok(info)
}

// ---------------------------------------------------------------------------------------------
// FPGetSrvrParms
// ---------------------------------------------------------------------------------------------

/// A volume as FPGetSrvrParms lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VolumeListing {
    pub name: String,
    pub has_password: bool,
}

pub fn encode_srvr_parms(server_time: i32, volumes: &[VolumeListing]) -> Vec<u8> {
    let mut o = Vec::new();
    o.extend_from_slice(&server_time.to_be_bytes());
    o.push(volumes.len().min(MAX_VOLUMES) as u8);
    for v in volumes.iter().take(MAX_VOLUMES) {
        o.push(if v.has_password { 0x80 } else { 0 });
        pascal(&mut o, &mac_roman_encode(&v.name, MAX_VOLUME_NAME));
    }
    o
}

pub fn decode_srvr_parms(b: &[u8]) -> Result<(i32, Vec<VolumeListing>)> {
    let time = be32(b, 0, "server time")? as i32;
    let n = *b.get(4).ok_or_else(|| anyhow!("volume count missing"))? as usize;
    let mut pos = 5;
    let mut v = Vec::with_capacity(n);
    for _ in 0..n {
        let flags = *b.get(pos).ok_or_else(|| anyhow!("volume flags missing"))?;
        let (name, next) = pascal_at(b, pos + 1, "volume name")?;
        v.push(VolumeListing {
            name: normalize(&name),
            has_password: flags & 0x80 != 0,
        });
        pos = next;
    }
    Ok((time, v))
}

// ---------------------------------------------------------------------------------------------
// Volume parameters
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VolumeParams {
    pub attributes: u16,
    pub signature: u16,
    pub created: i32,
    pub modified: i32,
    pub backup: i32,
    pub id: u16,
    pub bytes_free: u64,
    pub bytes_total: u64,
    pub name: String,
    pub block_size: u32,
}

/// Encode the parameters `bitmap` asks for. `Err(kFPBitmapErr)` for a bit NetGet does not know.
pub fn encode_vol_params(bitmap: u16, v: &VolumeParams) -> std::result::Result<Vec<u8>, i32> {
    if bitmap & !vol_bit::ALL != 0 {
        return Err(err::BITMAP_ERR);
    }
    let mut o = Vec::new();
    let mut name_at = None;
    for bit in 0..16u16 {
        let b = 1u16 << bit;
        if bitmap & b == 0 {
            continue;
        }
        match b {
            vol_bit::ATTRIBUTES => o.extend_from_slice(&v.attributes.to_be_bytes()),
            vol_bit::SIGNATURE => o.extend_from_slice(&v.signature.to_be_bytes()),
            vol_bit::CREATE_DATE => o.extend_from_slice(&v.created.to_be_bytes()),
            vol_bit::MOD_DATE => o.extend_from_slice(&v.modified.to_be_bytes()),
            vol_bit::BACKUP_DATE => o.extend_from_slice(&v.backup.to_be_bytes()),
            vol_bit::VOLUME_ID => o.extend_from_slice(&v.id.to_be_bytes()),
            vol_bit::BYTES_FREE => {
                o.extend_from_slice(&(v.bytes_free.min(u32::MAX as u64) as u32).to_be_bytes())
            }
            vol_bit::BYTES_TOTAL => {
                o.extend_from_slice(&(v.bytes_total.min(u32::MAX as u64) as u32).to_be_bytes())
            }
            vol_bit::NAME => {
                name_at = Some(o.len());
                o.extend_from_slice(&[0, 0]);
            }
            vol_bit::EXT_BYTES_FREE => o.extend_from_slice(&v.bytes_free.to_be_bytes()),
            vol_bit::EXT_BYTES_TOTAL => o.extend_from_slice(&v.bytes_total.to_be_bytes()),
            vol_bit::BLOCK_SIZE => o.extend_from_slice(&v.block_size.to_be_bytes()),
            _ => return Err(err::BITMAP_ERR),
        }
    }
    if let Some(p) = name_at {
        let off = o.len() as u16;
        o[p..p + 2].copy_from_slice(&off.to_be_bytes());
        pascal(&mut o, &mac_roman_encode(&v.name, MAX_VOLUME_NAME));
    }
    Ok(o)
}

pub fn decode_vol_params(bitmap: u16, b: &[u8]) -> Result<VolumeParams> {
    ensure!(
        bitmap & !vol_bit::ALL == 0,
        "volume bitmap {bitmap:#06x} has unknown bits"
    );
    let mut v = VolumeParams::default();
    let mut pos = 0usize;
    for bit in 0..16u16 {
        let m = 1u16 << bit;
        if bitmap & m == 0 {
            continue;
        }
        match m {
            vol_bit::ATTRIBUTES => {
                v.attributes = be16(b, pos, "volume attributes")?;
                pos += 2
            }
            vol_bit::SIGNATURE => {
                v.signature = be16(b, pos, "volume signature")?;
                pos += 2
            }
            vol_bit::CREATE_DATE => {
                v.created = be32(b, pos, "volume creation date")? as i32;
                pos += 4
            }
            vol_bit::MOD_DATE => {
                v.modified = be32(b, pos, "volume modification date")? as i32;
                pos += 4
            }
            vol_bit::BACKUP_DATE => {
                v.backup = be32(b, pos, "volume backup date")? as i32;
                pos += 4
            }
            vol_bit::VOLUME_ID => {
                v.id = be16(b, pos, "volume ID")?;
                pos += 2
            }
            vol_bit::BYTES_FREE => {
                v.bytes_free = be32(b, pos, "bytes free")? as u64;
                pos += 4
            }
            vol_bit::BYTES_TOTAL => {
                v.bytes_total = be32(b, pos, "bytes total")? as u64;
                pos += 4
            }
            vol_bit::NAME => {
                let off = be16(b, pos, "volume name offset")?;
                pos += 2;
                if off != 0 {
                    v.name = normalize(&pascal_at(b, off as usize, "volume name")?.0);
                }
            }
            vol_bit::EXT_BYTES_FREE => {
                v.bytes_free = be64(b, pos, "extended bytes free")?;
                pos += 8
            }
            vol_bit::EXT_BYTES_TOTAL => {
                v.bytes_total = be64(b, pos, "extended bytes total")?;
                pos += 8
            }
            vol_bit::BLOCK_SIZE => {
                v.block_size = be32(b, pos, "block size")?;
                pos += 4
            }
            _ => bail!("volume bitmap bit {bit} unknown"),
        }
    }
    Ok(v)
}

// ---------------------------------------------------------------------------------------------
// File and directory parameters
// ---------------------------------------------------------------------------------------------

/// Unix ownership and permissions (the UnixPrivileges parameter).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct UnixPrivs {
    pub uid: u32,
    pub gid: u32,
    /// `st_mode`, file-type bits included.
    pub mode: u32,
    /// Access rights: user, world, group, owner bytes, big-endian in that order.
    pub access: u32,
}

/// The access-rights word for a mode, as seen by a user who owns the item.
pub fn access_rights(mode: u32, writable: bool) -> u32 {
    let byte = |r: u32, w: u32, x: u32| -> u8 {
        let mut b = 0u8;
        if mode & r != 0 {
            b |= access::READ;
        }
        if mode & w != 0 && writable {
            b |= access::WRITE;
        }
        if mode & x != 0 {
            b |= access::SEARCH;
        }
        b
    };
    let owner = byte(0o400, 0o200, 0o100);
    let group = byte(0o040, 0o020, 0o010);
    let world = byte(0o004, 0o002, 0o001);
    let user = owner | access::USER_IS_OWNER;
    u32::from_be_bytes([user, world, group, owner])
}

/// One file or directory, as NetGet describes it on the wire.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NodeParams {
    pub is_dir: bool,
    pub attributes: u16,
    pub parent_id: u32,
    pub created: i32,
    pub modified: i32,
    pub backup: i32,
    pub finder_info: [u8; 32],
    /// The UTF-8 name if the reply had one, else the long name.
    pub name: String,
    pub node_id: u32,
    pub data_len: u64,
    pub rsrc_len: u64,
    pub offspring: u16,
    pub owner_id: u32,
    pub group_id: u32,
    pub access: u32,
    pub unix: UnixPrivs,
}

/// Encode a file's (or, with `is_dir`, a directory's) parameters for `bitmap`.
pub fn encode_node_params(bitmap: u16, n: &NodeParams) -> std::result::Result<Vec<u8>, i32> {
    let supported = if n.is_dir {
        dir_bit::SUPPORTED
    } else {
        file_bit::SUPPORTED
    };
    if bitmap & !supported != 0 {
        return Err(err::BITMAP_ERR);
    }
    let mut o = Vec::new();
    let mut long_at = None;
    let mut utf8_at = None;
    for bit in 0..16u16 {
        let m = 1u16 << bit;
        if bitmap & m == 0 {
            continue;
        }
        match (n.is_dir, m) {
            (_, file_bit::ATTRIBUTES) => o.extend_from_slice(&n.attributes.to_be_bytes()),
            (_, file_bit::PARENT_DIR_ID) => o.extend_from_slice(&n.parent_id.to_be_bytes()),
            (_, file_bit::CREATE_DATE) => o.extend_from_slice(&n.created.to_be_bytes()),
            (_, file_bit::MOD_DATE) => o.extend_from_slice(&n.modified.to_be_bytes()),
            (_, file_bit::BACKUP_DATE) => o.extend_from_slice(&n.backup.to_be_bytes()),
            (_, file_bit::FINDER_INFO) => o.extend_from_slice(&n.finder_info),
            (_, file_bit::LONG_NAME) => {
                long_at = Some(o.len());
                o.extend_from_slice(&[0, 0]);
            }
            (_, file_bit::SHORT_NAME) => o.extend_from_slice(&[0, 0]),
            (_, file_bit::NODE_ID) => o.extend_from_slice(&n.node_id.to_be_bytes()),
            (false, file_bit::DATA_FORK_LEN) => {
                o.extend_from_slice(&(n.data_len.min(u32::MAX as u64) as u32).to_be_bytes())
            }
            (false, file_bit::RSRC_FORK_LEN) => {
                o.extend_from_slice(&(n.rsrc_len.min(u32::MAX as u64) as u32).to_be_bytes())
            }
            (false, file_bit::EXT_DATA_FORK_LEN) => o.extend_from_slice(&n.data_len.to_be_bytes()),
            (false, file_bit::EXT_RSRC_FORK_LEN) => o.extend_from_slice(&n.rsrc_len.to_be_bytes()),
            (true, dir_bit::OFFSPRING_COUNT) => o.extend_from_slice(&n.offspring.to_be_bytes()),
            (true, dir_bit::OWNER_ID) => o.extend_from_slice(&n.owner_id.to_be_bytes()),
            (true, dir_bit::GROUP_ID) => o.extend_from_slice(&n.group_id.to_be_bytes()),
            (true, dir_bit::ACCESS_RIGHTS) => o.extend_from_slice(&n.access.to_be_bytes()),
            (_, file_bit::UTF8_NAME) => {
                utf8_at = Some(o.len());
                o.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
            }
            (_, file_bit::UNIX_PRIVS) => {
                o.extend_from_slice(&n.unix.uid.to_be_bytes());
                o.extend_from_slice(&n.unix.gid.to_be_bytes());
                o.extend_from_slice(&n.unix.mode.to_be_bytes());
                o.extend_from_slice(&n.unix.access.to_be_bytes());
            }
            _ => return Err(err::BITMAP_ERR),
        }
    }
    if let Some(p) = long_at {
        let off = o.len() as u16;
        o[p..p + 2].copy_from_slice(&off.to_be_bytes());
        pascal(&mut o, &mac_roman_encode(&n.name, MAX_LONG_NAME));
    }
    if let Some(p) = utf8_at {
        let off = o.len() as u16;
        o[p..p + 2].copy_from_slice(&off.to_be_bytes());
        let w = to_wire_utf8(&n.name);
        let w = &w.as_bytes()[..w.len().min(MAX_NAME_BYTES)];
        o.extend_from_slice(&UTF8_HINT.to_be_bytes());
        o.extend_from_slice(&(w.len() as u16).to_be_bytes());
        o.extend_from_slice(w);
    }
    Ok(o)
}

/// Decode a file's or directory's parameters.
pub fn decode_node_params(bitmap: u16, is_dir: bool, b: &[u8]) -> Result<NodeParams> {
    let mut n = NodeParams {
        is_dir,
        ..Default::default()
    };
    let mut pos = 0usize;
    let mut long_name = None;
    let mut utf8_name = None;
    for bit in 0..16u16 {
        let m = 1u16 << bit;
        if bitmap & m == 0 {
            continue;
        }
        match (is_dir, m) {
            (_, file_bit::ATTRIBUTES) => {
                n.attributes = be16(b, pos, "attributes")?;
                pos += 2
            }
            (_, file_bit::PARENT_DIR_ID) => {
                n.parent_id = be32(b, pos, "parent ID")?;
                pos += 4
            }
            (_, file_bit::CREATE_DATE) => {
                n.created = be32(b, pos, "creation date")? as i32;
                pos += 4
            }
            (_, file_bit::MOD_DATE) => {
                n.modified = be32(b, pos, "modification date")? as i32;
                pos += 4
            }
            (_, file_bit::BACKUP_DATE) => {
                n.backup = be32(b, pos, "backup date")? as i32;
                pos += 4
            }
            (_, file_bit::FINDER_INFO) => {
                let s = b
                    .get(pos..pos + 32)
                    .ok_or_else(|| anyhow!("Finder info cut short"))?;
                n.finder_info.copy_from_slice(s);
                pos += 32
            }
            (_, file_bit::LONG_NAME) => {
                let off = be16(b, pos, "long name offset")?;
                pos += 2;
                if off != 0 {
                    long_name = Some(pascal_at(b, off as usize, "long name")?.0);
                }
            }
            (_, file_bit::SHORT_NAME) => pos += 2,
            (_, file_bit::NODE_ID) => {
                n.node_id = be32(b, pos, "node ID")?;
                pos += 4
            }
            (false, file_bit::DATA_FORK_LEN) => {
                n.data_len = be32(b, pos, "data fork length")? as u64;
                pos += 4
            }
            (false, file_bit::RSRC_FORK_LEN) => {
                n.rsrc_len = be32(b, pos, "resource fork length")? as u64;
                pos += 4
            }
            (false, file_bit::EXT_DATA_FORK_LEN) => {
                n.data_len = be64(b, pos, "extended data fork length")?;
                pos += 8
            }
            (false, file_bit::EXT_RSRC_FORK_LEN) => {
                n.rsrc_len = be64(b, pos, "extended resource fork length")?;
                pos += 8
            }
            (false, file_bit::LAUNCH_LIMIT) => pos += 2,
            (true, dir_bit::OFFSPRING_COUNT) => {
                n.offspring = be16(b, pos, "offspring count")?;
                pos += 2
            }
            (true, dir_bit::OWNER_ID) => {
                n.owner_id = be32(b, pos, "owner ID")?;
                pos += 4
            }
            (true, dir_bit::GROUP_ID) => {
                n.group_id = be32(b, pos, "group ID")?;
                pos += 4
            }
            (true, dir_bit::ACCESS_RIGHTS) => {
                n.access = be32(b, pos, "access rights")?;
                pos += 4
            }
            (_, file_bit::UTF8_NAME) => {
                let off = be16(b, pos, "UTF-8 name offset")?;
                pos += 6;
                if off != 0 {
                    let p = off as usize + 4;
                    let len = be16(b, p, "UTF-8 name length")? as usize;
                    let s = b
                        .get(p + 2..p + 2 + len)
                        .ok_or_else(|| anyhow!("UTF-8 name cut short"))?;
                    utf8_name = Some(normalize(&String::from_utf8_lossy(s)));
                }
            }
            (_, file_bit::UNIX_PRIVS) => {
                n.unix = UnixPrivs {
                    uid: be32(b, pos, "uid")?,
                    gid: be32(b, pos + 4, "gid")?,
                    mode: be32(b, pos + 8, "mode")?,
                    access: be32(b, pos + 12, "unix access rights")?,
                };
                pos += 16
            }
            _ => bail!(
                "{} bitmap bit {bit} is not one NetGet decodes",
                if is_dir { "directory" } else { "file" }
            ),
        }
    }
    n.name = utf8_name
        .or(long_name.map(|s| normalize(&s)))
        .unwrap_or_default();
    Ok(n)
}

/// FPGetFileDirParms reply: both bitmaps, the FileDir flag, a pad byte, the parameters.
pub fn encode_file_dir_reply(
    file_bitmap: u16,
    dir_bitmap: u16,
    n: &NodeParams,
) -> std::result::Result<Vec<u8>, i32> {
    let mut o = Vec::new();
    o.extend_from_slice(&file_bitmap.to_be_bytes());
    o.extend_from_slice(&dir_bitmap.to_be_bytes());
    o.push(if n.is_dir { IS_DIR } else { 0 });
    o.push(0);
    let bitmap = if n.is_dir { dir_bitmap } else { file_bitmap };
    o.extend(encode_node_params(bitmap, n)?);
    Ok(o)
}

pub fn decode_file_dir_reply(b: &[u8]) -> Result<NodeParams> {
    let fb = be16(b, 0, "file bitmap")?;
    let db = be16(b, 2, "directory bitmap")?;
    let flag = *b.get(4).ok_or_else(|| anyhow!("FileDir flag missing"))?;
    let is_dir = flag & IS_DIR != 0;
    decode_node_params(
        if is_dir { db } else { fb },
        is_dir,
        b.get(6..).unwrap_or(&[]),
    )
}

/// An enumerate reply: bitmaps, count, then entries, each `length, flag[, pad], params`
/// padded to even. Stops at `max_entries` or before an entry would take the reply past
/// `max_size`. Returns the reply and how many entries it holds; `Err(kFPParamErr)` when not
/// even the first entry fits, as netatalk answers.
pub fn encode_enumerate_reply(
    kind: EnumerateKind,
    file_bitmap: u16,
    dir_bitmap: u16,
    nodes: &[NodeParams],
    max_entries: usize,
    max_size: usize,
) -> std::result::Result<(Vec<u8>, usize), i32> {
    let mut o = Vec::new();
    o.extend_from_slice(&file_bitmap.to_be_bytes());
    o.extend_from_slice(&dir_bitmap.to_be_bytes());
    o.extend_from_slice(&[0, 0]);
    let mut count = 0usize;
    for n in nodes {
        if count >= max_entries {
            break;
        }
        let bitmap = if n.is_dir { dir_bitmap } else { file_bitmap };
        if bitmap == 0 {
            continue;
        }
        let params = encode_node_params(bitmap, n)?;
        let mut len = kind.entry_header() + params.len();
        if len % 2 == 1 {
            len += 1;
        }
        if len > kind.max_entry_len() {
            return Err(err::PARAM_ERR);
        }
        if o.len() + len > max_size {
            if count == 0 {
                return Err(err::PARAM_ERR);
            }
            break;
        }
        match kind {
            EnumerateKind::Classic => {
                o.push(len as u8);
                o.push(if n.is_dir { IS_DIR } else { 0 });
            }
            _ => {
                o.extend_from_slice(&(len as u16).to_be_bytes());
                o.push(if n.is_dir { IS_DIR } else { 0 });
                o.push(0);
            }
        }
        o.extend_from_slice(&params);
        if (kind.entry_header() + params.len()) % 2 == 1 {
            o.push(0);
        }
        count += 1;
    }
    o[4..6].copy_from_slice(&(count as u16).to_be_bytes());
    Ok((o, count))
}

/// A reply that starts with a bitmap: the bitmap and the rest.
pub fn be16_prefixed(b: &[u8]) -> Result<(u16, &[u8])> {
    Ok((be16(b, 0, "bitmap")?, b.get(2..).unwrap_or(&[])))
}

/// An FPOpenFork reply: the fork's reference number, and its length when the bitmap asked for
/// one (0 otherwise).
pub fn decode_open_fork_reply(b: &[u8]) -> Result<(u16, u64)> {
    let bitmap = be16(b, 0, "file bitmap")?;
    let fork = be16(b, 2, "fork reference number")?;
    ensure!(fork != 0, "the server opened fork 0");
    let n = decode_node_params(bitmap, false, b.get(4..).unwrap_or(&[]))?;
    Ok((fork, n.data_len))
}

pub fn decode_enumerate_reply(kind: EnumerateKind, b: &[u8]) -> Result<Vec<NodeParams>> {
    let fb = be16(b, 0, "file bitmap")?;
    let db = be16(b, 2, "directory bitmap")?;
    let count = be16(b, 4, "entry count")? as usize;
    ensure!(
        count <= MAX_ENUMERATE_ENTRIES * 4,
        "an enumerate reply claiming {count} entries"
    );
    let mut pos = 6usize;
    let mut out = Vec::with_capacity(count.min(MAX_ENUMERATE_ENTRIES));
    for i in 0..count {
        let (len, flag) = match kind {
            EnumerateKind::Classic => (
                *b.get(pos).ok_or_else(|| anyhow!("entry {i} cut short"))? as usize,
                *b.get(pos + 1)
                    .ok_or_else(|| anyhow!("entry {i} cut short"))?,
            ),
            _ => (
                be16(b, pos, "entry length")? as usize,
                *b.get(pos + 2)
                    .ok_or_else(|| anyhow!("entry {i} cut short"))?,
            ),
        };
        let header = kind.entry_header();
        ensure!(len >= header, "entry {i} has length {len}");
        let body = b
            .get(pos + header..pos + len)
            .ok_or_else(|| anyhow!("entry {i} of length {len} runs past the reply"))?;
        let is_dir = flag & IS_DIR != 0;
        out.push(decode_node_params(
            if is_dir { db } else { fb },
            is_dir,
            body,
        )?);
        pos += len + (len % 2);
    }
    Ok(out)
}
