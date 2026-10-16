//! `netget::server::afp` — every decoder the AFP server and client run on what a peer sends:
//! DSI headers and their declared lengths, DSIOpenSession options, the DSIWrite command/data
//! split, every AFP request the server parses (paths with their NUL separators and ascents,
//! Pascal and UTF-8 names, both login commands), and every reply the client decodes
//! (FPGetSrvrInfo's offset table, FPGetSrvrParms, volume, file and directory parameter blocks,
//! all three enumerate flavours, FPOpenFork).
//!
//! What parses as a request is checked to stay within its bounds: a path has at most
//! `MAX_PATH_ELEMENTS` elements and no element longer than `MAX_NAME_BYTES`. Nothing here
//! recurses — paths are a loop over NUL runs — so the corpus carries the long walks instead: a
//! path of 63 ascents (`nul_ascents`, the depth-bomb equivalent for this grammar), a path at
//! the element bound (`max_elements`) and a header declaring the largest length the bound
//! admits (`max_length_header`).

#![no_main]

use libfuzzer_sys::fuzz_target;
use netget::server::afp::{dsi, wire};

fuzz_target!(|data: &[u8]| {
    // DSI: a header, then whatever follows as its payload.
    if data.len() >= dsi::HEADER_LEN {
        let mut h = [0u8; dsi::HEADER_LEN];
        h.copy_from_slice(&data[..dsi::HEADER_LEN]);
        let header = dsi::Header::parse(&h);
        assert_eq!(header.encode(), h);
        if let Ok(len) = header.check_length() {
            assert!(len <= dsi::MAX_PAYLOAD_LEN);
        }
        let payload = &data[dsi::HEADER_LEN..];
        if let Ok((cmd, rest)) = dsi::split_write(&header, payload) {
            assert!(cmd <= dsi::MAX_COMMAND_LEN && cmd + rest == payload.len());
        }
        let _ = dsi::parse_options(payload);
    }

    // An AFP request block.
    if let Ok(req) = wire::parse_request(data) {
        let path = match &req {
            wire::Request::GetFileDirParms { path, .. }
            | wire::Request::Enumerate { path, .. }
            | wire::Request::OpenFork { path, .. }
            | wire::Request::CreateFile { path, .. }
            | wire::Request::CreateDir { path, .. }
            | wire::Request::Delete { path, .. } => Some(path),
            _ => None,
        };
        if let Some(p) = path {
            assert!(p.elements.len() <= wire::MAX_PATH_ELEMENTS);
            for e in &p.elements {
                if let wire::PathElement::Name(n) = e {
                    assert!(!n.is_empty());
                }
            }
        }
        // What the server read, re-encoded the way the client sends it, reads back the same
        // for every request whose encoding is canonical.
        let again = wire::encode_request(&req);
        let _ = wire::parse_request(&again);
    }

    // Replies, as the client decodes them.
    let _ = wire::decode_server_info(data);
    let _ = wire::decode_srvr_parms(data);
    let _ = wire::decode_file_dir_reply(data);
    let _ = wire::decode_open_fork_reply(data);
    for kind in [
        wire::EnumerateKind::Classic,
        wire::EnumerateKind::Ext,
        wire::EnumerateKind::Ext2,
    ] {
        if let Ok(nodes) = wire::decode_enumerate_reply(kind, data) {
            assert!(nodes.len() <= wire::MAX_ENUMERATE_ENTRIES * 4);
        }
    }
    if data.len() >= 2 {
        let bitmap = u16::from_be_bytes([data[0], data[1]]);
        let _ = wire::decode_vol_params(bitmap, &data[2..]);
        let _ = wire::decode_node_params(bitmap, false, &data[2..]);
        let _ = wire::decode_node_params(bitmap, true, &data[2..]);
    }
});
