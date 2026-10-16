//! `netget::server::nis::wire` — every decoder the NIS server and client run on what a peer
//! sends: the ONC RPC call header (the portmapper's, shared), each YP v2 procedure's
//! arguments, and every result the client decodes (ypresp_val, ypresp_key_val, the
//! ypresp_all stream, ypresp_master, ypresp_order, ypresp_maplist), plus the field parse of a
//! value line.
//!
//! What parses is checked to stay within `yp.x`'s bounds: a domain ≤ YPMAXDOMAIN, a map ≤
//! YPMAXMAP, a key ≤ YPMAXRECORD, at most MAX_ENTRIES entries in an ALL and MAX_MAPS maps in a
//! MAPLIST. Nothing here recurses — the ypresp_all stream and the map list are linked lists
//! read in a loop — so the corpus carries the long chains instead: a stream of 2 000 empty
//! entries (`all_long_stream`, the depth-bomb equivalent for a linked list) and a map list at
//! the bound (`maplist_at_bound`).

#![no_main]

use libfuzzer_sys::fuzz_target;
use netget::server::nis::wire;
use netget::server::sunrpc::wire as rpc;

fuzz_target!(|data: &[u8]| {
    // As the server reads a call: the RPC header, then the procedure's arguments.
    if let Ok(Some(call)) = rpc::parse_call(data) {
        if let Ok(req) = wire::parse_request(call.procedure, call.args) {
            check(&req);
        }
    }
    // Every procedure over the raw bytes, as arguments.
    for p in 0..=12u32 {
        if let Ok(req) = wire::parse_request(p, data) {
            check(&req);
        }
    }
    // As the client reads a result.
    let _ = wire::read_bool(data);
    let _ = wire::read_resp_val(data);
    let _ = wire::read_resp_key_val(data);
    if let Ok((entries, _)) = wire::read_resp_all(data) {
        assert!(entries.len() <= wire::MAX_ENTRIES);
        for (k, v) in &entries {
            assert!(k.len() <= 3 * wire::YPMAXRECORD && v.len() <= 3 * wire::YPMAXRECORD);
            let _ = wire::entry_json("passwd.byname", k, v);
            let _ = wire::entry_json("hosts.byname", k, v);
        }
    }
    let _ = wire::read_resp_master(data);
    let _ = wire::read_resp_order(data);
    if let Ok((_, maps)) = wire::read_resp_maplist(data) {
        assert!(maps.len() <= wire::MAX_MAPS);
    }
    let text = String::from_utf8_lossy(data);
    for map in [
        "passwd.byname",
        "group.bygid",
        "hosts.byaddr",
        "netgroup",
        "mail.aliases",
    ] {
        let _ = wire::entry_json(map, "k", &text);
    }
});

fn check(req: &wire::Request) {
    use wire::Request::*;
    let (domain, map, key) = match req {
        Domain { domain, .. } | Maplist { domain } => (domain.as_str(), "", ""),
        Match { domain, map, key } | Next { domain, map, key } => {
            (domain.as_str(), map.as_str(), key.as_str())
        }
        First { domain, map }
        | All { domain, map }
        | Master { domain, map }
        | Order { domain, map } => (domain.as_str(), map.as_str(), ""),
        Null | Clear | Xfr => return,
    };
    assert!(!domain.is_empty() && domain.len() <= wire::YPMAXDOMAIN);
    assert!(map.len() <= wire::YPMAXMAP);
    assert!(key.len() <= wire::YPMAXRECORD);
    assert!(!domain.contains('/') && !map.contains('/'));
}
