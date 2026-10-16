//! NetGet's NIS server against `yp_raw.py`, a YP caller assembled from `yp.x` with python's
//! struct module, over TCP and UDP: every procedure, the structured entries rendered into
//! canonical lines, the RPC and YP error replies, the bounds, the fail-closed paths, a
//! registration with NetGet's own portmapper, and tshark's rpc/ypserv dissectors over both
//! directions. No LLM calls: the python policy in `support.rs` plays the model.
use super::support::{self, call, key, nokey, s, yp_raw, DOMAIN};
use netget::server::nis::wire::{self, proc_};
use serde_json::{json, Value};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const ALICE: &str = "alice:x:1000:1000:Alice Liddell:/home/alice:/bin/bash";
const BOB: &str = "bob:x:1001:100::/home/bob:/bin/sh";

fn stat(r: &Value) -> &str {
    r["result"]["stat"]
        .as_str()
        .unwrap_or_else(|| panic!("{r}"))
}

#[tokio::test]
async fn every_procedure_over_tcp_renders_canonical_lines() {
    let s0 = support::start(support::policy(), None).await;
    let r = yp_raw(
        s0.port,
        "tcp",
        json!([
            call(proc_::NULL, vec![], "void"),
            call(proc_::DOMAIN, vec![s(DOMAIN)], "bool"),
            call(proc_::DOMAIN, vec![s("other.test")], "bool"),
            key(proc_::MATCH, DOMAIN, "passwd.byname", "alice", "val"),
            key(proc_::MATCH, DOMAIN, "passwd.byname", "bob", "val"),
            key(proc_::MATCH, DOMAIN, "passwd.byuid", "1000", "val"),
            key(proc_::MATCH, DOMAIN, "passwd.byname", "mallory", "val"),
            key(proc_::MATCH, DOMAIN, "group.bygid", "100", "val"),
            key(proc_::MATCH, DOMAIN, "hosts.byname", "gw", "val"),
            key(proc_::MATCH, DOMAIN, "hosts.byaddr", "10.0.0.2", "val"),
            key(proc_::MATCH, DOMAIN, "netgroup", "admins", "val"),
            key(proc_::MATCH, DOMAIN, "mail.aliases", "root", "val"),
            key(proc_::MATCH, DOMAIN, "shadow.byname", "alice", "val"),
            key(proc_::MATCH, "other.test", "passwd.byname", "alice", "val"),
            nokey(proc_::FIRST, DOMAIN, "passwd.byname", "key_val"),
            key(proc_::NEXT, DOMAIN, "passwd.byname", "alice", "key_val"),
            key(proc_::NEXT, DOMAIN, "passwd.byname", "bob", "key_val"),
            key(proc_::NEXT, DOMAIN, "passwd.byname", "nobody", "key_val"),
            nokey(proc_::ALL, DOMAIN, "passwd.byname", "all"),
            nokey(proc_::ALL, DOMAIN, "hosts.byname", "all"),
            nokey(proc_::ALL, DOMAIN, "nomap", "all"),
            nokey(proc_::MASTER, DOMAIN, "passwd.byname", "master"),
            nokey(proc_::ORDER, DOMAIN, "passwd.byname", "order"),
            nokey(proc_::ORDER, DOMAIN, "nomap", "order"),
            call(proc_::MAPLIST, vec![s(DOMAIN)], "maplist"),
            call(proc_::MAPLIST, vec![s("other.test")], "maplist"),
            call(proc_::CLEAR, vec![], "void"),
        ]),
    )
    .await;
    assert!(r.iter().all(|x| x["accept_stat"] == 0), "{r:?}");
    assert_eq!(r[1]["result"], 1, "DOMAIN served");
    assert_eq!(r[2]["result"], 0, "DOMAIN refused");
    let val = |i: usize| (stat(&r[i]).to_string(), r[i]["result"]["val"].clone());
    assert_eq!(val(3), ("YP_TRUE".into(), json!(ALICE)));
    assert_eq!(
        val(4),
        ("YP_TRUE".into(), json!(BOB)),
        "password defaults to x"
    );
    assert_eq!(
        val(5),
        ("YP_TRUE".into(), json!(ALICE)),
        "byuid keys on uid"
    );
    assert_eq!(val(6), ("YP_NOKEY".into(), json!("")));
    assert_eq!(val(7), ("YP_TRUE".into(), json!("staff:x:100:alice,bob")));
    assert_eq!(
        val(8),
        ("YP_TRUE".into(), json!("10.0.0.1\tgateway gw")),
        "every host name is a key in hosts.byname"
    );
    assert_eq!(val(9), ("YP_TRUE".into(), json!("10.0.0.2\tfiles")));
    assert_eq!(
        val(10),
        (
            "YP_TRUE".into(),
            json!("(gateway,alice,netget.test) others")
        )
    );
    assert_eq!(val(11), ("YP_TRUE".into(), json!("alice, bob")));
    assert_eq!(stat(&r[12]), "YP_NOMAP");
    assert_eq!(stat(&r[13]), "YP_NODOM");
    assert_eq!(
        r[14]["result"],
        json!({"stat": "YP_TRUE", "key": "alice", "val": ALICE})
    );
    assert_eq!(
        r[15]["result"],
        json!({"stat": "YP_TRUE", "key": "bob", "val": BOB})
    );
    assert_eq!(stat(&r[16]), "YP_NOMORE", "NEXT after the last entry");
    assert_eq!(stat(&r[17]), "YP_NOKEY", "NEXT after a key the map lacks");
    assert_eq!(
        r[18]["result"],
        json!([{"stat": "YP_TRUE", "key": "alice", "val": ALICE},
               {"stat": "YP_TRUE", "key": "bob", "val": BOB}]),
        "ALL ends with more=FALSE and nothing after it"
    );
    let hosts: Vec<&str> = r[19]["result"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["key"].as_str().unwrap())
        .collect();
    assert_eq!(hosts, ["gateway", "gw", "files"]);
    assert_eq!(
        r[20]["result"],
        json!([{"stat": "YP_NOMAP", "key": "", "val": ""}]),
        "a failed ALL is one record with the status, then more=FALSE"
    );
    assert_eq!(
        r[21]["result"],
        json!({"stat": "YP_TRUE", "peer": "nis-master"})
    );
    assert_eq!(
        r[22]["result"],
        json!({"stat": "YP_TRUE", "order": 1_790_000_000u32})
    );
    assert_eq!(stat(&r[23]), "YP_NOMAP");
    assert_eq!(stat(&r[24]), "YP_TRUE");
    assert_eq!(
        r[24]["result"]["maps"].as_array().unwrap().len(),
        8,
        "{:?}",
        r[24]
    );
    assert_eq!(r[25]["result"], json!({"stat": "YP_NODOM", "maps": []}));

    // What the model was shown.
    let matches = support::events(&s0.state, s0.id, "nis_match").await;
    assert!(
        matches.contains(
            &json!({"domain": DOMAIN, "map": "passwd.byname", "key": "alice", "transport": "tcp"})
        ),
        "{matches:?}"
    );
    let walks = support::events(&s0.state, s0.id, "nis_map_read").await;
    assert!(walks
        .iter()
        .any(|w| w["procedure"] == "next" && w["key"] == "bob"));
}

#[tokio::test]
async fn udp_answers_and_domain_nonack_is_silent_for_a_refused_domain() {
    let s0 = support::start(support::policy(), None).await;
    let mut nonack_refused = call(proc_::DOMAIN_NONACK, vec![s("other.test")], "bool");
    nonack_refused["udp_timeout"] = json!(3);
    let r = yp_raw(
        s0.port,
        "udp",
        json!([
            key(proc_::MATCH, DOMAIN, "passwd.byname", "alice", "val"),
            call(proc_::DOMAIN_NONACK, vec![s(DOMAIN)], "bool"),
            nonack_refused,
            nokey(proc_::ORDER, DOMAIN, "passwd.byname", "order"),
            nokey(proc_::ALL, DOMAIN, "big.map", "all"),
        ]),
    )
    .await;
    assert_eq!(stat(&r[0]), "YP_TRUE");
    assert_eq!(r[0]["result"]["val"], ALICE);
    assert_eq!(r[1]["result"], 1);
    assert_eq!(r[2]["timeout"], true, "DOMAIN_NONACK says only yes: {r:?}");
    assert_eq!(stat(&r[3]), "YP_TRUE");
    assert_eq!(
        r[4]["result"],
        json!([{"stat": "YP_YPERR", "key": "", "val": ""}]),
        "100 KB of map does not fit a datagram: refused whole, not cut short"
    );
}

#[tokio::test]
async fn rpc_errors_bad_arguments_and_bounds() {
    let s0 = support::start(support::policy(), None).await;
    let long_key = "k".repeat(wire::YPMAXRECORD + 1);
    let long_domain = "d".repeat(wire::YPMAXDOMAIN + 1);
    let mut v1 = call(proc_::NULL, vec![], "void");
    v1["vers"] = json!(1);
    let mut other = call(proc_::NULL, vec![], "void");
    other["prog"] = json!(100_003);
    let r = yp_raw(
        s0.port,
        "tcp",
        json!([
            v1,
            other,
            call(proc_::XFR, vec![], "void"),
            call(12, vec![], "void"),
            key(proc_::MATCH, DOMAIN, "passwd.byname", &long_key, "val"),
            call(proc_::DOMAIN, vec![s(&long_domain)], "bool"),
            key(proc_::MATCH, "", "passwd.byname", "alice", "val"),
            key(proc_::MATCH, DOMAIN, "../etc", "alice", "val"),
            key(proc_::MATCH, DOMAIN, "passwd.byname", "", "val"),
            nokey(proc_::ALL, DOMAIN, "bad\tmap", "all"),
            call(proc_::DOMAIN, vec![s("")], "bool"),
            key(proc_::MATCH, DOMAIN, "passwd.byname", "alice", "val"),
            // ypmatch retries a missing key with its C terminator appended.
            key(proc_::MATCH, DOMAIN, "passwd.byname", "mallory\u{0}", "val"),
            key(proc_::MATCH, DOMAIN, "passwd.byname", "mal\u{1}lory", "val"),
        ]),
    )
    .await;
    assert_eq!(
        (r[0]["accept_stat"].as_u64(), &r[0]["low_high"]),
        (Some(2), &json!([2, 2])),
        "PROG_MISMATCH 2-2"
    );
    assert_eq!(r[1]["accept_stat"], 1, "PROG_UNAVAIL");
    assert_eq!(r[2]["accept_stat"], 3, "XFR is PROC_UNAVAIL");
    assert_eq!(r[3]["accept_stat"], 3, "PROC_UNAVAIL");
    assert_eq!(
        r[4]["accept_stat"], 4,
        "a key past YPMAXRECORD is GARBAGE_ARGS"
    );
    assert_eq!(
        r[5]["accept_stat"], 4,
        "a domain past YPMAXDOMAIN is GARBAGE_ARGS"
    );
    assert_eq!(stat(&r[6]), "YP_BADARGS");
    assert_eq!(stat(&r[7]), "YP_BADARGS", "a map name with / is refused");
    assert_eq!(stat(&r[8]), "YP_BADARGS", "an empty key");
    assert_eq!(
        r[9]["result"],
        json!([{"stat": "YP_BADARGS", "key": "", "val": ""}])
    );
    assert_eq!(r[10]["result"], 0, "DOMAIN of an empty name is false");
    assert_eq!(stat(&r[11]), "YP_TRUE", "the connection survives all of it");
    assert_eq!(
        stat(&r[12]),
        "YP_NOKEY",
        "a trailing NUL is the key's terminator, not a bad argument"
    );
    assert_eq!(stat(&r[13]), "YP_BADARGS", "any other control character");
    let asked: Vec<Value> = support::events(&s0.state, s0.id, "nis_match").await;
    assert_eq!(
        asked.iter().map(|e| e["key"].clone()).collect::<Vec<_>>(),
        [json!("mallory"), json!("alice")],
        "no refused call reached the model, and the NUL never does"
    );

    // RPC version 3: MSG_DENIED / RPC_MISMATCH.
    let mut rpc3 = call(proc_::NULL, vec![], "void");
    rpc3["rpcvers"] = json!(3);
    let r = yp_raw(s0.port, "udp", json!([rpc3])).await;
    assert_eq!(r[0]["reply_stat"], 1);
    assert_eq!(r[0]["words"], json!([0, 2, 2]));

    // A record announcing more than MAX_CALL closes the connection unread.
    let mut c = tokio::net::TcpStream::connect(("127.0.0.1", s0.port))
        .await
        .unwrap();
    let too_big = 0x8000_0000u32 | (wire::MAX_CALL as u32 + 1);
    c.write_all(&too_big.to_be_bytes()).await.unwrap();
    let mut rest = Vec::new();
    let n = tokio::time::timeout(Duration::from_secs(10), c.read_to_end(&mut rest))
        .await
        .unwrap()
        .unwrap_or(0);
    assert_eq!(n, 0, "{rest:?}");

    // So does a call split into more than MAX_CALL_FRAGMENTS fragments.
    let mut c = tokio::net::TcpStream::connect(("127.0.0.1", s0.port))
        .await
        .unwrap();
    let null: Vec<u8> = [9u32, 0, 2, wire::PROGRAM, 2, 0, 0, 0, 0, 0]
        .iter()
        .flat_map(|v| v.to_be_bytes())
        .collect();
    let mut frags = Vec::new();
    for (i, b) in null.chunks(4).enumerate() {
        let last = if i == null.len() / 4 - 1 {
            0x8000_0000
        } else {
            0
        };
        frags.extend((last | 4u32).to_be_bytes());
        frags.extend(b);
    }
    assert!(null.len() / 4 > wire::MAX_CALL_FRAGMENTS);
    c.write_all(&frags).await.unwrap();
    let mut rest = Vec::new();
    let n = tokio::time::timeout(Duration::from_secs(10), c.read_to_end(&mut rest))
        .await
        .unwrap()
        .unwrap_or(0);
    assert_eq!(n, 0, "{rest:?}");

    // The same call in MAX_CALL_FRAGMENTS fragments is answered.
    let mut c = tokio::net::TcpStream::connect(("127.0.0.1", s0.port))
        .await
        .unwrap();
    let mut frags = Vec::new();
    let pieces = null
        .chunks(null.len() / wire::MAX_CALL_FRAGMENTS + 1)
        .count();
    assert!(pieces <= wire::MAX_CALL_FRAGMENTS);
    for (i, b) in null
        .chunks(null.len() / wire::MAX_CALL_FRAGMENTS + 1)
        .enumerate()
    {
        let last = if i + 1 == pieces { 0x8000_0000 } else { 0 };
        frags.extend((last | b.len() as u32).to_be_bytes());
        frags.extend(b);
    }
    c.write_all(&frags).await.unwrap();
    let h = c.read_u32().await.unwrap();
    assert_eq!(h, 0x8000_0000 | 24, "an accepted NULL reply");
}

#[tokio::test]
async fn model_answers_that_would_forge_lines_or_overflow_fail_closed() {
    let s0 = support::start(support::policy(), None).await;
    let r = yp_raw(
        s0.port,
        "tcp",
        json!([
            key(proc_::MATCH, DOMAIN, "broken.byname", "eve", "val"),
            nokey(proc_::ALL, DOMAIN, "huge.map", "all"),
        ]),
    )
    .await;
    // broken.byname is a generic map given passwd fields; were it rendered as passwd, the
    // gecos "x:0:0" would shift every field after it. Either way, no line is invented.
    assert_eq!(r[0]["result"], json!({"stat": "YP_YPERR", "val": ""}));
    assert_eq!(
        r[1]["result"],
        json!([{"stat": "YP_YPERR", "key": "", "val": ""}]),
        "{} entries is past MAX_ENTRIES",
        wire::MAX_ENTRIES + 1
    );

    // A passwd entry whose gecos holds ':' is refused rather than rendered.
    let colon = json!([{"event_pattern":"*","handler":{"type":"static","actions":[
        {"type":"nis_entries","entries":[{"name":"eve","uid":0,"gid":0,"gecos":"x:0:0:root","home":"/","shell":"/bin/sh"}]}]}}]);
    let s1 = support::start(Some(colon.as_array().unwrap().clone()), None).await;
    let r = yp_raw(
        s1.port,
        "tcp",
        json!([key(proc_::MATCH, DOMAIN, "passwd.byname", "eve", "val")]),
    )
    .await;
    assert_eq!(r[0]["result"], json!({"stat": "YP_YPERR", "val": ""}));
}

#[tokio::test]
async fn a_failed_model_fails_closed_and_invents_nothing() {
    // No handler, and a model that cannot be reached.
    let s0 = support::start(None, None).await;
    let r = yp_raw(
        s0.port,
        "tcp",
        json!([
            key(proc_::MATCH, DOMAIN, "passwd.byname", "root", "val"),
            nokey(proc_::ALL, DOMAIN, "passwd.byname", "all"),
            nokey(proc_::FIRST, DOMAIN, "passwd.byname", "key_val"),
            nokey(proc_::MASTER, DOMAIN, "passwd.byname", "master"),
            call(proc_::MAPLIST, vec![s(DOMAIN)], "maplist"),
            call(proc_::DOMAIN, vec![s(DOMAIN)], "bool"),
        ]),
    )
    .await;
    assert_eq!(r[0]["result"], json!({"stat": "YP_YPERR", "val": ""}));
    assert_eq!(
        r[1]["result"],
        json!([{"stat": "YP_YPERR", "key": "", "val": ""}])
    );
    assert_eq!(
        r[2]["result"],
        json!({"stat": "YP_YPERR", "key": "", "val": ""})
    );
    assert_eq!(r[3]["result"], json!({"stat": "YP_YPERR", "peer": ""}));
    assert_eq!(r[4]["result"], json!({"stat": "YP_YPERR", "maps": []}));
    assert_eq!(r[5]["result"], 0, "a failed DOMAIN is false");
    let mut nonack = call(proc_::DOMAIN_NONACK, vec![s(DOMAIN)], "bool");
    nonack["udp_timeout"] = json!(5);
    let r = yp_raw(s0.port, "udp", json!([nonack])).await;
    assert_eq!(r[0]["timeout"], true, "a failed DOMAIN_NONACK is silent");
}

/// A portmapper that is NetGet's own sunrpc server: the registration the NIS server makes at
/// start and removes at stop, as the portmapper's model was shown them.
#[tokio::test]
async fn registers_with_a_portmapper_and_removes_itself_at_stop() {
    let accept = json!([{"event_pattern":"*","handler":{"type":"static","actions":[{"type":"sunrpc_accept"}]}}]);
    let (pm_state, pm_id, pm_port) = start_portmapper(accept).await;
    let s0 = support::start(
        support::policy(),
        Some(json!({"portmapper": format!("127.0.0.1:{pm_port}")})),
    )
    .await;
    let regs = registrations(&pm_state, pm_id).await;
    let mut sets: Vec<(String, u64)> = regs
        .iter()
        .filter(|r| r["operation"] == "set")
        .map(|r| {
            assert_eq!(r["program"], wire::PROGRAM);
            assert_eq!(r["program_name"], "ypserv");
            assert_eq!(r["program_version"], 2);
            (
                r["protocol"].as_str().unwrap().to_string(),
                r["port"].as_u64().unwrap(),
            )
        })
        .collect();
    sets.sort();
    assert_eq!(
        sets,
        [
            ("tcp".to_string(), u64::from(s0.port)),
            ("udp".to_string(), u64::from(s0.port))
        ]
    );
    s0.state.remove_server(s0.id).await;
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if registrations(&pm_state, pm_id)
                .await
                .iter()
                .any(|r| r["operation"] == "unset" && r["program"] == wire::PROGRAM)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("an UNSET when the server stops");

    // A portmapper that refuses: the server does not start.
    let refuse = json!([{"event_pattern":"*","handler":{"type":"static","actions":[{"type":"sunrpc_reject"}]}}]);
    let (_s, _i, refusing) = start_portmapper(refuse).await;
    let err = support::try_start(
        support::policy(),
        Some(json!({"portmapper": format!("127.0.0.1:{refusing}")})),
    )
    .await
    .err()
    .expect("a refused registration fails the start");
    assert!(format!("{err:#}").contains("refused"), "{err:#}");
}

async fn start_portmapper(
    handlers: Value,
) -> (
    netget::state::app_state::AppState,
    netget::state::ServerId,
    u16,
) {
    let state =
        netget::state::app_state::AppState::new_with_options(false, "http://127.0.0.1:1".into());
    state
        .set_llm_client(netget::llm::OllamaClient::new("http://127.0.0.1:1"))
        .await;
    let (tx, _) = tokio::sync::mpsc::unbounded_channel();
    let id = netget::cli::management::ServerForm {
        protocol: "sunrpc".into(),
        port: Some(0),
        host: Some("127.0.0.1".into()),
        instruction: Some("Be a portmapper".into()),
        event_handlers: Some(handlers.as_array().unwrap().clone()),
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .unwrap();
    let port = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Some(a) = state.get_server(id).await.and_then(|s| s.local_addr) {
                break a.port();
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    (state, id, port)
}

async fn registrations(
    state: &netget::state::app_state::AppState,
    id: netget::state::ServerId,
) -> Vec<Value> {
    state
        .list_access_logs_for(
            Some(netget::state::AccessLogOwner::Server(id.as_u32())),
            None,
        )
        .await
        .iter()
        .map(|e| serde_json::to_value(e).unwrap())
        .filter(|e| e["event_type"] == "sunrpc_register")
        .map(|e| e["request"].clone())
        .collect()
}

fn rpc_call(xid: u32, procedure: u32, args: &[u8]) -> Vec<u8> {
    let mut m: Vec<u8> = [xid, 0, 2, wire::PROGRAM, 2, procedure, 0, 0, 0, 0]
        .iter()
        .flat_map(|v| v.to_be_bytes())
        .collect();
    m.extend_from_slice(args);
    m
}

/// tshark's rpc and ypserv dissectors read every call and reply, over TCP and UDP, and find
/// the fields where `yp.x` puts them.
#[tokio::test]
async fn replies_through_the_pcap_oracle() {
    let s0 = support::start(support::policy(), None).await;
    let calls = [
        rpc_call(1, proc_::DOMAIN, &wire::req_domain(DOMAIN)),
        rpc_call(
            2,
            proc_::MATCH,
            &wire::req_key(DOMAIN, "passwd.byname", "alice"),
        ),
        rpc_call(3, proc_::FIRST, &wire::req_nokey(DOMAIN, "group.byname")),
        rpc_call(
            4,
            proc_::NEXT,
            &wire::req_key(DOMAIN, "group.byname", "staff"),
        ),
        rpc_call(5, proc_::ALL, &wire::req_nokey(DOMAIN, "passwd.byname")),
        rpc_call(6, proc_::ALL, &wire::req_nokey(DOMAIN, "nomap")),
        rpc_call(7, proc_::MASTER, &wire::req_nokey(DOMAIN, "passwd.byname")),
        rpc_call(8, proc_::ORDER, &wire::req_nokey(DOMAIN, "passwd.byname")),
        rpc_call(9, proc_::MAPLIST, &wire::req_domain(DOMAIN)),
    ];
    let mut c = tokio::net::TcpStream::connect(("127.0.0.1", s0.port))
        .await
        .unwrap();
    let mut exchanged = Vec::new();
    for m in &calls {
        let mut rec = (0x8000_0000u32 | m.len() as u32).to_be_bytes().to_vec();
        rec.extend_from_slice(m);
        c.write_all(&rec).await.unwrap();
        let h = c.read_u32().await.unwrap();
        let mut body = vec![0u8; (h & 0x7fff_ffff) as usize];
        c.read_exact(&mut body).await.unwrap();
        let mut reply = h.to_be_bytes().to_vec();
        reply.extend(body);
        exchanged.push((rec, reply));
    }
    let oracle = || {
        exchanged.iter().fold(
            crate::helpers::pcap_oracle::PcapOracle::tcp("nis")
                .port(s0.port)
                .also_named("ypserv"),
            |o, (call, reply)| o.to_server(call).from_server(reply),
        )
    };
    oracle().assert_clean();
    let rows = oracle()
        .fields(&[
            "ypserv.procedure_v2",
            "ypserv.status",
            "ypserv.value",
            "ypserv.key",
            "ypserv.peer",
            "ypserv.map",
        ])
        .unwrap();
    let row = |i: usize| rows.iter().filter(|r| r[0] != "").nth(i).cloned();
    // Replies are the even rows after each call: call i is row 2i, its reply 2i+1.
    let reply = |i: usize| row(2 * i + 1).unwrap_or_else(|| panic!("{rows:?}"));
    assert_eq!(reply(1)[2], ALICE, "MATCH value: {rows:?}");
    assert_eq!(
        (reply(2)[2].as_str(), reply(2)[3].as_str()),
        ("staff:x:100:alice,bob", "staff"),
        "FIRST: tshark reads the value before the key, as yp.x has it: {rows:?}"
    );
    assert_eq!(reply(3)[3], "wheel", "NEXT after staff: {rows:?}");
    assert!(reply(4)[2].contains(ALICE), "ALL: {rows:?}");
    assert_eq!(reply(6)[4], "nis-master", "MASTER: {rows:?}");
    assert!(reply(8)[5].contains("passwd.byname"), "MAPLIST: {rows:?}");

    // And over UDP.
    let u = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut oracle = crate::helpers::pcap_oracle::PcapOracle::udp("nis")
        .port(s0.port)
        .also_named("ypserv");
    for m in &calls[..4] {
        u.send_to(m, ("127.0.0.1", s0.port)).await.unwrap();
        let mut buf = vec![0u8; 65_536];
        let n = tokio::time::timeout(Duration::from_secs(20), u.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();
        oracle = oracle.to_server(m).from_server(&buf[..n]);
    }
    oracle.assert_clean();
}
