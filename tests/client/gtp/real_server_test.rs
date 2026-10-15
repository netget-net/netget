//! NetGet's GTP client as an SGW on S5/S8 against **wmnsk/go-gtp** playing the PGW
//! (`gtp-peer pgw`, built by `tests/client/gtp/install_peers.py`; `NETGET_GTP_GO_PEER` names
//! it). The peer parses every datagram with go-gtp and prints what it decoded, so the
//! assertions are on what an independent implementation read off NetGet's bytes — and every
//! answer NetGet acted on was encoded by go-gtp. Fails rather than skips without it. No LLM
//! calls: a script handler plays the model, and every step of the chain is the model's action
//! taken on the previous step's event.
//!
//! The chain: echo the path; on the echo response create a session; on acceptance send an ICMP
//! echo request through the tunnel and echo the user plane; on the echo reply that comes back
//! through the tunnel modify the bearer; on acceptance send an End Marker and delete the
//! session. The PGW drops the first Create Session Request, probes NetGet with Echo Requests
//! on both planes, and sends one G-PDU to a TEID NetGet never gave out, which the model answers
//! with an Error Indication.
use crate::helpers::pcap_oracle::PcapOracle;
use netget::cli::management::ClientForm;
use netget::state::app_state::AppState;
use netget::state::client_handles::ClientSendOutcome;
use netget::state::{AccessLogOwner, ClientId};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::AsyncBufReadExt;
use tokio::sync::mpsc;

const CHAIN: &str = r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']; e=i['event']
a=[]
if t=='gtp_client_ready':
  a=[{'type':'gtp_echo','plane':'control'}]
elif t=='gtp_response':
  r=e.get('request')
  if r=='echo_request' and e.get('plane')!='user':
    a=[{'type':'gtp_create_session','imsi':'001010123456789','apn':'internet','msisdn':'15551234567',
        'mei':'3534900698733190','mcc':'001','mnc':'01','pdn_type':'ipv4','ebi':5,'rat_type':'EUTRAN',
        'ambr_uplink_kbps':20000,'ambr_downlink_kbps':80000,
        'qos':{'qci':9,'arp_priority_level':2,'pre_emption_capability':True,'pre_emption_vulnerability':False,
               'mbr_uplink_kbps':1000,'mbr_downlink_kbps':4000,'gbr_uplink_kbps':500,'gbr_downlink_kbps':2000}}]
  elif r=='create_session' and e.get('accepted'):
    a=[{'type':'gtp_send_gpdu','session':e['session'],'destination':'10.45.0.1','protocol':'icmp_echo',
        'identifier':7,'sequence':1,'payload':'hello through the tunnel'},
       {'type':'gtp_echo','plane':'user'}]
  elif r=='modify_bearer' and e.get('accepted'):
    a=[{'type':'gtp_send_end_marker','session':e['session']},{'type':'gtp_delete_session','session':e['session']}]
elif t=='gtp_tunnel_packet':
  icmp=e['inner'].get('icmp') or {}
  if e['known_tunnel'] and icmp.get('type_name')=='echo_reply':
    a=[{'type':'gtp_modify_bearer','session':e['session']}]
  elif not e['known_tunnel']:
    a=[{'type':'gtp_send_error_indication','teid':e['teid']}]
print(json.dumps({'actions':a}))"#;

type Lines = Arc<Mutex<Vec<Value>>>;

async fn wait_line(lines: &Lines, what: &str, pred: impl Fn(&Value) -> bool) -> Value {
    let found = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if let Some(v) = lines.lock().unwrap().iter().find(|v| pred(v)).cloned() {
                return v;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await;
    found.unwrap_or_else(|_| {
        panic!(
            "the peer never reported {what}; it printed:\n{}",
            lines
                .lock()
                .unwrap()
                .iter()
                .map(|l| {
                    let mut l = l.clone();
                    l.as_object_mut().map(|o| o.remove("raw"));
                    l.to_string()
                })
                .collect::<Vec<_>>()
                .join("\n")
        )
    })
}

pub async fn wait_event(state: &AppState, id: ClientId, pred: impl Fn(&Value) -> bool) -> Value {
    let found = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let hit = state
                .list_access_logs_for(Some(AccessLogOwner::Client(id.as_u32())), None)
                .await
                .iter()
                .map(|e| serde_json::to_value(e).unwrap())
                .find(|e| pred(e))
                .map(|e| e["request"].clone());
            if let Some(e) = hit {
                return e;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await;
    match found {
        Ok(e) => e,
        Err(_) => panic!(
            "no matching event; NetGet saw: {:?}",
            state
                .list_access_logs_for(Some(AccessLogOwner::Client(id.as_u32())), None)
                .await
                .iter()
                .map(|e| serde_json::to_value(e).unwrap())
                .map(|e| format!("{} {}", e["event_type"], e["request"]))
                .collect::<Vec<_>>()
        ),
    }
}

fn hex_of(v: &Value) -> Vec<u8> {
    hex::decode(v["raw"].as_str().expect("raw")).expect("hex")
}

#[tokio::test]
async fn netget_sgw_against_go_gtp_pgw() {
    let peer = std::env::var("NETGET_GTP_GO_PEER").unwrap_or_default();
    assert!(
        !peer.is_empty() && std::path::Path::new(&peer).exists(),
        "NETGET_GTP_GO_PEER must name the go-gtp peer: python3 tests/client/gtp/install_peers.py <dir> (needs Go 1.24+)"
    );
    let mut pgw = tokio::process::Command::new(peer)
        .arg("pgw")
        .stdout(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut out = tokio::io::BufReader::new(pgw.stdout.take().unwrap()).lines();
    let first: Value = serde_json::from_str(&out.next_line().await.unwrap().unwrap()).unwrap();
    let control = first["listening"].as_str().unwrap().to_string();
    let user_port: u16 = first["user"]
        .as_str()
        .unwrap()
        .rsplit(':')
        .next()
        .unwrap()
        .parse()
        .unwrap();
    let lines: Lines = Arc::new(Mutex::new(Vec::new()));
    let sink = lines.clone();
    tokio::spawn(async move {
        while let Ok(Some(l)) = out.next_line().await {
            let v: Value = serde_json::from_str(&l)
                .unwrap_or_else(|e| json!({"unreadable": l, "error": e.to_string()}));
            sink.lock().unwrap().push(v);
        }
    });

    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    let (tx, _) = mpsc::unbounded_channel();
    let id = ClientForm {
        protocol: "gtp".into(),
        remote_addr: Some(control.clone()),
        instruction: Some("Run one session through its life".into()),
        startup_params: Some(json!({"interface": "s5", "user_plane_port": 0,
            "peer_user_plane_port": user_port, "t3_response_ms": 400, "n3_requests": 3})),
        event_handlers: Some(vec![json!({"event_pattern":"*","handler":{"type":"script","language":"python","code":CHAIN}})]),
        ..Default::default()
    }
    .create(&state, netget::llm::OllamaClient::new("http://127.0.0.1:1"), tx)
    .await
    .expect("connect");

    // 1. Echo on the control plane, Recovery carried both ways.
    let echo = wait_line(&lines, "an echo request", |v| v["got"] == "echo_request").await;
    assert_eq!(echo["recovery"], 0, "{echo}");
    let echoed = wait_event(&state, id, |e| {
        e["event_type"] == "gtp_response"
            && e["request"]["request"] == "echo_request"
            && e["request"]["plane"].is_null()
    })
    .await;
    assert_eq!(echoed["recovery"], 5, "{echoed}");

    // 2. Create Session: the first copy was dropped, the retransmission is byte-identical, and
    //    go-gtp read every IE the model asked for.
    let first_copy = wait_line(&lines, "a create session request", |v| {
        v["got"] == "create_session" && v["copy"] == 1
    })
    .await;
    let second_copy = wait_line(&lines, "a retransmitted create session request", |v| {
        v["got"] == "create_session" && v["copy"] == 2
    })
    .await;
    assert_eq!(
        first_copy["raw"], second_copy["raw"],
        "a retransmission must be the same datagram"
    );
    let created = wait_event(&state, id, |e| {
        e["event_type"] == "gtp_response" && e["request"]["request"] == "create_session"
    })
    .await;
    let local_c = created["local_control_teid"]
        .as_u64()
        .expect("local_control_teid");
    let local_u = created["local_data_teid"]
        .as_u64()
        .expect("local_data_teid");
    let c = &second_copy;
    assert_eq!(c["header_teid"], 0, "{c}");
    assert_eq!(c["imsi"], "001010123456789", "{c}");
    assert_eq!(c["msisdn"], "15551234567", "{c}");
    assert_eq!(c["mei"], "3534900698733190", "{c}");
    assert_eq!(
        (c["mcc"].clone(), c["mnc"].clone()),
        (json!("001"), json!("01")),
        "{c}"
    );
    assert_eq!(c["rat_type"], 6, "{c}");
    assert_eq!(c["apn"], "internet", "{c}");
    assert_eq!(c["selection_mode"], 0, "{c}");
    assert_eq!(c["pdn_type"], 1, "{c}");
    assert_eq!(c["paa"], "0100000000", "{c}");
    assert_eq!(c["ambr"], json!([20000, 80000]), "{c}");
    assert_eq!(c["pco_containers"], json!([13]), "{c}");
    assert_eq!(c["recovery"], 0, "{c}");
    assert_eq!(
        c["sender_fteid"],
        json!({"instance": 0, "interface_type": 6, "teid": local_c, "ipv4": "127.0.0.1"}),
        "{c}"
    );
    assert_eq!(c["bearer"]["ebi"], 5, "{c}");
    assert_eq!(
        c["bearer"]["fteids"],
        json!([{"instance": 2, "interface_type": 4, "teid": local_u, "ipv4": "127.0.0.1"}]),
        "{c}"
    );
    assert_eq!(
        c["bearer"]["qos"],
        json!({"qci": 9, "priority_level": 2, "pci": 0, "pvi": 1,
               "mbr_ul": 1000, "mbr_dl": 4000, "gbr_ul": 500, "gbr_dl": 2000}),
        "{c}"
    );
    // ... and NetGet read go-gtp's answer.
    assert_eq!(created["accepted"], true, "{created}");
    assert_eq!(created["cause"], "request_accepted", "{created}");
    assert_eq!(created["ue_address"], "10.45.0.7", "{created}");
    assert_eq!(created["peer_control_teid"], 0x0A0B_0C01, "{created}");
    assert_eq!(created["peer_data_teid"], 0x0A0B_0C02, "{created}");
    assert_eq!(created["peer_data_address"], "127.0.0.1", "{created}");
    assert_eq!(created["dns_servers"], json!(["10.45.0.53"]), "{created}");
    assert_eq!(created["ambr_uplink_kbps"], 50000, "{created}");
    assert_eq!(created["ambr_downlink_kbps"], 150000, "{created}");
    assert_eq!(created["recovery"], 5, "{created}");
    assert_eq!(created["bearer"]["charging_id"], 77, "{created}");
    assert_eq!(created["bearer"]["ebi"], 5, "{created}");
    let session = created["session"].as_u64().expect("session");

    // 3. NetGet answered the PGW's control-plane Echo Request in Rust.
    let probe = wait_line(&lines, "NetGet's echo response", |v| {
        v["got"] == "echo_response"
    })
    .await;
    assert_eq!(
        (probe["seq"].clone(), probe["recovery"].clone()),
        (json!(0xABCD), json!(0)),
        "{probe}"
    );

    // 4. The G-PDU, as go-gtp and a host-style reading of the inner packet saw it.
    let gpdu = wait_line(&lines, "a G-PDU", |v| v["got"] == "gpdu").await;
    assert_eq!(gpdu["teid"], 0x0A0B_0C02, "{gpdu}");
    assert_eq!(
        gpdu["inner"],
        json!({"ipv4": true, "length_ok": true, "src": "10.45.0.7", "dst": "10.45.0.1", "protocol": 1,
               "ttl": 64, "ip_checksum_ok": true, "icmp_type": 8, "icmp_id": 7, "icmp_seq": 1,
               "icmp_checksum_ok": true, "payload": "hello through the tunnel"}),
        "{gpdu}"
    );
    // The echo reply came back on NetGet's own TEID and NetGet decoded it.
    let back = wait_event(&state, id, |e| {
        e["event_type"] == "gtp_tunnel_packet" && e["request"]["known_tunnel"] == true
    })
    .await;
    assert_eq!(back["teid"], local_u, "{back}");
    assert_eq!(back["session"], session, "{back}");
    let inner = &back["inner"];
    assert_eq!(
        (inner["source"].clone(), inner["destination"].clone()),
        (json!("10.45.0.1"), json!("10.45.0.7")),
        "{back}"
    );
    assert_eq!(inner["ipv4_header_checksum_ok"], true, "{back}");
    assert_eq!(
        inner["icmp"],
        json!({"type": 0, "type_name": "echo_reply", "code": 0, "identifier": 7, "sequence": 1, "checksum_ok": true}),
        "{back}"
    );
    assert_eq!(inner["payload"], "hello through the tunnel", "{back}");

    // 5. User plane echoes, both directions.
    let user_echo = wait_line(&lines, "NetGet's user-plane echo request", |v| {
        v["got"] == "user_echo_request"
    })
    .await;
    let user_echoed = wait_event(&state, id, |e| {
        e["event_type"] == "gtp_response" && e["request"]["plane"] == "user"
    })
    .await;
    assert_eq!(user_echoed["sequence"], user_echo["seq"], "{user_echoed}");
    assert_eq!(user_echoed["recovery"], 5, "{user_echoed}");
    let user_probe = wait_line(&lines, "NetGet's user-plane echo response", |v| {
        v["got"] == "user_echo_response"
    })
    .await;
    assert_eq!(
        (user_probe["seq"].clone(), user_probe["recovery"].clone()),
        (json!(0x0BEE), json!(0)),
        "{user_probe}"
    );

    // 6. The G-PDU to a TEID NetGet never gave out reached the model as an unknown tunnel, and
    //    the model's Error Indication names it.
    let stray = wait_event(&state, id, |e| {
        e["event_type"] == "gtp_tunnel_packet" && e["request"]["known_tunnel"] == false
    })
    .await;
    assert_eq!(stray["teid"], 0x00DE_AD00, "{stray}");
    let ind = wait_line(&lines, "an Error Indication", |v| {
        v["got"] == "error_indication"
    })
    .await;
    assert_eq!(
        (ind["teid_data_i"].clone(), ind["peer_address"].clone()),
        (json!(0x00DE_AD00), json!("127.0.0.1")),
        "{ind}"
    );

    // 7. Modify Bearer to the PGW's control TEID, naming NetGet's S5/S8-U endpoint.
    let modify = wait_line(&lines, "a modify bearer request", |v| {
        v["got"] == "modify_bearer"
    })
    .await;
    assert_eq!(modify["header_teid"], 0x0A0B_0C01, "{modify}");
    assert_eq!(
        modify["bearer"],
        json!({"ebi": 5, "fteids": [{"instance": 1, "interface_type": 4, "teid": local_u, "ipv4": "127.0.0.1"}]}),
        "{modify}"
    );
    // 8. End Marker on the PGW's TEID, then Delete Session.
    let marker = wait_line(&lines, "an End Marker", |v| v["got"] == "end_marker").await;
    assert_eq!(marker["teid"], 0x0A0B_0C02, "{marker}");
    let delete = wait_line(&lines, "a delete session request", |v| {
        v["got"] == "delete_session"
    })
    .await;
    assert_eq!(
        (delete["header_teid"].clone(), delete["linked_ebi"].clone()),
        (json!(0x0A0B_0C01), json!(5)),
        "{delete}"
    );
    let deleted = wait_event(&state, id, |e| {
        e["event_type"] == "gtp_response" && e["request"]["request"] == "delete_session"
    })
    .await;
    assert_eq!(deleted["accepted"], true, "{deleted}");

    // 9. The session is gone: an injected Modify is refused before anything is sent, and so is
    //    an IMSI that is not one.
    let outcome = state
        .send_to_client(
            id,
            json!({"type":"gtp_modify_bearer","session":session}),
            Duration::from_secs(5),
        )
        .await
        .unwrap();
    assert!(
        matches!(&outcome, ClientSendOutcome::Rejected { error } if error.contains("no session")),
        "{outcome:?}"
    );
    let outcome = state
        .send_to_client(
            id,
            json!({"type":"gtp_create_session","imsi":"12","apn":"internet"}),
            Duration::from_secs(5),
        )
        .await
        .unwrap();
    assert!(
        matches!(&outcome, ClientSendOutcome::Rejected { error } if error.contains("imsi")),
        "{outcome:?}"
    );
    // An injected echo is answered with the response's event data.
    let outcome = state
        .send_to_client(id, json!({"type":"gtp_echo"}), Duration::from_secs(10))
        .await
        .unwrap();
    assert!(
        matches!(&outcome, ClientSendOutcome::Executed { detail } if detail.contains("\"recovery\":5")),
        "{outcome:?}"
    );

    // 10. The pcap oracle: tshark's gtpv2 and gtp dissectors over both directions of both
    //     planes, NetGet's datagrams as the client side.
    let all = lines.lock().unwrap().clone();
    let mut c_oracle = PcapOracle::udp("gtp").port(2123).also_named("gtpv2");
    let mut u_oracle = PcapOracle::udp("gtp").port(2152);
    for v in &all {
        let Some(plane) = v["plane"].as_str() else {
            continue;
        };
        if v["raw"].is_null() {
            continue;
        }
        let bytes = hex_of(v);
        let ours = v.get("got").is_some();
        match (plane, ours) {
            ("control", true) => c_oracle = c_oracle.to_server(&bytes),
            ("control", false) => c_oracle = c_oracle.from_server(&bytes),
            ("user", true) => u_oracle = u_oracle.to_server(&bytes),
            (_, _) => u_oracle = u_oracle.from_server(&bytes),
        }
    }
    c_oracle.assert_clean();
    u_oracle.assert_clean();
}
