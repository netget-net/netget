//! NetGet's DNS client against ISC BIND's **`named`**, a third-party authoritative server,
//! spawned unprivileged on loopback with a zone it signs itself (`dnssec-policy default`,
//! inline signing). Nothing on the wire was written by this repository except NetGet.
//!
//! A script handler plays the model: on `dns_connected` it asks for `www.example.org A` with
//! `dnssec`, and on that answer it asks for the zone (AXFR). The test then changes the zone,
//! reloads named, and injects an IXFR from the old serial through the command channel. Every
//! result is checked twice — against what `dig` reads from the same server, and against named's
//! own log of the transfers it served, which is condition 4 of the client bar asserted from the
//! server's side.
//!
//! **No test here skips.** A missing `named` or `dig` fails with the package to install.


use crate::helpers::real_server::{run_tool, InstallHint, RealServer};
use crate::helpers::E2EResult;
use netget::cli::management::ClientForm;
use netget::state::app_state::AppState;
use netget::state::{AccessLogOwner, ClientId};
use serde_json::{json, Value};
use std::process::Command;
use std::time::Duration;

const BIND: InstallHint = InstallHint {
    brew: "bind",
    apt: "bind9 bind9-dnsutils",
};

const ZONE_V1: &str = "$TTL 300
@ IN SOA ns1.example.org. hostmaster.example.org. 100 3600 600 604800 300
@ IN NS ns1.example.org.
ns1 IN A 192.0.2.53
www IN A 192.0.2.80
mail IN A 192.0.2.25
@ IN MX 10 mail.example.org.
";

/// `named` in the foreground, logging to stderr, on `{port}` only, transfers allowed, and the
/// zone signed inline with BIND's default policy (ECDSA P-256). `ixfr-from-differences` makes
/// a reload of the edited file produce an IXFR difference rather than a new full zone.
async fn start_named() -> E2EResult<RealServer> {
    RealServer::builder("named", BIND)
        .config_file("example.org.zone", ZONE_V1)
        .config_file(
            "named.conf",
            r#"options {
  directory "{dir}";
  listen-on port {port} { 127.0.0.1; };
  listen-on-v6 { none; };
  pid-file "{dir}/named.pid";
  recursion no;
  dnssec-validation no;
  allow-transfer { any; };
  ixfr-from-differences yes;
};
controls { };
zone "example.org" {
  type primary;
  file "{dir}/example.org.zone";
  dnssec-policy default;
  inline-signing yes;
  key-directory "{dir}";
};
"#,
        )
        .args(["-g", "-c", "{dir}/named.conf"])
        .ready_when_log_matches(r"zone example\.org/IN \(signed\): (loaded|sending notifies)")
        .startup_timeout(Duration::from_secs(30))
        .start()
        .await
}

async fn dig(server: &RealServer, args: &[&str]) -> E2EResult<String> {
    let mut cmd = Command::new("dig");
    cmd.args(["@127.0.0.1", "-p", &server.port.to_string(), "+tries=1"])
        .args(args);
    run_tool(cmd, "dig", BIND).await
}

/// The signed serial named serves now.
async fn serial(server: &RealServer) -> E2EResult<u32> {
    let out = dig(server, &["+short", "example.org.", "SOA"]).await?;
    Ok(out
        .split_whitespace()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| format!("no SOA serial in {out:?}"))?)
}

const HANDLER: &str = r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']; e=i['event']
if t=='dns_connected': a=[{'type':'send_dns_query','domain':'www.example.org.','query_type':'A','dnssec':True,'recursion_desired':False}]
elif t=='dns_response_received' and e['domain'].startswith('www'): a=[{'type':'send_dns_zone_transfer','zone':'example.org.'}]
else: a=[]
print(json.dumps({'actions':a}))"#;

async fn events(state: &AppState, id: ClientId, kind: &str) -> Vec<Value> {
    let mut rows: Vec<Value> = state
        .list_access_logs_for(Some(AccessLogOwner::Client(id.as_u32())), None)
        .await
        .iter()
        .map(|e| serde_json::to_value(e).unwrap())
        .filter(|e| e["event_type"] == kind)
        .collect();
    rows.sort_by_key(|e| e["id"].as_u64());
    rows.into_iter().map(|e| e["request"].clone()).collect()
}

async fn wait_for(state: &AppState, id: ClientId, kind: &str, n: usize) -> Vec<Value> {
    tokio::time::timeout(Duration::from_secs(45), async {
        loop {
            let found = events(state, id, kind).await;
            if found.len() >= n {
                break found;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("no {kind} reached the handler"))
}

#[tokio::test]
async fn dns_client_queries_with_dnssec_and_transfers_from_bind() -> E2EResult<()> {
    let server = start_named().await?;
    let result = exercise(&server).await;
    server.with_log(result)
}

async fn exercise(server: &RealServer) -> E2EResult<()> {
    // Inline signing may bump the serial once more after "loaded"; wait until it settles.
    let mut old_serial = serial(server).await?;
    for _ in 0..20 {
        tokio::time::sleep(Duration::from_millis(250)).await;
        let now = serial(server).await?;
        if now == old_serial {
            break;
        }
        old_serial = now;
    }

    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    let (tx, _) = tokio::sync::mpsc::unbounded_channel();
    let id = ClientForm {
        protocol: "dns".into(),
        remote_addr: Some(server.addr()),
        instruction: Some("Look up www, then transfer the zone".into()),
        event_handlers: Some(vec![json!({
            "event_pattern": "*",
            "handler": {"type": "script", "language": "python", "code": HANDLER}
        })]),
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
        tx,
    )
    .await
    .map_err(|e| format!("create dns client: {e}"))?;

    // The DO query: the A record and named's signature over it.
    let answer = wait_for(&state, id, "dns_response_received", 1)
        .await
        .remove(0);
    let answers = answer["answers"].as_array().unwrap();
    assert!(
        answers
            .iter()
            .any(|a| a["type"] == "A" && a["ip"] == "192.0.2.80"),
        "{answer}"
    );
    let rrsig = answers
        .iter()
        .find(|a| a["type"] == "RRSIG")
        .unwrap_or_else(|| panic!("named signed the answer for a DO query: {answer}"));
    assert_eq!(rrsig["type_covered"], "A");
    assert_eq!(rrsig["algorithm"], 13);
    assert_eq!(rrsig["signer"], "example.org.");

    // The AXFR the handler asked for: the same records dig counts, DNSKEY and NSEC included.
    let axfr = wait_for(&state, id, "dns_zone_transfer_received", 1)
        .await
        .remove(0);
    assert_eq!(axfr["form"], "full", "{axfr}");
    assert_eq!(axfr["serial"], old_serial);
    let dig_axfr = dig(
        server,
        &["+nocmd", "+nostats", "+nocomments", "axfr", "example.org."],
    )
    .await?;
    let dig_count = dig_axfr.lines().filter(|l| !l.trim().is_empty()).count();
    assert_eq!(
        axfr["record_count"], dig_count,
        "the same zone dig reads: {axfr}"
    );
    let types: Vec<&str> = axfr["records"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|r| r["type"].as_str())
        .collect();
    for t in ["SOA", "DNSKEY", "NSEC", "RRSIG", "MX"] {
        assert!(types.contains(&t), "{t} in the transfer: {types:?}");
    }

    // Change the zone and reload: named computes the difference and signs it.
    let zone = server.dir().join("example.org.zone");
    std::fs::write(
        &zone,
        ZONE_V1
            .replace(" 100 3600", " 101 3600")
            .replace("192.0.2.80", "192.0.2.81"),
    )?;
    let pid: i32 = std::fs::read_to_string(server.dir().join("named.pid"))?
        .trim()
        .parse()?;
    nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(pid),
        nix::sys::signal::Signal::SIGHUP,
    )?;
    let mut new_serial = old_serial;
    for _ in 0..80 {
        tokio::time::sleep(Duration::from_millis(250)).await;
        new_serial = serial(server).await?;
        if new_serial != old_serial
            && dig(server, &["+short", "www.example.org."])
                .await?
                .contains("192.0.2.81")
        {
            break;
        }
    }
    assert_ne!(new_serial, old_serial, "named reloaded the edited zone");

    // IXFR from the old serial, injected as the dashboard's [ send ] would.
    state
        .send_to_client(
            id,
            json!({"type": "send_dns_zone_transfer", "zone": "example.org.", "serial": old_serial}),
            Duration::from_secs(60),
        )
        .await?;
    let ixfr = wait_for(&state, id, "dns_zone_transfer_received", 2)
        .await
        .remove(1);
    assert_eq!(ixfr["transfer_type"], "IXFR", "{ixfr}");
    assert_eq!(ixfr["form"], "incremental", "{ixfr}");
    assert_eq!(ixfr["serial"], new_serial);
    let records = ixfr["records"].as_array().unwrap();
    let ip_pos = |ip: &str| {
        records
            .iter()
            .position(|r| r["type"] == "A" && r["ip"] == ip)
    };
    let (deleted, added) = (ip_pos("192.0.2.80"), ip_pos("192.0.2.81"));
    assert!(
        deleted.is_some() && added.is_some() && deleted < added,
        "the old address deleted before the new one is added: {ixfr}"
    );
    // Smaller than the zone: a difference, not the zone again.
    assert!(ixfr["record_count"].as_u64() < axfr["record_count"].as_u64());

    // named's own account of what it served, in its log.
    let log = server.log();
    assert!(
        log.contains("AXFR started") || log.contains("AXFR ended"),
        "named served the AXFR"
    );
    assert!(
        log.contains("IXFR started") || log.contains("IXFR ended"),
        "named served the IXFR"
    );
    Ok(())
}
