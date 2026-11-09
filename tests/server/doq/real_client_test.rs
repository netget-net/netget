//! Two independent DoQ clients against the DoQ server, each failing rather than skipping when
//! it is absent:
//!
//! - Knot `kdig +quic` (libngtcp2 + Knot's own DNS codec), which also verifies the server's
//!   certificate against the CA and hostname it is given.
//! - AdGuard `dnsproxy` (quic-go + miekg/dns) with the server as its `quic://` upstream: kdig
//!   asks dnsproxy over plain UDP, and dnsproxy carries each query to NetGet over DoQ (setting
//!   the id to 0 and restoring it). It is pointed at a self-signed certificate with
//!   `--insecure`, so it proves the framing and the DNS, not the certificate check kdig makes.
//!   `scripts/test-peers/install-dnsproxy.sh` installs the pinned release; set
//!   `NETGET_DNSPROXY_BIN` to it.
//!
//! The answers are distinctive (192.0.2.19, 2001:db8::19, NXDOMAIN for MX, SERVFAIL for an answer
//! with nothing sendable, an SRV record), so each can only have come from the script handler
//! below. Loopback only; nothing contacts external DNS.
use super::support::*;
use serde_json::json;
use std::process::Stdio;
use std::time::Duration;

const HANDLER: &str = r#"import json,sys
e=json.load(sys.stdin)['event']; d=e['domain'].rstrip('.').lower(); kind=e['query_type']
def respond(actions): print(json.dumps({'actions':actions}))
if d=='nothing.example': respond([{'type':'notify_operator','message':'nothing to send'}])
elif kind=='A': respond([{'type':'send_dns_a_response','domain':e['domain'],'query_id':0,'ip':'192.0.2.19','ttl':17}])
elif kind=='AAAA': respond([{'type':'send_dns_aaaa_response','domain':e['domain'],'query_id':0,'ip':'2001:db8::19','ttl':23}])
elif kind=='SRV': respond([{'type':'send_dns_records','query_id':0,'domain':e['domain'],'query_type':'SRV','answers':[{'type':'SRV','priority':0,'weight':5,'port':8853,'target':'doq.independent.example.'}]}])
else: respond([{'type':'send_dns_nxdomain','query_id':0,'domain':e['domain'],'query_type':kind}])"#;

/// What kdig answered, and the cases every client below is asked.
const CASES: [(&str, &str, &str); 5] = [
    ("independent.example", "A", "192.0.2.19"),
    ("independent.example", "AAAA", "2001:db8::19"),
    ("independent.example", "MX", "status: NXDOMAIN"),
    (
        "_dns._udp.independent.example",
        "SRV",
        "8853 doq.independent.example.",
    ),
    ("nothing.example", "A", "status: SERVFAIL"),
];

async fn fixture() -> Fixture {
    Fixture::new(
        json!({}),
        Some(json!({"type":"script","language":"python","code":HANDLER})),
    )
    .await
}

async fn kdig(args: &[String]) -> String {
    let output = tokio::time::timeout(
        Duration::from_secs(15),
        tokio::process::Command::new("kdig").args(args).output(),
    )
    .await
    .expect("kdig did not finish")
    .expect("kdig is required: brew install knot / apt install knot-dnsutils (with QUIC support)");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    assert!(
        output.status.success(),
        "kdig {args:?} failed: {stdout} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    stdout
}

#[tokio::test]
async fn kdig_over_quic_authenticates_the_server_and_reads_every_answer() {
    let f = fixture().await;
    for (name, kind, expected) in CASES {
        let stdout = kdig(&[
            "+quic".into(),
            format!("+tls-ca={}", f.dir.path().join("cert.pem").display()),
            "+tls-hostname=localhost".into(),
            "+timeout=5".into(),
            "+retry=0".into(),
            "@127.0.0.1".into(),
            "-p".into(),
            f.addr.port().to_string(),
            name.into(),
            kind.into(),
        ])
        .await;
        assert!(stdout.contains(expected), "{name} {kind}: {stdout}");
        assert!(stdout.contains("QUIC"), "kdig did not use QUIC: {stdout}");
    }
    f.close().await;
}

#[tokio::test]
async fn adguard_dnsproxy_carries_queries_to_the_server_over_doq() {
    let f = fixture().await;
    let port = std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let binary = std::env::var("NETGET_DNSPROXY_BIN").unwrap_or_else(|_| "dnsproxy".into());
    let mut proxy = tokio::process::Command::new(&binary)
        .args([
            "--listen=127.0.0.1",
            "--insecure",
            "--timeout=5s",
            "--upstream-mode=load_balance",
        ])
        .arg(format!("--port={port}"))
        .arg(format!("--upstream=quic://127.0.0.1:{}", f.addr.port()))
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .unwrap_or_else(|e| {
            panic!(
                "dnsproxy ({binary}) is required and this test never skips: run \
                 scripts/test-peers/install-dnsproxy.sh <dir> and set NETGET_DNSPROXY_BIN ({e})"
            )
        });
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            assert!(
                proxy.try_wait().unwrap().is_none(),
                "dnsproxy exited before binding"
            );
            if std::net::UdpSocket::bind(("127.0.0.1", port)).is_err() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("dnsproxy did not bind its UDP port");

    for (name, kind, expected) in CASES {
        let stdout = kdig(&[
            "+notcp".into(),
            "+timeout=8".into(),
            "+retry=0".into(),
            "@127.0.0.1".into(),
            "-p".into(),
            port.to_string(),
            name.into(),
            kind.into(),
        ])
        .await;
        assert!(
            stdout.contains(expected),
            "{name} {kind} via dnsproxy: {stdout}"
        );
    }
    // The answers came over DoQ from this server, one stream each.
    let server = f.state.get_server(f.server).await.unwrap();
    let received: u64 = server
        .connections
        .values()
        .map(|c| c.packets_received)
        .sum();
    assert!(
        received >= CASES.len() as u64,
        "the server saw {received} DoQ queries for {} asked",
        CASES.len()
    );
    proxy.kill().await.unwrap();
    proxy.wait().await.unwrap();
    f.close().await;
}
