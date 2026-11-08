//! Live-LLM DNS suite. Setup (LiveProtocolTest, model-driven) and request
//! handling (LiveRequestTest, deterministic `--server` start) are separate
//! tests — see tcp.rs for the rationale. The model must answer real
//! hickory-net queries, which means echoing the query ID and building a
//! correct wire response.
//!
//! COVERS: dns: dns_query

use crate::helpers::llm_live::{
    live_llm_enabled, LiveProtocolTest, LiveRequestTest, FIRST_BYTE_TIMEOUT,
};
use crate::helpers::E2EResult;
use hickory_net::client::{Client, ClientHandle};
use hickory_net::runtime::TokioRuntimeProvider;
use hickory_net::udp::UdpClientStream;
use hickory_proto::rr::{DNSClass, Name, RData, RecordType};
use std::net::SocketAddr;
use std::str::FromStr;

/// Setup: a bare natural-language prompt must produce a running DNS server.
#[tokio::test]
async fn dns_setup_via_llm() -> E2EResult<()> {
    if !live_llm_enabled() {
        return Ok(());
    }
    let server = LiveProtocolTest::new("dns")
        .setup_prompt(
            "Start a DNS server on port {AVAILABLE_PORT}. \
             Answer every A query with the IP 127.0.0.1.",
        )
        .start()
        .await?;
    server.finish().await
}

/// Request type: A-record query for an instructed name → instructed IP.
/// Validated with hickory-net, an independent DNS implementation, so the
/// model's answer must be a spec-correct packet with the right query ID.
#[tokio::test]
async fn dns_a_record_query() -> E2EResult<()> {
    if !live_llm_enabled() {
        return Ok(());
    }
    let server = LiveRequestTest::new(
        "dns",
        "When an A record query arrives for test.netget.example, answer with \
         the IP 10.20.30.40. Answer any other query with 127.0.0.1.",
    )
    .start()
    .await?;

    let result = query_a(&server.addr(), "test.netget.example.", "10.20.30.40")
        .await
        .and(server.expect_llm_answered().await);

    server.finish().await?;
    result
}

async fn query_a(addr: &str, name: &str, expected_ip: &str) -> E2EResult<()> {
    let address: SocketAddr = addr.parse()?;
    // Generous timeout: the answer is a live model round-trip.
    let stream = UdpClientStream::builder(address, TokioRuntimeProvider::new())
        .with_timeout(Some(FIRST_BYTE_TIMEOUT))
        .with_max_retries(1)
        .build();
    let (mut client, bg) = Client::<TokioRuntimeProvider>::from_sender(stream);
    tokio::spawn(bg);

    let response = client
        .query(Name::from_str(name)?, DNSClass::IN, RecordType::A)
        .await?;

    let answers = &response.answers;
    if answers.is_empty() {
        return Err(format!("DNS response for {} carried no answers", name).into());
    }
    let ips: Vec<String> = answers
        .iter()
        .filter_map(|record| match &record.data {
            RData::A(ip) => Some(ip.to_string()),
            _ => None,
        })
        .collect();
    if ips.iter().any(|ip| ip == expected_ip) {
        println!("✅ dns: {} resolved to {:?}", name, ips);
        Ok(())
    } else {
        Err(format!(
            "Expected {} to resolve to {}, got A records: {:?}",
            name, expected_ip, ips
        )
        .into())
    }
}
