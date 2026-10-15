//! End-to-end DNS-over-TLS (DoT) tests for NetGet
//!
//! This test spawns a single NetGet DoT server with mocks
//! and validates multiple query types against the same server instance.

use crate::helpers::{E2EResult, NetGetConfig};
use hickory_proto::op::{Message as DnsMessage, Query};
use hickory_proto::rr::{Name, RecordType};
use rustls::{ClientConfig, RootCertStore};
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

/// Helper to query DoT server
async fn query_dot(port: u16, domain: &str, record_type: RecordType) -> E2EResult<DnsMessage> {
    // Initialize rustls crypto provider (required for rustls 0.23+)
    use rustls::crypto::CryptoProvider;
    let _ = CryptoProvider::install_default(rustls::crypto::ring::default_provider());

    let address: SocketAddr = format!("127.0.0.1:{}", port).parse()?;

    // Create a TLS client config that accepts self-signed certificates (for testing)
    let root_store = RootCertStore::empty();
    let mut config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    // Disable certificate verification for self-signed certs in tests
    config
        .dangerous()
        .set_certificate_verifier(Arc::new(NoCertificateVerification));

    let tls_config = Arc::new(config);
    let connector = TlsConnector::from(tls_config);

    // Connect via TLS
    let tcp_stream = TcpStream::connect(address).await?;
    let domain_name = rustls::pki_types::ServerName::try_from("localhost")
        .map_err(|e| anyhow::anyhow!("Invalid server name: {}", e))?;
    let mut tls_stream = connector.connect(domain_name, tcp_stream).await?;

    // Build DNS query. A real resolver picks the id at random and drops any reply whose
    // id does not match, so the test must do the same — otherwise a server that never
    // echoes the id looks healthy here while failing against every real client (item 47).
    let name = Name::from_str(domain)?;
    let query_id: u16 = rand::random();
    let mut query_msg = DnsMessage::new();
    query_msg.set_id(query_id);
    query_msg.add_query(Query::query(name.clone(), record_type));
    query_msg.set_recursion_desired(true);

    // Serialize to wire format
    let query_bytes = query_msg.to_vec()?;

    // Send with length prefix (DoT protocol: 2-byte length + DNS message)
    let len = query_bytes.len() as u16;
    tls_stream.write_all(&len.to_be_bytes()).await?;
    tls_stream.write_all(&query_bytes).await?;

    // Read response with length prefix
    let mut len_buf = [0u8; 2];
    tls_stream.read_exact(&mut len_buf).await?;
    let response_len = u16::from_be_bytes(len_buf) as usize;

    let mut response_buf = vec![0u8; response_len];
    tls_stream.read_exact(&mut response_buf).await?;

    // Parse DNS response
    let dns_response = DnsMessage::from_vec(&response_buf)?;

    // RFC 1035 §4.1.1: the reply's ID must equal the request's. Enforcing it here is the
    // whole point of the dynamic mocks above.
    assert_eq!(
        dns_response.id(),
        query_id,
        "DoT reply for {domain} carried transaction id {} but the query used {query_id}; \
         a real resolver would discard this reply",
        dns_response.id()
    );

    // The reply must also echo the question, which is how a resolver confirms it is
    // looking at an answer to the query it asked.
    assert_eq!(
        dns_response.queries().len(),
        1,
        "reply must echo exactly one question"
    );
    assert_eq!(
        dns_response.queries()[0].name(),
        &name,
        "reply must echo the queried name"
    );

    Ok(dns_response)
}

/// The single A record in a reply's answer section, decoded to an address.
///
/// Returns `None` if the answer section is empty or holds something other than one A
/// record — both of which must fail the test rather than pass quietly.
fn answer_a(response: &DnsMessage) -> Option<std::net::Ipv4Addr> {
    let answers = response.answers();
    if answers.len() != 1 {
        return None;
    }
    match answers[0].data() {
        Some(hickory_proto::rr::RData::A(addr)) => Some(addr.0),
        _ => None,
    }
}

/// Certificate verifier that accepts all certificates (for testing only)
///
/// `pub(crate)` so `llm_failure_test` can reuse it rather than growing a second copy that
/// drifts from this one.
#[derive(Debug)]
pub(crate) struct NoCertificateVerification;

impl rustls::client::danger::ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

#[tokio::test]
async fn test_dot_server() -> E2EResult<()> {
    println!("\n=== E2E Test: DNS-over-TLS Server with Mocks ===");

    // Create a DoT server with mocks
    let server_config = NetGetConfig::new("Listen on port {AVAILABLE_PORT} via DoT. Respond to all A record queries for example.com with IP 93.184.216.34 and TTL 300.")
        .with_log_level("info")
        .with_mock(|mock| {
            mock
                // The three query mocks echo the *client's* transaction id and queried name
                // out of the event, per CLAUDE.md's dynamic-mock rule. They used to hardcode
                // `"query_id": 1`, which only went unnoticed because the raw TLS client below
                // never checked the id — so the suite could not have detected a server that
                // replied with the wrong one. Each response now carries a distinct IP too, so
                // an answer routed to the wrong query is visible.
                //
                // Mock 1: foo.example.com - MUST BE FIRST (most specific, avoids substring match)
                .on_event("dot_query")
                .and_event_data_contains("domain", "foo.example.com")
                .respond_with_actions_from_event(|event_data| {
                    serde_json::json!([
                        {
                            "type": "send_dns_a_response",
                            "query_id": event_data["query_id"],
                            "domain": event_data["domain"],
                            "ip": "93.184.216.36",
                            "ttl": 300
                        }
                    ])
                })
                .expect_calls(1)
                .and()
                // Mock 2: example.com - MUST BE SECOND (specific)
                .on_event("dot_query")
                .and_event_data_contains("domain", "example.com")
                .respond_with_actions_from_event(|event_data| {
                    serde_json::json!([
                        {
                            "type": "send_dns_a_response",
                            "query_id": event_data["query_id"],
                            "domain": event_data["domain"],
                            "ip": "93.184.216.34",
                            "ttl": 300
                        }
                    ])
                })
                .expect_calls(1)
                .and()
                // Mock 3: test.com - MUST BE THIRD (specific)
                .on_event("dot_query")
                .and_event_data_contains("domain", "test.com")
                .respond_with_actions_from_event(|event_data| {
                    serde_json::json!([
                        {
                            "type": "send_dns_a_response",
                            "query_id": event_data["query_id"],
                            "domain": event_data["domain"],
                            "ip": "93.184.216.35",
                            "ttl": 300
                        }
                    ])
                })
                .expect_calls(1)
                .and()
                // Mock 4: Server startup - MUST BE LAST (less specific)
                .on_instruction_containing("Listen on port")
                .and_instruction_containing("DoT")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "DoT",
                        "instruction": "Respond to all A record queries for example.com with IP 93.184.216.34 and TTL 300"
                    }
                ]))
                .expect_calls(1)
                .and()
        });

    let server = crate::helpers::start_netget_server(server_config).await?;

    // Extract server port
    let port = server.port;
    println!("DoT server started on port {}", port);

    // Wait for server to fully initialize
    server.wait_for_mocks(30).await;

    // Each query gets a distinct IP so a reply routed to the wrong question is visible.
    // `query_dot` additionally asserts the transaction id and question are echoed.
    println!("\n[Test 1] First query - example.com A record...");
    let response1 = query_dot(port, "example.com.", RecordType::A).await?;
    assert_eq!(
        answer_a(&response1),
        Some("93.184.216.34".parse().unwrap()),
        "example.com must resolve to the address its handler chose"
    );

    println!("\n[Test 2] Second query - testing TLS connection reuse...");
    let response2 = query_dot(port, "test.com.", RecordType::A).await?;
    assert_eq!(
        answer_a(&response2),
        Some("93.184.216.35".parse().unwrap()),
        "test.com must resolve to its own address, not example.com's"
    );

    println!("\n[Test 3] Third query - different domain...");
    let response3 = query_dot(port, "foo.example.com.", RecordType::A).await?;
    assert_eq!(
        answer_a(&response3),
        Some("93.184.216.36".parse().unwrap()),
        "foo.example.com must resolve to its own address"
    );

    println!("\n=== All DoT tests passed! ===");

    // Verify mock expectations were met
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;

    // Cleanup
    server.stop().await?;

    Ok(())
}
