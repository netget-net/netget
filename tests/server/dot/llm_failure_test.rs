//! What a DoT resolver gets when the LLM backend fails: SERVFAIL, not silence.
//!
//! DoT is DNS, and the plain-DNS reasoning applies with extra force. A stub resolver blocks on
//! the answer and, getting nothing, burns its full per-server timeout before trying anywhere
//! else - and here that timeout is more expensive still, because a TLS connection is costly
//! enough that resolvers pin one and serialise queries over it, so one unanswered query delays
//! everything behind it.
//!
//! The reply has to echo the transaction id and the question section. Without them a stub
//! resolver discards the packet as unsolicited and the client is back to waiting, so a
//! SERVFAIL that fails those two checks is worth exactly as much as silence - which is why
//! this test asserts them rather than just the response code.

use crate::helpers::{start_netget_server, E2EResult, NetGetConfig};
use hickory_proto::op::{Message as DnsMessage, Query, ResponseCode};
use hickory_proto::rr::{Name, RecordType};
use rustls::{ClientConfig, RootCertStore};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

#[tokio::test]
async fn test_dot_answers_servfail_when_llm_fails() -> E2EResult<()> {
    let prompt = "listen on port {AVAILABLE_PORT} via dot. Resolve example.com";

    let config = NetGetConfig::new_no_scripts(prompt).with_mock(|mock| {
        mock.on_instruction_containing("via dot")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "DoT",
                    "instruction": "Resolve example.com"
                }
            ]))
            .expect_calls(1)
            .and()
        // No rule for the DoT query event.
    });

    let server = start_netget_server(config).await?;
    tokio::time::sleep(Duration::from_millis(800)).await;

    use rustls::crypto::CryptoProvider;
    let _ = CryptoProvider::install_default(rustls::crypto::ring::default_provider());

    let mut tls_config = ClientConfig::builder()
        .with_root_certificates(RootCertStore::empty())
        .with_no_client_auth();
    tls_config
        .dangerous()
        .set_certificate_verifier(Arc::new(super::e2e_test::NoCertificateVerification));
    let connector = TlsConnector::from(Arc::new(tls_config));

    let tcp = TcpStream::connect(format!("127.0.0.1:{}", server.port)).await?;
    let name = rustls::pki_types::ServerName::try_from("localhost")
        .map_err(|e| anyhow::anyhow!("Invalid server name: {}", e))?;
    let mut tls_stream = connector.connect(name, tcp).await?;

    let domain = Name::from_str("example.com.")?;
    let query_id: u16 = rand::random();
    let mut query = DnsMessage::new();
    query.set_id(query_id);
    query.add_query(Query::query(domain.clone(), RecordType::A));
    query.set_recursion_desired(true);
    let query_bytes = query.to_vec()?;

    tls_stream
        .write_all(&(query_bytes.len() as u16).to_be_bytes())
        .await?;
    tls_stream.write_all(&query_bytes).await?;

    let mut len_buf = [0u8; 2];
    tokio::time::timeout(Duration::from_secs(25), tls_stream.read_exact(&mut len_buf))
        .await
        .map_err(|_| {
            "No DoT reply within 25s - the server went silent on LLM failure, which is the \
             exact defect this test exists to catch"
        })??;
    let mut response_buf = vec![0u8; u16::from_be_bytes(len_buf) as usize];
    tokio::time::timeout(
        Duration::from_secs(10),
        tls_stream.read_exact(&mut response_buf),
    )
    .await
    .map_err(|_| "the DoT length prefix arrived but the message did not")??;

    let response = DnsMessage::from_vec(&response_buf)?;
    println!("DoT reply: {response:?}");

    assert_eq!(
        response.response_code(),
        ResponseCode::ServFail,
        "expected SERVFAIL. NOERROR with an empty answer section would tell the resolver the \
         name exists and has no A record, and it would cache that."
    );
    assert_eq!(
        response.id(),
        query_id,
        "the reply must echo the transaction id or a stub resolver discards it as \
         unsolicited, leaving the client exactly as stuck as with silence"
    );
    assert_eq!(
        response.queries().len(),
        1,
        "the reply must echo the question section"
    );
    assert_eq!(
        response.queries()[0].name(),
        &domain,
        "the reply must echo the queried name"
    );
    assert!(
        response.answers().is_empty(),
        "a SERVFAIL must not carry answers: {response:?}"
    );

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}
