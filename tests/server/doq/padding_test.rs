//! EDNS(0) Padding over DoQ. RFC 9250 §5.4 requires a DoQ implementation to protect against
//! traffic analysis by padding, either the DNS messages (RFC 7830, with RFC 8467's 468-octet
//! response blocks) or the QUIC packets; this server pads the messages, through the DNS
//! server's `dns::StreamQuery`, whenever the query carries a Padding option.
//! `tests/server/dns/padding_test.rs` holds the shared handler and assertions.
//!
//! | promise | how it is driven |
//! |---|---|
//! | a query with a Padding option gets a reply padded to a block | an answer and a SERVFAIL, each on its own stream |
//! | the pad never passes 65535 octets | a 65 526-octet answer is sent unpadded, not refused |
//! | a query without one is not padded | EDNS without Padding, and no EDNS |
//! | a real client | `kdig +quic +padding` reads a padded reply, `kdig +quic +nopadding` an unpadded one |
//!
//! Every query is answered by a Python script handler, so no model is reached. Loopback only.
use super::support::Fixture;
use crate::server::dns::padding_test::{
    a_record, assert_kdig_padded, assert_kdig_unpadded, assert_padded, assert_unpadded, query,
    rcode, Ask, HANDLER, NEAR_LIMIT_REPLY,
};
use crate::server::dns::zone_support::run;
use hickory_proto::op::{Message, ResponseCode};
use netget::server::dns::PADDING_BLOCK;
use netget::server::doq::wire::{frame, MAX_FRAME_BYTES};
use serde_json::json;
use std::time::Duration;

async fn fixture() -> Fixture {
    Fixture::new(
        json!({}),
        Some(json!({"type":"script","language":"python","code":HANDLER})),
    )
    .await
}

/// One query on a fresh stream, FINed; the DNS message that came back, without its prefix.
async fn exchange(c: &quinn::Connection, message: &[u8]) -> Vec<u8> {
    let (mut send, mut recv) = c.open_bi().await.unwrap();
    send.write_all(&frame(message).unwrap()).await.unwrap();
    send.finish().unwrap();
    let reply = tokio::time::timeout(Duration::from_secs(20), recv.read_to_end(MAX_FRAME_BYTES))
        .await
        .expect("no DoQ reply within 20s")
        .expect("the stream was answered");
    let length = u16::from_be_bytes([reply[0], reply[1]]) as usize;
    assert_eq!(length + 2, reply.len(), "one framed message on the stream");
    reply[2..].to_vec()
}

#[tokio::test]
async fn doq_replies_are_padded_when_asked_and_only_then() {
    let f = fixture().await;
    let (_endpoint, c) = f.peer().await;

    let reply = exchange(&c, &query("pad.test", 0, Ask::Padding(1232))).await;
    assert_padded(&reply, "DoQ answer");
    assert_eq!(reply.len(), PADDING_BLOCK);
    assert_eq!(a_record(&reply).as_deref(), Some("192.0.2.53"));

    let reply = exchange(&c, &query("nothing.test", 0, Ask::Padding(1232))).await;
    assert_eq!(rcode(&reply), ResponseCode::ServFail);
    assert_padded(&reply, "DoQ SERVFAIL");

    let reply = exchange(&c, &query("near.test", 0, Ask::Padding(1232))).await;
    assert_eq!(rcode(&reply), ResponseCode::NoError);
    assert_unpadded(&reply, "DoQ, 65 526-octet answer");
    assert_eq!(reply.len(), NEAR_LIMIT_REPLY);

    let reply = exchange(&c, &query("pad.test", 0, Ask::EdnsOnly)).await;
    assert_unpadded(&reply, "DoQ, EDNS without Padding");
    assert_eq!(a_record(&reply).as_deref(), Some("192.0.2.53"));
    let reply = exchange(&c, &query("pad.test", 0, Ask::NoEdns)).await;
    assert!(Message::from_vec(&reply).unwrap().edns.is_none());
    f.close().await;
}

#[tokio::test]
async fn kdig_reads_padded_doq_replies() {
    let f = fixture().await;
    let ca = format!("+tls-ca={}", f.dir.path().join("cert.pem").display());
    let kdig = |padding: &str| {
        let argv: Vec<String> = [
            "+quic",
            ca.as_str(),
            "+tls-hostname=localhost",
            padding,
            "+timeout=10",
            "+retry=0",
            "@127.0.0.1",
            "-p",
            &f.addr.port().to_string(),
            "pad.test",
            "A",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        async move { run("kdig", &argv, "knot-dnsutils (kdig, built with QUIC)").await }
    };
    let out = kdig("+padding").await;
    assert!(out.contains("QUIC"), "kdig did not use QUIC: {out}");
    assert_kdig_padded(&out, "kdig +quic +padding");
    let out = kdig("+nopadding").await;
    assert_kdig_unpadded(&out, "kdig +quic +nopadding");
    f.close().await;
}
