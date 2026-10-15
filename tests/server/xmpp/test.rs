//! End-to-end XMPP tests for NetGet.
//!
//! The peer is a real XMPP parser: `xmpp-parsers` (already a dependency of the `xmpp`
//! feature, and the stanza layer every `tokio-xmpp`-based client uses). Everything the
//! server writes is fed through it, so a stanza that is not well-formed, that lands in the
//! wrong namespace, or whose text was interpolated without XML escaping fails the test the
//! same way it would break a real client's stream.
//!
//! It is not a full client: the server has no STARTTLS and no SASL exchange, so
//! `tokio_xmpp::Client` cannot complete its connect. The stream header, `<stream:features>`
//! and the stanzas are nonetheless parsed by exactly the types that client is built on.

#![cfg(unix)]

use super::super::super::helpers::{self, E2EResult, NetGetConfig};
use std::str::FromStr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use xmpp_parsers::minidom::Element;

const XML_DECL: &str = "<?xml version='1.0'?>";
const STREAM_NS: &str = "http://etherx.jabber.org/streams";
const CLIENT_NS: &str = "jabber:client";

const CLIENT_HEADER: &str = "<?xml version='1.0'?><stream:stream xmlns='jabber:client' \
     xmlns:stream='http://etherx.jabber.org/streams' to='localhost' version='1.0'>";

/// Accumulates the server's half of the XML stream and parses it with `xmpp-parsers`.
///
/// An XML stream is one element that never closes, so it cannot be parsed as it stands.
/// Appending the closing tag to whatever has arrived so far turns it into a document; a
/// parse failure then simply means the stanza is still incomplete, which is the same
/// incremental-parse condition a real client is in.
struct StreamPeer {
    stream: tokio::net::TcpStream,
    raw: String,
}

impl StreamPeer {
    async fn connect(port: u16) -> E2EResult<Self> {
        let stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port)).await?;
        Ok(Self {
            stream,
            raw: String::new(),
        })
    }

    async fn send(&mut self, xml: &str) -> E2EResult<()> {
        self.stream.write_all(xml.as_bytes()).await?;
        self.stream.flush().await?;
        Ok(())
    }

    fn try_parse(&self) -> Option<Element> {
        let body = self.raw.strip_prefix(XML_DECL).unwrap_or(&self.raw);
        Element::from_str(&format!("{}</stream:stream>", body)).ok()
    }

    /// Read until the server's stream parses and has at least `n` top-level children.
    async fn wait_for_children(&mut self, n: usize, what: &str) -> Element {
        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        loop {
            if let Some(element) = self.try_parse() {
                if element.children().count() >= n {
                    return element;
                }
            }

            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                panic!(
                    "timed out waiting for {} ({} top-level stanzas). Raw stream so far:\n{}",
                    what, n, self.raw
                );
            }

            let mut buf = vec![0u8; 4096];
            match tokio::time::timeout(remaining, self.stream.read(&mut buf)).await {
                Ok(Ok(0)) => panic!(
                    "server closed the stream while waiting for {}. Raw stream so far:\n{}",
                    what, self.raw
                ),
                Ok(Ok(read)) => {
                    self.raw
                        .push_str(&String::from_utf8_lossy(&buf[..read]).to_string());
                }
                Ok(Err(e)) => panic!("read error while waiting for {}: {}", what, e),
                Err(_) => panic!(
                    "timed out waiting for {} ({} top-level stanzas). Raw stream so far:\n{}",
                    what, n, self.raw
                ),
            }
        }
    }

    /// Assert the stream header itself, which RFC 6120 section 4.7 constrains.
    fn assert_stream_header(&self, element: &Element, from: &str, id: &str) {
        assert!(
            self.raw.starts_with(XML_DECL),
            "RFC 6120 4.2: the initial stream header should be preceded by an XML \
             declaration, got: {}",
            &self.raw[..self.raw.len().min(80)]
        );
        assert_eq!(element.name(), "stream", "root element must be <stream/>");
        assert_eq!(
            element.ns(),
            STREAM_NS,
            "the stream element must be in the {} namespace",
            STREAM_NS
        );
        assert_eq!(
            element.attr("from"),
            Some(from),
            "stream header 'from' must be the server's domain"
        );
        assert_eq!(element.attr("id"), Some(id), "stream header 'id'");
        assert_eq!(
            element.attr("version"),
            Some("1.0"),
            "RFC 6120 4.7.5: a stream header must declare version='1.0'"
        );
    }
}

/// Stream header + stream features, parsed by `xmpp-parsers`.
///
/// 1 startup call + 1 stream event = 2 LLM calls.
#[tokio::test]
async fn test_xmpp_stream_header_and_features() -> E2EResult<()> {
    let prompt = "listen on port {AVAILABLE_PORT} via xmpp domain=example.test. \
        When a client opens a stream, answer with the server stream header and the \
        stream features advertising PLAIN and SCRAM-SHA-1.";

    let config = NetGetConfig::new(prompt).with_mock(|mock| {
        mock.on_prompt_containing("listen on port")
            .respond_with_actions(serde_json::json!([{
                "type": "open_server",
                "port": 0,
                "base_stack": "XMPP",
                "startup_params": {"domain": "example.test"},
                "instruction": "Answer a stream open with header and features"
            }]))
            .expect_calls(1)
            .and()
            .on_event("xmpp_data_received")
            .and_event_data_contains("xml_data", "stream:stream")
            .respond_with_actions(serde_json::json!([
                {"type": "send_stream_header", "stream_id": "stream-abc"},
                {"type": "send_stream_features", "mechanisms": ["PLAIN", "SCRAM-SHA-1"]}
            ]))
            .expect_calls(1)
            .and()
    });

    let server = helpers::start_netget_server(config).await?;
    let mut peer = StreamPeer::connect(server.port).await?;
    peer.send(CLIENT_HEADER).await?;

    // Header + <stream:features/>
    let stream = peer
        .wait_for_children(1, "the stream header and features")
        .await;

    // `from` is omitted by the action, so it must fall back to the `domain` startup
    // parameter rather than the hardcoded default.
    peer.assert_stream_header(&stream, "example.test", "stream-abc");

    let features_el = stream
        .children()
        .find(|c| c.name() == "features")
        .unwrap_or_else(|| {
            panic!(
                "no <stream:features/> in the server's stream. Raw stream:\n{}",
                peer.raw
            )
        });
    assert_eq!(
        features_el.ns(),
        STREAM_NS,
        "RFC 6120 4.3.2: <features/> belongs to the stream namespace"
    );

    let features = xmpp_parsers::stream_features::StreamFeatures::try_from(features_el.clone())
        .unwrap_or_else(|e| panic!("xmpp-parsers rejected <stream:features/>: {}", e));
    assert_eq!(
        features.sasl_mechanisms.mechanisms,
        vec!["PLAIN".to_string(), "SCRAM-SHA-1".to_string()],
        "the advertised SASL mechanisms must be the ones the model listed, in order"
    );

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

/// A full message and presence round trip, parsed into `xmpp-parsers` stanza types.
///
/// The message body deliberately contains `&`, `<`, `>` and an apostrophe: interpolated
/// unescaped they produce a malformed stream, and a real client's parser drops the whole
/// stream on the first well-formedness error rather than skipping one stanza.
///
/// 1 startup call + 3 stream events = 4 LLM calls.
#[tokio::test]
async fn test_xmpp_message_and_presence_round_trip() -> E2EResult<()> {
    // The literal body the server must reproduce, character for character, after escaping
    // and re-parsing.
    const BODY: &str = "Echo: 5 < 6 & 7 > 3, it's \"quoted\"";

    let prompt = "listen on port {AVAILABLE_PORT} via xmpp. Answer a stream open with the \
        server stream header, echo message stanzas back, and acknowledge presence.";

    let config = NetGetConfig::new(prompt).with_mock(|mock| {
        mock.on_prompt_containing("listen on port")
            .respond_with_actions(serde_json::json!([{
                "type": "open_server",
                "port": 0,
                "base_stack": "XMPP",
                "instruction": "Echo messages, acknowledge presence"
            }]))
            .expect_calls(1)
            .and()
            .on_event("xmpp_data_received")
            .and_event_data_contains("xml_data", "stream:stream")
            .respond_with_actions(serde_json::json!([
                {"type": "send_stream_header", "from": "localhost", "stream_id": "stream-456"}
            ]))
            .expect_calls(1)
            .and()
            .on_event("xmpp_data_received")
            .and_event_data_contains("xml_data", "<message")
            .respond_with_actions(serde_json::json!([{
                "type": "send_message",
                "from": "bot@localhost",
                "to": "alice@localhost/desktop",
                "message_type": "chat",
                "body": BODY
            }]))
            .expect_calls(1)
            .and()
            .on_event("xmpp_data_received")
            .and_event_data_contains("xml_data", "<presence")
            .respond_with_actions(serde_json::json!([{
                "type": "send_presence",
                "from": "server@localhost",
                "show": "chat",
                "status": "Server online"
            }]))
            .expect_calls(1)
            .and()
    });

    let server = helpers::start_netget_server(config).await?;
    let mut peer = StreamPeer::connect(server.port).await?;

    peer.send(CLIENT_HEADER).await?;
    let stream = peer.wait_for_children(0, "the stream header").await;
    peer.assert_stream_header(&stream, "localhost", "stream-456");

    // ---- message ----------------------------------------------------------------------
    peer.send(
        "<message from='alice@localhost/desktop' to='bot@localhost' type='chat'>\
         <body>Hello XMPP!</body></message>",
    )
    .await?;
    let stream = peer.wait_for_children(1, "the echoed message stanza").await;

    let message_el = stream
        .children()
        .find(|c| c.name() == "message")
        .unwrap_or_else(|| panic!("no <message/> in the stream. Raw stream:\n{}", peer.raw));
    assert_eq!(
        message_el.ns(),
        CLIENT_NS,
        "a stanza sent inside a jabber:client stream inherits that default namespace"
    );

    let message = xmpp_parsers::message::Message::try_from(message_el.clone())
        .unwrap_or_else(|e| panic!("xmpp-parsers rejected the message stanza: {}", e));
    assert_eq!(
        message.from.as_ref().map(|j| j.to_string()),
        Some("bot@localhost".to_string())
    );
    assert_eq!(
        message.to.as_ref().map(|j| j.to_string()),
        Some("alice@localhost/desktop".to_string()),
        "the full JID including the resource must survive"
    );
    assert_eq!(
        message.type_,
        xmpp_parsers::message::MessageType::Chat,
        "type='chat' must parse as a chat message"
    );
    let body = message
        .bodies
        .values()
        .next()
        .unwrap_or_else(|| panic!("message stanza carries no <body/>"));
    assert_eq!(
        body.as_str(),
        BODY,
        "the body must come back byte-for-byte after XML escaping and re-parsing"
    );

    // ---- presence ---------------------------------------------------------------------
    peer.send("<presence><show>chat</show><status>Available</status></presence>")
        .await?;
    let stream = peer.wait_for_children(2, "the presence stanza").await;

    let presence_el = stream
        .children()
        .find(|c| c.name() == "presence")
        .unwrap_or_else(|| panic!("no <presence/> in the stream. Raw stream:\n{}", peer.raw));
    let presence = xmpp_parsers::presence::Presence::try_from(presence_el.clone())
        .unwrap_or_else(|e| panic!("xmpp-parsers rejected the presence stanza: {}", e));

    assert_eq!(
        presence.from.as_ref().map(|j| j.to_string()),
        Some("server@localhost".to_string())
    );
    assert_eq!(
        presence.type_,
        xmpp_parsers::presence::Type::None,
        "RFC 6121 4.7.1: an available presence carries no 'type' attribute at all — \
         type='available' is not a legal value"
    );
    assert_eq!(
        presence.show,
        Some(xmpp_parsers::presence::Show::Chat),
        "<show>chat</show>"
    );
    assert_eq!(
        presence.statuses.values().next().map(|s| s.as_str()),
        Some("Server online"),
        "<status/> text"
    );

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}
