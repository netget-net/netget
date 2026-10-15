//! Characters XML 1.0 forbids never reach an XMPP stream.
//!
//! XML 1.0's `Char` production admits tab, LF, CR and `U+0020` upwards, less `U+FFFE` and
//! `U+FFFF`. Anything else - a C0 control such as the `U+001B` a model copies out of a terminal
//! transcript - makes the document ill-formed however it is written, and a strict parser ends
//! the whole stream on it rather than skipping the stanza. `xml_escape` drops those characters
//! and keeps tab, LF and CR.
//!
//! The second test drives the server's own `send_message` and parses the stanza with
//! `xmpp-parsers` (rxml underneath, the parser every tokio-xmpp client runs), so it fails the
//! way a real client's stream would.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features xmpp --test server -- xmpp::xml_escape --test-threads=100

#![cfg(unix)]

use std::str::FromStr;

use netget::llm::actions::protocol_trait::{ActionResult, Server};
use netget::server::xmpp::actions::{xml_escape, XmppProtocol};
use xmpp_parsers::minidom::Element;

#[test]
fn forbidden_xml_characters_are_dropped_and_whitespace_controls_kept() {
    assert_eq!(xml_escape("a\u{1}b\u{FFFF}c"), "abc");
    assert_eq!(xml_escape("tab\there\nline\rcr"), "tab\there\nline\rcr");

    // Every C0 control other than tab, LF and CR, and both noncharacters.
    let forbidden: String = (0u32..0x20)
        .filter(|c| ![0x9, 0xA, 0xD].contains(c))
        .chain([0xFFFE, 0xFFFF])
        .map(|c| char::from_u32(c).unwrap())
        .collect();
    assert_eq!(xml_escape(&forbidden), "");

    // The edges of the permitted ranges survive, and markup is still escaped.
    let allowed = "\u{20}\u{D7FF}\u{E000}\u{FFFD}\u{10000}\u{10FFFF}";
    assert_eq!(xml_escape(allowed), allowed);
    assert_eq!(xml_escape("<a\u{1b}&'\">"), "&lt;a&amp;&apos;&quot;&gt;");
}

#[test]
fn a_body_with_control_characters_still_yields_a_well_formed_message() {
    let action = serde_json::json!({
        "type": "send_message",
        "from": "bot\u{0}@localhost",
        "to": "alice@localhost/desktop",
        "message_type": "chat",
        "body": "\u{1b}[1mbold\u{1b}[0m\u{1} line one\nline two\u{FFFF}\tend & done",
    });
    let bytes = match XmppProtocol::new()
        .execute_action(action)
        .expect("send_message")
    {
        ActionResult::Output(bytes) => bytes,
        _ => panic!("send_message should produce output"),
    };
    let xml = String::from_utf8(bytes).expect("utf-8");

    // The stanza is written inside a `jabber:client` stream; give it that default namespace
    // so it can be parsed on its own.
    let rooted = xml.replacen("<message ", "<message xmlns='jabber:client' ", 1);
    let element =
        Element::from_str(&rooted).unwrap_or_else(|e| panic!("not well-formed XML ({e}): {xml:?}"));
    let message = xmpp_parsers::message::Message::try_from(element)
        .unwrap_or_else(|e| panic!("not a valid message stanza ({e:?}): {xml:?}"));

    let body = message
        .bodies
        .values()
        .next()
        .expect("the message has a body");
    assert_eq!(body, "[1mbold[0m line one\nline two\tend & done");
    assert_eq!(
        message.from.map(|j| j.to_string()).as_deref(),
        Some("bot@localhost")
    );
}
