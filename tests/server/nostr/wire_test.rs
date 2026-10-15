//! The NIP-01 codec in isolation: id, signature, filters, message parsing, refusals.
//!
//! NIP-01 publishes no test vectors, so the vectors here were signed by an independent
//! implementation: `nak event --sec <key> --ts <t> …` (nak 0.20.7, go-nostr). Each is verified
//! by NetGet's own `verify_event`, which recomputes the id from the canonical serialisation — so
//! a disagreement about escaping between go-nostr and NetGet fails here. The second vector
//! carries every escape class NIP-01 names plus C0 controls, non-BMP text and U+2028.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features nostr --test server -- nostr::wire --test-threads=100

use super::common::{author, note, AUTHOR_PUBKEY, RELAY_SECRET};
use netget::server::nostr::wire::{
    self, compute_id, parse_client_message, parse_filter, parse_supplied_event, select_events,
    serialize_for_id, verify_event, with_prefix, ClientMessage, Escaping, RelayKey,
};
use serde_json::{json, Value};

/// Signed by nak with the tests' author key.
const NAK_VECTORS: &[&str] = &[
    r#"{"kind":1,"id":"4601ba921e79b93ee9610fc66536bcab72e34da88d62bf03c662440682a45033","pubkey":"17162c921dc4d2518f9a101db33695df1afb56ab82f5ff3e5da6eec3ca5cd917","created_at":1700000000,"tags":[],"content":"hello","sig":"5faead673a8e534c473d951da9726ce7263b38c4d77c525eeb7e6ad06b48a0000edda8f74706fdb3ed88c826925a21e028f2ad558633d815e60ac4c4038400ee"}"#,
    r#"{"kind":1,"id":"ede3685aa62627e9a0246c0709c4167017ced5cb79b663245cab1b17afc05955","pubkey":"17162c921dc4d2518f9a101db33695df1afb56ab82f5ff3e5da6eec3ca5cd917","created_at":1700000001,"tags":[["t","nostr"],["e","5c83da77af1dec6d7289834998ad7aafbd9e2191396d75ec3cc27f5a77226f36"]],"content":"line1\nline2 \"quoted\" back\\slash\ttab\rcr\u0008bs\u000cfeed\u0001ctl\u001fus ✓ 😀   / end","sig":"580226f6414004a05ae24b7c0d0c7e5f1f83333b81556f7c836d51bae94aa30a175ed6a24f7c7d53ddddbf3e17ed4ef57d6d64838ec111e77e54a1a40f38170c"}"#,
    r#"{"kind":30023,"id":"dd33d27f37234efb5aed686741f921d429cb4d0133bf2461ad4d5915ec5f4da3","pubkey":"17162c921dc4d2518f9a101db33695df1afb56ab82f5ff3e5da6eec3ca5cd917","created_at":1700000002,"tags":[["title","A \\ B"],["d","slug \"x\""]],"content":"","sig":"220ea946129a847a7bcdeae1bf5c7cc7e43039f45097db9cab201e07c9e6c80a74736e0c1eca3f6c8f15fd9e1002d0af7102fadc74711bd2c3158907ef278a00"}"#,
];

fn vector(i: usize) -> Value {
    serde_json::from_str(NAK_VECTORS[i]).unwrap()
}

#[test]
fn events_signed_by_nak_verify() {
    for (i, raw) in NAK_VECTORS.iter().enumerate() {
        let event = verify_event(&vector(i)).unwrap_or_else(|r| panic!("vector {i}: {r:?}"));
        assert_eq!(event.pubkey, AUTHOR_PUBKEY);
        assert!(raw.contains(&event.id));
    }
    let contested = verify_event(&vector(1)).unwrap();
    assert!(contested.content.contains('\u{1}') && contested.content.contains('\u{2028}'));
}

fn sha(s: &str) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(s.as_bytes()))
}

fn serialized(escaping: Escaping, e: &wire::Event) -> String {
    serialize_for_id(
        escaping,
        &e.pubkey,
        e.created_at,
        e.kind,
        &e.tags,
        &e.content,
    )
}

/// Where the implementations disagree, measured: nak signed vector 1 — which holds U+0008,
/// U+000C, U+0001 and U+001F — under the go-nostr escaping and under neither of the others.
#[test]
fn nak_signs_contested_controls_the_go_nostr_way_and_netget_accepts_all_three() {
    let event = verify_event(&vector(1)).unwrap();
    assert_eq!(sha(&serialized(Escaping::GoNostr, &event)), event.id);
    assert_ne!(sha(&serialized(Escaping::Json, &event)), event.id);
    assert_ne!(sha(&serialized(Escaping::Nip01Literal, &event)), event.id);

    // The JSON escaping, which NetGet signs with: named \b \f, \u00xx for the rest, and
    // non-ASCII, U+2028 and '/' verbatim.
    let json_form = serialized(Escaping::Json, &event);
    assert!(json_form.starts_with("[0,\"17162c92"), "{json_form}");
    assert!(
        json_form.contains(r#"",1700000001,1,[["t","nostr"],["e","5c83"#),
        "no whitespace between elements: {json_form}"
    );
    for escaped in [
        r"\n", r#"\""#, r"\\", r"\t", r"\r", r"\b", r"\f", r"\u0001", r"\u001f",
    ] {
        assert!(
            json_form.contains(escaped),
            "{escaped} missing: {json_form}"
        );
    }
    for verbatim in ["✓", "😀", "\u{2028}", " / end"] {
        assert!(
            json_form.contains(verbatim),
            "{verbatim:?} not verbatim: {json_form}"
        );
    }

    // An event signed under the NIP-01-literal escaping (\b \f named, U+0001 raw) verifies
    // too, and the same event re-signed the JSON way does.
    let key = author();
    let secp = secp256k1::Secp256k1::new();
    let keypair = secp256k1::Keypair::from_seckey_slice(
        &secp,
        &hex::decode(super::common::AUTHOR_SECRET).unwrap(),
    )
    .unwrap();
    let content = "bell\u{7} back\u{8}space";
    for escaping in [Escaping::Nip01Literal, Escaping::Json, Escaping::GoNostr] {
        let id = sha(&serialize_for_id(
            escaping,
            AUTHOR_PUBKEY,
            1,
            1,
            &[],
            content,
        ));
        let digest: [u8; 32] = hex::decode(&id).unwrap().try_into().unwrap();
        let sig = secp.sign_schnorr_no_aux_rand(&secp256k1::Message::from_digest(digest), &keypair);
        let event = json!({
            "id": id, "pubkey": key.pubkey_hex(), "created_at": 1, "kind": 1,
            "tags": [], "content": content, "sig": hex::encode(sig.serialize()),
        });
        verify_event(&event).unwrap_or_else(|r| panic!("{escaping:?}: {r:?}"));
    }
}

#[test]
fn a_changed_field_or_signature_is_refused_with_its_own_reason() {
    let mut content = vector(0);
    content["content"] = json!("hellO");
    let refusal = verify_event(&content).unwrap_err();
    assert_eq!(refusal.decision, "fail_closed_invalid_id");
    assert!(refusal.message.starts_with("invalid: "), "{refusal:?}");
    assert_eq!(refusal.id.as_deref(), vector(0)["id"].as_str());

    // Recompute the id so only the signature is wrong.
    let mut resigned = vector(0);
    resigned["content"] = json!("hellO");
    resigned["id"] = json!(compute_id(AUTHOR_PUBKEY, 1700000000, 1, &[], "hellO"));
    let refusal = verify_event(&resigned).unwrap_err();
    assert_eq!(refusal.decision, "fail_closed_invalid_signature");

    let mut bad_sig = vector(0);
    let sig = bad_sig["sig"].as_str().unwrap().to_string();
    bad_sig["sig"] = json!(format!(
        "{}{}",
        &sig[..127],
        if sig.ends_with('e') { 'f' } else { 'e' }
    ));
    assert_eq!(
        verify_event(&bad_sig).unwrap_err().decision,
        "fail_closed_invalid_signature"
    );

    let mut upper = vector(0);
    upper["id"] = json!(vector(0)["id"].as_str().unwrap().to_uppercase());
    let refusal = verify_event(&upper).unwrap_err();
    assert!(refusal.id.is_none(), "an uppercase id is not a NIP-01 id");

    for (field, value) in [
        ("kind", json!(70000)),
        ("created_at", json!(-1)),
        ("tags", json!([["t", 5]])),
        ("content", json!(null)),
        ("pubkey", json!("abc")),
    ] {
        let mut broken = vector(0);
        broken[field] = value;
        assert_eq!(
            verify_event(&broken).unwrap_err().decision,
            "fail_closed_invalid_event",
            "{field}"
        );
    }
}

#[test]
fn the_relay_key_signs_events_nak_style_and_round_trips() {
    let key = RelayKey::from_hex(RELAY_SECRET).unwrap();
    let event = key.sign(
        1700000500,
        1,
        vec![vec!["t".into(), "film".into()]],
        "a \"quoted\"\nnote ✓".into(),
    );
    assert_eq!(event.pubkey, key.pubkey_hex());
    let verified = verify_event(&event.to_json()).expect("our own signature verifies");
    assert_eq!(verified, event);
    // The same key from a vector: the author's pubkey is what nak derived.
    assert_eq!(author().pubkey_hex(), AUTHOR_PUBKEY);
    assert!(RelayKey::from_hex("zz").is_err());
    assert!(
        RelayKey::from_hex(&"0".repeat(64)).is_err(),
        "zero is not a secret key"
    );
}

fn filter(v: Value) -> wire::Filter {
    parse_filter(&v).unwrap()
}

#[test]
fn filters_match_as_nip01_says_and_limit_takes_the_newest() {
    let a = note("a", vec![vec!["t".into(), "film".into()]], 100);
    let b = note("b", vec![vec!["t".into(), "food".into()]], 300);
    let c = note("c", vec![], 200);
    let reaction = author().sign(250, 7, vec![], "+".into());
    let events = vec![a.clone(), b.clone(), c.clone(), reaction.clone()];

    assert_eq!(
        select_events(&[filter(json!({"kinds": [1]}))], &events, true),
        vec![0, 1, 2]
    );
    assert_eq!(
        select_events(
            &[filter(json!({"kinds": [1], "since": 150, "until": 250}))],
            &events,
            true
        ),
        vec![2]
    );
    assert_eq!(
        select_events(&[filter(json!({"#t": ["film"]}))], &events, true),
        vec![0]
    );
    assert_eq!(
        select_events(
            &[filter(json!({"authors": [AUTHOR_PUBKEY], "kinds": [7]}))],
            &events,
            true
        ),
        vec![3]
    );
    assert_eq!(
        select_events(&[filter(json!({"ids": [c.id]}))], &events, true),
        vec![2]
    );
    // Newest first under limit, returned in the supplied order.
    assert_eq!(
        select_events(&[filter(json!({"limit": 2}))], &events, true),
        vec![1, 3]
    );
    // Live delivery ignores limit.
    assert_eq!(
        select_events(&[filter(json!({"limit": 2}))], &events, false).len(),
        4
    );
    // Filters are ORed.
    assert_eq!(
        select_events(
            &[
                filter(json!({"#t": ["film"]})),
                filter(json!({"kinds": [7]}))
            ],
            &events,
            true
        ),
        vec![0, 3]
    );
    // An extension key is kept for the model and not matched on.
    let with_search = filter(json!({"kinds": [1], "search": "x"}));
    assert_eq!(with_search.raw["search"], "x");
    assert_eq!(select_events(&[with_search], &events, true).len(), 3);
}

#[test]
fn malformed_filters_are_refused() {
    for bad in [
        json!("not an object"),
        json!({"kinds": ["one"]}),
        json!({"kinds": [70000]}),
        json!({"authors": ["abc"]}),
        json!({"ids": "x"}),
        json!({"since": -5}),
        json!({"#t": [1]}),
        json!({"search": {"nested": true}}),
    ] {
        assert!(parse_filter(&bad).is_err(), "{bad}");
    }
}

fn refusal(text: &str) -> wire::Refusal {
    match parse_client_message(text) {
        Err(r) => r,
        Ok(m) => panic!("{text} parsed as {m:?}"),
    }
}

fn frame(r: &wire::Refusal) -> Value {
    serde_json::from_str(&r.reply).unwrap()
}

#[test]
fn client_messages_parse_and_mechanical_refusals_are_answered() {
    match parse_client_message(&format!(r#"["EVENT",{}]"#, NAK_VECTORS[0])).unwrap() {
        ClientMessage::Event(e) => assert_eq!(e.content, "hello"),
        other => panic!("{other:?}"),
    }
    match parse_client_message(r##"["REQ","sub1",{"kinds":[1]},{"#p":["x"]}]"##).unwrap() {
        ClientMessage::Req {
            subscription_id,
            filters,
        } => {
            assert_eq!(subscription_id, "sub1");
            assert_eq!(filters.len(), 2);
        }
        other => panic!("{other:?}"),
    }
    assert!(matches!(
        parse_client_message(r#"["CLOSE","sub1"]"#).unwrap(),
        ClientMessage::Close { .. }
    ));

    // A tampered event is an OK false with its id.
    let mut tampered = vector(0);
    tampered["content"] = json!("tampered");
    let r = refusal(&format!(r#"["EVENT",{tampered}]"#));
    assert_eq!(
        frame(&r),
        json!([
            "OK",
            tampered["id"],
            false,
            "invalid: event id does not match the hash of its content"
        ])
    );

    let notice = |text: &str| frame(&refusal(text))[0].clone();
    assert_eq!(notice("not json"), "NOTICE");
    assert_eq!(notice("{}"), "NOTICE");
    assert_eq!(notice("[5]"), "NOTICE");
    assert_eq!(notice(r#"["COUNT","x",{}]"#), "NOTICE");
    assert_eq!(notice(r#"["REQ","",{}]"#), "NOTICE");
    assert_eq!(notice(r#"["EVENT",{"id":"x"}]"#), "NOTICE");

    let long = "s".repeat(wire::MAX_SUBSCRIPTION_ID_CHARS + 1);
    let r = refusal(&format!(r#"["REQ","{long}",{{}}]"#));
    assert_eq!(frame(&r)[0], "CLOSED");
    assert_eq!(r.decision, "fail_closed_bad_subscription_id");
    // 64 characters, not bytes: a multi-byte id at the limit is fine.
    let at_limit = "é".repeat(wire::MAX_SUBSCRIPTION_ID_CHARS);
    assert!(parse_client_message(&format!(r#"["REQ","{at_limit}",{{}}]"#)).is_ok());

    let filters = ["{}"; wire::MAX_FILTERS + 1].join(",");
    let r = refusal(&format!(r#"["REQ","s",{filters}]"#));
    assert_eq!(r.decision, "fail_closed_too_many_filters");
    assert_eq!(frame(&r)[0], "CLOSED");
    let filters = ["{}"; wire::MAX_FILTERS].join(",");
    assert!(parse_client_message(&format!(r#"["REQ","s",{filters}]"#)).is_ok());
    assert_eq!(refusal(r#"["REQ","s"]"#).decision, "fail_closed_bad_filter");
}

/// serde_json's recursion limit (128) is on in this tree: a depth bomb is a parse error.
#[test]
fn a_depth_bomb_is_a_parse_error_not_a_stack_overflow() {
    for depth in [129usize, 60_000] {
        let text = format!(r#"["REQ","s",{}{}]"#, "[".repeat(depth), "]".repeat(depth));
        let r = refusal(&text);
        assert_eq!(r.decision, "fail_closed_malformed");
        assert_eq!(
            frame(&r),
            json!(["NOTICE", "invalid: message is nested too deeply"])
        );
    }
}

#[test]
fn reasons_keep_a_nip01_prefix_or_get_one() {
    assert_eq!(
        with_prefix("rate-limited: slow down", "blocked"),
        "rate-limited: slow down"
    );
    assert_eq!(with_prefix("spam", "blocked"), "blocked: spam");
    assert_eq!(with_prefix("", "restricted"), "restricted:");
    assert_eq!(with_prefix("errors: x", "blocked"), "blocked: errors: x");
}

#[test]
fn events_the_model_supplies_are_read_leniently_and_bounded() {
    let e =
        parse_supplied_event(&json!({"kind": "1", "content": "x", "tags": [["n", 5]]})).unwrap();
    assert_eq!(
        (e.kind, e.tags),
        (1, vec![vec!["n".to_string(), "5".to_string()]])
    );
    let profile = parse_supplied_event(&json!({"kind": 0, "content": {"name": "relay"}})).unwrap();
    assert_eq!(profile.content, r#"{"name":"relay"}"#);
    assert!(parse_supplied_event(&json!({"content": "no kind"})).is_err());
    // Controls the id escapings disagree about are dropped, so every client agrees on the id.
    let clean = parse_supplied_event(
        &json!({"kind": 1, "content": "a\u{1}b\nc\u{8}", "tags": [["t", "x\u{7}"]]}),
    )
    .unwrap();
    assert_eq!(clean.content, "ab\nc");
    assert_eq!(clean.tags, vec![vec!["t".to_string(), "x".to_string()]]);
    assert!(parse_supplied_event(&json!({"kind": 1, "tags": "t"})).is_err());
    let too_many = json!(vec![json!({"kind": 1}); wire::MAX_EVENTS_PER_ANSWER + 1]);
    assert!(wire::parse_supplied_events(Some(&too_many)).is_err());
}
