//! The Gemini wire format in isolation, as properties over arbitrary model input.
//!
//! The guarantee pinned here is the one the protocol's safety rests on: **whatever the model
//! writes, a client parsing the result per the specification sees the lines the model meant, of
//! the types the model chose** — a text line never becomes a link, a heading never spans two
//! lines, a preformatted block never closes early — and a response header is always one
//! well-formed `<status> <meta>` line with a body only after 2x.
//!
//! The classifier below is written from the specification's line-type rules (§5 of the gemtext
//! specification), not from NetGet's renderer.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features gemini --test server -- gemini::wire --test-threads=100


use netget::server::gemini::wire::{
    gemtext_mime, leading_status, parse_request, percent_decode, render_gemtext, render_response,
    GemtextLine, RequestRefusal, MAX_META_BYTES, STATUS_CODES,
};
use proptest::prelude::*;

#[derive(Debug, PartialEq, Eq)]
enum Kind {
    Text,
    Link,
    Heading,
    List,
    Quote,
    Toggle,
    Pre,
}

/// Classify every line of a gemtext document the way a client must.
fn classify(doc: &str) -> Vec<(Kind, String)> {
    let mut pre = false;
    let mut out = Vec::new();
    for line in doc.lines() {
        if line.starts_with("```") {
            pre = !pre;
            out.push((Kind::Toggle, line.to_string()));
        } else if pre {
            out.push((Kind::Pre, line.to_string()));
        } else if line.starts_with("=>") {
            out.push((Kind::Link, line.to_string()));
        } else if line.starts_with('#') {
            out.push((Kind::Heading, line.to_string()));
        } else if line.starts_with("* ") {
            out.push((Kind::List, line.to_string()));
        } else if line.starts_with('>') {
            out.push((Kind::Quote, line.to_string()));
        } else {
            out.push((Kind::Text, line.to_string()));
        }
    }
    out
}

fn line_strategy() -> impl Strategy<Value = GemtextLine> {
    let text = "(\\PC|[\n\r\t#*>=`]){0,120}";
    prop_oneof![
        text.prop_map(GemtextLine::Text),
        (text, "[a-z/:.]{1,30}").prop_map(|(t, u)| GemtextLine::Link { url: u, text: t }),
        (1u8..=3, text).prop_map(|(l, t)| GemtextLine::Heading(l, t)),
        text.prop_map(GemtextLine::ListItem),
        text.prop_map(GemtextLine::Quote),
        (text, text).prop_map(|(a, t)| GemtextLine::Preformatted { alt: a, text: t }),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// Each model line lands as exactly the types it asked for, and preformatted blocks
    /// balance: a client ends the document outside a block.
    #[test]
    fn every_line_keeps_its_type(lines in proptest::collection::vec(line_strategy(), 0..12)) {
        let doc = render_gemtext(&lines);
        let classified = classify(&doc);
        let mut i = 0;
        for line in &lines {
            match line {
                GemtextLine::Text(t) => {
                    let n = t.replace("\r\n", "\n").replace('\r', "\n").split('\n').count();
                    for _ in 0..n {
                        prop_assert_eq!(&classified[i].0, &Kind::Text, "{:?}", classified[i]);
                        i += 1;
                    }
                }
                GemtextLine::Link { .. } => {
                    prop_assert_eq!(&classified[i].0, &Kind::Link);
                    i += 1;
                }
                GemtextLine::Heading(level, _) => {
                    prop_assert_eq!(&classified[i].0, &Kind::Heading);
                    let prefix = format!("{} ", "#".repeat(*level as usize));
                    prop_assert!(classified[i].1.starts_with(&prefix), "{:?}", classified[i]);
                    i += 1;
                }
                GemtextLine::ListItem(_) => {
                    prop_assert_eq!(&classified[i].0, &Kind::List);
                    i += 1;
                }
                GemtextLine::Quote(t) => {
                    let n = t.replace("\r\n", "\n").replace('\r', "\n").split('\n').count();
                    for _ in 0..n {
                        prop_assert_eq!(&classified[i].0, &Kind::Quote);
                        i += 1;
                    }
                }
                GemtextLine::Preformatted { text, .. } => {
                    prop_assert_eq!(&classified[i].0, &Kind::Toggle);
                    i += 1;
                    let n = text.replace("\r\n", "\n").replace('\r', "\n").split('\n').count();
                    for _ in 0..n {
                        prop_assert_eq!(&classified[i].0, &Kind::Pre, "{:?}", classified[i]);
                        i += 1;
                    }
                    prop_assert_eq!(&classified[i].0, &Kind::Toggle);
                    i += 1;
                }
            }
        }
        prop_assert_eq!(i, classified.len(), "extra lines: {:?}", &classified[i..]);
    }

    /// A header is one `<2 digits> <meta>` line of at most 1024 bytes of meta, and a body
    /// follows only a 2x.
    #[test]
    fn a_response_header_is_always_well_formed(
        idx in 0..STATUS_CODES.len(),
        meta in "(\\PC|[\r\n\t ]){0,1100}",
        body in proptest::option::of("\\PC{0,50}"),
    ) {
        let status = STATUS_CODES[idx].0;
        // An Err is a refusal the executor reports to the model; only what renders is checked.
        if let Ok((wire, _)) = render_response(status, &meta, body.as_deref()) {
            let end = wire.find("\r\n").unwrap();
            let header = &wire[..end];
            prop_assert_eq!(leading_status(wire.as_bytes()), Some(status));
            let m = &header[3..];
            prop_assert!(!m.is_empty() && m.len() <= MAX_META_BYTES);
            prop_assert!(!m.contains(['\r', '\n']));
            let rest = &wire[end + 2..];
            if (20..30).contains(&status) {
                prop_assert_eq!(rest, body.as_deref().unwrap_or(""));
            } else {
                prop_assert_eq!(rest, "");
            }
        }
    }

    /// Percent-encoding every byte of a string and decoding it gives the string back.
    #[test]
    fn percent_decoding_inverts_percent_encoding(s in "\\PC{0,100}") {
        let encoded: String = s.bytes().map(|b| format!("%{b:02X}")).collect();
        prop_assert_eq!(percent_decode(&encoded), s);
    }
}

#[test]
fn requests_are_validated_as_the_specification_says() {
    let ok = parse_request("gemini://example.org/a/b?x%20y").unwrap();
    assert_eq!(ok.host, "example.org");
    assert_eq!(ok.path, "/a/b");
    assert_eq!(ok.query.as_deref(), Some("x y"));
    assert_eq!(parse_request("gemini://example.org").unwrap().path, "/");
    assert_eq!(parse_request("gemini://example.org/").unwrap().query, None);

    assert_eq!(
        parse_request("https://example.org/"),
        Err(RequestRefusal::ProxyRefused)
    );
    for bad in [
        "/relative",
        "gemini://u@example.org/",
        "gemini://example.org/#f",
        "\u{feff}gemini://example.org/",
        "gemini:///x",
    ] {
        assert!(
            matches!(parse_request(bad), Err(RequestRefusal::BadRequest(_))),
            "{bad:?} must be a bad request"
        );
    }
    let long = format!("gemini://h/{}", "a".repeat(1014));
    assert_eq!(long.len(), 1025);
    assert_eq!(
        parse_request(&long),
        Err(RequestRefusal::BadRequest("Request too long"))
    );
    assert_eq!(parse_request(&long[..1024]).unwrap().host, "h");
}

#[test]
fn percent_decode_leaves_invalid_escapes_alone() {
    assert_eq!(percent_decode("100%"), "100%");
    assert_eq!(percent_decode("%zz%4"), "%zz%4");
    assert_eq!(percent_decode("%+1"), "%+1");
    assert_eq!(percent_decode("a+b"), "a+b");
    assert_eq!(percent_decode("%C3%A9%"), "é%");
}

#[test]
fn responses_have_defaults_and_reject_what_the_spec_does_not_define() {
    assert_eq!(render_response(51, "", None).unwrap().0, "51 Not found\r\n");
    assert_eq!(
        render_response(20, "", Some("hi")).unwrap().0,
        "20 text/gemini; charset=utf-8\r\nhi"
    );
    let (wire, dropped) = render_response(40, "busy", Some("body")).unwrap();
    assert_eq!(wire, "40 busy\r\n");
    assert!(dropped);
    assert_eq!(
        render_response(10, "What\r\n20 text/plain", None)
            .unwrap()
            .0,
        "10 What  20 text/plain\r\n",
        "a CRLF in the meta cannot forge a second header"
    );
    assert!(render_response(25, "x", None).is_err());
    assert!(render_response(99, "x", None).is_err());
    assert!(render_response(30, "", None).is_err());
    assert!(render_response(44, "soon", None).is_err());
    assert!(render_response(20, &"m".repeat(1025), None).is_err());
    assert_eq!(
        gemtext_mime(Some("en-GB")),
        "text/gemini; charset=utf-8; lang=en-GB"
    );
    assert_eq!(
        gemtext_mime(Some("en; x=1")),
        "text/gemini; charset=utf-8",
        "a lang that is not a BCP 47 list is dropped, not written into the header"
    );
}

#[test]
fn a_link_url_with_whitespace_is_refused() {
    assert!(GemtextLine::from_parts("link", "t", Some("/a b"), None).is_err());
    assert!(GemtextLine::from_parts("link", "t", None, None).is_err());
    assert!(GemtextLine::from_parts("banner", "t", None, None).is_err());
}
