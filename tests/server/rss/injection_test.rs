//! Model-supplied feed content must not be able to forge feed structure.
//!
//! RSS is XML generated from strings the model wrote, which is the CR/LF-injection class in an
//! XML costume: if a title containing `</title></item><item><title>` reached the document
//! verbatim, one model answer could manufacture entries the operator never asked for, and a
//! `]]>` inside an item description could close the CDATA section the `rss` crate puts it in
//! and turn the rest of that description into markup. The same shape turned a 331 into a login
//! in FTP.
//!
//! It does not, and this test is the measurement rather than the assumption. The mechanism is
//! in the `rss` crate and is worth naming so a future dependency bump is checked against it:
//!
//! * text elements go through `quick_xml::events::BytesText::new`, which is documented as
//!   taking an *unescaped* string and escapes it on write — so `<`, `>` and `&` cannot open a
//!   tag;
//! * an item's `<description>` and `<content:encoded>` are the exception — they are emitted as
//!   CDATA via `BytesCData::escaped`, which **splits** the content on `]]>` into consecutive
//!   CDATA sections rather than escaping it, so the terminator cannot appear inside one;
//! * a category's `domain` is an XML attribute, and `BytesStart::push_attribute` escapes
//!   attribute values, so a `"` cannot close it.
//!
//! What no escaping can fix, and what netget therefore filters itself, is the set of characters
//! XML 1.0 §2.2 forbids outright. There is no entity for NUL; a raw one in a title yields a
//! document every conforming reader rejects, so the server would answer 200 with something
//! unparseable. `xml_safe` drops them and the last test here proves a feed survives one.
//!
//! The evidence is `feed-rs`, not the `rss` crate: parsing our own output with the library that
//! produced it would show only that one crate round-trips through itself, which is exactly the
//! circularity that held this protocol at Experimental. A second implementation reading the
//! bytes off the socket is the only thing that settles what a real reader sees.


use crate::server::helpers::*;

/// A title that tries to close its element and open a second `<item>`.
const FORGED_ITEM: &str =
    "Benign</title></item><item><title>Injected Entry</title><link>http://evil.example/</link>\
     <description>forged</description></item><item><title>trailing";

/// A description that tries to close the CDATA section the `rss` crate wraps it in.
const CDATA_BREAKOUT: &str = "safe]]><script>alert(1)</script><![CDATA[ tail";

/// A category domain that tries to close its attribute and add another.
const ATTR_BREAKOUT: &str = "x\" onload=\"boom";

#[tokio::test]
async fn model_content_cannot_forge_feed_structure() -> E2EResult<()> {
    let config =
        NetGetConfig::new("listen on port 0 via rss\nServe a feed at /f.xml").with_mock(|mock| {
            mock.on_event("rss_feed_requested")
                .and_event_data_contains("path", "/f.xml")
                .respond_with_actions(serde_json::json!([{
                    "type": "generate_rss_feed",
                    "title": FORGED_ITEM,
                    "link": "http://localhost/f.xml",
                    "description": "A & B <not a tag>",
                    "items": [{
                        "title": "The only entry",
                        "link": "http://localhost/1",
                        "description": CDATA_BREAKOUT,
                        "categories": [{"name": "c", "domain": ATTR_BREAKOUT}]
                    }]
                }]))
                .expect_calls(1)
                .and()
                .on_instruction_containing("listen")
                .and_instruction_containing("rss")
                .respond_with_actions(serde_json::json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "RSS",
                    "instruction": "RSS feed server"
                }]))
                .expect_calls(1)
                .and()
        });

    let test_state = start_netget_server(config).await?;
    let url = format!("http://127.0.0.1:{}/f.xml", test_state.port);

    let response = reqwest::Client::new().get(&url).send().await?;
    assert_eq!(response.status(), 200, "hostile content must still serve");
    let body = response.text().await?;

    // The independent reader. If the forged markup had survived, this is where it shows: a
    // parser that accepted the document would report the injected entries as real ones.
    let feed = feed_rs::parser::parse(body.as_bytes())
        .map_err(|e| format!("feed-rs rejected the served feed: {e}\n---\n{body}"))?;

    assert_eq!(
        feed.feed_type,
        feed_rs::model::FeedType::RSS2,
        "the document must still be RSS 2.0, not something the injection reshaped"
    );

    // The whole point: one item in, one entry out. A successful forgery would give three.
    assert_eq!(
        feed.entries.len(),
        1,
        "model content forged {} entries; only the one the action declared may exist\n---\n{}",
        feed.entries.len(),
        body
    );
    assert_eq!(
        feed.entries[0].title.as_ref().map(|t| t.content.as_str()),
        Some("The only entry"),
        "the surviving entry must be ours"
    );

    // The channel title is the hostile string itself, as data. Getting this back verbatim is
    // what proves the markup was escaped rather than dropped or executed.
    assert_eq!(
        feed.title.as_ref().map(|t| t.content.as_str()),
        Some(FORGED_ITEM),
        "the title must come back as the literal text the model wrote\n---\n{body}"
    );
    assert_eq!(
        feed.description.as_ref().map(|t| t.content.as_str()),
        Some("A & B <not a tag>"),
        "bare & and < must survive as characters, not as escapes or as markup"
    );

    // The CDATA terminator must not have ended the section: the tail after `]]>` is still part
    // of the description, and the `<script>` between them is text rather than an element.
    // feed-rs maps an RSS item's `<description>` onto `Entry::summary`.
    let entry_description = feed.entries[0]
        .summary
        .as_ref()
        .map(|t| t.content.as_str())
        .unwrap_or_default();
    assert!(
        entry_description.contains("tail"),
        "the text after `]]>` must still be inside the description, not loose markup: {entry_description:?}\n---\n{body}"
    );
    assert!(
        entry_description.contains("<script>") || entry_description.contains("&lt;script&gt;"),
        "the injected element must survive as description text: {entry_description:?}"
    );

    // The attribute breakout must not have produced a second attribute. `onload=` appearing as
    // a *name* would mean the quote closed the value; as part of the value it is inert.
    assert!(
        !body.contains("onload=\"boom\""),
        "category domain closed its attribute and injected another\n---\n{body}"
    );

    test_state.wait_for_mocks(30).await;
    test_state.verify_mocks().await?;
    Ok(())
}

/// A character XML forbids must not make the served document unparseable.
///
/// This is the failure escaping cannot reach: `\u{0}` has no entity, so passing it through
/// yields a 200 carrying a document `feed-rs` — and every browser — refuses. The server filters
/// them instead, and the rest of the string has to survive intact.
#[tokio::test]
async fn xml_illegal_control_characters_do_not_break_the_feed() -> E2EResult<()> {
    let config =
        NetGetConfig::new("listen on port 0 via rss\nServe a feed at /c.xml").with_mock(|mock| {
            mock.on_event("rss_feed_requested")
                .and_event_data_contains("path", "/c.xml")
                .respond_with_actions(serde_json::json!([{
                    "type": "generate_rss_feed",
                    "title": "Head\u{0}er\u{1}",
                    "link": "http://localhost/c.xml",
                    "description": "keeps\ttab and\nnewline",
                    "items": []
                }]))
                .expect_calls(1)
                .and()
                .on_instruction_containing("listen")
                .and_instruction_containing("rss")
                .respond_with_actions(serde_json::json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "RSS",
                    "instruction": "RSS feed server"
                }]))
                .expect_calls(1)
                .and()
        });

    let test_state = start_netget_server(config).await?;
    let url = format!("http://127.0.0.1:{}/c.xml", test_state.port);
    let body = reqwest::Client::new()
        .get(&url)
        .send()
        .await?
        .text()
        .await?;

    let feed = feed_rs::parser::parse(body.as_bytes())
        .map_err(|e| format!("feed-rs rejected the served feed: {e}\n---\n{body}"))?;
    assert_eq!(
        feed.title.as_ref().map(|t| t.content.as_str()),
        Some("Header"),
        "the forbidden characters must be dropped and nothing else"
    );
    assert!(
        feed.description
            .as_ref()
            .is_some_and(|d| d.content.contains('\t')),
        "tab is legal in XML 1.0 and must be kept"
    );

    test_state.wait_for_mocks(30).await;
    test_state.verify_mocks().await?;
    Ok(())
}

/// A channel field the action declares `required: true` must be refused, not defaulted.
///
/// The server used to substitute `"Untitled Feed"` / `"http://localhost"` / `"No description"`,
/// so an answer naming none of the three produced a complete-looking feed and nothing recorded
/// that the model had not supplied one. The refusal has to be visible on the wire as something
/// other than 404, because 404 is the model's way of saying "this path has no feed" and
/// collapsing the two would make a netget-side refusal indistinguishable from a decision.
#[tokio::test]
async fn a_feed_missing_its_required_fields_is_refused_not_defaulted() -> E2EResult<()> {
    let config =
        NetGetConfig::new("listen on port 0 via rss\nServe a feed at /m.xml").with_mock(|mock| {
            mock.on_event("rss_feed_requested")
                .and_event_data_contains("path", "/m.xml")
                .respond_with_actions(serde_json::json!([{
                    "type": "generate_rss_feed",
                    "items": []
                }]))
                .expect_calls(1)
                .and()
                .on_instruction_containing("listen")
                .and_instruction_containing("rss")
                .respond_with_actions(serde_json::json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "RSS",
                    "instruction": "RSS feed server"
                }]))
                .expect_calls(1)
                .and()
        });

    let test_state = start_netget_server(config).await?;
    let url = format!("http://127.0.0.1:{}/m.xml", test_state.port);
    let response = reqwest::Client::new().get(&url).send().await?;

    let status = response.status();
    let body = response.text().await?;
    assert_ne!(
        status, 200,
        "a feed with no title, link or description must not be served as one: {body}"
    );
    assert_ne!(
        status, 404,
        "404 is the model saying the path has no feed; a refused answer must be distinct"
    );
    assert!(
        !body.contains("Untitled Feed") && !body.contains("No description"),
        "the invented defaults must be gone: {body}"
    );

    test_state.wait_for_mocks(30).await;
    test_state.verify_mocks().await?;
    Ok(())
}
