//! The `answer_with` hint `gemini_request` carries, and the page example it replaced.
//!
//! The model answered "/guestbook asks the visitor for their name before showing anything"
//! with a page first and the input prompt second - only the first response is sent - and
//! answered "serve a home page titled Welcome to the NetGet capsule" with the example page
//! ("Welcome", "A capsule served by NetGet.") first.

use netget::server::gemini::actions::{answer_with_for_request, GEMINI_REQUEST_EVENT};

#[test]
fn a_first_request_names_the_path_and_leads_with_the_51() {
    let hint = answer_with_for_request("/guestbook", None);
    assert!(
        hint.starts_with(
            "the visitor asked for /guestbook (not the home page, which is /). Exactly one \
             action - only the first is sent."
        ),
        "{hint}"
    );
    assert!(
        hint.contains("send_gemini_input with that question and nothing else"),
        "{hint}"
    );
    assert!(hint.contains("word for word"), "{hint}");
    // The 51 is a literal action, and it comes before the page: told "only the home page
    // exists", the model otherwise served the home page for any path.
    assert!(
        hint.contains(r#"{"type": "send_gemini_response", "status": 51, "meta": "Not found"}"#),
        "{hint}"
    );
    assert!(
        hint.find("\"status\": 51") < hint.find("send_gemtext"),
        "{hint}"
    );

    let home = answer_with_for_request("/", None);
    assert!(
        home.starts_with("the visitor asked for / (the home page)."),
        "{home}"
    );
}

#[test]
fn an_answered_prompt_asks_for_the_page_that_follows() {
    let hint = answer_with_for_request("/guestbook", Some("Ada"));
    assert!(
        hint.contains("answered the prompt at /guestbook with \"Ada\""),
        "{hint}"
    );
    assert!(hint.contains("send_gemtext"), "{hint}");
}

#[test]
fn the_page_examples_are_placeholders() {
    let mut texts: Vec<String> = GEMINI_REQUEST_EVENT
        .actions
        .iter()
        .map(|a| a.example.to_string())
        .collect();
    texts.push(
        GEMINI_REQUEST_EVENT
            .effective_response_example()
            .to_string(),
    );
    for text in texts {
        assert!(
            !text.contains("\"Welcome\"") && !text.contains("A capsule served by NetGet"),
            "{text}"
        );
    }
}

/// A text line carrying a url is rendered as the paragraph and then its link, rather than as a
/// paragraph whose url is dropped - the shape llama3.1:8b used for "with a link to /about" in
/// two runs of five.
#[test]
fn a_text_line_with_a_url_keeps_its_link() {
    use netget::llm::actions::protocol_trait::{ActionResult, Server};
    use netget::server::gemini::actions::GeminiProtocol;
    let render = |lines: serde_json::Value| match GeminiProtocol::new()
        .execute_action(serde_json::json!({"type": "send_gemtext", "lines": lines}))
    {
        Ok(ActionResult::Output(bytes)) => String::from_utf8(bytes).unwrap(),
        other => panic!("expected a page, got {other:?}"),
    };
    let page = render(serde_json::json!([
        {"type": "heading1", "text": "Welcome to the NetGet capsule"},
        {"type": "text", "text": "A capsule for the NetGet tool", "url": "/about", "alt": "Learn more"}
    ]));
    assert!(
        page.ends_with("\nA capsule for the NetGet tool\n=> /about Learn more\n"),
        "{page:?}"
    );
    // With no label of its own, the text is the link's label.
    let page = render(serde_json::json!([{"type": "text", "text": "About", "url": "/about"}]));
    assert!(page.ends_with("\r\n=> /about About\n"), "{page:?}");
    // A text line with no url is still only text.
    let page = render(serde_json::json!([{"type": "text", "text": "plain"}]));
    assert!(page.ends_with("\r\nplain\n"), "{page:?}");
}
