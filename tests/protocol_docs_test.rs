//! `--docs` renders live protocol documentation. Guards that the renderer walks
//! the registries and includes real per-protocol detail rather than a stub.

use netget::protocol::render_all_protocol_docs;

#[test]
fn docs_include_server_protocols_with_detail() {
    let doc = render_all_protocol_docs();
    assert!(doc.contains("Server protocols"), "must list servers");
    // A known server and its keyword/stack detail must be present.
    assert!(doc.contains("HTTP"), "http server must appear");
    assert!(
        doc.contains("Stack:"),
        "per-protocol stack line must render"
    );
    assert!(doc.contains("Keywords:"), "keywords must render");
    // The http_request event and its send_http_response action must surface.
    assert!(doc.contains("http_request"), "http event must render");
    assert!(
        doc.contains("send_http_response"),
        "http action must render"
    );
    assert!(
        doc.len() > 500,
        "docs should be substantial, got {}",
        doc.len()
    );
}
