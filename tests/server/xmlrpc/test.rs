//! End-to-end XML-RPC tests for NetGet
//!
//! These tests spawn the actual NetGet binary with XML-RPC prompts
//! and validate the responses using real HTTP clients to send XML-RPC requests.


use super::super::super::helpers::{self, E2EResult, NetGetConfig};
use quick_xml::events::Event;
use quick_xml::Reader;

/// Helper to build XML-RPC methodCall
fn build_method_call(method_name: &str, params: &[(&str, &str)]) -> String {
    let mut xml = format!(
        r#"<?xml version="1.0"?>
<methodCall>
  <methodName>{}</methodName>
  <params>"#,
        method_name
    );

    for (value_type, value) in params {
        xml.push_str(&format!(
            r#"
    <param>
      <value><{}>{}</{}></value>
    </param>"#,
            value_type, value, value_type
        ));
    }

    xml.push_str(
        r#"
  </params>
</methodCall>"#,
    );

    xml
}

/// Helper to parse XML-RPC response and extract value
fn parse_xmlrpc_response(xml: &str) -> E2EResult<String> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    let mut buf = Vec::new();
    let mut in_value = false;
    let mut in_fault = false;
    let mut result = String::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(ref e)) => {
                if e.name().as_ref() == b"value" {
                    in_value = true;
                } else if e.name().as_ref() == b"fault" {
                    in_fault = true;
                }
            }
            Ok(Event::Text(e)) if in_value && !in_fault => {
                result = e.unescape()?.to_string();
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(anyhow::anyhow!("XML parse error: {}", e).into()),
            _ => {}
        }
        buf.clear();
    }

    Ok(result)
}

#[tokio::test]
async fn test_xmlrpc_simple_method() -> E2EResult<()> {
    println!("\n=== E2E Test: Simple XML-RPC Method Call ===");

    // PROMPT: Simple add method
    let prompt = "listen on port {AVAILABLE_PORT} via xmlrpc stack. Implement method 'add' that takes two integers and returns their sum.";

    // Start the server
    let config = NetGetConfig::new(prompt).with_mock(|mock| {
        mock
            // Mock 1: Server startup (user command)
            .on_instruction_containing("listen on port")
            .and_instruction_containing("xmlrpc")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "XML-RPC",
                    "instruction": "Implement add method"
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 2: Method call received (xmlrpc_method_call event)
            .on_event("xmlrpc_method_call")
            .and_event_data_contains("method_name", "add")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "xmlrpc_success_response",
                    "value_type": "int",
                    "value": 8
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let server = helpers::start_netget_server(config).await?;
    println!(
        "Server started: {} stack on port {}",
        server.stack, server.port
    );

    // Verify it's actually an XML-RPC server
    assert_eq!(
        server.stack, "XML-RPC",
        "Expected XML-RPC server but got {}",
        server.stack
    );

    // VALIDATION: Call add method with 5 + 3
    let xml_request = build_method_call("add", &[("int", "5"), ("int", "3")]);
    println!("Sending XML-RPC request:\n{}", xml_request);

    let client = reqwest::Client::new();
    let url = format!("http://127.0.0.1:{}/RPC2", server.port);

    let response = client
        .post(&url)
        .header("Content-Type", "text/xml")
        .body(xml_request)
        .send()
        .await?;

    assert_eq!(response.status(), 200);

    let response_xml = response.text().await?;
    println!("Received XML-RPC response:\n{}", response_xml);

    // Parse and validate response
    let result = parse_xmlrpc_response(&response_xml)?;
    println!("Parsed result: {}", result);

    // Should contain 8 (5+3)
    assert!(result.contains("8"), "Expected sum of 8, got: {}", result);

    println!("✓ XML-RPC method call validated");

    // Verify mock expectations were met
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;

    server.stop().await?;
    println!("=== Test passed ===\n");
    Ok(())
}

#[tokio::test]
async fn test_xmlrpc_introspection_list_methods() -> E2EResult<()> {
    println!("\n=== E2E Test: XML-RPC system.listMethods Introspection ===");

    // PROMPT: Server with introspection
    let prompt = "listen on port {AVAILABLE_PORT} via xmlrpc stack. Implement these methods: add, subtract, multiply. Also support system.listMethods introspection.";

    // Start the server
    let config = NetGetConfig::new(prompt).with_mock(|mock| {
        mock.on_instruction_containing("listen on port")
            .and_instruction_containing("xmlrpc")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "XML-RPC",
                    "instruction": "Implement add, subtract, multiply methods with introspection"
                }
            ]))
            .expect_calls(1)
            .and()
            .on_event("xmlrpc_method_call")
            .and_event_data_contains("method_name", "system.listMethods")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "xmlrpc_list_methods_response",
                    "methods": ["add", "subtract", "multiply", "system.listMethods"]
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let server = helpers::start_netget_server(config).await?;
    println!("Server started on port {}", server.port);

    // VALIDATION: Call system.listMethods
    let xml_request = build_method_call("system.listMethods", &[]);
    println!("Sending system.listMethods request");

    let client = reqwest::Client::new();
    let url = format!("http://127.0.0.1:{}/", server.port);

    let response = client
        .post(&url)
        .header("Content-Type", "text/xml")
        .body(xml_request)
        .send()
        .await?;

    assert_eq!(response.status(), 200);

    let response_xml = response.text().await?;
    println!("Received response:\n{}", response_xml);

    // Verify response contains method names
    assert!(response_xml.contains("add") || response_xml.contains("system.listMethods"));

    println!("✓ Introspection validated");
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    println!("=== Test passed ===\n");
    Ok(())
}

#[tokio::test]
async fn test_xmlrpc_fault_response() -> E2EResult<()> {
    println!("\n=== E2E Test: XML-RPC Fault Response ===");

    // PROMPT: Server that returns fault for unknown methods
    let prompt = "listen on port {AVAILABLE_PORT} via xmlrpc stack. Implement method 'greet'. For unknown methods, return fault code -32601 with message 'Method not found'.";

    // Start the server
    let config = NetGetConfig::new(prompt).with_mock(|mock| {
        mock.on_instruction_containing("listen on port")
            .and_instruction_containing("xmlrpc")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "XML-RPC",
                    "instruction": "Implement greet method, fault for unknown"
                }
            ]))
            .expect_calls(1)
            .and()
            .on_event("xmlrpc_method_call")
            .and_event_data_contains("method_name", "nonExistentMethod")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "xmlrpc_fault_response",
                    "fault_code": -32601,
                    "fault_string": "Method not found"
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let server = helpers::start_netget_server(config).await?;
    println!("Server started on port {}", server.port);

    // VALIDATION: Call non-existent method
    let xml_request = build_method_call("nonExistentMethod", &[]);
    println!("Calling non-existent method");

    let client = reqwest::Client::new();
    let url = format!("http://127.0.0.1:{}/", server.port);

    let response = client
        .post(&url)
        .header("Content-Type", "text/xml")
        .body(xml_request)
        .send()
        .await?;

    // XML-RPC returns HTTP 200 even for faults (fault is in XML body)
    assert_eq!(response.status(), 200);

    let response_xml = response.text().await?;
    println!("Received fault response:\n{}", response_xml);

    // Verify it's a fault response
    assert!(response_xml.contains("<fault>"), "Expected fault response");
    assert!(
        response_xml.contains("faultCode") || response_xml.contains("-32601"),
        "Expected fault code"
    );

    println!("✓ Fault response validated");
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    println!("=== Test passed ===\n");
    Ok(())
}

#[tokio::test]
async fn test_xmlrpc_string_parameter() -> E2EResult<()> {
    println!("\n=== E2E Test: XML-RPC String Parameter ===");

    // PROMPT: String echo method
    let prompt = "listen on port {AVAILABLE_PORT} via xmlrpc stack. Implement method 'greet' that takes a name (string) and returns 'Hello, [name]!'.";

    // Start the server
    let config = NetGetConfig::new(prompt)
        .with_mock(|mock| {
            mock
                .on_instruction_containing("listen on port")
                .and_instruction_containing("xmlrpc")
                .respond_with_actions(serde_json::json!([{"type": "open_server", "port": 0, "base_stack": "XML-RPC", "instruction": "Greet method"}]))
                .expect_calls(1)
                .and()
                .on_event("xmlrpc_method_call")
                .and_event_data_contains("method_name", "greet")
                .respond_with_actions(serde_json::json!([{"type": "xmlrpc_success_response", "value_type": "string", "value": "Hello, Alice!"}]))
                .expect_calls(1)
                .and()
        });
    let server = helpers::start_netget_server(config).await?;
    println!("Server started on port {}", server.port);

    // VALIDATION: Call greet method
    let xml_request = build_method_call("greet", &[("string", "Alice")]);
    println!("Calling greet method with 'Alice'");

    let client = reqwest::Client::new();
    let url = format!("http://127.0.0.1:{}/", server.port);

    let response = client
        .post(&url)
        .header("Content-Type", "text/xml")
        .body(xml_request)
        .send()
        .await?;

    assert_eq!(response.status(), 200);

    let response_xml = response.text().await?;
    println!("Received response:\n{}", response_xml);

    let result = parse_xmlrpc_response(&response_xml)?;
    println!("Parsed result: {}", result);

    // Should contain greeting
    assert!(
        result.contains("Alice"),
        "Expected greeting with 'Alice', got: {}",
        result
    );

    println!("✓ String parameter validated");
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    println!("=== Test passed ===\n");
    Ok(())
}

#[tokio::test]
async fn test_xmlrpc_boolean_parameter() -> E2EResult<()> {
    println!("\n=== E2E Test: XML-RPC Boolean Parameter ===");

    // PROMPT: Boolean parameter
    let prompt = "listen on port {AVAILABLE_PORT} via xmlrpc stack. Implement method 'toggle' that takes a boolean and returns the opposite.";

    // Start the server
    let config = NetGetConfig::new(prompt)
        .with_mock(|mock| {
            mock
                .on_instruction_containing("listen on port")
                .and_instruction_containing("xmlrpc")
                .respond_with_actions(serde_json::json!([{"type": "open_server", "port": 0, "base_stack": "XML-RPC", "instruction": "Toggle method"}]))
                .expect_calls(1)
                .and()
                .on_event("xmlrpc_method_call")
                .and_event_data_contains("method_name", "toggle")
                .respond_with_actions(serde_json::json!([{"type": "xmlrpc_success_response", "value_type": "boolean", "value": 0}]))
                .expect_calls(1)
                .and()
        });
    let server = helpers::start_netget_server(config).await?;
    println!("Server started on port {}", server.port);

    // VALIDATION: Call toggle method with true (1)
    let xml_request = build_method_call("toggle", &[("boolean", "1")]);
    println!("Calling toggle method with true");

    let client = reqwest::Client::new();
    let url = format!("http://127.0.0.1:{}/", server.port);

    let response = client
        .post(&url)
        .header("Content-Type", "text/xml")
        .body(xml_request)
        .send()
        .await?;

    assert_eq!(response.status(), 200);

    let response_xml = response.text().await?;
    println!("Received response:\n{}", response_xml);

    // Should contain boolean response
    assert!(
        response_xml.contains("<boolean>")
            || response_xml.contains("0")
            || response_xml.contains("false"),
        "Expected boolean in response"
    );

    println!("✓ Boolean parameter validated");
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    println!("=== Test passed ===\n");
    Ok(())
}

#[tokio::test]
async fn test_xmlrpc_multiple_parameters() -> E2EResult<()> {
    println!("\n=== E2E Test: XML-RPC Multiple Parameters ===");

    // PROMPT: Multiple parameters
    let prompt = "listen on port {AVAILABLE_PORT} via xmlrpc stack. Implement method 'concat' that takes two strings and returns them concatenated with a space between.";

    // Start the server
    let config = NetGetConfig::new(prompt)
        .with_mock(|mock| {
            mock
                .on_instruction_containing("listen on port")
                .and_instruction_containing("xmlrpc")
                .respond_with_actions(serde_json::json!([{"type": "open_server", "port": 0, "base_stack": "XML-RPC", "instruction": "Concat method"}]))
                .expect_calls(1)
                .and()
                .on_event("xmlrpc_method_call")
                .and_event_data_contains("method_name", "concat")
                .respond_with_actions(serde_json::json!([{"type": "xmlrpc_success_response", "value_type": "string", "value": "Hello World"}]))
                .expect_calls(1)
                .and()
        });
    let server = helpers::start_netget_server(config).await?;
    println!("Server started on port {}", server.port);

    // VALIDATION: Call concat method
    let xml_request = build_method_call("concat", &[("string", "Hello"), ("string", "World")]);
    println!("Calling concat method");

    let client = reqwest::Client::new();
    let url = format!("http://127.0.0.1:{}/", server.port);

    let response = client
        .post(&url)
        .header("Content-Type", "text/xml")
        .body(xml_request)
        .send()
        .await?;

    assert_eq!(response.status(), 200);

    let response_xml = response.text().await?;
    println!("Received response:\n{}", response_xml);

    let result = parse_xmlrpc_response(&response_xml)?;
    println!("Parsed result: {}", result);

    // Should contain both words
    assert!(
        result.contains("Hello") && result.contains("World"),
        "Expected 'Hello World', got: {}",
        result
    );

    println!("✓ Multiple parameters validated");
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    println!("=== Test passed ===\n");
    Ok(())
}

#[tokio::test]
async fn test_xmlrpc_non_post_request() -> E2EResult<()> {
    println!("\n=== E2E Test: XML-RPC Non-POST Request (Should Fail) ===");

    // PROMPT: Standard XML-RPC server
    let prompt = "listen on port {AVAILABLE_PORT} via xmlrpc stack. Implement method 'test'.";

    // Start the server (GET request won't trigger LLM, only server startup)
    let config = NetGetConfig::new(prompt)
        .with_mock(|mock| {
            mock
                .on_instruction_containing("xmlrpc")
                .respond_with_actions(serde_json::json!([{"type": "open_server", "port": 0, "base_stack": "XML-RPC", "instruction": "Test method"}]))
                .expect_calls(1)
                .and()
        });
    let server = helpers::start_netget_server(config).await?;
    println!("Server started on port {}", server.port);

    // VALIDATION: Try GET request (XML-RPC requires POST)
    let client = reqwest::Client::new();
    let url = format!("http://127.0.0.1:{}/", server.port);

    let response = client.get(&url).send().await?;

    // Should return 200 with fault (XML-RPC returns 200 for faults)
    assert_eq!(response.status(), 200);

    let response_xml = response.text().await?;
    println!("Received response:\n{}", response_xml);

    // Should be a fault response for invalid request
    assert!(
        response_xml.contains("<fault>") || response_xml.contains("Invalid request"),
        "Expected fault for non-POST request"
    );

    println!("✓ Non-POST rejection validated");
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    println!("=== Test passed ===\n");
    Ok(())
}

/// Two refusals the parser and the fault executor used to get wrong, in one server.
///
/// * **Deep `<array>` nesting is refused.** The depth guard was on `<value>` alone, so
///   `<array><array><array>…` — 7 bytes a level, and well-formed — pushed a container per
///   level with no check at all. A body at the 4 MiB cap bought about 600 000 of them. The
///   parser is iterative, so this was allocation rather than a stack overflow, but it is
///   allocation a peer chooses and nothing needs.
/// * **A quoted `fault_code` is not silently "internal error".** The executor did
///   `.and_then(|v| v.as_i64()).unwrap_or(-32603)`, so `"fault_code": "-32601"` — the quoted
///   form models routinely produce, and the form every other numeric field here already
///   accepts through `as_integer` — became `-32603` on the wire: the model said "no such
///   method" and the caller was told netget had broken.
///
/// LLM call budget: 1 (server startup). The nesting refusal never reaches a model.
#[tokio::test]
async fn test_xmlrpc_refuses_deep_nesting_and_honours_a_quoted_fault_code() -> E2EResult<()> {
    let prompt = "listen on port {AVAILABLE_PORT} via xmlrpc stack. Implement method 'greet'.";

    let config = NetGetConfig::new(prompt).with_mock(|mock| {
        mock.on_instruction_containing("listen on port")
            .and_instruction_containing("xmlrpc")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "XML-RPC",
                    "instruction": "Implement greet"
                }
            ]))
            .expect_calls(1)
            .and()
            .on_event("xmlrpc_method_call")
            .and_event_data_contains("method_name", "greet")
            // The model quotes the number, as models do. It must reach the wire as -32601.
            .respond_with_actions(serde_json::json!([
                {
                    "type": "xmlrpc_fault_response",
                    "fault_code": "-32601",
                    "fault_string": "Method not found"
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let server = helpers::start_netget_server(config).await?;
    let url = format!("http://127.0.0.1:{}/", server.port);
    let client = reqwest::Client::new();

    // --- deep nesting is refused, before any model call -----------------------------------
    //
    // 300 levels: well past MAX_VALUE_DEPTH (64) and small enough that the request itself is
    // trivial, which is the point — the cost is all on the receiving side.
    let depth = 300;
    let mut nested = String::from(
        "<?xml version=\"1.0\"?><methodCall><methodName>deep</methodName><params><param>",
    );
    for _ in 0..depth {
        nested.push_str("<array><data>");
    }
    for _ in 0..depth {
        nested.push_str("</data></array>");
    }
    nested.push_str("</param></params></methodCall>");

    let response = tokio::time::timeout(
        std::time::Duration::from_secs(25),
        client
            .post(&url)
            .header("Content-Type", "text/xml")
            .body(nested)
            .send(),
    )
    .await
    .map_err(|_| "XML-RPC neither answered nor failed within 25s on a deeply nested request")??;

    assert_eq!(response.status(), 200);
    let body = response.text().await?;
    println!("deep-nesting response:\n{body}");
    assert!(
        body.contains("<fault>") && body.contains("-32700"),
        "deep nesting must be a parse-error fault, not accepted: {body}"
    );

    // --- a quoted fault_code reaches the wire as the number it names ----------------------
    let response = tokio::time::timeout(
        std::time::Duration::from_secs(25),
        client
            .post(&url)
            .header("Content-Type", "text/xml")
            .body(build_method_call("greet", &[("string", "world")]))
            .send(),
    )
    .await
    .map_err(|_| "XML-RPC did not answer the greet call within 25s")??;

    assert_eq!(response.status(), 200);
    let body = response.text().await?;
    println!("quoted fault_code response:\n{body}");
    assert!(
        body.contains("<fault>"),
        "the handler chose a fault; the caller must get one: {body}"
    );
    assert!(
        body.contains("-32601"),
        "a quoted fault_code must reach the wire as the number it names, not -32603: {body}"
    );
    assert!(
        !body.contains("-32603"),
        "-32603 means the quoted code was silently discarded: {body}"
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}
