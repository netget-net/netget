//! End-to-end IPP tests for NetGet
//!
//! These tests spawn the actual NetGet binary with IPP prompts
//! and validate the responses using HTTP clients (IPP runs over HTTP).

// Helper module imported from parent

use super::super::super::helpers::{self, E2EResult, NetGetConfig};
use std::time::Duration;

// ---------------------------------------------------------------------------
// A real IPP response decoder
//
// These tests used to assert only `status() == 200` and print the first bytes. That is why
// the encoder could put `hex::encode` of ASCII text on the wire, encode every attribute as
// `nameWithoutLanguage` regardless of type, and hardcode request-id 1 and version 2.0 —
// three bugs a real client rejects — while the suite stayed green. Everything below decodes
// the response and asserts on it.
// ---------------------------------------------------------------------------

const OPERATION_ATTRIBUTES_TAG: u8 = 0x01;
const JOB_ATTRIBUTES_TAG: u8 = 0x02;
const END_OF_ATTRIBUTES_TAG: u8 = 0x03;
const PRINTER_ATTRIBUTES_TAG: u8 = 0x04;

const TAG_INTEGER: u8 = 0x21;
const TAG_ENUM: u8 = 0x23;
const TAG_NAME: u8 = 0x42;
const TAG_URI: u8 = 0x45;
const TAG_CHARSET: u8 = 0x47;
const TAG_NATURAL_LANGUAGE: u8 = 0x48;

/// One decoded IPP attribute: which group it was in, its name, its value tag, its value.
#[derive(Debug, Clone, PartialEq, Eq)]
struct IppAttribute {
    group: u8,
    name: String,
    tag: u8,
    value: Vec<u8>,
}

impl IppAttribute {
    fn as_text(&self) -> String {
        String::from_utf8_lossy(&self.value).into_owned()
    }

    /// IPP `integer` and `enum` are both four-byte big-endian signed values.
    fn as_i32(&self) -> Option<i32> {
        if self.value.len() != 4 {
            return None;
        }
        Some(i32::from_be_bytes([
            self.value[0],
            self.value[1],
            self.value[2],
            self.value[3],
        ]))
    }
}

/// A decoded IPP response message (RFC 8010 §3).
#[derive(Debug)]
struct IppResponse {
    version_major: u8,
    version_minor: u8,
    status: u16,
    request_id: u32,
    attributes: Vec<IppAttribute>,
}

impl IppResponse {
    fn find(&self, name: &str) -> Option<&IppAttribute> {
        self.attributes.iter().find(|a| a.name == name)
    }

    fn expect(&self, name: &str) -> &IppAttribute {
        self.find(name).unwrap_or_else(|| {
            panic!(
                "IPP response has no attribute '{name}'; it has: {:?}",
                self.attributes.iter().map(|a| &a.name).collect::<Vec<_>>()
            )
        })
    }
}

/// Decode an IPP message, or fail the test explaining where decoding stopped.
///
/// Written by hand and strictly, because the point is to reject a malformed message rather
/// than to be forgiving of one: a lenient parser here would reproduce the original problem.
fn decode_ipp(body: &[u8]) -> IppResponse {
    assert!(
        body.len() >= 9,
        "IPP message is {} bytes; the 8-byte header plus a terminating tag is the minimum",
        body.len()
    );

    let mut response = IppResponse {
        version_major: body[0],
        version_minor: body[1],
        status: u16::from_be_bytes([body[2], body[3]]),
        request_id: u32::from_be_bytes([body[4], body[5], body[6], body[7]]),
        attributes: Vec::new(),
    };

    let mut pos = 8;
    let mut group = 0u8;
    // The name of the attribute a zero-length name continues (RFC 8010 additional values).
    let mut last_name = String::new();

    loop {
        assert!(
            pos < body.len(),
            "IPP message ended without 0x03 terminator"
        );
        let tag = body[pos];
        pos += 1;

        if tag == END_OF_ATTRIBUTES_TAG {
            assert_eq!(
                pos,
                body.len(),
                "{} trailing bytes after the end-of-attributes tag",
                body.len() - pos
            );
            return response;
        }

        // Delimiter tags (0x00–0x0f) start a new attribute group and carry no value.
        if tag < 0x10 {
            group = tag;
            continue;
        }

        let read_len = |pos: usize| -> usize {
            assert!(pos + 2 <= body.len(), "IPP message truncated in a length");
            u16::from_be_bytes([body[pos], body[pos + 1]]) as usize
        };

        let name_len = read_len(pos);
        pos += 2;
        assert!(pos + name_len <= body.len(), "IPP name runs past end");
        let name = if name_len == 0 {
            last_name.clone()
        } else {
            let n = String::from_utf8_lossy(&body[pos..pos + name_len]).into_owned();
            last_name = n.clone();
            n
        };
        pos += name_len;

        let value_len = read_len(pos);
        pos += 2;
        assert!(pos + value_len <= body.len(), "IPP value runs past end");
        let value = body[pos..pos + value_len].to_vec();
        pos += value_len;

        response.attributes.push(IppAttribute {
            group,
            name,
            tag,
            value,
        });
    }
}

/// Build an IPP request header with the caller's version and request id.
///
/// Both are deliberately *not* 2.0/1: RFC 8011 requires the response to echo them, and the
/// server hardcoded 2.0 and request-id 1 until recently. A request that used the defaults
/// could not have detected either bug.
fn ipp_request(version: (u8, u8), operation: u16, request_id: u32, printer_uri: &str) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&[version.0, version.1]);
    body.extend_from_slice(&operation.to_be_bytes());
    body.extend_from_slice(&request_id.to_be_bytes());

    body.push(OPERATION_ATTRIBUTES_TAG);

    let mut attr = |tag: u8, name: &str, value: &[u8]| {
        body.push(tag);
        body.extend_from_slice(&(name.len() as u16).to_be_bytes());
        body.extend_from_slice(name.as_bytes());
        body.extend_from_slice(&(value.len() as u16).to_be_bytes());
        body.extend_from_slice(value);
    };

    attr(TAG_CHARSET, "attributes-charset", b"utf-8");
    attr(
        TAG_NATURAL_LANGUAGE,
        "attributes-natural-language",
        b"en-us",
    );
    attr(TAG_URI, "printer-uri", printer_uri.as_bytes());

    body.push(END_OF_ATTRIBUTES_TAG);
    body
}

/// Assertions every IPP response must satisfy, whatever the operation.
fn assert_response_envelope(response: &IppResponse, version: (u8, u8), request_id: u32) {
    assert_eq!(
        (response.version_major, response.version_minor),
        version,
        "RFC 8011 §4.1.8: the response must echo the request's version. \
         ipptool speaks 1.1 and rejects a 2.0 reply outright."
    );
    assert_eq!(
        response.request_id, request_id,
        "RFC 8011 §4.1.1: the response must echo the request's request-id, \
         or the client cannot match it to its request"
    );
    assert_eq!(
        response.status, 0x0000,
        "expected successful-ok (0x0000), got 0x{:04x}",
        response.status
    );

    // RFC 8010 §3.1.4: attributes-charset and attributes-natural-language must be the first
    // two attributes of the operation group, in that order.
    let operation_group: Vec<&IppAttribute> = response
        .attributes
        .iter()
        .filter(|a| a.group == OPERATION_ATTRIBUTES_TAG)
        .collect();
    assert!(
        operation_group.len() >= 2,
        "operation group must carry at least charset and natural-language"
    );
    assert_eq!(operation_group[0].name, "attributes-charset");
    assert_eq!(operation_group[0].tag, TAG_CHARSET);
    assert_eq!(operation_group[0].as_text(), "utf-8");
    assert_eq!(operation_group[1].name, "attributes-natural-language");
    assert_eq!(operation_group[1].tag, TAG_NATURAL_LANGUAGE);
    assert_eq!(operation_group[1].as_text(), "en-us");
}

#[tokio::test]
async fn test_ipp_get_printer_attributes() -> E2EResult<()> {
    println!("\n=== E2E Test: IPP Get-Printer-Attributes ===");

    // PROMPT: Tell the LLM to act as an IPP printer
    let prompt = "Open IPP on port {AVAILABLE_PORT}. When clients send Get-Printer-Attributes IPP requests, \
        use ipp_printer_attributes action with attributes={\"printer-name\":\"NetGet Printer\",\
        \"printer-state\":\"idle\",\"printer-uri-supported\":\"ipp://localhost:{AVAILABLE_PORT}/printers/netget\"}.";

    // Start the server with mocks
    let config = NetGetConfig::new(prompt)
        .with_mock(|mock| {
            mock
                // Mock 1: Server startup (user command)
                .on_instruction_containing("Open IPP")
                .and_instruction_containing("port")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "IPP",
                        "instruction": "IPP printer responding to Get-Printer-Attributes with printer-name='NetGet Printer', printer-state='idle'"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 2: IPP request received (ipp_request_received event). The server
                // names the answering action from the operation id; a Get-Printer-Attributes
                // event that did not would leave a small model to guess, which is how the
                // real-model eval answered it with a job-refusal status.
                .on_event("ipp_request_received")
                .and_event_data_contains("answer_with", "ipp_printer_attributes")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "ipp_printer_attributes",
                        "attributes": {
                            "printer-name": "NetGet Printer",
                            "printer-state": "idle",
                            "printer-uri-supported": format!("ipp://localhost:{{AVAILABLE_PORT}}/printers/netget")
                        }
                    }
                ]))
                .expect_calls(1)
                .and()
        });

    let mut server = helpers::start_netget_server(config).await?;
    println!("Server started on port {}", server.port);

    // VALIDATION: Send HTTP POST request to IPP endpoint
    println!("Sending Get-Printer-Attributes request...");

    let client = reqwest::Client::new();

    // IPP 1.1 with a request id that is neither 0 nor 1, so the echo assertions below are
    // real. Operation 0x000B is Get-Printer-Attributes.
    const VERSION: (u8, u8) = (0x01, 0x01);
    const REQUEST_ID: u32 = 0x1234_5678;
    let uri = format!("ipp://localhost:{}/printers/netget", server.port);
    let body = ipp_request(VERSION, 0x000B, REQUEST_ID, &uri);

    let response = match tokio::time::timeout(
        Duration::from_secs(10),
        client
            .post(format!("http://127.0.0.1:{}/printers/netget", server.port))
            .header("Content-Type", "application/ipp")
            .body(body)
            .send(),
    )
    .await
    {
        Ok(Ok(resp)) => {
            println!("✓ Received HTTP response: {}", resp.status());
            resp
        }
        Ok(Err(e)) => {
            println!("✗ HTTP request error: {}", e);
            return Err(e.into());
        }
        Err(_) => {
            println!("✗ HTTP request timeout");
            return Err("Request timeout".into());
        }
    };

    assert_eq!(response.status(), 200, "Expected HTTP 200 OK");
    assert_eq!(
        response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok()),
        Some("application/ipp"),
        "an IPP reply must be served as application/ipp"
    );

    let response_body = response.bytes().await?;
    println!("Received IPP response: {} bytes", response_body.len());

    let ipp = decode_ipp(&response_body);
    assert_response_envelope(&ipp, VERSION, REQUEST_ID);

    // The three attributes the handler supplied must come back in the printer group, each
    // with the value tag its *type* implies — the encoder used to emit nameWithoutLanguage
    // for everything, so printer-state went out as text where clients read an enum.
    let printer_name = ipp.expect("printer-name");
    assert_eq!(printer_name.group, PRINTER_ATTRIBUTES_TAG);
    assert_eq!(
        printer_name.tag, TAG_NAME,
        "a *-name attribute must be nameWithoutLanguage (0x42)"
    );
    assert_eq!(printer_name.as_text(), "NetGet Printer");

    let printer_state = ipp.expect("printer-state");
    assert_eq!(printer_state.group, PRINTER_ATTRIBUTES_TAG);
    assert_eq!(
        printer_state.tag, TAG_ENUM,
        "printer-state is an enum (0x23), not text"
    );
    assert_eq!(
        printer_state.as_i32(),
        Some(3),
        "'idle' is printer-state enum 3"
    );

    let uri_supported = ipp.expect("printer-uri-supported");
    assert_eq!(uri_supported.group, PRINTER_ATTRIBUTES_TAG);
    assert_eq!(
        uri_supported.tag, TAG_URI,
        "a *-uri-supported attribute must carry the uri tag (0x45)"
    );
    assert!(
        uri_supported.as_text().starts_with("ipp://localhost:"),
        "unexpected printer-uri-supported: {}",
        uri_supported.as_text()
    );

    println!("✓ IPP Get-Printer-Attributes test completed\n");

    // Verify mock expectations were met
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;

    Ok(())
}

#[tokio::test]
async fn test_ipp_print_job() -> E2EResult<()> {
    println!("\n=== E2E Test: IPP Print-Job ===");

    let prompt = "Open IPP on port {AVAILABLE_PORT}. When clients send Print-Job IPP requests, \
        use ipp_job_attributes action with attributes={\"job-id\":1,\"job-state\":\"processing\",\
        \"job-name\":\"test\"}.";

    let config = NetGetConfig::new(prompt)
        .with_mock(|mock| {
            mock
                // Mock 1: Server startup (user command)
                .on_instruction_containing("Open IPP")
                .and_instruction_containing("port")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "IPP",
                        "instruction": "IPP printer accepting Print-Job requests with job-id=1, job-state='processing'"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 2: IPP Print-Job request received
                .on_event("ipp_request_received")
                .and_event_data_contains("answer_with", "ipp_job_attributes")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "ipp_job_attributes",
                        "attributes": {
                            "job-id": 1,
                            "job-state": "processing",
                            "job-name": "test"
                        }
                    }
                ]))
                .expect_calls(1)
                .and()
        });

    let mut server = helpers::start_netget_server(config).await?;
    println!("Server started on port {}", server.port);

    println!("Sending Print-Job request...");

    let client = reqwest::Client::new();

    // Operation 0x0002 is Print-Job. A different version and request id from the previous
    // test, again so the echo assertions cannot pass by coincidence.
    const VERSION: (u8, u8) = (0x02, 0x00);
    const REQUEST_ID: u32 = 0x0000_02A7;
    let uri = format!("ipp://localhost:{}/printers/netget", server.port);
    let mut body = ipp_request(VERSION, 0x0002, REQUEST_ID, &uri);
    // Document data follows the end-of-attributes tag.
    body.extend_from_slice(b"Test print job");

    let response = client
        .post(format!("http://127.0.0.1:{}/printers/netget", server.port))
        .header("Content-Type", "application/ipp")
        .body(body)
        .send()
        .await?;

    println!("✓ Received HTTP response: {}", response.status());

    assert_eq!(response.status(), 200, "Expected HTTP 200 OK");

    let response_body = response.bytes().await?;
    let ipp = decode_ipp(&response_body);
    assert_response_envelope(&ipp, VERSION, REQUEST_ID);

    // Job attributes land in the job group, and each carries the tag its JSON type implies:
    // job-id is a number, so integer; job-state is an enum; job-name is a name.
    let job_id = ipp.expect("job-id");
    assert_eq!(job_id.group, JOB_ATTRIBUTES_TAG);
    assert_eq!(
        job_id.tag, TAG_INTEGER,
        "a numeric attribute must be integer (0x21), not text"
    );
    assert_eq!(job_id.as_i32(), Some(1));

    let job_state = ipp.expect("job-state");
    assert_eq!(job_state.group, JOB_ATTRIBUTES_TAG);
    assert_eq!(job_state.tag, TAG_ENUM, "job-state is an enum (0x23)");
    assert_eq!(
        job_state.as_i32(),
        Some(5),
        "'processing' is job-state enum 5"
    );

    let job_name = ipp.expect("job-name");
    assert_eq!(job_name.group, JOB_ATTRIBUTES_TAG);
    assert_eq!(job_name.tag, TAG_NAME);
    assert_eq!(job_name.as_text(), "test");

    println!("✓ IPP Print-Job test completed\n");

    // Verify mock expectations were met
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;

    Ok(())
}

#[tokio::test]
async fn test_ipp_status_only_response() -> E2EResult<()> {
    println!("\n=== E2E Test: IPP status-only response ===");

    let prompt = "Open IPP on port {AVAILABLE_PORT}. Reject Print-Job with IPP status \
        server-error-not-accepting-jobs and the message 'Printer is not accepting jobs'.";

    let config = NetGetConfig::new(prompt).with_mock(|mock| {
        mock
            // Mock 1: Server startup (user command)
            .on_instruction_containing("Open IPP")
            .and_instruction_containing("port")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "IPP",
                    "instruction": "IPP server rejecting jobs with server-error-not-accepting-jobs"
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 2: reject the job.
            //
            // This mock used to return `{"type": "http_response", ...}`, which IPP has no
            // executor for — the server rejected it and answered with a fallback, and the
            // test passed anyway because it only asserted "2xx or 405". Both halves are
            // fixed: the action is one IPP actually offers, and the assertions decode the
            // reply.
            .on_event("ipp_request_received")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "ipp_response",
                    "ipp_status": "server-error-not-accepting-jobs",
                    "status_message": "Printer is not accepting jobs"
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let mut server = helpers::start_netget_server(config).await?;
    println!("Server started on port {}", server.port);

    println!("Sending Print-Job request that the printer will refuse...");

    const VERSION: (u8, u8) = (0x01, 0x01);
    const REQUEST_ID: u32 = 0x00BE_EF01;
    let uri = format!("ipp://localhost:{}/printers/netget", server.port);

    let client = reqwest::Client::new();
    let response = client
        .post(format!("http://127.0.0.1:{}/printers/netget", server.port))
        .header("Content-Type", "application/ipp")
        .body(ipp_request(VERSION, 0x0002, REQUEST_ID, &uri))
        .send()
        .await?;

    println!("✓ Received HTTP response: {}", response.status());

    // RFC 8011: an IPP-level error is still HTTP 200; the failure is in the IPP status.
    assert_eq!(
        response.status(),
        200,
        "an IPP error must still be carried over HTTP 200"
    );

    let response_body = response.bytes().await?;
    let ipp = decode_ipp(&response_body);

    assert_eq!(
        (ipp.version_major, ipp.version_minor),
        VERSION,
        "the response must echo the request's version even on an error"
    );
    assert_eq!(
        ipp.request_id, REQUEST_ID,
        "the response must echo the request's request-id even on an error"
    );
    assert_eq!(
        ipp.status, 0x0506,
        "'server-error-not-accepting-jobs' encodes as 0x0506, got 0x{:04x}",
        ipp.status
    );
    assert_eq!(
        ipp.expect("status-message").as_text(),
        "Printer is not accepting jobs",
        "the handler's status message must reach the client"
    );
    // A status-only reply carries no printer or job group.
    assert!(
        ipp.attributes
            .iter()
            .all(|a| a.group == OPERATION_ATTRIBUTES_TAG),
        "a status-only response must not invent a printer or job group"
    );

    println!("✓ IPP status-only response test completed\n");

    // Verify mock expectations were met
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;

    Ok(())
}
