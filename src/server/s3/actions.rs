//! S3 protocol actions and event types
//!
//! Defines the actions the LLM can take in response to S3 API requests.

use crate::llm::actions::{
    protocol_trait::{ActionResult, Server},
    ActionDefinition, Parameter, ParameterDefinition,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::EventType;
use crate::state::app_state::AppState;
use anyhow::Result;
use serde_json::{json, Value};
use std::sync::LazyLock;

/// S3 protocol handler
pub struct S3Protocol {
    // Could store connection state here if needed
}

impl S3Protocol {
    pub fn new() -> Self {
        Self {}
    }
}

/// S3 request event - triggered when an S3 API request is received
pub static S3_REQUEST_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "s3_request",
        "S3 API request received",
        json!({"type": "placeholder", "event_id": "s3_request"}),
    )
    .with_parameters(vec![
        Parameter {
            name: "operation".to_string(),
            type_hint: "string".to_string(),
            description: "S3 operation (GetObject, PutObject, ListBuckets, etc.)".to_string(),
            required: true,
        },
        Parameter {
            name: "bucket".to_string(),
            type_hint: "string".to_string(),
            description: "Bucket name (if applicable)".to_string(),
            required: false,
        },
        Parameter {
            name: "key".to_string(),
            type_hint: "string".to_string(),
            description: "Object key/path (if applicable)".to_string(),
            required: false,
        },
        Parameter {
            name: "request_details".to_string(),
            type_hint: "object".to_string(),
            description: "Additional request details (headers, query params, etc.)".to_string(),
            required: false,
        },
    ])
    .with_actions(vec![
        send_s3_object_action(),
        send_s3_object_list_action(),
        send_s3_bucket_list_action(),
        send_s3_write_result_action(),
        send_s3_error_action(),
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("S3 {operation} {bucket}/{key}")
            .with_debug("S3 {operation} bucket={bucket}, key={key}")
            .with_trace("S3: {json_pretty(.)}"),
    )
});

fn send_s3_object_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_s3_object".to_string(),
        description: "Send the body of an S3 object in response to a GetObject request. \
                      'content' holds the object bytes and the optional 'encoding' field says how \
                      to turn it into bytes: omit 'encoding' (or use \"utf8\") for text objects, \
                      or set \"encoding\": \"base64\" to send arbitrary binary content. There is \
                      no auto-detection - a base64-looking string is sent literally unless you \
                      set \"encoding\": \"base64\"."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "content".to_string(),
                type_hint: "string".to_string(),
                description: "Object body. Interpreted according to 'encoding': as literal text \
                              by default, or as base64-encoded bytes when \
                              \"encoding\": \"base64\""
                    .to_string(),
                required: true,
            },
            encoding_parameter(),
            Parameter {
                name: "content_type".to_string(),
                type_hint: "string".to_string(),
                description: "Content-Type header (e.g., 'text/plain', 'application/json'). \
                              Must be a single line of printable ASCII; an unusable value is \
                              replaced with 'application/octet-stream'"
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "etag".to_string(),
                type_hint: "string".to_string(),
                description: "ETag for the object, normally the quoted MD5 of the body. Must be \
                              a single line of printable ASCII; an unusable value is dropped"
                    .to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_s3_object",
            "content": "Hello, World!",
            "encoding": "utf8",
            "content_type": "text/plain",
            "etag": "\"d41d8cd98f00b204e9800998ecf8427e\""
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> S3 send object ({content_type})")
                .with_debug("S3 send_s3_object: content_type={content_type} etag={etag}"),
        ),
    }
}

fn send_s3_object_list_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_s3_object_list".to_string(),
        description: "Send list of objects in bucket (ListObjects response)".to_string(),
        parameters: vec![
            Parameter {
                name: "objects".to_string(),
                type_hint: "array".to_string(),
                description: "Array of objects with 'key', 'size', 'last_modified' fields"
                    .to_string(),
                required: true,
            },
            Parameter {
                name: "is_truncated".to_string(),
                type_hint: "boolean".to_string(),
                description: "Whether there are more objects to list".to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_s3_object_list",
            "objects": [
                {"key": "file1.txt", "size": 1024, "last_modified": "2024-01-01T00:00:00Z"},
                {"key": "file2.jpg", "size": 2048, "last_modified": "2024-01-02T00:00:00Z"}
            ],
            "is_truncated": false
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> S3 list objects ({objects_len} items)")
                .with_debug("S3 send_s3_object_list: count={objects_len} truncated={is_truncated}"),
        ),
    }
}

fn send_s3_bucket_list_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_s3_bucket_list".to_string(),
        description: "Send list of buckets (ListBuckets response)".to_string(),
        parameters: vec![Parameter {
            name: "buckets".to_string(),
            type_hint: "array".to_string(),
            description: "Array of buckets with 'name', 'creation_date' fields".to_string(),
            required: true,
        }],
        example: json!({
            "type": "send_s3_bucket_list",
            "buckets": [
                {"name": "my-bucket", "creation_date": "2024-01-01T00:00:00Z"},
                {"name": "test-bucket", "creation_date": "2024-01-02T00:00:00Z"}
            ]
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> S3 list buckets ({buckets_len} buckets)")
                .with_debug("S3 send_s3_bucket_list: count={buckets_len}"),
        ),
    }
}

/// Acknowledge a write that produced no body: PutObject, CreateBucket, DeleteObject, HeadObject.
///
/// These four verbs have no content to return, so before this action existed the model had no
/// way to say "yes" to them at all — the server fell through to an empty `200 OK` whenever the
/// answer contained no S3 action. That made silence indistinguishable from approval on exactly
/// the operations that mutate state, which is the fail-open pattern the root `CLAUDE.md` calls
/// the most dangerous in this codebase. It could not be removed until there was an affirmative
/// verb to replace it, which is what this is.
fn send_s3_write_result_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_s3_write_result".to_string(),
        description: "Acknowledge a successful write or metadata request that returns no body \
                      (PutObject, CreateBucket, DeleteObject, HeadObject). Required: without it \
                      these operations are refused."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "status_code".to_string(),
                type_hint: "number".to_string(),
                description: "HTTP status: 200 for PutObject/CreateBucket/HeadObject, 204 for \
                              DeleteObject. Defaults to 200."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "etag".to_string(),
                type_hint: "string".to_string(),
                description: "ETag of the stored object (PutObject). Sent as the ETag header."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "location".to_string(),
                type_hint: "string".to_string(),
                description: "Location of the created bucket (CreateBucket), e.g. \"/my-bucket\"."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "content_length".to_string(),
                type_hint: "number".to_string(),
                description: "Size in bytes (HeadObject). Sent as the Content-Length header."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "content_type".to_string(),
                type_hint: "string".to_string(),
                description: "MIME type (HeadObject).".to_string(),
                required: false,
            },
            Parameter {
                name: "last_modified".to_string(),
                type_hint: "string".to_string(),
                description: "RFC 1123 timestamp (HeadObject), e.g. \"Mon, 01 Jan 2024 00:00:00 \
                              GMT\"."
                    .to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_s3_write_result",
            "status_code": 200,
            "etag": "\"d41d8cd98f00b204e9800998ecf8427e\""
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> S3 write acknowledged (HTTP {status_code})")
                .with_debug("S3 send_s3_write_result: status={status_code} etag={etag}"),
        ),
    }
}

fn send_s3_error_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_s3_error".to_string(),
        description: "Send S3 error response".to_string(),
        parameters: vec![
            Parameter {
                name: "error_code".to_string(),
                type_hint: "string".to_string(),
                description: "S3 error code (NoSuchBucket, NoSuchKey, AccessDenied, etc.)"
                    .to_string(),
                required: true,
            },
            Parameter {
                name: "message".to_string(),
                type_hint: "string".to_string(),
                description: "Error message".to_string(),
                required: true,
            },
            Parameter {
                name: "status_code".to_string(),
                type_hint: "number".to_string(),
                description: "HTTP status code (404, 403, 500, etc.)".to_string(),
                required: true,
            },
        ],
        example: json!({
            "type": "send_s3_error",
            "error_code": "NoSuchKey",
            "message": "The specified key does not exist",
            "status_code": 404
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> S3 error {error_code} (HTTP {status_code})")
                .with_debug("S3 send_s3_error: error_code={error_code} status={status_code} message='{message}'"),
        ),
    }
}

/// Shared `encoding` parameter for the outbound object body.
///
/// Object bodies are the one place in this protocol where the payload is genuinely
/// binary, so - following the `send_tcp_data` precedent - the encoding is stated
/// explicitly by the caller and actually decoded by [`decode_object_content`],
/// rather than guessed.
fn encoding_parameter() -> Parameter {
    Parameter {
        name: "encoding".to_string(),
        type_hint: "string".to_string(),
        description: "How to convert 'content' into the object bytes. \"utf8\" (the default when \
                      omitted) sends the characters of 'content' unchanged - use it for text, \
                      JSON, XML and other textual objects. \"base64\" decodes 'content' as \
                      base64 - use it for images, archives and any other binary object, e.g. \
                      {\"content\": \"SGVsbG8=\", \"encoding\": \"base64\"} sends the 5 bytes \
                      'Hello', whereas the same 'content' without \"encoding\": \"base64\" sends \
                      the 8 characters S-G-V-s-b-G-8-=. No other values are accepted"
            .to_string(),
        required: false,
    }
}

/// Turn the `content` field of `send_s3_object` into the exact object bytes,
/// honouring the action's optional `encoding` field.
///
/// Returns the bytes re-encoded as base64 for transport through
/// [`ActionResult::Custom`], whose payload is JSON and so cannot carry raw bytes.
/// The server side decodes this canonical form, which it produced itself and which
/// therefore cannot fail.
fn decode_object_content(content: &str, action: &Value) -> Result<String> {
    use base64::Engine;
    let engine = base64::engine::general_purpose::STANDARD;

    let encoding = action
        .get("encoding")
        .and_then(|v| v.as_str())
        .unwrap_or("utf8");

    match encoding {
        "utf8" => Ok(engine.encode(content.as_bytes())),
        "base64" => {
            // Tolerate the whitespace and line wrapping models often emit.
            let cleaned: String = content
                .chars()
                .filter(|c| !c.is_ascii_whitespace())
                .collect();
            engine
                .decode(cleaned.as_bytes())
                .map(|_| cleaned)
                .map_err(|e| {
                    anyhow::anyhow!(
                        "Invalid base64 in 'content': {e}. Use standard base64 with padding, e.g. \
                     \"SGVsbG8=\" for the 5 bytes 'Hello'. To send this string as literal text, \
                     omit 'encoding' or set it to \"utf8\"."
                    )
                })
        }
        other => Err(anyhow::anyhow!(
            "Invalid 'encoding' value {other:?}. Valid values are \"utf8\" (default, send the \
             characters of 'content' as-is) and \"base64\" (decode 'content' as base64-encoded \
             bytes)."
        )),
    }
}

pub fn get_s3_event_types() -> Vec<EventType> {
    vec![S3_REQUEST_EVENT.clone()]
}

impl crate::llm::actions::protocol_trait::Protocol for S3Protocol {
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        // Deliberately empty. `port` is a top-level `open_server` field, not a startup
        // parameter, and this protocol performs no authentication: `require_authentication`,
        // `access_key`, `secret_key` and `region` used to be declared here but `spawn()`
        // never read any of them, so accepting them told the caller that requests would be
        // authenticated when every request was in fact served unconditionally.
        vec![]
    }

    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        // No async actions for S3 currently
        vec![]
    }

    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            send_s3_object_action(),
            send_s3_object_list_action(),
            send_s3_bucket_list_action(),
            send_s3_write_result_action(),
            send_s3_error_action(),
        ]
    }

    fn protocol_name(&self) -> &'static str {
        "S3"
    }

    fn get_event_types(&self) -> Vec<EventType> {
        get_s3_event_types()
    }

    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>HTTP>S3"
    }

    fn keywords(&self) -> Vec<&'static str> {
        vec!["s3", "aws s3", "s3 bucket", "object storage", "minio"]
    }

    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Beta)
            .implementation("hyper v1.5 HTTP with manual S3 REST API")
            .llm_control("All S3 operations (GetObject, PutObject, ListBuckets)")
            .e2e_testing(
                "TWO independent clients, neither #[ignore]d and neither able to skip. \
                 (1) rust-s3 0.37 (`Bucket`, path-style) in tests/server/s3/e2e_test.rs: \
                 ListObjects, GetObject, PutObject, HeadObject and DeleteObject, each pinned to \
                 expect_calls(1) through a retry helper so a response rust-s3 REJECTED would \
                 retry and break the count. \
                 (2) the real `aws s3api` CLI (botocore) in tests/server/s3/real_client_test.rs: \
                 it parses our hand-written ListBucketResult XML itself and prints JSON, and the \
                 test asserts two objects, both keys -- including one containing a `/`, the one \
                 most likely to be mangled by escaping -- and Size as a number; then GetObject \
                 writes the body to a file and the bytes are compared. Verified by adding a \
                 third object to the listing, which the test then reports. \
                 S3 is the one protocol in the AWS family where the second client exercises a \
                 hand-written DOCUMENT rather than a serde struct, which is why an element name \
                 or namespace our own parser round-trips happily is worth a second reader. \
                 botocore is forced to path-style addressing (AWS_S3_ADDRESSING_STYLE); its \
                 default puts the bucket in the hostname, which is neither resolvable here nor \
                 what this server routes. \
                 THE TEST CANNOT REACH REAL AWS: --endpoint-url on every call, the port asserted \
                 non-zero before the CLI is spawned, and credentials, region, profile and the \
                 EC2 metadata service overridden in the child's environment -- the sibling \
                 DynamoDB client once signed real requests against real AWS by dropping its \
                 target. \
                 UNPROVEN, and worth saying plainly: NO SIGNATURE IS VALIDATED. Also unproven: \
                 multipart upload, versioning, pagination past the first page, and range GETs.",
            )

            .notes("Virtual objects (no persistence); no SigV4 auth; binary bodies via encoding=base64")
            .max_inbound_bytes(crate::server::s3::MAX_REQUEST_BYTES)
            .request_only("S3 is HTTP request/response; a server cannot send a peer anything unprompted")
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }

    fn description(&self) -> &'static str {
        "S3-compatible object storage server"
    }

    fn example_prompt(&self) -> &'static str {
        "Start an S3-compatible server on port 9000 with a test-bucket containing hello.txt"
    }

    fn group_name(&self) -> &'static str {
        "Web & File"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        use serde_json::json;

        // Deterministic S3 responses routed on the parsed operation: one bucket,
        // one canned object, NoSuchKey for everything else. No LLM call.
        let script = r#"import json, sys
data = json.load(sys.stdin)
event = data["event"]
if data["event_type_id"] == "s3_request":
    op = event.get("operation", "")
    if op == "ListBuckets":
        actions = [{"type": "send_s3_bucket_list",
                    "buckets": [{"name": "test-bucket",
                                 "creation_date": "2024-01-01T00:00:00Z"}]}]
    elif op == "GetObject":
        actions = [{"type": "send_s3_object", "content": "Hello, World!",
                    "encoding": "utf8", "content_type": "text/plain"}]
    else:
        actions = [{"type": "send_s3_error", "error_code": "NoSuchKey",
                    "message": "The specified key does not exist",
                    "status_code": 404}]
else:
    actions = []
print(json.dumps({"actions": actions}))"#;

        StartupExamples::new(
            // LLM mode: generate object contents on demand from the request key.
            json!({
                "type": "open_server",
                "port": 9000,
                "base_stack": "s3",
                "instruction": "Serve an S3 bucket named 'reports'. When a client GETs any object whose key ends in .json, generate a small JSON report containing the current date and the object key; for .txt objects return a short generated note. Remember which keys have been requested and list them when the bucket is listed."
            }),
            // Script mode: fixed bucket/object responses, no LLM call.
            json!({
                "type": "open_server",
                "port": 9000,
                "base_stack": "s3",
                "event_handlers": [{
                    "event_pattern": "s3_request",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": script
                    }
                }]
            }),
            // Static mode: Fixed responses
            json!({
                "type": "open_server",
                "port": 9000,
                "base_stack": "s3",
                "event_handlers": [{
                    "event_pattern": "s3_request",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "send_s3_bucket_list",
                            "buckets": [{"name": "test-bucket", "creation_date": "2024-01-01T00:00:00Z"}]
                        }]
                    }
                }]
            }),
        )
    }
}

impl Server for S3Protocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::server::s3::S3Server;
            S3Server::spawn_with_llm_actions(
                ctx.legacy_listen_addr(),
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.server_id,
            )
            .await
        })
    }

    fn execute_action(&self, action: Value) -> Result<ActionResult> {
        let action_type = action
            .get("type")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("Missing action type"))?;

        match action_type {
            "send_s3_object" => {
                let content = action
                    .get("content")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow::anyhow!("Missing content"))?;

                // Decode here so an invalid 'encoding' or malformed base64 surfaces as an
                // action failure the model is told about, instead of silently putting the
                // literal characters of a base64 string into the object body.
                let content_b64 = decode_object_content(content, &action)?;

                let content_type = action
                    .get("content_type")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());

                let etag = action
                    .get("etag")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());

                Ok(ActionResult::Custom {
                    name: "s3_object".to_string(),
                    data: json!({
                        "content_b64": content_b64,
                        "content_type": content_type,
                        "etag": etag
                    }),
                })
            }
            "send_s3_object_list" => {
                let objects = action
                    .get("objects")
                    .ok_or_else(|| anyhow::anyhow!("Missing objects"))?
                    .clone();

                let is_truncated = action
                    .get("is_truncated")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);

                Ok(ActionResult::Custom {
                    name: "s3_object_list".to_string(),
                    data: json!({
                        "objects": objects,
                        "is_truncated": is_truncated
                    }),
                })
            }
            "send_s3_bucket_list" => {
                let buckets = action
                    .get("buckets")
                    .ok_or_else(|| anyhow::anyhow!("Missing buckets"))?
                    .clone();

                Ok(ActionResult::Custom {
                    name: "s3_bucket_list".to_string(),
                    data: json!({
                        "buckets": buckets
                    }),
                })
            }
            "send_s3_write_result" => {
                // Every field is optional: the four operations this answers differ in which
                // headers they carry, and a model that supplies none still gets a valid 200.
                // What is NOT optional is emitting the action at all — that is the point.
                // Range-check before narrowing. This check used to sit *after* `as u16`, and
                // `65736 as u16` is 200 — a wrapped value passed it and was then
                // indistinguishable from a model that legitimately asked for 200, so an
                // explicit refusal arrived at the peer as a successful write.
                let status_code = action
                    .get("status_code")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(200);
                if !(100..=599).contains(&status_code) {
                    anyhow::bail!(
                        "send_s3_write_result status_code {} is outside 100-599",
                        status_code
                    );
                }
                let status_code = status_code as u16;
                let mut data = json!({ "status_code": status_code });
                for field in ["etag", "location", "content_type", "last_modified"] {
                    if let Some(v) = action.get(field).and_then(|v| v.as_str()) {
                        data[field] = json!(v);
                    }
                }
                if let Some(v) = action.get("content_length").and_then(|v| v.as_u64()) {
                    data["content_length"] = json!(v);
                }

                Ok(ActionResult::Custom {
                    name: "s3_write_result".to_string(),
                    data,
                })
            }
            "send_s3_error" => {
                let error_code = action
                    .get("error_code")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow::anyhow!("Missing error_code"))?
                    .to_string();

                let message = action
                    .get("message")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow::anyhow!("Missing message"))?
                    .to_string();

                // Range-check before narrowing: `as u16` on a u64 wraps, so 65540 became 4
                // and reached `StatusCode::from_u16`, which rejected it — the peer then got a
                // 500 and the model was told nothing. `send_s3_write_result` has checked this
                // since it was written; this arm had not.
                let status_code = action
                    .get("status_code")
                    .and_then(|v| v.as_u64())
                    .ok_or_else(|| anyhow::anyhow!("Missing or invalid status_code"))?;
                if !(100..=599).contains(&status_code) {
                    anyhow::bail!(
                        "send_s3_error status_code {} is outside 100-599. S3 uses 404 for \
                         NoSuchKey/NoSuchBucket, 403 for AccessDenied and 500 for InternalError.",
                        status_code
                    );
                }
                let status_code = status_code as u16;

                Ok(ActionResult::Custom {
                    name: "s3_error".to_string(),
                    data: json!({
                        "error_code": error_code,
                        "message": message,
                        "status_code": status_code
                    }),
                })
            }
            _ => Err(anyhow::anyhow!("Unknown action type: {}", action_type)),
        }
    }
}
