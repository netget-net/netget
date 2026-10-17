//! Maven repository protocol actions implementation

use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter,
};
use crate::protocol::EventType;
use crate::state::app_state::AppState;
use anyhow::{Context, Result};
use serde_json::json;
use std::collections::HashMap;
use std::sync::LazyLock;

use crate::protocol::log_template::LogTemplate;

/// Maven protocol action handler
pub struct MavenProtocol;

impl MavenProtocol {
    pub fn new() -> Self {
        Self
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for MavenProtocol {
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        // Maven has no async actions - it's purely request-response
        Vec::new()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            send_maven_artifact_action(),
            send_maven_metadata_action(),
            send_maven_error_action(),
        ]
    }
    fn protocol_name(&self) -> &'static str {
        "Maven"
    }
    fn get_event_types(&self) -> Vec<EventType> {
        get_maven_event_types()
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>HTTP>Maven"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["maven", "maven repository", "maven repo", "via maven"]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Beta)
            .implementation("hyper v1.0 HTTP server with Maven repository path parsing")
            .llm_control(
                "Artifact availability, content generation (POM, JAR, checksums), version metadata",
            )
            .e2e_testing(
                "The real `mvn` binary, in \
                 tests/server/maven/e2e_test.rs::test_maven_cli_download, which is not \
                 #[ignore]d and fails rather than skips when mvn is absent: \
                 `mvn dependency:get` resolves com.netget.test:maven-test:1.0.0, verifies \
                 the .sha1 companions (computed by `shasum`, not by NetGet) and writes the \
                 artifact into its local repository, and the test asserts the stored JAR and \
                 POM are byte-for-byte what NetGet served. Nothing outside 127.0.0.1 is \
                 contacted: a test-owned settings.xml mirrors * at the server under test and \
                 Maven's split local repository resolves its own plugins from the machine's \
                 existing ~/.m2 cache. Three further mocked suites cover POM/JAR/checksum/\
                 metadata routing, multi-version and classifier selection; \
                 llm_failure_test.rs asserts the fail-closed 500/503 and that no internal \
                 error text reaches the wire. The JAR served is a REAL archive - a zip built \
                 by Python's zipfile, which NetGet does not own - and the same test then runs \
                 `mvn dependency:unpack`, so Maven opens the artifact with its own unarchiver \
                 and the test asserts the resource inside it. A client has therefore used an \
                 artifact from this repository, not merely fetched and checksummed one; that \
                 was the one gap this field named while the rating sat at Experimental. \
                 Untested: deploy/PUT (not implemented), SNAPSHOT resolution, GPG signatures, \
                 and any client other than mvn (Gradle and sbt are unproven)",
            )
            .max_inbound_bytes(crate::server::maven::MAX_REQUEST_BODY_BYTES)
            .request_only(
                "Maven is HTTP request/response; a server cannot send a peer anything unprompted",
            )
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "Maven repository server serving Java artifacts"
    }
    fn example_prompt(&self) -> &'static str {
        "Maven repository on port 8080 serving a simple library com.example:hello-world:1.0.0 with a JAR and POM file"
    }
    fn group_name(&self) -> &'static str {
        "Application"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;

        // Deterministic: serve fixed maven-metadata for every artifact request,
        // no LLM call.
        let script = r#"import json, sys
data = json.load(sys.stdin)
event = data["event"]
if data["event_type_id"] == "maven_artifact_request":
    actions = [{"type": "send_maven_metadata", "group_id": "com.example",
                "artifact_id": "hello-world", "versions": ["1.0.0"],
                "latest": "1.0.0", "release": "1.0.0"}]
else:
    actions = []
print(json.dumps({"actions": actions}))"#;

        StartupExamples::new(
            // LLM mode
            json!({
                "type": "open_server",
                "port": 8080,
                "base_stack": "maven",
                "instruction": "Maven repository server. Serve artifact com.example:hello-world:1.0.0 with JAR and POM files."
            }),
            // Script mode
            json!({
                "type": "open_server",
                "port": 8080,
                "base_stack": "maven",
                "event_handlers": [{
                    "event_pattern": "maven_artifact_request",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": script
                    }
                }]
            }),
            // Static mode
            json!({
                "type": "open_server",
                "port": 8080,
                "base_stack": "maven",
                "event_handlers": [{
                    "event_pattern": "maven_artifact_request",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "send_maven_metadata",
                            "group_id": "com.example",
                            "artifact_id": "hello-world",
                            "versions": ["1.0.0"],
                            "latest": "1.0.0",
                            "release": "1.0.0"
                        }]
                    }
                }]
            }),
        )
    }
}

// Implement Server trait (server-specific functionality)
impl Server for MavenProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::server::maven::MavenServer;
            MavenServer::spawn_with_llm_actions(
                ctx.legacy_listen_addr(),
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.server_id,
            )
            .await
        })
    }
    fn execute_action(&self, action: serde_json::Value) -> Result<ActionResult> {
        let action_type = action
            .get("type")
            .and_then(|v| v.as_str())
            .context("Missing 'type' field in action")?;

        match action_type {
            "send_maven_artifact" => self.execute_send_maven_artifact(action),
            "send_maven_metadata" => self.execute_send_maven_metadata(action),
            "send_maven_error" => self.execute_send_maven_error(action),
            _ => Err(anyhow::anyhow!("Unknown Maven action: {action_type}")),
        }
    }
}

/// Escape XML text content so a coordinate containing `&` or `<` cannot produce
/// a maven-metadata.xml that Maven refuses to parse.
fn xml_escape(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&apos;"),
            _ => escaped.push(c),
        }
    }
    escaped
}

/// Read an HTTP status code from an action, rejecting values hyper cannot build
/// a response from instead of silently truncating them into a valid-looking one.
fn status_from_action(action: &serde_json::Value, default: u16) -> Result<u16> {
    match action.get("status").and_then(|v| v.as_u64()) {
        None => Ok(default),
        Some(status) if (100..=599).contains(&status) => Ok(status as u16),
        Some(status) => Err(anyhow::anyhow!(
            "Invalid 'status' {status}: HTTP status codes are 100-599"
        )),
    }
}

impl MavenProtocol {
    /// Execute send_maven_artifact sync action
    fn execute_send_maven_artifact(&self, action: serde_json::Value) -> Result<ActionResult> {
        let status = status_from_action(&action, 200)?;

        let content_type = action
            .get("content_type")
            .and_then(|v| v.as_str())
            .unwrap_or("application/octet-stream");

        let mut headers = HashMap::new();
        headers.insert("Content-Type".to_string(), content_type.to_string());

        // Add optional custom headers
        if let Some(custom_headers) = action.get("headers").and_then(|v| v.as_object()) {
            for (k, v) in custom_headers {
                if let Some(v_str) = v.as_str() {
                    headers.insert(k.clone(), v_str.to_string());
                }
            }
        }

        // The body is either UTF-8 text (POM, checksum, maven-metadata.xml) or
        // base64-encoded bytes. Exactly one of the two must be present: guessing
        // would make "48656c6c6f" ambiguous between text and encoded bytes.
        let body = action.get("body").and_then(|v| v.as_str());
        let body_base64 = action.get("body_base64").and_then(|v| v.as_str());

        let response_data = match (body, body_base64) {
            (Some(_), Some(_)) => {
                anyhow::bail!("Provide either 'body' or 'body_base64', not both")
            }
            (None, None) => {
                anyhow::bail!("Missing 'body' parameter (or 'body_base64' for binary artifacts)")
            }
            (Some(text), None) => json!({
                "status": status,
                "headers": headers,
                "body": text
            }),
            (None, Some(encoded)) => {
                use base64::Engine;
                base64::engine::general_purpose::STANDARD
                    .decode(encoded)
                    .context("'body_base64' is not valid base64")?;
                json!({
                    "status": status,
                    "headers": headers,
                    "body_base64": encoded
                })
            }
        };

        Ok(ActionResult::Output(
            serde_json::to_vec(&response_data)
                .context("Failed to serialize Maven artifact response")?,
        ))
    }

    /// Execute send_maven_metadata sync action
    fn execute_send_maven_metadata(&self, action: serde_json::Value) -> Result<ActionResult> {
        let group_id = action
            .get("group_id")
            .and_then(|v| v.as_str())
            .context("Missing 'group_id' parameter")?;

        let artifact_id = action
            .get("artifact_id")
            .and_then(|v| v.as_str())
            .context("Missing 'artifact_id' parameter")?;

        let versions = action
            .get("versions")
            .and_then(|v| v.as_array())
            .context("Missing 'versions' parameter")?;

        let latest = action.get("latest").and_then(|v| v.as_str());

        let release = action.get("release").and_then(|v| v.as_str());

        // Generate maven-metadata.xml. Element order follows the repository
        // metadata schema Maven itself writes: latest, release, then versions.
        let mut xml = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<metadata>
  <groupId>{}</groupId>
  <artifactId>{}</artifactId>
  <versioning>
"#,
            xml_escape(group_id),
            xml_escape(artifact_id)
        );

        if let Some(latest_ver) = latest {
            xml.push_str(&format!(
                "    <latest>{}</latest>\n",
                xml_escape(latest_ver)
            ));
        }

        if let Some(release_ver) = release {
            xml.push_str(&format!(
                "    <release>{}</release>\n",
                xml_escape(release_ver)
            ));
        }

        xml.push_str("    <versions>\n");

        for version in versions {
            let v = version
                .as_str()
                .context("Every entry in 'versions' must be a version string")?;
            xml.push_str(&format!("      <version>{}</version>\n", xml_escape(v)));
        }

        xml.push_str("    </versions>\n  </versioning>\n</metadata>\n");

        let mut headers = HashMap::new();
        headers.insert("Content-Type".to_string(), "application/xml".to_string());

        let response_data = json!({
            "status": 200,
            "headers": headers,
            "body": xml
        });

        Ok(ActionResult::Output(
            serde_json::to_vec(&response_data)
                .context("Failed to serialize Maven metadata response")?,
        ))
    }

    /// Execute send_maven_error sync action
    fn execute_send_maven_error(&self, action: serde_json::Value) -> Result<ActionResult> {
        let status = status_from_action(&action, 404)?;

        let message = action
            .get("message")
            .and_then(|v| v.as_str())
            .unwrap_or("Not Found");

        let response_data = json!({
            "status": status,
            "headers": {
                "Content-Type": "text/plain"
            },
            "body": message
        });

        Ok(ActionResult::Output(
            serde_json::to_vec(&response_data)
                .context("Failed to serialize Maven error response")?,
        ))
    }
}

/// Action definition for send_maven_artifact (sync)
fn send_maven_artifact_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_maven_artifact".to_string(),
        description: "Send a Maven artifact file (JAR, POM, checksum, etc.)".to_string(),
        parameters: vec![
            Parameter {
                name: "status".to_string(),
                type_hint: "number".to_string(),
                description: "HTTP status code (default: 200)".to_string(),
                required: false,
            },
            Parameter {
                name: "content_type".to_string(),
                type_hint: "string".to_string(),
                description: "Content-Type header (default: application/octet-stream)".to_string(),
                required: false,
            },
            Parameter {
                name: "body".to_string(),
                type_hint: "string".to_string(),
                description: "Artifact content as UTF-8 text: POM XML, maven-metadata.xml, or a checksum digest. Sent byte for byte. Required unless body_base64 is given".to_string(),
                required: false,
            },
            Parameter {
                name: "body_base64".to_string(),
                type_hint: "string".to_string(),
                description: "Artifact content as base64-encoded bytes, decoded before sending. Only for a real binary artifact a script or static handler already holds; do not try to write JAR (ZIP) bytes by hand - serve text and a matching Content-Type instead".to_string(),
                required: false,
            },
            Parameter {
                name: "headers".to_string(),
                type_hint: "object".to_string(),
                description: "Optional additional headers".to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_maven_artifact",
            "status": 200,
            "content_type": "application/xml",
            "body": "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<project>\n  <modelVersion>4.0.0</modelVersion>\n  <groupId>com.example</groupId>\n  <artifactId>mylib</artifactId>\n  <version>1.0.0</version>\n</project>\n"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> Maven {status} {content_type} ({body_len}B)")
                .with_debug("Maven send_maven_artifact: status={status} type={content_type}"),
        ),
    }
}

/// Action definition for send_maven_metadata (sync)
fn send_maven_metadata_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_maven_metadata".to_string(),
        description: "Send Maven metadata XML listing available versions".to_string(),
        parameters: vec![
            Parameter {
                name: "group_id".to_string(),
                type_hint: "string".to_string(),
                description: "Maven group ID (e.g., 'com.example')".to_string(),
                required: true,
            },
            Parameter {
                name: "artifact_id".to_string(),
                type_hint: "string".to_string(),
                description: "Maven artifact ID".to_string(),
                required: true,
            },
            Parameter {
                name: "versions".to_string(),
                type_hint: "array".to_string(),
                description: "Array of available version strings".to_string(),
                required: true,
            },
            Parameter {
                name: "latest".to_string(),
                type_hint: "string".to_string(),
                description: "Latest version (optional)".to_string(),
                required: false,
            },
            Parameter {
                name: "release".to_string(),
                type_hint: "string".to_string(),
                description: "Latest release version (optional)".to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_maven_metadata",
            "group_id": "com.example",
            "artifact_id": "mylib",
            "versions": ["1.0.0", "1.0.1", "1.1.0"],
            "latest": "1.1.0",
            "release": "1.1.0"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> Maven metadata {group_id}:{artifact_id}")
                .with_debug(
                    "Maven send_maven_metadata: {group_id}:{artifact_id} versions={versions_len}",
                ),
        ),
    }
}

/// Action definition for send_maven_error (sync)
fn send_maven_error_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_maven_error".to_string(),
        description: "Send an error response (typically 404 Not Found)".to_string(),
        parameters: vec![
            Parameter {
                name: "status".to_string(),
                type_hint: "number".to_string(),
                description: "HTTP status code (default: 404)".to_string(),
                required: false,
            },
            Parameter {
                name: "message".to_string(),
                type_hint: "string".to_string(),
                description: "Error message (default: 'Not Found')".to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_maven_error",
            "status": 404,
            "message": "Artifact not found"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> Maven error {status}: {message}")
                .with_debug("Maven send_maven_error: status={status} message={message}"),
        ),
    }
}

// ============================================================================
// Maven Action Constants
// ============================================================================

pub static SEND_MAVEN_ARTIFACT_ACTION: LazyLock<ActionDefinition> =
    LazyLock::new(|| send_maven_artifact_action());
pub static SEND_MAVEN_METADATA_ACTION: LazyLock<ActionDefinition> =
    LazyLock::new(|| send_maven_metadata_action());
pub static SEND_MAVEN_ERROR_ACTION: LazyLock<ActionDefinition> =
    LazyLock::new(|| send_maven_error_action());

// ============================================================================
// Maven Event Type Constants
// ============================================================================

/// Maven artifact request event - triggered when client requests an artifact
pub static MAVEN_ARTIFACT_REQUEST_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "maven_artifact_request",
        "Maven artifact request received from client",
        json!({
            "type": "send_maven_artifact",
            "status": 200,
            "content_type": "application/xml",
            "body": "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<project>\n  <modelVersion>4.0.0</modelVersion>\n  <groupId>com.example</groupId>\n  <artifactId>mylib</artifactId>\n  <version>1.0.0</version>\n</project>\n"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "method".to_string(),
            type_hint: "string".to_string(),
            description: "HTTP method (usually GET)".to_string(),
            required: true,
        },
        Parameter {
            name: "uri".to_string(),
            type_hint: "string".to_string(),
            description: "Full request URI".to_string(),
            required: true,
        },
        Parameter {
            name: "group_id".to_string(),
            type_hint: "string".to_string(),
            description: "Maven group ID (e.g., 'com.example')".to_string(),
            required: true,
        },
        Parameter {
            name: "artifact_id".to_string(),
            type_hint: "string".to_string(),
            description: "Maven artifact ID".to_string(),
            required: true,
        },
        Parameter {
            name: "version".to_string(),
            type_hint: "string".to_string(),
            description: "Artifact version (null for metadata requests)".to_string(),
            required: false,
        },
        Parameter {
            name: "classifier".to_string(),
            type_hint: "string".to_string(),
            description: "Artifact classifier (e.g., 'sources', 'javadoc')".to_string(),
            required: false,
        },
        Parameter {
            name: "extension".to_string(),
            type_hint: "string".to_string(),
            description: "File extension (e.g., 'jar', 'pom', 'xml')".to_string(),
            required: true,
        },
        Parameter {
            name: "is_metadata".to_string(),
            type_hint: "boolean".to_string(),
            description: "True if requesting maven-metadata.xml".to_string(),
            required: true,
        },
        Parameter {
            name: "is_checksum".to_string(),
            type_hint: "boolean".to_string(),
            description: "True if requesting a checksum file".to_string(),
            required: true,
        },
        Parameter {
            name: "checksum_type".to_string(),
            type_hint: "string".to_string(),
            description: "Checksum type if is_checksum is true (sha1, md5, sha256, sha512)"
                .to_string(),
            required: false,
        },
        Parameter {
            name: "headers".to_string(),
            type_hint: "object".to_string(),
            description: "HTTP request headers".to_string(),
            required: true,
        },
    ])
    .with_actions(vec![
        SEND_MAVEN_ARTIFACT_ACTION.clone(),
        SEND_MAVEN_METADATA_ACTION.clone(),
        SEND_MAVEN_ERROR_ACTION.clone(),
    ])
});

/// Get Maven event types
pub fn get_maven_event_types() -> Vec<EventType> {
    vec![MAVEN_ARTIFACT_REQUEST_EVENT.clone()]
}
