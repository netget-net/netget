//! Maven client protocol actions implementation

use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, Parameter, ParameterDefinition,
};
use crate::protocol::EventType;
use crate::state::app_state::AppState;
use anyhow::{Context, Result};
use serde_json::json;
use std::sync::LazyLock;

/// Maven client connected event
pub static MAVEN_CLIENT_CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new("maven_connected", "Maven client connected to repository", json!({"type": "download_artifact", "group_id": "org.apache.commons", "artifact_id": "commons-lang3", "version": "3.12.0"})).with_parameters(vec![
        Parameter {
            name: "repository_url".to_string(),
            type_hint: "string".to_string(),
            description: "Maven repository base URL".to_string(),
            required: true,
        },
    ])
});

/// Maven artifact downloaded event
pub static MAVEN_CLIENT_ARTIFACT_DOWNLOADED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "maven_artifact_downloaded",
        "Maven artifact successfully downloaded",
        json!({"type": "download_pom", "group_id": "org.apache.commons", "artifact_id": "commons-collections4", "version": "4.4"}),
    )
    .with_parameters(vec![
        Parameter {
            name: "group_id".to_string(),
            type_hint: "string".to_string(),
            description: "Maven artifact group ID".to_string(),
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
            description: "Maven artifact version".to_string(),
            required: true,
        },
        Parameter {
            name: "packaging".to_string(),
            type_hint: "string".to_string(),
            description: "Artifact packaging type (jar, war, pom, etc.)".to_string(),
            required: true,
        },
        Parameter {
            name: "size_bytes".to_string(),
            type_hint: "number".to_string(),
            description: "Downloaded artifact size in bytes".to_string(),
            required: true,
        },
    ])
});

/// Maven POM received event
pub static MAVEN_CLIENT_POM_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "maven_pom_received",
        "Maven POM file downloaded and received",
        json!({"type": "download_artifact", "group_id": "com.google.guava", "artifact_id": "guava", "version": "31.1-jre"}),
    )
    .with_parameters(vec![
        Parameter {
            name: "group_id".to_string(),
            type_hint: "string".to_string(),
            description: "Maven artifact group ID".to_string(),
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
            description: "Maven artifact version".to_string(),
            required: true,
        },
        Parameter {
            name: "pom_content".to_string(),
            type_hint: "string".to_string(),
            description: "POM file XML content".to_string(),
            required: true,
        },
    ])
});

/// Maven metadata received event
pub static MAVEN_CLIENT_METADATA_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "maven_metadata_received",
        "Maven metadata XML received with version information",
        json!({"type": "download_artifact", "group_id": "com.google.guava", "artifact_id": "guava", "version": "31.1-jre"}),
    )
    .with_parameters(vec![
        Parameter {
            name: "group_id".to_string(),
            type_hint: "string".to_string(),
            description: "Maven artifact group ID".to_string(),
            required: true,
        },
        Parameter {
            name: "artifact_id".to_string(),
            type_hint: "string".to_string(),
            description: "Maven artifact ID".to_string(),
            required: true,
        },
        Parameter {
            name: "metadata_content".to_string(),
            type_hint: "string".to_string(),
            description: "Maven metadata XML content".to_string(),
            required: true,
        },
    ])
});

/// Maven client protocol action handler
pub struct MavenClientProtocol;

impl MavenClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for MavenClientProtocol {
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![ParameterDefinition {
            name: "repository_url".to_string(),
            description: "Maven repository base URL (defaults to Maven Central)".to_string(),
            type_hint: "string".to_string(),
            required: false,
            example: json!("https://repo.maven.apache.org/maven2"),
            default: None,
        }]
    }
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![
            ActionDefinition {
                name: "download_artifact".to_string(),
                description:
                    "Download a Maven artifact by coordinates (groupId:artifactId:version)"
                        .to_string(),
                parameters: vec![
                    Parameter {
                        name: "group_id".to_string(),
                        type_hint: "string".to_string(),
                        description: "Maven group ID (e.g., 'org.apache.commons')".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "artifact_id".to_string(),
                        type_hint: "string".to_string(),
                        description: "Maven artifact ID (e.g., 'commons-lang3')".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "version".to_string(),
                        type_hint: "string".to_string(),
                        description: "Artifact version (e.g., '3.12.0')".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "packaging".to_string(),
                        type_hint: "string".to_string(),
                        description:
                            "Artifact packaging type (jar, war, pom, etc.), defaults to 'jar'"
                                .to_string(),
                        required: false,
                    },
                ],
                example: json!({
                    "type": "download_artifact",
                    "group_id": "org.apache.commons",
                    "artifact_id": "commons-lang3",
                    "version": "3.12.0",
                    "packaging": "jar"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "download_pom".to_string(),
                description: "Download and parse a Maven POM file".to_string(),
                parameters: vec![
                    Parameter {
                        name: "group_id".to_string(),
                        type_hint: "string".to_string(),
                        description: "Maven group ID".to_string(),
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
                        description: "Artifact version".to_string(),
                        required: true,
                    },
                ],
                example: json!({
                    "type": "download_pom",
                    "group_id": "org.springframework.boot",
                    "artifact_id": "spring-boot-starter",
                    "version": "2.7.0"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "search_versions".to_string(),
                description: "Search for available versions of a Maven artifact".to_string(),
                parameters: vec![
                    Parameter {
                        name: "group_id".to_string(),
                        type_hint: "string".to_string(),
                        description: "Maven group ID".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "artifact_id".to_string(),
                        type_hint: "string".to_string(),
                        description: "Maven artifact ID".to_string(),
                        required: true,
                    },
                ],
                example: json!({
                    "type": "search_versions",
                    "group_id": "junit",
                    "artifact_id": "junit"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "disconnect".to_string(),
                description: "Disconnect from the Maven repository".to_string(),
                parameters: vec![],
                example: json!({
                    "type": "disconnect"
                }),
                log_template: None,
            },
        ]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            ActionDefinition {
                name: "download_artifact".to_string(),
                description: "Download another Maven artifact in response to received data"
                    .to_string(),
                parameters: vec![
                    Parameter {
                        name: "group_id".to_string(),
                        type_hint: "string".to_string(),
                        description: "Maven group ID".to_string(),
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
                        description: "Artifact version".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "packaging".to_string(),
                        type_hint: "string".to_string(),
                        description: "Artifact packaging type".to_string(),
                        required: false,
                    },
                ],
                example: json!({
                    "type": "download_artifact",
                    "group_id": "com.google.guava",
                    "artifact_id": "guava",
                    "version": "31.1-jre"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "download_pom".to_string(),
                description: "Download POM file in response to received data".to_string(),
                parameters: vec![
                    Parameter {
                        name: "group_id".to_string(),
                        type_hint: "string".to_string(),
                        description: "Maven group ID".to_string(),
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
                        description: "Artifact version".to_string(),
                        required: true,
                    },
                ],
                example: json!({
                    "type": "download_pom",
                    "group_id": "org.apache.commons",
                    "artifact_id": "commons-collections4",
                    "version": "4.4"
                }),
                log_template: None,
            },
        ]
    }
    fn protocol_name(&self) -> &'static str {
        "Maven"
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            EventType::new(
                "maven_connected",
                "Triggered when Maven client connects to repository",
                json!({"type": "download_artifact", "group_id": "org.apache.commons", "artifact_id": "commons-lang3", "version": "3.12.0"}),
            ),
            EventType::new(
                "maven_artifact_downloaded",
                "Triggered when Maven artifact is successfully downloaded",
                json!({"type": "download_pom", "group_id": "org.apache.commons", "artifact_id": "commons-collections4", "version": "4.4"}),
            ),
            EventType::new(
                "maven_pom_received",
                "Triggered when POM file is downloaded and received",
                json!({"type": "download_artifact", "group_id": "com.google.guava", "artifact_id": "guava", "version": "31.1-jre"}),
            ),
            EventType::new(
                "maven_metadata_received",
                "Triggered when Maven metadata is received",
                json!({"type": "download_artifact", "group_id": "com.google.guava", "artifact_id": "guava", "version": "31.1-jre"}),
            ),
        ]
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>HTTP>Maven"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "maven",
            "maven client",
            "connect to maven",
            "maven repository",
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .implementation("reqwest HTTP client with Maven repository protocol")
            .llm_control("Full control over artifact resolution, POM parsing, version search")
            .e2e_testing("Maven Central or local Maven repository")
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "Maven client for downloading artifacts and resolving dependencies from Maven repositories"
    }
    fn example_prompt(&self) -> &'static str {
        "Connect to Maven Central and download commons-lang3:3.12.0"
    }
    fn group_name(&self) -> &'static str {
        "Package Managers"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        use serde_json::json;

        StartupExamples::new(
            // LLM mode: LLM controls Maven operations
            json!({
                "type": "open_client",
                "remote_addr": "repo.maven.apache.org",
                "base_stack": "maven",
                "instruction": "Download commons-lang3 version 3.12.0 and show its dependencies"
            }),
            // Script mode: Code-based artifact handling
            json!({
                "type": "open_client",
                "remote_addr": "repo.maven.apache.org",
                "base_stack": "maven",
                "event_handlers": [{
                    "event_pattern": "maven_artifact_downloaded",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "<maven_client_handler>"
                    }
                }]
            }),
            // Static mode: Fixed artifact download
            json!({
                "type": "open_client",
                "remote_addr": "repo.maven.apache.org",
                "base_stack": "maven",
                "event_handlers": [
                    {
                        "event_pattern": "maven_connected",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "download_artifact",
                                "group_id": "org.apache.commons",
                                "artifact_id": "commons-lang3",
                                "version": "3.12.0"
                            }]
                        }
                    },
                    {
                        "event_pattern": "maven_artifact_downloaded",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "disconnect"
                            }]
                        }
                    }
                ]
            }),
        )
    }
}

// Implement Client trait (client-specific functionality)
impl Client for MavenClientProtocol {
    fn connect(
        &self,
        ctx: crate::protocol::ConnectContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::client::maven::MavenClient;
            // The declared startup parameter, honoured. `repository_url` has been in
            // `get_startup_parameters()` since this client was written and nothing
            // read it: `connect()` forwarded `ctx.remote_addr` and dropped
            // `ctx.startup_params` on the floor, so the advertised knob did nothing
            // when turned. `?`, never `unwrap()` - an undeclared or wrong-typed key
            // must produce a clean error naming it, not a panic in the connect task.
            let remote_addr = match ctx.startup_params.as_ref() {
                Some(params) => params
                    .get_optional_string("repository_url")?
                    .unwrap_or(ctx.remote_addr),
                None => ctx.remote_addr,
            };
            MavenClient::connect_with_llm_actions(
                remote_addr,
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.client_id,
            )
            .await
        })
    }
    fn execute_action(&self, action: serde_json::Value) -> Result<ClientActionResult> {
        let action_type = action
            .get("type")
            .and_then(|v| v.as_str())
            .context("Missing 'type' field in action")?;

        match action_type {
            "download_artifact" => {
                let group_id = action
                    .get("group_id")
                    .and_then(|v| v.as_str())
                    .context("Missing 'group_id' field")?
                    .to_string();

                let artifact_id = action
                    .get("artifact_id")
                    .and_then(|v| v.as_str())
                    .context("Missing 'artifact_id' field")?
                    .to_string();

                let version = action
                    .get("version")
                    .and_then(|v| v.as_str())
                    .context("Missing 'version' field")?
                    .to_string();

                let packaging = action
                    .get("packaging")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());

                Ok(ClientActionResult::Custom {
                    name: "maven_download_artifact".to_string(),
                    data: json!({
                        "group_id": group_id,
                        "artifact_id": artifact_id,
                        "version": version,
                        "packaging": packaging,
                    }),
                })
            }
            "download_pom" => {
                let group_id = action
                    .get("group_id")
                    .and_then(|v| v.as_str())
                    .context("Missing 'group_id' field")?
                    .to_string();

                let artifact_id = action
                    .get("artifact_id")
                    .and_then(|v| v.as_str())
                    .context("Missing 'artifact_id' field")?
                    .to_string();

                let version = action
                    .get("version")
                    .and_then(|v| v.as_str())
                    .context("Missing 'version' field")?
                    .to_string();

                Ok(ClientActionResult::Custom {
                    name: "maven_download_pom".to_string(),
                    data: json!({
                        "group_id": group_id,
                        "artifact_id": artifact_id,
                        "version": version,
                    }),
                })
            }
            "search_versions" => {
                let group_id = action
                    .get("group_id")
                    .and_then(|v| v.as_str())
                    .context("Missing 'group_id' field")?
                    .to_string();

                let artifact_id = action
                    .get("artifact_id")
                    .and_then(|v| v.as_str())
                    .context("Missing 'artifact_id' field")?
                    .to_string();

                Ok(ClientActionResult::Custom {
                    name: "maven_search_versions".to_string(),
                    data: json!({
                        "group_id": group_id,
                        "artifact_id": artifact_id,
                    }),
                })
            }
            "disconnect" => Ok(ClientActionResult::Disconnect),
            _ => Err(anyhow::anyhow!(
                "Unknown Maven client action: {}",
                action_type
            )),
        }
    }
}
