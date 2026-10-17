//! Kubernetes client protocol actions implementation

use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, Parameter, ParameterDefinition,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::EventType;
use crate::state::app_state::AppState;
use anyhow::{Context, Result};
use serde_json::json;
use std::sync::LazyLock;

/// Kubernetes client connected event
pub static K8S_CLIENT_CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "k8s_connected",
        "Kubernetes client connected to cluster API",
        json!({"type": "k8s_list_pods", "namespace": "default"}),
    )
    .with_parameters(vec![
        Parameter {
            name: "cluster_url".to_string(),
            type_hint: "string".to_string(),
            description: "The address this client was opened with: \"default\" when the \
                          kubeconfig decides the cluster, otherwise the kubeconfig path"
                .to_string(),
            required: true,
        },
        Parameter {
            name: "namespace".to_string(),
            type_hint: "string".to_string(),
            description: "Namespace every action that does not name one itself will use"
                .to_string(),
            required: true,
        },
    ])
});

/// Kubernetes client resource received event
pub static K8S_CLIENT_RESOURCE_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "k8s_resource_received",
        "Kubernetes resource operation completed",
        json!({"type": "k8s_list_pods", "namespace": "default"}),
    )
    .with_parameters(vec![
        Parameter {
            name: "operation".to_string(),
            type_hint: "string".to_string(),
            description: "Operation performed (list, get, create, delete, etc.)".to_string(),
            required: true,
        },
        Parameter {
            name: "resource_type".to_string(),
            type_hint: "string".to_string(),
            description: "Resource type (pods, deployments, services, etc.)".to_string(),
            required: true,
        },
        Parameter {
            name: "namespace".to_string(),
            type_hint: "string".to_string(),
            description: "Kubernetes namespace".to_string(),
            required: true,
        },
        Parameter {
            name: "response".to_string(),
            type_hint: "object".to_string(),
            description: "Operation response data".to_string(),
            required: true,
        },
    ])
});

/// Kubernetes client protocol action handler
pub struct KubernetesClientProtocol;

impl Default for KubernetesClientProtocol {
    fn default() -> Self {
        Self
    }
}

impl KubernetesClientProtocol {
    pub fn new() -> Self {
        Self::default()
    }
}

// Implement Protocol trait with common methods
impl Protocol for KubernetesClientProtocol {
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "namespace".to_string(),
                description: "Default namespace for operations (default: 'default')".to_string(),
                type_hint: "string".to_string(),
                required: false,
                example: json!("kube-system"),
                default: None,
            },
            ParameterDefinition {
                name: "kubeconfig".to_string(),
                description: "Path to kubeconfig file (default: ~/.kube/config)".to_string(),
                type_hint: "string".to_string(),
                required: false,
                example: json!("~/.kube/config"),
                default: None,
            },
        ]
    }

    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![
            ActionDefinition {
                name: "k8s_list_pods".to_string(),
                description: "List all pods in a namespace".to_string(),
                parameters: vec![
                    Parameter {
                        name: "namespace".to_string(),
                        type_hint: "string".to_string(),
                        description:
                            "Namespace to list pods from (optional, uses default if not specified)"
                                .to_string(),
                        required: false,
                    },
                    Parameter {
                        name: "label_selector".to_string(),
                        type_hint: "string".to_string(),
                        description: "Label selector to filter pods (e.g., 'app=nginx')"
                            .to_string(),
                        required: false,
                    },
                ],
                example: json!({
                    "type": "k8s_list_pods",
                    "namespace": "default",
                    "label_selector": "app=nginx"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "k8s_get_pod".to_string(),
                description: "Get details of a specific pod".to_string(),
                parameters: vec![
                    Parameter {
                        name: "name".to_string(),
                        type_hint: "string".to_string(),
                        description: "Pod name".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "namespace".to_string(),
                        type_hint: "string".to_string(),
                        description: "Namespace (optional)".to_string(),
                        required: false,
                    },
                ],
                example: json!({
                    "type": "k8s_get_pod",
                    "name": "nginx-abc123",
                    "namespace": "default"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "k8s_get_logs".to_string(),
                description: "Get logs from a pod".to_string(),
                parameters: vec![
                    Parameter {
                        name: "name".to_string(),
                        type_hint: "string".to_string(),
                        description: "Pod name".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "namespace".to_string(),
                        type_hint: "string".to_string(),
                        description: "Namespace (optional)".to_string(),
                        required: false,
                    },
                ],
                example: json!({
                    "type": "k8s_get_logs",
                    "name": "nginx-abc123",
                    "namespace": "default"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "k8s_create_pod".to_string(),
                description: "Create a new pod".to_string(),
                parameters: vec![
                    Parameter {
                        name: "spec".to_string(),
                        type_hint: "object".to_string(),
                        description: "Pod specification (Kubernetes Pod manifest)".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "namespace".to_string(),
                        type_hint: "string".to_string(),
                        description: "Namespace (optional)".to_string(),
                        required: false,
                    },
                ],
                example: json!({
                    "type": "k8s_create_pod",
                    "namespace": "default",
                    "spec": {
                        "apiVersion": "v1",
                        "kind": "Pod",
                        "metadata": {
                            "name": "nginx"
                        },
                        "spec": {
                            "containers": [{
                                "name": "nginx",
                                "image": "nginx:latest"
                            }]
                        }
                    }
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "k8s_delete_pod".to_string(),
                description: "Delete a pod by name in a namespace. The apiserver accepts the \
                              request immediately; a Deployment or ReplicaSet controlling the \
                              pod will create a replacement, so this restarts a pod rather \
                              than removing it for good."
                    .to_string(),
                parameters: vec![
                    Parameter {
                        name: "name".to_string(),
                        type_hint: "string".to_string(),
                        description: "Pod name".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "namespace".to_string(),
                        type_hint: "string".to_string(),
                        description: "Namespace (optional)".to_string(),
                        required: false,
                    },
                ],
                example: json!({
                    "type": "k8s_delete_pod",
                    "name": "nginx",
                    "namespace": "default"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "k8s_list_deployments".to_string(),
                description: "List all deployments in a namespace".to_string(),
                parameters: vec![
                    Parameter {
                        name: "namespace".to_string(),
                        type_hint: "string".to_string(),
                        description: "Namespace (optional)".to_string(),
                        required: false,
                    },
                    Parameter {
                        name: "label_selector".to_string(),
                        type_hint: "string".to_string(),
                        description: "Label selector (optional)".to_string(),
                        required: false,
                    },
                ],
                example: json!({
                    "type": "k8s_list_deployments",
                    "namespace": "default"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "k8s_list_services".to_string(),
                description: "List all services in a namespace".to_string(),
                parameters: vec![
                    Parameter {
                        name: "namespace".to_string(),
                        type_hint: "string".to_string(),
                        description: "Namespace (optional)".to_string(),
                        required: false,
                    },
                    Parameter {
                        name: "label_selector".to_string(),
                        type_hint: "string".to_string(),
                        description: "Label selector (optional)".to_string(),
                        required: false,
                    },
                ],
                example: json!({
                    "type": "k8s_list_services",
                    "namespace": "kube-system"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "disconnect".to_string(),
                description: "Disconnect from the Kubernetes cluster".to_string(),
                parameters: vec![],
                example: json!({
                    "type": "disconnect"
                }),
                log_template: None,
            },
        ]
    }

    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![ActionDefinition {
            name: "k8s_list_pods".to_string(),
            description: "List pods in response to a previous operation".to_string(),
            parameters: vec![Parameter {
                name: "namespace".to_string(),
                type_hint: "string".to_string(),
                description: "Namespace (optional)".to_string(),
                required: false,
            }],
            example: json!({
                "type": "k8s_list_pods",
                "namespace": "default"
            }),
            log_template: Some(
                LogTemplate::new()
                    .with_info("-> K8s list pods (ns={namespace})")
                    .with_debug("Kubernetes k8s_list_pods: namespace={namespace}"),
            ),
        }]
    }

    fn protocol_name(&self) -> &'static str {
        "Kubernetes"
    }

    /// The two statics, cloned — **not** freshly built copies.
    ///
    /// This used to construct a second `EventType` per id with its own wording and no
    /// `.with_parameters(...)`, so the model was shown a `k8s_connected` with no fields while
    /// the event that actually fires declares `cluster_url`. Two declarations of one event
    /// drift the moment either is edited; there is only one now.
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            K8S_CLIENT_CONNECTED_EVENT.clone(),
            K8S_CLIENT_RESOURCE_RECEIVED_EVENT.clone(),
        ]
    }

    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>TLS>HTTP>K8s API"
    }

    fn keywords(&self) -> Vec<&'static str> {
        vec!["kubernetes", "k8s", "kubectl", "kube", "cluster"]
    }

    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .implementation(
                "kube 0.99 + k8s-openapi 0.24 (v1_30 types) over rustls. Verbs: list pods / \
                 deployments / services, get pod, pod logs (last 100 lines), create pod, \
                 delete pod. No watch, exec, port-forward, patch, scale or custom resources.",
            )
            .llm_control(
                "The model issues those verbs and is called again with the result \
                 (k8s_resource_received), so a listing can be followed up on. Follow-ups run \
                 through run_operation_once, which raises no event and therefore terminates.",
            )
            .e2e_testing(
                "tests/client/kubernetes/command_channel_test.rs - no cluster and no LLM: \
                 KUBECONFIG is pointed at a throwaway file whose only cluster is a loopback \
                 HTTP stub, an injected k8s_list_pods is asserted to have reached \
                 /api/v1/namespaces/default/pods, and the developer's own ~/.kube/config is \
                 never read. There is NO test against a real cluster: the minikube/kind tests \
                 in e2e_test.rs were placeholders that asserted nothing and have been removed, \
                 which is why this stays Experimental.",
            )
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }

    fn description(&self) -> &'static str {
        "Kubernetes API client for cluster management"
    }

    fn example_prompt(&self) -> &'static str {
        "Connect to Kubernetes cluster and list all pods in the default namespace"
    }

    fn group_name(&self) -> &'static str {
        "Cloud & Orchestration"
    }
    /// **`remote_addr` must be `"default"`, or a `kubeconfig` startup parameter must name a
    /// file.** These examples said `"kubernetes.local:6443"`, which `connect()` refuses
    /// outright — this client has no host:port form, because a cluster address alone carries
    /// no credentials or CA and `kube` cannot be pointed at one. A model copying the old
    /// example got "address is not understood" every time.
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        use serde_json::json;

        StartupExamples::new(
            // LLM mode: LLM handles Kubernetes cluster queries
            json!({
                "type": "open_client",
                "remote_addr": "default",
                "base_stack": "kubernetes",
                "instruction": "Connect to Kubernetes cluster and list all pods in the default namespace",
                "startup_params": {
                    "namespace": "default"
                }
            }),
            // Script mode: Code-based Kubernetes handling, against an explicit kubeconfig
            json!({
                "type": "open_client",
                "remote_addr": "default",
                "base_stack": "kubernetes",
                "startup_params": {
                    "namespace": "default",
                    "kubeconfig": "~/.kube/config"
                },
                "event_handlers": [{
                    "event_pattern": "k8s_connected",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "<kubernetes_client_handler>"
                    }
                }]
            }),
            // Static mode: Fixed Kubernetes action
            json!({
                "type": "open_client",
                "remote_addr": "default",
                "base_stack": "kubernetes",
                "startup_params": {
                    "namespace": "default"
                },
                "event_handlers": [{
                    "event_pattern": "k8s_connected",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "k8s_list_pods",
                            "namespace": "default"
                        }]
                    }
                }]
            }),
        )
    }
}

// Implement Client trait with client-specific methods
impl Client for KubernetesClientProtocol {
    fn connect(
        &self,
        ctx: crate::protocol::ConnectContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::client::kubernetes::KubernetesClient;
            KubernetesClient::connect_with_llm_actions(
                ctx.remote_addr,
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.client_id,
                ctx.startup_params,
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
            "k8s_list_pods" => {
                let namespace = action
                    .get("namespace")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());

                let label_selector = action
                    .get("label_selector")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());

                Ok(ClientActionResult::Custom {
                    name: "k8s_operation".to_string(),
                    data: json!({
                        "operation": "list",
                        "resource_type": "pods",
                        "namespace": namespace,
                        "label_selector": label_selector,
                    }),
                })
            }
            "k8s_get_pod" => {
                let name = action
                    .get("name")
                    .and_then(|v| v.as_str())
                    .context("Missing 'name' field")?
                    .to_string();

                let namespace = action
                    .get("namespace")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());

                Ok(ClientActionResult::Custom {
                    name: "k8s_operation".to_string(),
                    data: json!({
                        "operation": "get",
                        "resource_type": "pod",
                        "name": name,
                        "namespace": namespace,
                    }),
                })
            }
            "k8s_get_logs" => {
                let name = action
                    .get("name")
                    .and_then(|v| v.as_str())
                    .context("Missing 'name' field")?
                    .to_string();

                let namespace = action
                    .get("namespace")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());

                Ok(ClientActionResult::Custom {
                    name: "k8s_operation".to_string(),
                    data: json!({
                        "operation": "logs",
                        "resource_type": "pod",
                        "name": name,
                        "namespace": namespace,
                    }),
                })
            }
            "k8s_create_pod" => {
                let spec = action.get("spec").context("Missing 'spec' field")?.clone();

                let namespace = action
                    .get("namespace")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());

                Ok(ClientActionResult::Custom {
                    name: "k8s_operation".to_string(),
                    data: json!({
                        "operation": "create",
                        "resource_type": "pod",
                        "spec": spec,
                        "namespace": namespace,
                    }),
                })
            }
            "k8s_delete_pod" => {
                let name = action
                    .get("name")
                    .and_then(|v| v.as_str())
                    .context("Missing 'name' field")?
                    .to_string();

                let namespace = action
                    .get("namespace")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());

                Ok(ClientActionResult::Custom {
                    name: "k8s_operation".to_string(),
                    data: json!({
                        "operation": "delete",
                        "resource_type": "pod",
                        "name": name,
                        "namespace": namespace,
                    }),
                })
            }
            "k8s_list_deployments" => {
                let namespace = action
                    .get("namespace")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());

                let label_selector = action
                    .get("label_selector")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());

                Ok(ClientActionResult::Custom {
                    name: "k8s_operation".to_string(),
                    data: json!({
                        "operation": "list",
                        "resource_type": "deployments",
                        "namespace": namespace,
                        "label_selector": label_selector,
                    }),
                })
            }
            "k8s_list_services" => {
                let namespace = action
                    .get("namespace")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());

                let label_selector = action
                    .get("label_selector")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());

                Ok(ClientActionResult::Custom {
                    name: "k8s_operation".to_string(),
                    data: json!({
                        "operation": "list",
                        "resource_type": "services",
                        "namespace": namespace,
                        "label_selector": label_selector,
                    }),
                })
            }
            "disconnect" => Ok(ClientActionResult::Disconnect),
            _ => Err(anyhow::anyhow!(
                "Unknown Kubernetes client action: {}",
                action_type
            )),
        }
    }
}
