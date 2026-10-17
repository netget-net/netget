//! Kubernetes API server actions.
//!
//! Three events, four actions, all structured JSON. Nothing here carries encoded bytes: a
//! Kubernetes object *is* a JSON document, so the model hands over the document and NetGet
//! puts the right envelope around it.
//!
//! Every event attaches its own action list with `.with_actions(...)` — `call_llm` builds the
//! model's tool list from `event.event_type.actions`, so an event that omits it leaves the
//! model unable to answer at all.

use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter, ParameterDefinition,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::EventType;
use crate::state::app_state::AppState;
use anyhow::{Context, Result};
use serde_json::json;
use std::sync::LazyLock;
use tracing::debug;

/// `GET` on a collection: `/api/v1/namespaces/default/pods`, `/api/v1/nodes`.
pub static K8S_LIST_REQUEST: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "k8s_list_request",
        "A Kubernetes client (kubectl, client-go, kube-rs) listed a resource collection. \
         Invent the objects that should exist in this cluster and return them.",
        json!({
            "type": "k8s_list_response",
            "kind": "PodList",
            "apiVersion": "v1",
            "items": [{
                "metadata": {"name": "web-0", "namespace": "default",
                             "creationTimestamp": "2026-08-10T09:00:00Z"},
                "spec": {"containers": [{"name": "web", "image": "nginx:1.27"}]},
                "status": {"phase": "Running",
                           "containerStatuses": [{"name": "web", "ready": true, "restartCount": 0}]}
            }]
        }),
    )
    .with_actions(vec![
        list_response_action(),
        table_response_action(),
        status_action(),
    ])
});

/// `GET` on a single named object: `/api/v1/namespaces/default/pods/web-0`.
pub static K8S_GET_REQUEST: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "k8s_get_request",
        "A Kubernetes client requested one named object. Return that object, or a Status with \
         code 404 and reason NotFound if it should not exist.",
        json!({
            "type": "k8s_object_response",
            "object": {
                "kind": "Pod",
                "apiVersion": "v1",
                "metadata": {"name": "web-0", "namespace": "default",
                             "creationTimestamp": "2026-08-10T09:00:00Z"},
                "spec": {"containers": [{"name": "web", "image": "nginx:1.27"}]},
                "status": {"phase": "Running"}
            }
        }),
    )
    .with_actions(vec![object_response_action(), status_action()])
});

/// `POST` / `PUT` / `PATCH` / `DELETE` on a collection or object.
pub static K8S_WRITE_REQUEST: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "k8s_write_request",
        "A Kubernetes client created, updated, patched or deleted an object. Decide whether to \
         admit the write: return the resulting object, or a Status rejecting it.",
        json!({
            "type": "k8s_object_response",
            "status_code": 201,
            "object": {
                "kind": "Pod",
                "apiVersion": "v1",
                "metadata": {"name": "web-1", "namespace": "default", "uid": "b2c1…"},
                "status": {"phase": "Pending"}
            }
        }),
    )
    .with_actions(vec![object_response_action(), status_action()])
});

/// Kubernetes API server protocol handler.
pub struct KubernetesProtocol {}

impl KubernetesProtocol {
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for KubernetesProtocol {
    fn default() -> Self {
        Self::new()
    }
}

impl Protocol for KubernetesProtocol {
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![]
    }

    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            list_response_action(),
            object_response_action(),
            table_response_action(),
            status_action(),
        ]
    }

    fn protocol_name(&self) -> &'static str {
        "Kubernetes"
    }

    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            K8S_LIST_REQUEST.clone(),
            K8S_GET_REQUEST.clone(),
            K8S_WRITE_REQUEST.clone(),
        ]
    }

    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>HTTP>KUBERNETES"
    }

    fn keywords(&self) -> Vec<&'static str> {
        // Deliberately specific. No generic single words ("api", "cluster") - those collide
        // with unrelated protocols and break keyword resolution for both.
        vec!["kubernetes", "k8s", "kube-apiserver", "kubectl"]
    }

    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{
            DevelopmentState, PrivilegeRequirement, ProtocolMetadataV2,
        };

        ProtocolMetadataV2::builder()
            // Beta, on evidence rather than on vibes: `tests/server/kubernetes/e2e_test.rs`
            // drives the **real kubectl binary** through version / get pods / get nodes /
            // get pod -o json / a 404 NotFound / delete, and `require_kubectl()` **fails**
            // rather than skipping when the binary is absent. A skip-when-missing gate is a
            // silent pass, which is what held this at Experimental; it is not what holds it
            // now. Not Stable: TLS has never been driven by kubectl, and watch, OpenAPI,
            // admission, RBAC and authentication are all absent (see `notes`).
            .state(DevelopmentState::Beta)
            .privilege_requirement(PrivilegeRequirement::None)
            .well_known_port(6443)
            .implementation(
                "hyper HTTP/1.1 + serde_json, optional tokio-rustls TLS. JSON only - no \
                 protobuf, so no protoc, kube or k8s-openapi dependency. Discovery (/version, \
                 /api, /apis, /api/v1, /apis/{g}/{v}) is served deterministically from the \
                 startup resource table; Table output (as=Table;v=1;g=meta.k8s.io) is rendered \
                 server-side like a real apiserver's TableConvertor.",
            )
            .llm_control(
                "The model invents the entire cluster: every list, get and write is answered \
                 by k8s_list_response / k8s_object_response / k8s_table_response / k8s_status. \
                 NetGet stores no resources. The advertised resource set (including CRDs) comes \
                 from the 'resources' startup parameter.",
            )
            .e2e_testing(
                "tests/server/kubernetes/e2e_test.rs - mocked LLM, driven by the real kubectl \
                 binary via a generated kubeconfig, plus reqwest for wire-level assertions. The \
                 kubectl gate HARD FAILS when the binary is missing rather than skipping, so a \
                 machine without kubectl reports that instead of a silent pass. \
                 tests/server/kubernetes/guard_test.rs covers the request-body cap, the \
                 status-code range check and Table rendering of hostile numbers.",
            )
            .notes(
                "Validated against real kubectl v1.22.4 (darwin/arm64) over plain HTTP: \
                 'kubectl version', 'kubectl get pods', 'kubectl get nodes', 'kubectl get pod \
                 <name> -o json', 'kubectl get pods' against an empty cluster, a 404 NotFound \
                 Status and 'kubectl delete pod'. TLS is implemented via the shared \
                 tls_cert_manager (tls_enabled=true) and exercised by a rustls client in the \
                 suite, but has NOT been driven by kubectl. Request bodies are capped at 3 MiB \
                 (the apiserver's own maxRequestBodyBytes) and refused with a 413 \
                 RequestEntityTooLarge Status. NOT implemented: watch (?watch=true returns a \
                 501 Status), OpenAPI schema endpoints (/openapi/* returns 404, so 'kubectl \
                 explain' and client-side apply validation will not work), admission, RBAC, \
                 authentication (no Authorization header is checked and none is put in the \
                 event, so the model cannot make that decision either - every request is \
                 served), protobuf content negotiation, and server-side apply.",
            )
            .max_inbound_bytes(crate::server::kubernetes::MAX_REQUEST_BODY_BYTES)
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }

    fn description(&self) -> &'static str {
        "Kubernetes API server with an LLM-invented cluster (kubectl-compatible)"
    }

    fn example_prompt(&self) -> &'static str {
        "Be a Kubernetes API server on port 6443 with three nginx pods running in the default namespace"
    }

    fn group_name(&self) -> &'static str {
        "AI & API"
    }

    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        // The eight TLS parameters are shared with every other TLS-capable server and are read
        // by extract_tls_config_from_params() in spawn().
        let mut params = crate::server::tls_cert_manager::get_tls_startup_parameters();
        params.push(ParameterDefinition {
            name: "kubernetes_version".to_string(),
            type_hint: "string".to_string(),
            description: format!(
                "Kubernetes version reported by GET /version, e.g. \"v1.29.4\" (default: {})",
                super::DEFAULT_KUBERNETES_VERSION
            ),
            required: false,
            example: json!("v1.29.4"),
            default: None,
        });
        params.push(ParameterDefinition {
            name: "resources".to_string(),
            type_hint: "array".to_string(),
            description:
                "Resources advertised by API discovery, replacing the built-in set. Each entry: \
                 {\"group\": \"\" for core, \"version\": \"v1\", \"name\": plural URL segment, \
                 \"kind\": object kind, \"namespaced\": bool, \"shortNames\": [..]}. Use this to \
                 advertise CRDs. A resource that is not advertised here is answered with a 404 \
                 Status, because kubectl resolves names through discovery before it requests \
                 anything."
                    .to_string(),
            required: false,
            example: json!([
                {"group": "", "version": "v1", "name": "pods", "kind": "Pod",
                 "namespaced": true, "shortNames": ["po"]},
                {"group": "example.com", "version": "v1", "name": "widgets", "kind": "Widget",
                 "namespaced": true, "shortNames": ["wd"]}
            ]),
            default: None,
        });
        params
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;

        StartupExamples::new(
            // LLM mode
            json!({
                "type": "open_server",
                "port": 6443,
                "base_stack": "kubernetes",
                "instruction": "Kubernetes API server for a small production cluster. The \
                                default namespace runs three nginx pods (web-0, web-1, web-2), \
                                all Running. There are two nodes, node-1 (control-plane) and \
                                node-2, both Ready on v1.29.4. Answer every list with \
                                k8s_list_response and every single-object get with \
                                k8s_object_response; return k8s_status with code 404 and reason \
                                NotFound for anything that does not exist."
            }),
            // Script mode
            json!({
                "type": "open_server",
                "port": 6443,
                "base_stack": "kubernetes",
                "event_handlers": [{
                    "event_pattern": "k8s_list_request",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "return {'type': 'k8s_list_response', 'kind': 'PodList', 'apiVersion': 'v1', 'items': [{'metadata': {'name': 'web-0', 'namespace': 'default'}, 'spec': {'containers': [{'name': 'web', 'image': 'nginx:1.27'}]}, 'status': {'phase': 'Running'}}]}"
                    }
                }]
            }),
            // Static mode
            json!({
                "type": "open_server",
                "port": 6443,
                "base_stack": "kubernetes",
                "event_handlers": [{
                    "event_pattern": "k8s_list_request",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "k8s_list_response",
                            "kind": "PodList",
                            "apiVersion": "v1",
                            "items": [{
                                "metadata": {"name": "web-0", "namespace": "default"},
                                "spec": {"containers": [{"name": "web", "image": "nginx:1.27"}]},
                                "status": {"phase": "Running"}
                            }]
                        }]
                    }
                }]
            }),
        )
    }
}

impl Server for KubernetesProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use super::{
                ApiSurface, KubernetesConfig, KubernetesServer, DEFAULT_KUBERNETES_VERSION,
            };

            // Startup parameters are untrusted LLM/MCP input: propagate the error with `?`
            // so the caller gets a clean message naming the key, and no half-registered server.
            let (tls_config, kubernetes_version, surface) = match ctx.startup_params.as_ref() {
                Some(params) => {
                    let tls_config =
                        crate::server::tls_cert_manager::extract_tls_config_from_params(params)?;
                    let version = params
                        .get_optional_string("kubernetes_version")?
                        .unwrap_or_else(|| DEFAULT_KUBERNETES_VERSION.to_string());
                    let surface = match params.get_optional_array("resources")? {
                        Some(values) => ApiSurface::from_startup_value(values)?,
                        None => ApiSurface::builtin(),
                    };
                    (tls_config, version, surface)
                }
                None => (
                    None,
                    DEFAULT_KUBERNETES_VERSION.to_string(),
                    ApiSurface::builtin(),
                ),
            };

            KubernetesServer::spawn_with_llm_actions(
                ctx.legacy_listen_addr(),
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.server_id,
                tls_config,
                KubernetesConfig {
                    surface: std::sync::Arc::new(surface),
                    kubernetes_version,
                },
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
            "k8s_list_response" => Self::execute_list_response(action),
            "k8s_object_response" => Self::execute_object_response(action),
            "k8s_table_response" => Self::execute_table_response(action),
            "k8s_status" => Self::execute_status(action),
            other => Err(anyhow::anyhow!("Unknown Kubernetes action: {other}")),
        }
    }
}

impl KubernetesProtocol {
    fn execute_list_response(action: serde_json::Value) -> Result<ActionResult> {
        let items = action
            .get("items")
            .context("k8s_list_response is missing the required 'items' array")?;
        if !items.is_array() {
            return Err(anyhow::anyhow!(
                "k8s_list_response 'items' must be an array of Kubernetes objects"
            ));
        }
        debug!(
            "Kubernetes list response: {} item(s)",
            items.as_array().map(|a| a.len()).unwrap_or(0)
        );
        Ok(ActionResult::Custom {
            name: "k8s_list_response".to_string(),
            data: json!({
                "kind": action.get("kind").cloned(),
                "apiVersion": action.get("apiVersion").cloned(),
                "resourceVersion": action.get("resourceVersion").cloned(),
                "items": items,
            }),
        })
    }

    fn execute_object_response(action: serde_json::Value) -> Result<ActionResult> {
        let object = action
            .get("object")
            .context("k8s_object_response is missing the required 'object'")?;
        if !object.is_object() {
            return Err(anyhow::anyhow!(
                "k8s_object_response 'object' must be a Kubernetes object, not a scalar"
            ));
        }
        let status_code = action
            .get("status_code")
            .and_then(|v| v.as_u64())
            .unwrap_or(200);
        if !(100..600).contains(&status_code) {
            return Err(anyhow::anyhow!(
                "k8s_object_response 'status_code' must be between 100 and 599, got {status_code}"
            ));
        }
        debug!("Kubernetes object response ({})", status_code);
        Ok(ActionResult::Custom {
            name: "k8s_object_response".to_string(),
            data: json!({"object": object, "status_code": status_code}),
        })
    }

    fn execute_table_response(action: serde_json::Value) -> Result<ActionResult> {
        let columns = action
            .get("columns")
            .and_then(|v| v.as_array())
            .context("k8s_table_response is missing the required 'columns' array")?;
        let rows = action
            .get("rows")
            .and_then(|v| v.as_array())
            .context("k8s_table_response is missing the required 'rows' array")?;
        debug!(
            "Kubernetes table response: {} column(s), {} row(s)",
            columns.len(),
            rows.len()
        );
        Ok(ActionResult::Custom {
            name: "k8s_table_response".to_string(),
            data: json!({"columns": columns, "rows": rows}),
        })
    }

    fn execute_status(action: serde_json::Value) -> Result<ActionResult> {
        let code = action
            .get("code")
            .and_then(|v| v.as_u64())
            .context("k8s_status is missing the required numeric 'code'")?;
        if !(100..600).contains(&code) {
            return Err(anyhow::anyhow!(
                "k8s_status 'code' must be an HTTP status between 100 and 599, got {code}"
            ));
        }
        let reason = action
            .get("reason")
            .and_then(|v| v.as_str())
            .unwrap_or("InternalError")
            .to_string();
        let message = action
            .get("message")
            .and_then(|v| v.as_str())
            .unwrap_or("unspecified error")
            .to_string();
        debug!("Kubernetes status response: {} {}", code, reason);
        Ok(ActionResult::Custom {
            name: "k8s_status".to_string(),
            data: json!({
                "code": code,
                "reason": reason,
                "message": message,
                "details": action.get("details").cloned(),
            }),
        })
    }
}

// ---------------------------------------------------------------------------
// Action definitions
// ---------------------------------------------------------------------------

fn list_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "k8s_list_response".to_string(),
        description:
            "Answer a collection request with the objects that exist. NetGet wraps them in the \
             correct List envelope and, when the client asked for Table output (kubectl get \
             does), renders the columns a real apiserver would."
                .to_string(),
        parameters: vec![
            Parameter {
                name: "items".to_string(),
                type_hint: "array".to_string(),
                description:
                    "Array of Kubernetes objects, each with metadata/spec/status as plain JSON. \
                     Include metadata.creationTimestamp in RFC3339 so the AGE column is right. \
                     An empty array is a valid answer meaning 'no such resources'."
                        .to_string(),
                required: true,
            },
            Parameter {
                name: "kind".to_string(),
                type_hint: "string".to_string(),
                description:
                    "List kind, e.g. \"PodList\". Defaults to the kind the requested resource \
                     was advertised with in API discovery."
                        .to_string(),
                required: false,
            },
            Parameter {
                name: "apiVersion".to_string(),
                type_hint: "string".to_string(),
                description:
                    "apiVersion of the list, e.g. \"v1\" or \"apps/v1\". Defaults to the group \
                     version from the request URL."
                        .to_string(),
                required: false,
            },
            Parameter {
                name: "resourceVersion".to_string(),
                type_hint: "string".to_string(),
                description: "Opaque resource version string for the list (default: \"1\")"
                    .to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "k8s_list_response",
            "kind": "PodList",
            "apiVersion": "v1",
            "items": [{
                "metadata": {"name": "web-0", "namespace": "default",
                             "creationTimestamp": "2026-08-10T09:00:00Z"},
                "spec": {"containers": [{"name": "web", "image": "nginx:1.27"}]},
                "status": {"phase": "Running",
                           "containerStatuses": [{"name": "web", "ready": true, "restartCount": 0}]}
            }]
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> Kubernetes {kind}")
                .with_debug("Kubernetes k8s_list_response: kind={kind} apiVersion={apiVersion}"),
        ),
    }
}

fn object_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "k8s_object_response".to_string(),
        description:
            "Answer a single-object request (GET by name, or a create/update/patch) with the \
             object itself. Use k8s_status instead to reject the request."
                .to_string(),
        parameters: vec![
            Parameter {
                name: "object".to_string(),
                type_hint: "object".to_string(),
                description:
                    "The Kubernetes object as plain JSON: kind, apiVersion, metadata, spec, \
                     status. kind and apiVersion are filled in from the request URL if omitted."
                        .to_string(),
                required: true,
            },
            Parameter {
                name: "status_code".to_string(),
                type_hint: "number".to_string(),
                description:
                    "HTTP status: 200 for a get or update, 201 for a create (default: 200)"
                        .to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "k8s_object_response",
            "object": {
                "kind": "Pod",
                "apiVersion": "v1",
                "metadata": {"name": "web-0", "namespace": "default",
                             "creationTimestamp": "2026-08-10T09:00:00Z"},
                "spec": {"containers": [{"name": "web", "image": "nginx:1.27"}]},
                "status": {"phase": "Running"}
            }
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> Kubernetes object ({status_code})")
                .with_debug("Kubernetes k8s_object_response: status={status_code}"),
        ),
    }
}

fn table_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "k8s_table_response".to_string(),
        description:
            "Answer a `kubectl get` with explicit table columns and rows, bypassing NetGet's \
             automatic rendering. Only meaningful when the event's as_table field is true."
                .to_string(),
        parameters: vec![
            Parameter {
                name: "columns".to_string(),
                type_hint: "array".to_string(),
                description: "Column headers as strings, e.g. [\"NAME\", \"STATUS\", \"AGE\"]"
                    .to_string(),
                required: true,
            },
            Parameter {
                name: "rows".to_string(),
                type_hint: "array".to_string(),
                description:
                    "One entry per row: {\"cells\": [...one string per column...], \"name\": \
                     object name, \"namespace\": optional namespace}"
                        .to_string(),
                required: true,
            },
        ],
        example: json!({
            "type": "k8s_table_response",
            "columns": ["NAME", "READY", "STATUS", "RESTARTS", "AGE"],
            "rows": [
                {"name": "web-0", "namespace": "default",
                 "cells": ["web-0", "1/1", "Running", "0", "5m"]}
            ]
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> Kubernetes table")
                .with_debug("Kubernetes k8s_table_response: explicit columns/rows"),
        ),
    }
}

fn status_action() -> ActionDefinition {
    ActionDefinition {
        name: "k8s_status".to_string(),
        description:
            "Reject or fail a request with a Kubernetes Status object — the error envelope every \
             real client understands. This is how you say 'not found', 'forbidden' or \
             'conflict'; it is structurally distinct from returning an object, so a refusal is \
             never mistaken for an answer."
                .to_string(),
        parameters: vec![
            Parameter {
                name: "code".to_string(),
                type_hint: "number".to_string(),
                description: "HTTP status code: 404 not found, 403 forbidden, 409 conflict, \
                              422 invalid, 500 internal"
                    .to_string(),
                required: true,
            },
            Parameter {
                name: "reason".to_string(),
                type_hint: "string".to_string(),
                description:
                    "Machine-readable reason: NotFound, Forbidden, AlreadyExists, Conflict, \
                     Invalid, Unauthorized, InternalError"
                        .to_string(),
                required: false,
            },
            Parameter {
                name: "message".to_string(),
                type_hint: "string".to_string(),
                description:
                    "Human-readable message, e.g. 'pods \"web-9\" not found'. kubectl prints \
                     this verbatim."
                        .to_string(),
                required: false,
            },
            Parameter {
                name: "details".to_string(),
                type_hint: "object".to_string(),
                description:
                    "Optional StatusDetails, e.g. {\"name\": \"web-9\", \"kind\": \"pods\"}"
                        .to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "k8s_status",
            "code": 404,
            "reason": "NotFound",
            "message": "pods \"web-9\" not found",
            "details": {"name": "web-9", "kind": "pods"}
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> Kubernetes Status {code} {reason}")
                .with_debug("Kubernetes k8s_status: code={code} reason={reason} message={message}"),
        ),
    }
}
