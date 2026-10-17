//! Docker Engine API actions.
//!
//! One event, eight actions. Each read the model answers has exactly one action that answers
//! it (`resource` in the event says which), plus `send_docker_error` for a refusal in Docker's
//! own `{"message": …}` shape. Every action carries structured fields; NetGet renders the JSON
//! document the Docker CLI's Go decoder expects, filling what the model left out.

use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter, ParameterDefinition,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::EventType;
use crate::state::app_state::AppState;
use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

use super::api;

/// Any read the model decides: version, info, container list/inspect, images, networks, volumes.
pub static DOCKER_API_REQUEST_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "docker_api_request",
        "A Docker client (the docker CLI, an SDK, Portainer…) read the Docker Engine API. \
         `resource` says what it asked for and which action answers it: version -> \
         send_docker_version, info -> send_docker_info, containers -> send_docker_containers \
         (query.all == \"1\" means include stopped ones), container -> send_docker_container \
         (for `id`, which may be a name or an ID prefix), images -> send_docker_images, \
         networks -> send_docker_networks, volumes -> send_docker_volumes. Use \
         send_docker_error with status 404 for something that does not exist.",
        json!({
            "type": "send_docker_containers",
            "containers": [example_container()]
        }),
    )
    .with_actions(all_actions())
});

/// What one route's request is, in the words its event description uses.
fn route_request(route: &api::Route) -> &'static str {
    use api::Route as R;
    match route {
        R::Version => "This request is `docker version`: answer it with send_docker_version.",
        R::Info => "This request is `docker info`: answer it with send_docker_info.",
        R::ContainerList => {
            "This request is `docker ps` (`docker ps -a` when query.all == \"1\", which \
             includes stopped containers): answer it with send_docker_containers."
        }
        R::ContainerInspect(_) => {
            "This request inspects one container, named by `id` (a name or an ID prefix): \
             answer with that container's fields in send_docker_container, or send_docker_error \
             with status 404 when there is no such container."
        }
        R::ImageList => "This request is `docker images`: answer it with send_docker_images.",
        R::NetworkList => {
            "This request is `docker network ls`: answer it with send_docker_networks."
        }
        R::VolumeList => "This request is `docker volume ls`: answer it with send_docker_volumes.",
        R::Ping | R::Mutating | R::NotFound => "",
    }
}

/// `docker_api_request` as raised for one route: the same event id, offering only the action
/// that answers that route and `send_docker_error`.
///
/// Every route has exactly one answering action, and the connection loop ignores any other
/// (`decision=fail_closed_no_action`), so offering all eight only ever offered seven wrong
/// answers. llama3.1:8b took one: asked to inspect a container on a host with no containers, it
/// answered `send_docker_volumes` with `[{"name": "none"}]` five runs in five, reasoning that it
/// was answering "the resource=volumes request". With the two actions that can answer an
/// inspect, the same prompt is answered with the 404. The id is unchanged, so handlers written
/// for `docker_api_request` match as before; `get_event_types` still declares the one event with
/// every action, which is what documentation and handler validation read.
static ROUTE_EVENTS: LazyLock<Vec<(&'static str, EventType)>> = LazyLock::new(|| {
    use api::Route as R;
    [
        R::Version,
        R::Info,
        R::ContainerList,
        R::ContainerInspect(String::new()),
        R::ImageList,
        R::NetworkList,
        R::VolumeList,
    ]
    .iter()
    .filter_map(|route| {
        let resource = route.resource()?;
        let answering = route.answering_action()?;
        let actions: Vec<ActionDefinition> = all_actions()
            .into_iter()
            .filter(|a| a.name == answering || a.name == "send_docker_error")
            .collect();
        let example = actions.first()?.example.clone();
        let event = EventType::new(
            "docker_api_request",
            format!(
                "A Docker client (the docker CLI, an SDK, Portainer…) read the Docker Engine \
                 API. {} Use send_docker_error for a refusal.",
                route_request(route)
            ),
            example,
        )
        .with_actions(actions);
        Some((resource, event))
    })
    .collect()
});

/// The event to raise for a request whose route resolved to `resource`: the route's own
/// narrowed `docker_api_request`, or the declared one with every action for anything else.
pub fn event_for_resource(resource: &str) -> &'static EventType {
    ROUTE_EVENTS
        .iter()
        .find(|(r, _)| *r == resource)
        .map(|(_, event)| event)
        .unwrap_or(&DOCKER_API_REQUEST_EVENT)
}

fn all_actions() -> Vec<ActionDefinition> {
    vec![
        send_docker_version_action(),
        send_docker_info_action(),
        send_docker_containers_action(),
        send_docker_container_action(),
        send_docker_images_action(),
        send_docker_networks_action(),
        send_docker_volumes_action(),
        send_docker_error_action(),
    ]
}

/// Docker Engine API protocol handler.
pub struct DockerProtocol;

impl DockerProtocol {
    pub fn new() -> Self {
        Self
    }
}

impl Default for DockerProtocol {
    fn default() -> Self {
        Self::new()
    }
}

/// Defaults used when validating in the executor, which has no server configuration. Only the
/// shape is being checked there; the running server renders with its real identity.
fn validation_identity() -> api::EngineIdentity {
    api::EngineIdentity {
        engine_version: super::DEFAULT_ENGINE_VERSION.to_string(),
        api_version: super::DEFAULT_API_VERSION.to_string(),
    }
}

/// The action's own fields without `type` — the flat shape the single-object actions take.
fn without_type(action: &Value) -> Value {
    let mut v = action.clone();
    if let Some(obj) = v.as_object_mut() {
        obj.remove("type");
    }
    v
}

impl Protocol for DockerProtocol {
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        Vec::new()
    }

    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        all_actions()
    }

    fn protocol_name(&self) -> &'static str {
        "Docker"
    }

    fn get_event_types(&self) -> Vec<EventType> {
        vec![DOCKER_API_REQUEST_EVENT.clone()]
    }

    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>HTTP>DOCKER"
    }

    fn keywords(&self) -> Vec<&'static str> {
        vec!["docker", "dockerd", "docker engine", "docker api", "moby"]
    }

    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{
            DevelopmentState, PrivilegeRequirement, ProtocolMetadataV2,
        };

        ProtocolMetadataV2::builder()
            // Beta on evidence: tests/server/docker/real_client_test.rs drives the real docker
            // CLI (a Go client decoding into the Engine's own types) through version, ps -a,
            // images, inspect, network ls, volume ls and info, asserting it prints exactly the
            // handler's values, and hard-fails when the binary is absent. Not Stable: one
            // client, no fuzz target, no pcap-oracle test, and the API is a read-only subset.
            .state(DevelopmentState::Beta)
            .well_known_port(2375)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation(
                "hyper HTTP/1.1, plain TCP (the unauthenticated tcp://…:2375 shape). /_ping \
                 (HEAD and GET) and /vX.Y/ version negotiation are served deterministically; \
                 every read raises docker_api_request and the model answers with a structured \
                 action that NetGet renders into the document the Docker CLI decodes, filling \
                 HostConfig/NetworkSettings/Components and the other fields nobody reads.",
            )
            .llm_control(
                "Which containers, images, networks and volumes exist, their states, ports and \
                 labels, and what /version and /info report. NetGet stores nothing between \
                 requests.",
            )
            .e2e_testing(
                "tests/server/docker/real_client_test.rs - the real docker CLI (docker -H \
                 tcp://127.0.0.1:PORT) runs version, ps -a, images, inspect, network ls and \
                 volume ls against a static handler and must print exactly the handler's values; \
                 DOCKER_CONFIG is a temp dir and DOCKER_HOST/DOCKER_CONTEXT are removed so the \
                 machine's real daemon is never contacted. HARD FAILS when docker is absent. \
                 e2e_test.rs covers the mocked model path.",
            )
            .notes(
                "Read-only subset: /_ping, /version, /info, /containers/json (all, filters \
                 passed through as query), /containers/{id}/json, /images/json, /networks, \
                 /volumes. Every POST/PUT/DELETE (create, start, stop, exec, pull, rm, build) is \
                 a static 501 in Docker's error shape. Not implemented: /images/{id}/json (so \
                 docker inspect falls back to 'No such object' for images), logs, events, \
                 stats, attach, the swarm endpoints, TLS (2376) and authentication - the API \
                 on 2375 has none, and neither does this.",
            )
            .max_inbound_bytes(super::MAX_REQUEST_BODY_BYTES)
            // LLM failure: 503 + Retry-After (overloaded) or 500, each with Docker's
            // {"message": ...} carrying a fixed category - the CLI prints it as the error.
            .answers_on_failure()
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }

    fn description(&self) -> &'static str {
        "Docker Engine API (read-only) whose containers and images the model invents"
    }

    fn example_prompt(&self) -> &'static str {
        "Be a Docker daemon on port 2375 running an nginx web container and a stopped postgres \
         container, with nginx:1.27 and postgres:16 images"
    }

    fn group_name(&self) -> &'static str {
        "AI & API"
    }

    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "api_version".to_string(),
                type_hint: "string".to_string(),
                description: format!(
                    "Highest Engine API version advertised by /_ping and accepted in /vX.Y/ \
                     prefixes (default {}). The docker CLI negotiates down to it.",
                    super::DEFAULT_API_VERSION
                ),
                required: false,
                example: json!("1.47"),
                default: Some(serde_json::json!(super::DEFAULT_API_VERSION)),
            },
            ParameterDefinition {
                name: "engine_version".to_string(),
                type_hint: "string".to_string(),
                description: format!(
                    "Engine version in the Server header and the default for /version and \
                     /info (default {}).",
                    super::DEFAULT_ENGINE_VERSION
                ),
                required: false,
                example: json!("27.5.1"),
                default: Some(serde_json::json!(super::DEFAULT_ENGINE_VERSION)),
            },
        ]
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;

        StartupExamples::new(
            json!({
                "type": "open_server",
                "port": 2375,
                "base_stack": "docker",
                "instruction": "Docker host for a small web app. Containers: 'web' (nginx:1.27, \
                                running, port 8080->80/tcp) and 'db' (postgres:16, exited with \
                                code 0 an hour ago). Images: nginx:1.27 and postgres:16. One \
                                bridge network and one volume 'pgdata'. Say 'No such \
                                container' (404) for anything else."
            }),
            json!({
                "type": "open_server",
                "port": 2375,
                "base_stack": "docker",
                "event_handlers": [{
                    "event_pattern": "docker_api_request",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "import json, sys\nevent = json.load(sys.stdin)['event']\nres = event.get('resource')\nweb = {'id': 'a1b2c3d4e5f6a7b8', 'names': ['web'], 'image': 'nginx:1.27', 'command': 'nginx -g daemon off;', 'state': 'running', 'status': 'Up 2 hours', 'ports': [{'private_port': 80, 'public_port': 8080, 'type': 'tcp'}]}\nif res == 'containers':\n    act = {'type': 'send_docker_containers', 'containers': [web]}\nelif res == 'container' and event.get('id') in ('web', 'a1b2c3d4e5f6', 'a1b2c3d4e5f6a7b8'):\n    act = dict(web, type='send_docker_container')\nelif res == 'images':\n    act = {'type': 'send_docker_images', 'images': [{'repo_tags': ['nginx:1.27'], 'size': 187000000}]}\nelif res == 'version':\n    act = {'type': 'send_docker_version'}\nelif res == 'info':\n    act = {'type': 'send_docker_info', 'containers_running': 1, 'images': 1}\nelif res == 'networks':\n    act = {'type': 'send_docker_networks', 'networks': [{'name': 'bridge'}]}\nelif res == 'volumes':\n    act = {'type': 'send_docker_volumes', 'volumes': []}\nelse:\n    act = {'type': 'send_docker_error', 'status': 404, 'message': 'No such container: ' + str(event.get('id'))}\nprint(json.dumps({'actions': [act]}))"
                    }
                }]
            }),
            json!({
                "type": "open_server",
                "port": 2375,
                "base_stack": "docker",
                "event_handlers": [{
                    "event_pattern": "docker_api_request",
                    "handler": {
                        "type": "static",
                        "actions": example_static_actions()
                    }
                }]
            }),
        )
    }
}

impl Server for DockerProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            let (api_version, engine_version) = match ctx.startup_params.as_ref() {
                Some(params) => (
                    params
                        .get_optional_string("api_version")?
                        .unwrap_or_else(|| super::DEFAULT_API_VERSION.to_string()),
                    params
                        .get_optional_string("engine_version")?
                        .unwrap_or_else(|| super::DEFAULT_ENGINE_VERSION.to_string()),
                ),
                None => (
                    super::DEFAULT_API_VERSION.to_string(),
                    super::DEFAULT_ENGINE_VERSION.to_string(),
                ),
            };
            if api::parse_version(&api_version).is_none()
                || api::parse_version(&api_version) < api::parse_version(api::MIN_API_VERSION)
            {
                return Err(anyhow::anyhow!(
                    "api_version {api_version:?} must look like 1.47 and be at least {}",
                    api::MIN_API_VERSION
                ));
            }
            if engine_version.is_empty()
                || !engine_version
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '+' | '_'))
            {
                return Err(anyhow::anyhow!(
                    "engine_version {engine_version:?} must be a version string like 27.5.1"
                ));
            }
            super::DockerServer::spawn_with_llm_actions(
                ctx.legacy_listen_addr(),
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.server_id,
                super::DockerConfig {
                    identity: api::EngineIdentity {
                        engine_version,
                        api_version,
                    },
                },
            )
            .await
        })
    }

    fn execute_action(&self, action: Value) -> Result<ActionResult> {
        let action_type = action
            .get("type")
            .and_then(|v| v.as_str())
            .context("Missing 'type' field in action")?;
        let identity = validation_identity();
        let refuse = |reason: String| anyhow::anyhow!("{action_type} refused: {reason}");

        let data = match action_type {
            "send_docker_version" => {
                let flat = without_type(&action);
                api::render_version(&flat, &identity).map_err(refuse)?;
                flat
            }
            "send_docker_info" => {
                let flat = without_type(&action);
                api::render_info(&flat, &identity).map_err(refuse)?;
                flat
            }
            "send_docker_containers" => {
                let list = action
                    .get("containers")
                    .context("send_docker_containers needs a 'containers' array")?;
                api::render_container_list(list).map_err(refuse)?;
                json!({"containers": list})
            }
            "send_docker_container" => {
                // Either flat fields or a nested `container` object.
                let container = action
                    .get("container")
                    .cloned()
                    .unwrap_or_else(|| without_type(&action));
                api::render_container(&container).map_err(refuse)?;
                json!({"container": container})
            }
            "send_docker_images" => {
                let list = action
                    .get("images")
                    .context("send_docker_images needs an 'images' array")?;
                api::render_images(list).map_err(refuse)?;
                json!({"images": list})
            }
            "send_docker_networks" => {
                let list = action
                    .get("networks")
                    .context("send_docker_networks needs a 'networks' array")?;
                api::render_networks(list).map_err(refuse)?;
                json!({"networks": list})
            }
            "send_docker_volumes" => {
                let list = action
                    .get("volumes")
                    .context("send_docker_volumes needs a 'volumes' array")?;
                api::render_volumes(list).map_err(refuse)?;
                json!({"volumes": list})
            }
            "send_docker_error" => {
                let status = action.get("status").and_then(|v| v.as_u64()).unwrap_or(500);
                if !(400..600).contains(&status) {
                    return Err(anyhow::anyhow!(
                        "send_docker_error 'status' must be a 4xx or 5xx HTTP status, got {status}"
                    ));
                }
                let message = action
                    .get("message")
                    .and_then(|v| v.as_str())
                    .context("send_docker_error needs a 'message'")?;
                json!({"status": status, "message": message})
            }
            other => return Err(anyhow::anyhow!("Unknown Docker action: {other}")),
        };
        Ok(ActionResult::Custom {
            name: action_type.to_string(),
            data,
        })
    }
}

// ---------------------------------------------------------------------------
// Action definitions
// ---------------------------------------------------------------------------

fn example_container() -> Value {
    json!({
        "id": "3f4e1a2b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f",
        "names": ["web"],
        "image": "nginx:1.27",
        "command": "nginx -g 'daemon off;'",
        "state": "running",
        "status": "Up 2 hours",
        "created": "2026-09-01T10:00:00Z",
        "ports": [{"private_port": 80, "public_port": 8080, "type": "tcp"}],
        "labels": {"app": "web"}
    })
}

/// One answer per route. A static handler answers every `docker_api_request` with the same
/// action list, and the server picks the action that answers the route the request hit, so a
/// fixed host is one static rule.
pub fn example_static_actions() -> Value {
    let mut container = example_container();
    container["type"] = json!("send_docker_container");
    json!([
        {"type": "send_docker_version", "version": "27.5.1"},
        {"type": "send_docker_info", "name": "netget-docker", "containers_running": 1,
         "images": 1, "operating_system": "Ubuntu 24.04 LTS", "ncpu": 4},
        {"type": "send_docker_containers", "containers": [example_container()]},
        container,
        {"type": "send_docker_images", "images": [{"repo_tags": ["nginx:1.27"],
                                                   "size": 187654321}]},
        {"type": "send_docker_networks", "networks": [{"name": "bridge"}]},
        {"type": "send_docker_volumes", "volumes": []}
    ])
}

fn param(name: &str, type_hint: &str, description: &str, required: bool) -> Parameter {
    Parameter {
        name: name.to_string(),
        type_hint: type_hint.to_string(),
        description: description.to_string(),
        required,
    }
}

fn send_docker_version_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_docker_version".to_string(),
        description: "Answer resource=version (docker version's Server section). Every field \
                      is optional; NetGet fills the rest."
            .to_string(),
        parameters: vec![
            param(
                "version",
                "string",
                "Engine version, e.g. \"27.5.1\"",
                false,
            ),
            param("api_version", "string", "API version, e.g. \"1.47\"", false),
            param("os", "string", "Default \"linux\"", false),
            param("arch", "string", "Default \"amd64\"", false),
            param("kernel_version", "string", "Kernel version string", false),
            param("go_version", "string", "Go version string", false),
            param("git_commit", "string", "Short commit hash", false),
        ],
        example: json!({"type": "send_docker_version", "version": "27.5.1", "arch": "amd64"}),
        log_template: Some(LogTemplate::new().with_info("-> Docker version {version}")),
    }
}

fn send_docker_info_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_docker_info".to_string(),
        description: "Answer resource=info (docker info). Every field is optional; counts \
                      default to 0 and Containers to the sum of running, paused and stopped."
            .to_string(),
        parameters: vec![
            param(
                "name",
                "string",
                "Host name shown as Name in docker info",
                false,
            ),
            param("containers_running", "number", "Running containers", false),
            param("containers_paused", "number", "Paused containers", false),
            param("containers_stopped", "number", "Stopped containers", false),
            param("images", "number", "Number of images on the host", false),
            param(
                "server_version",
                "string",
                "Engine version shown as Server Version",
                false,
            ),
            param(
                "operating_system",
                "string",
                "e.g. \"Ubuntu 24.04 LTS\"",
                false,
            ),
            param(
                "kernel_version",
                "string",
                "Kernel version string, e.g. \"6.8.0-45-generic\"",
                false,
            ),
            param(
                "architecture",
                "string",
                "CPU architecture, e.g. \"x86_64\" or \"aarch64\"",
                false,
            ),
            param("ncpu", "number", "Number of CPUs on the host", false),
            param("mem_total", "number", "Memory in bytes", false),
            param("labels", "array", "Engine labels, [\"key=value\"]", false),
        ],
        example: json!({
            "type": "send_docker_info",
            "name": "build-host-1",
            "containers_running": 1,
            "containers_stopped": 1,
            "images": 2,
            "operating_system": "Ubuntu 24.04 LTS",
            "ncpu": 8
        }),
        log_template: Some(LogTemplate::new().with_info("-> Docker info {name}")),
    }
}

const CONTAINER_FIELDS: &str = "{\"id\": hex or alphanumeric (optional; derived from the name), \
     \"names\": [\"web\"], \"image\": \"nginx:1.27\", \"command\": \"nginx -g 'daemon off;'\", \
     \"state\": created|running|paused|restarting|removing|exited|dead, \"status\": \"Up 2 \
     hours\" (optional, derived from state), \"exit_code\": number, \"created\": unix seconds \
     or RFC 3339, \"ports\": [{\"private_port\": 80, \"public_port\": 8080, \"type\": \"tcp\"}], \
     \"labels\": {}, \"env\": [\"KEY=value\"], \"ip\": \"172.17.0.2\"}";

fn send_docker_containers_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_docker_containers".to_string(),
        description: format!(
            "Answer resource=containers (docker ps). Without query.all=\"1\" list only running \
             containers. Each entry: {CONTAINER_FIELDS}"
        ),
        parameters: vec![param(
            "containers",
            "array",
            "The containers, possibly empty",
            true,
        )],
        example: json!({"type": "send_docker_containers", "containers": [example_container()]}),
        log_template: Some(LogTemplate::new().with_info("-> Docker containers")),
    }
}

fn send_docker_container_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_docker_container".to_string(),
        description: format!(
            "Answer resource=container (docker inspect) for the event's id with one container's \
             fields at the top level of the action: {CONTAINER_FIELDS}. Use send_docker_error \
             404 if no such container exists."
        ),
        parameters: vec![
            param("names", "array", "Container name, e.g. [\"web\"]", true),
            param("image", "string", "Image reference", true),
            param(
                "id",
                "string",
                "Container ID in hex (derived from the name if omitted)",
                false,
            ),
            param(
                "state",
                "string",
                "Container state (default running)",
                false,
            ),
            param(
                "command",
                "string",
                "Command line the container runs, e.g. \"nginx -g daemon off;\"",
                false,
            ),
            param("created", "string", "RFC 3339 or unix seconds", false),
            param("ports", "array", "Published ports", false),
            param("env", "array", "Environment, [\"KEY=value\"]", false),
            param(
                "labels",
                "object",
                "Container labels as {\"key\": \"value\"}",
                false,
            ),
        ],
        example: {
            let mut c = example_container();
            c["type"] = json!("send_docker_container");
            c
        },
        log_template: Some(LogTemplate::new().with_info("-> Docker container {image}")),
    }
}

fn send_docker_images_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_docker_images".to_string(),
        description: "Answer resource=images (docker images). Each entry: {\"repo_tags\": \
                      [\"nginx:1.27\"], \"id\": optional hex, \"size\": bytes, \"created\": unix \
                      seconds or RFC 3339, \"labels\": {}}"
            .to_string(),
        parameters: vec![param("images", "array", "The images, possibly empty", true)],
        example: json!({
            "type": "send_docker_images",
            "images": [{"repo_tags": ["nginx:1.27"], "size": 187654321,
                        "created": "2026-08-20T00:00:00Z"}]
        }),
        log_template: Some(LogTemplate::new().with_info("-> Docker images")),
    }
}

fn send_docker_networks_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_docker_networks".to_string(),
        description: "Answer resource=networks (docker network ls). Each entry: {\"name\": \
                      \"bridge\", \"driver\": \"bridge\", \"scope\": \"local\", \"id\": optional}"
            .to_string(),
        parameters: vec![param(
            "networks",
            "array",
            "The networks on the host (bridge, host, custom ones)",
            true,
        )],
        example: json!({
            "type": "send_docker_networks",
            "networks": [{"name": "bridge", "driver": "bridge"}, {"name": "host", "driver": "host"}]
        }),
        log_template: Some(LogTemplate::new().with_info("-> Docker networks")),
    }
}

fn send_docker_volumes_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_docker_volumes".to_string(),
        description: "Answer resource=volumes (docker volume ls). Each entry: {\"name\": \
                      \"pgdata\", \"driver\": \"local\", \"labels\": {}}"
            .to_string(),
        parameters: vec![param(
            "volumes",
            "array",
            "The volumes, possibly empty",
            true,
        )],
        example: json!({"type": "send_docker_volumes", "volumes": [{"name": "pgdata"}]}),
        log_template: Some(LogTemplate::new().with_info("-> Docker volumes")),
    }
}

fn send_docker_error_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_docker_error".to_string(),
        description: "Refuse a request with Docker's error shape; the CLI prints the message as \
                      'Error response from daemon: <message>'. 404 for a missing object."
            .to_string(),
        parameters: vec![
            param(
                "status",
                "number",
                "HTTP status, 4xx or 5xx (default 500)",
                false,
            ),
            param(
                "message",
                "string",
                "e.g. \"No such container: web9\"",
                true,
            ),
        ],
        example: json!({
            "type": "send_docker_error",
            "status": 404,
            "message": "No such container: web9"
        }),
        log_template: Some(LogTemplate::new().with_info("-> Docker error {status}: {message}")),
    }
}
