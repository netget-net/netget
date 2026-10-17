//! Beanstalkd actions: what the model is told, and how its answers become wire bytes.
//!
//! The model is the queue. It decides which job ids exist, what `reserve` hands out and what
//! the stats say; NetGet keeps no jobs. Every action is rendered by [`super::wire`], so the
//! model supplies ids, bodies, a status word from a fixed list and stats key/value pairs, never
//! a reply line or a byte count. The executor has no per-connection state; the session loop
//! checks that each reply answers the command it is sent for (`wire::reply_fits`).

use super::wire;
use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::EventType;
use crate::state::app_state::AppState;
use anyhow::{anyhow, Context, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

pub struct BeanstalkdProtocol;

impl BeanstalkdProtocol {
    pub fn new() -> Self {
        Self
    }
}

impl Default for BeanstalkdProtocol {
    fn default() -> Self {
        Self::new()
    }
}

impl Protocol for BeanstalkdProtocol {
    fn get_startup_parameters(&self) -> Vec<crate::llm::actions::ParameterDefinition> {
        vec![
            crate::llm::actions::ParameterDefinition {
                name: "first_byte_timeout_secs".to_string(),
                type_hint: "number".to_string(),
                description: "Seconds a new connection may send no command before the server \
                              closes it. Default 300, the window a `manual` rule gives a human - \
                              the peer may be NetGet's own TCP client with an event parked for \
                              its operator. Lower it for a listener exposed to strangers."
                    .to_string(),
                required: false,
                example: json!(300),
                default: Some(serde_json::json!(super::FIRST_COMMAND_TIMEOUT.as_secs())),
            },
            crate::llm::actions::ParameterDefinition {
                name: "idle_timeout_secs".to_string(),
                type_hint: "number".to_string(),
                description: "Seconds the server waits for the next command after answering \
                              one. Default 300. A worker blocked in `reserve` is not idle - the \
                              server owes it an answer - so this never cuts a waiting reserve."
                    .to_string(),
                required: false,
                example: json!(300),
                default: Some(serde_json::json!(super::IDLE_TIMEOUT.as_secs())),
            },
        ]
    }
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        Vec::new()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            insert_job_action(),
            reserve_job_action(),
            wait_for_job_action(),
            found_job_action(),
            status_action(),
            stats_action(),
            tubes_action(),
            close_connection_action(),
        ]
    }
    fn protocol_name(&self) -> &'static str {
        "Beanstalkd"
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            BEANSTALKD_PUT_EVENT.clone(),
            BEANSTALKD_RESERVE_EVENT.clone(),
            BEANSTALKD_JOB_COMMAND_EVENT.clone(),
            BEANSTALKD_STATS_EVENT.clone(),
        ]
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>Beanstalkd"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["beanstalkd", "beanstalk", "work queue", "job queue"]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{
            DevelopmentState, PrivilegeRequirement, ProtocolMetadataV2,
        };

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Beta)
            .well_known_port(11300)
            // 11300 is unprivileged, and so is every port a test picks.
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation(
                "Hand-written beanstalkd text protocol (protocol.txt, 1.13) over tokio TCP: \
                 command lines, put bodies read by declared length, RESERVED/FOUND bodies \
                 counted and YAML stats and tube lists rendered by NetGet",
            )
            .llm_control(
                "The queue: job ids for put, the job reserve hands out (or holding the worker \
                 until one exists), the outcome of delete/release/bury/touch/kick/peek, and \
                 the stats and tube list",
            )
            .e2e_testing(
                "tests/server/beanstalkd/real_client_test.rs drives the greenstalk 2.1 Python \
                 client (pip `greenstalk`) through use/watch/ignore, put, reserve, \
                 reserve-with-timeout, delete, release, bury, touch, kick, peek, stats, \
                 stats-tube, stats-job, list-tubes and an oversize put, asserting on what \
                 greenstalk returned or raised. It fails, never skips, when python3 or \
                 greenstalk is absent. tests/server/beanstalkd/e2e_test.rs covers the \
                 mocked-model path on a raw socket.",
            )
            .notes(
                "Implements every command in protocol.txt except the drain/binlog admin \
                 surface: put, use, reserve, reserve-with-timeout, reserve-job, delete, release, \
                 bury, touch, watch, ignore, peek, peek-ready, peek-delayed, peek-buried, kick, \
                 kick-job, stats, stats-job, stats-tube, list-tubes, list-tube-used, \
                 list-tubes-watched, pause-tube and quit. use/watch/ignore/list-tube-used/\
                 list-tubes-watched/quit are answered by NetGet from the connection's own tube \
                 state; the rest are the model's. NetGet stores no jobs: the model supplies \
                 ids and bodies. Job bodies reach the model as UTF-8 text (invalid bytes \
                 replaced). Command lines are capped at upstream's 224 bytes and job bodies at \
                 upstream's default max-job-size, 65535, checked against the declared size \
                 before any body byte is read. On backend failure, no answer, or a reply that \
                 does not answer the command, the peer gets INTERNAL_ERROR (OUT_OF_MEMORY when \
                 the backend is at capacity) and the session continues. No pcap oracle: this \
                 Wireshark build has no beanstalkd dissector.",
            )
            .max_inbound_bytes(wire::MAX_JOB_BYTES)
            // INTERNAL_ERROR / OUT_OF_MEMORY, which every beanstalkd client already handles.
            .answers_on_failure()
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "Beanstalkd work queue server - the model is the queue"
    }
    fn example_prompt(&self) -> &'static str {
        "Beanstalkd on port 11300 - a work queue that hands workers image-resize jobs"
    }
    fn group_name(&self) -> &'static str {
        "Core"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        StartupExamples::new(
            json!({
                "type": "open_server",
                "port": 11300,
                "base_stack": "beanstalkd",
                "instruction": "Beanstalkd work queue. Accept every put with increasing job \
                                ids starting at 1. When a worker reserves, hand out an \
                                image-resize job such as {\"image\": 7, \"width\": 640}."
            }),
            json!({
                "type": "open_server",
                "port": 11300,
                "base_stack": "beanstalkd",
                "event_handlers": [{
                    "event_pattern": "beanstalkd_put",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "import json, sys\nevent = json.load(sys.stdin)['event']\nprint(json.dumps({'actions': [{'type': 'insert_beanstalkd_job', 'job_id': 1000 + len(event.get('body', ''))}]}))"
                    }
                }, {
                    "event_pattern": "beanstalkd_reserve",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "reserve_beanstalkd_job",
                            "job_id": 1,
                            "body": "{\"image\": 7, \"width\": 640}"
                        }]
                    }
                }]
            }),
            json!({
                "type": "open_server",
                "port": 11300,
                "base_stack": "beanstalkd",
                "event_handlers": [{
                    "event_pattern": "beanstalkd_reserve",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "reserve_beanstalkd_job",
                            "job_id": 1,
                            "body": "resize image 7"
                        }]
                    }
                }, {
                    "event_pattern": "beanstalkd_job_command",
                    "handler": {
                        "type": "static",
                        "actions": [{"type": "send_beanstalkd_status", "status": "DELETED"}]
                    }
                }]
            }),
        )
    }
}

impl Server for BeanstalkdProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            let secs = |name: &str| -> anyhow::Result<Option<u64>> {
                Ok(ctx
                    .startup_params
                    .as_ref()
                    .map(|p| p.get_optional_u64(name))
                    .transpose()?
                    .flatten())
            };
            let first_byte_timeout_secs = secs("first_byte_timeout_secs")?;
            let idle_timeout_secs = secs("idle_timeout_secs")?;

            crate::server::beanstalkd::BeanstalkdServer::spawn_with_llm_actions(
                ctx.legacy_listen_addr(),
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.server_id,
                first_byte_timeout_secs,
                idle_timeout_secs,
            )
            .await
        })
    }

    fn execute_action(&self, action: Value) -> Result<ActionResult> {
        let action_type = action
            .get("type")
            .and_then(|v| v.as_str())
            .context("Missing 'type' field in action")?;

        let rendered = match action_type {
            "insert_beanstalkd_job" => {
                let buried = action
                    .get("buried")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                wire::render_inserted(job_id(&action)?, buried)
            }
            "reserve_beanstalkd_job" => {
                wire::render_job(wire::JobReply::Reserved, job_id(&action)?, body(&action)?)
            }
            "send_beanstalkd_found" => {
                wire::render_job(wire::JobReply::Found, job_id(&action)?, body(&action)?)
            }
            "wait_for_beanstalkd_job" => return Ok(ActionResult::WaitForMore),
            "send_beanstalkd_status" => {
                let status = action
                    .get("status")
                    .and_then(Value::as_str)
                    .context("send_beanstalkd_status needs 'status'")?;
                let count = match action.get("count") {
                    None | Some(Value::Null) => None,
                    Some(v) => Some(
                        v.as_u64()
                            .or_else(|| v.as_str().and_then(|s| s.trim().parse().ok()))
                            .context("'count' must be a non-negative integer")?,
                    ),
                };
                wire::render_status(status, count)
            }
            "send_beanstalkd_stats" => {
                let stats = action
                    .get("stats")
                    .and_then(Value::as_object)
                    .context("send_beanstalkd_stats needs 'stats', an object of name: value")?;
                wire::render_stats(stats)
            }
            "send_beanstalkd_tubes" => {
                let tubes: Vec<String> = action
                    .get("tubes")
                    .and_then(Value::as_array)
                    .context("send_beanstalkd_tubes needs 'tubes', an array of tube names")?
                    .iter()
                    .map(|t| t.as_str().unwrap_or("").to_string())
                    .collect();
                wire::render_tube_list(&tubes)
            }
            "close_connection" => return Ok(ActionResult::CloseConnection),
            _ => return Err(anyhow!("Unknown Beanstalkd action: {}", action_type)),
        };
        let rendered = rendered.map_err(|e| anyhow!("{action_type}: {e}"))?;
        Ok(ActionResult::Output(rendered.into_bytes()))
    }
}

fn job_id(action: &Value) -> Result<u64> {
    action
        .get("job_id")
        .and_then(|v| {
            v.as_u64()
                .or_else(|| v.as_str().and_then(|s| s.trim().parse().ok()))
        })
        .context("Missing or non-numeric 'job_id' (a positive integer)")
}

fn body(action: &Value) -> Result<&str> {
    match action.get("body") {
        Some(Value::String(s)) => Ok(s),
        _ => Err(anyhow!("'body' must be the job's text")),
    }
}

fn param(name: &str, type_hint: &str, description: &str, required: bool) -> Parameter {
    Parameter {
        name: name.to_string(),
        type_hint: type_hint.to_string(),
        description: description.to_string(),
        required,
    }
}

fn insert_job_action() -> ActionDefinition {
    ActionDefinition {
        name: "insert_beanstalkd_job".to_string(),
        description: "Accept a put: NetGet answers INSERTED <job_id>, or BURIED <job_id> when \
                      buried is true (the job went straight to the buried list). You choose \
                      the id; producers use it to refer to the job later."
            .to_string(),
        parameters: vec![
            param(
                "job_id",
                "number",
                "The new job's id, a positive integer",
                true,
            ),
            param(
                "buried",
                "boolean",
                "true to answer BURIED instead of INSERTED",
                false,
            ),
        ],
        example: json!({"type": "insert_beanstalkd_job", "job_id": 17}),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> beanstalkd INSERTED {job_id}")
                .with_debug("beanstalkd insert_beanstalkd_job: job_id={job_id}"),
        ),
    }
}

fn reserve_job_action() -> ActionDefinition {
    ActionDefinition {
        name: "reserve_beanstalkd_job".to_string(),
        description: "Hand a job to a worker that reserved: NetGet answers RESERVED <job_id> \
                      <bytes> followed by the body. Give the body as text; NetGet counts it. \
                      The example's id and body are placeholders for the shape, never data."
            .to_string(),
        parameters: vec![
            param("job_id", "number", "The job's id, a positive integer", true),
            param(
                "body",
                "string",
                "The job's payload as text, exactly as your instructions give it (at most \
                 65535 bytes)",
                true,
            ),
        ],
        example: json!({
            "type": "reserve_beanstalkd_job",
            "job_id": 1,
            "body": "<the job's text, word for word>"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> beanstalkd RESERVED {job_id}")
                .with_debug("beanstalkd reserve_beanstalkd_job: job_id={job_id}"),
        ),
    }
}

fn wait_for_job_action() -> ActionDefinition {
    ActionDefinition {
        name: "wait_for_beanstalkd_job".to_string(),
        description: "There is no job for this reserve yet: keep the worker waiting. For \
                      reserve-with-timeout NetGet answers TIMED_OUT when the worker's timeout \
                      runs out; a plain reserve waits until a job is sent to this connection \
                      (e.g. from the dashboard) or the worker hangs up."
            .to_string(),
        parameters: vec![],
        example: json!({"type": "wait_for_beanstalkd_job"}),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> beanstalkd worker keeps waiting")
                .with_debug("beanstalkd wait_for_beanstalkd_job"),
        ),
    }
}

fn found_job_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_beanstalkd_found".to_string(),
        description: "Answer a peek with the job: NetGet writes FOUND <job_id> <bytes> and the \
                      body. For no such job, use send_beanstalkd_status with NOT_FOUND."
            .to_string(),
        parameters: vec![
            param("job_id", "number", "The job's id, a positive integer", true),
            param("body", "string", "The job's payload as text", true),
        ],
        example: json!({
            "type": "send_beanstalkd_found",
            "job_id": 1,
            "body": "<the job's text, word for word>"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> beanstalkd FOUND {job_id}")
                .with_debug("beanstalkd send_beanstalkd_found: job_id={job_id}"),
        ),
    }
}

fn status_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_beanstalkd_status".to_string(),
        description: "Answer with one status word. delete -> DELETED; release -> RELEASED (or \
                      BURIED); bury -> BURIED; touch -> TOUCHED; kick-job -> KICKED; kick -> \
                      KICKED with count; pause-tube -> PAUSED; any job/tube that does not exist \
                      -> NOT_FOUND; reserve-with-timeout with no job -> TIMED_OUT; put while \
                      draining -> DRAINING. OUT_OF_MEMORY / INTERNAL_ERROR answer anything."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "status".to_string(),
                type_hint: "string".to_string(),
                description: "The reply word; it must be one that answers the command (see above)"
                    .to_string(),
                required: true,
            }
            .with_choices(wire::STATUS_WORDS.iter().copied()),
            param(
                "count",
                "number",
                "Only with KICKED answering kick: how many jobs were kicked",
                false,
            ),
        ],
        example: json!({"type": "send_beanstalkd_status", "status": "DELETED"}),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> beanstalkd {status}")
                .with_debug("beanstalkd send_beanstalkd_status: status={status}"),
        ),
    }
}

fn stats_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_beanstalkd_stats".to_string(),
        description: "Answer stats, stats-tube or stats-job with a flat report. NetGet renders \
                      it as the YAML dictionary beanstalkd sends (OK <bytes> then ---). Use \
                      beanstalkd's own stat names (the event's answer_with lists them) with \
                      the figures your instructions give; the example's figures are \
                      placeholders, never data."
            .to_string(),
        parameters: vec![param(
            "stats",
            "object",
            "Object of stat name -> number or string: current-jobs-ready, \
             current-jobs-reserved, current-jobs-delayed, current-jobs-buried, total-jobs, \
             version, ...",
            true,
        )],
        example: json!({
            "type": "send_beanstalkd_stats",
            "stats": {"current-jobs-ready": 0, "current-jobs-delayed": 0, "version": "0.0"}
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> beanstalkd stats")
                .with_debug("beanstalkd send_beanstalkd_stats"),
        ),
    }
}

fn tubes_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_beanstalkd_tubes".to_string(),
        description: "Answer list-tubes with the tubes that exist. NetGet renders the YAML \
                      list (OK <bytes> then ---)."
            .to_string(),
        parameters: vec![param(
            "tubes",
            "array",
            "Array of tube names (letters, digits and -+/;.$_(), at most 200 bytes)",
            true,
        )],
        example: json!({"type": "send_beanstalkd_tubes", "tubes": ["default", "images"]}),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> beanstalkd tube list")
                .with_debug("beanstalkd send_beanstalkd_tubes"),
        ),
    }
}

fn close_connection_action() -> ActionDefinition {
    ActionDefinition {
        name: "close_connection".to_string(),
        description: "Close the beanstalkd connection after any reply".to_string(),
        parameters: vec![],
        example: json!({"type": "close_connection"}),
        log_template: Some(
            LogTemplate::new()
                .with_info("beanstalkd connection closed")
                .with_debug("beanstalkd close_connection"),
        ),
    }
}

/// The `answer_with` field of `beanstalkd_reserve`.
///
/// `reserve_beanstalkd_job`'s example body used to be `{"image": 7, "width": 640}`. Told "the
/// images tube holds one waiting job, number 7, whose text is: resize photo.jpg to 640 wide",
/// llama3.1:8b handed out job 7 with that example body, five runs in five - the example's 7
/// and 640 matched the instruction closely enough to pass for it. The example is now a
/// placeholder, and the request says where the body comes from.
pub fn reserve_answer_with(tubes: &[String]) -> String {
    format!(
        "reserve_beanstalkd_job with the id of a job your instructions say is waiting in one \
         of the tubes this worker watches ({}), and as its body that job's text exactly as \
         your instructions give it, word for word. wait_for_beanstalkd_job when your \
         instructions give no waiting job in those tubes",
        tubes.join(", ")
    )
}

/// The `answer_with` field of `beanstalkd_stats`: the action, and beanstalkd's own stat names
/// for the scope.
///
/// Told "5 ready jobs and 2 buried jobs, running version 1.13", llama3.1:8b answered `stats`
/// with the example's own names - `current-jobs-ready`, `current-jobs-reserved`, `total-jobs`,
/// `version` - putting the 2 buried jobs under `current-jobs-reserved` because the example had
/// no `current-jobs-buried` to put them in, five runs in five. The request now carries the
/// names beanstalkd itself reports for the scope, so the model can find the one each figure
/// belongs to.
pub fn stats_answer_with(scope: &str) -> String {
    let names = match scope {
        "tubes" => {
            return "send_beanstalkd_tubes with every tube your instructions say exists \
                    (default always does)"
                .to_string()
        }
        "job" => {
            "id, tube, state (ready, delayed, reserved or buried), pri, age, delay, ttr, \
                  time-left, reserves, timeouts, releases, buries, kicks"
        }
        "tube" => {
            "name, current-jobs-urgent, current-jobs-ready, current-jobs-reserved, \
                   current-jobs-delayed, current-jobs-buried, total-jobs, current-using, \
                   current-waiting, current-watching, pause"
        }
        _ => {
            "current-jobs-urgent, current-jobs-ready, current-jobs-reserved, \
              current-jobs-delayed, current-jobs-buried, total-jobs, current-tubes, \
              current-connections, current-workers, uptime, version"
        }
    };
    format!(
        "send_beanstalkd_stats whose stats object uses beanstalkd's own names for this scope - \
         {names} - with every figure your instructions give put under the name it belongs to \
         (buried jobs under current-jobs-buried, ready jobs under current-jobs-ready, and so \
         on). Send NOT_FOUND with send_beanstalkd_status for a tube or job that does not exist"
    )
}

/// `put <pri> <delay> <ttr> <bytes>` with its body.
pub static BEANSTALKD_PUT_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "beanstalkd_put",
        "A producer put a job into a tube. Accept it with insert_beanstalkd_job and a job id \
         you choose (ids are positive and should not repeat), or refuse with DRAINING.",
        json!({"type": "insert_beanstalkd_job", "job_id": 17}),
    )
    .with_parameters(vec![
        param("tube", "string", "The tube the connection is using", true),
        param("priority", "number", "0 is most urgent", true),
        param(
            "delay",
            "number",
            "Seconds before the job becomes ready",
            true,
        ),
        param("ttr", "number", "Seconds a worker may hold the job", true),
        param(
            "body",
            "string",
            "The job's payload as text (invalid UTF-8 replaced)",
            true,
        ),
        param(
            "body_bytes",
            "number",
            "The payload's length in bytes",
            true,
        ),
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("beanstalkd put into {tube} ({body_bytes} bytes)")
            .with_debug("beanstalkd beanstalkd_put: tube={tube} priority={priority}"),
    )
    .with_actions(vec![
        insert_job_action(),
        status_action(),
        close_connection_action(),
    ])
    .with_alternative_example(json!({"type": "send_beanstalkd_status", "status": "DRAINING"}))
});

/// `reserve` / `reserve-with-timeout <seconds>`
pub static BEANSTALKD_RESERVE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "beanstalkd_reserve",
        "A worker wants a job from one of the tubes it watches. Hand one out with \
         reserve_beanstalkd_job, or keep it waiting with wait_for_beanstalkd_job when there is \
         none (NetGet answers TIMED_OUT itself when timeout_secs runs out).",
        json!({
            "type": "reserve_beanstalkd_job",
            "job_id": 1,
            "body": "<the job's text, word for word>"
        }),
    )
    .with_parameters(vec![
        param("tubes", "array", "The tubes this worker watches", true),
        param(
            "answer_with",
            "string",
            "Which answer this reserve takes: the waiting job your instructions give, with \
             its id and its text word for word, or wait_for_beanstalkd_job when there is none",
            true,
        ),
        param(
            "timeout_secs",
            "number",
            "Present for reserve-with-timeout: how long the worker will wait",
            false,
        ),
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("beanstalkd reserve from {tubes}")
            .with_debug("beanstalkd beanstalkd_reserve: tubes={tubes}"),
    )
    .with_actions(vec![
        reserve_job_action(),
        wait_for_job_action(),
        status_action(),
        close_connection_action(),
    ])
    .with_alternative_example(json!({"type": "wait_for_beanstalkd_job"}))
});

/// Every command about one job, or about the used tube's jobs.
pub static BEANSTALKD_JOB_COMMAND_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "beanstalkd_job_command",
        "A client sent a command about a job or tube: delete, release, bury, touch, kick-job, \
         reserve-job, peek, peek-ready, peek-delayed, peek-buried, kick or pause-tube. Answer \
         with send_beanstalkd_status (DELETED, RELEASED, BURIED, TOUCHED, KICKED, PAUSED or \
         NOT_FOUND), send_beanstalkd_found for a peek, or reserve_beanstalkd_job for \
         reserve-job.",
        json!({"type": "send_beanstalkd_status", "status": "DELETED"}),
    )
    .with_parameters(vec![
        Parameter {
            name: "command".to_string(),
            type_hint: "string".to_string(),
            description: "Which beanstalkd command the client sent; it decides which answer fits"
                .to_string(),
            required: true,
        }
        .with_choices([
            "delete",
            "release",
            "bury",
            "touch",
            "kick-job",
            "reserve-job",
            "peek",
            "peek-ready",
            "peek-delayed",
            "peek-buried",
            "kick",
            "pause-tube",
        ]),
        param(
            "job_id",
            "number",
            "The job the command names (absent for peek-ready/-delayed/-buried, kick and \
             pause-tube)",
            false,
        ),
        param(
            "tube",
            "string",
            "The tube in use, or the tube pause-tube names",
            true,
        ),
        param(
            "priority",
            "number",
            "release and bury: the new priority",
            false,
        ),
        param(
            "delay",
            "number",
            "release: the new delay; pause-tube: seconds to pause",
            false,
        ),
        param("bound", "number", "kick: at most this many jobs", false),
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("beanstalkd {command} {job_id}")
            .with_debug("beanstalkd beanstalkd_job_command: command={command} job_id={job_id}"),
    )
    .with_actions(vec![
        status_action(),
        found_job_action(),
        reserve_job_action(),
        close_connection_action(),
    ])
    .with_alternative_example(json!({"type": "send_beanstalkd_status", "status": "NOT_FOUND"}))
});

/// `stats`, `stats-tube <tube>`, `stats-job <id>`, `list-tubes`
pub static BEANSTALKD_STATS_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "beanstalkd_stats",
        "A client asked about the queue. scope 'server' (stats), 'tube' (stats-tube), 'job' \
         (stats-job) -> send_beanstalkd_stats, or NOT_FOUND for an unknown tube/job; scope \
         'tubes' (list-tubes) -> send_beanstalkd_tubes.",
        json!({
            "type": "send_beanstalkd_stats",
            "stats": {"current-jobs-ready": 0, "current-jobs-delayed": 0, "version": "0.0"}
        }),
    )
    .with_parameters(vec![
        param(
            "answer_with",
            "string",
            "Which answer this request takes, with beanstalkd's own stat names for its scope",
            true,
        ),
        Parameter {
            name: "scope".to_string(),
            type_hint: "string".to_string(),
            description: "What the client asked about: the whole server, one tube, one job, or \
                          the list of tubes"
                .to_string(),
            required: true,
        }
        .with_choices(["server", "tube", "job", "tubes"]),
        param("tube", "string", "scope 'tube': the tube", false),
        param("job_id", "number", "scope 'job': the job", false),
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("beanstalkd stats {scope}")
            .with_debug("beanstalkd beanstalkd_stats: scope={scope}"),
    )
    .with_actions(vec![
        stats_action(),
        tubes_action(),
        status_action(),
        close_connection_action(),
    ])
    .with_alternative_example(json!({"type": "send_beanstalkd_tubes", "tubes": ["default"]}))
});
