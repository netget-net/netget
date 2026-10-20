//! Draining the feedback buffer — the other half of `provide_feedback`.
//!
//! `provide_feedback` accumulates entries on the owning server or client
//! (`AppState::add_server_feedback` / `add_client_feedback`) and
//! `call_llm_for_feedback` knows how to turn a batch of them into adjustment actions.
//! Nothing connected the two: the buffer was written and never read, and
//! `call_llm_for_feedback` had no callers at all. The tool was advertised to the model
//! whenever `feedback_instructions` was set, the model could call it, and the result went
//! nowhere — which is worse than not offering the tool, because the model has no way to
//! discover that its report was discarded.
//!
//! This module is the missing drain. It is polled from the same 1-second timer that runs
//! due scheduled tasks (`execute_due_tasks`), because a feedback batch is the same shape of
//! work: timer-driven, LLM-answered, and it adjusts a running instance.
//!
//! Coverage follows that timer exactly — the dashboard (`tui::event_loop`) and non-interactive mode
//! drive it; MCP mode does not run a task timer at all, so neither scheduled tasks nor
//! feedback fire there. That is a pre-existing MCP gap, not a property of this module.
//!
//! # What a feedback answer may do
//!
//! A feedback batch belongs to exactly one instance, runs unattended off a timer, and is told
//! to be conservative. Its vocabulary is therefore [`get_feedback_actions`] — adjustments to
//! *that* instance and nothing else — and the same list is what the prompt advertises, what the
//! response validator accepts and what [`apply_feedback_actions`] executes. Opening, closing
//! or reconnecting instances, closing connections, databases and the model switch are not in
//! it: an automatic loop on server #3 must not be able to stop every server.
//!
//! Every action outside the list, and every action inside it that names another instance or a
//! field that would restart this one, is **refused and recorded as a failure**. The plain
//! executor's "must be handled by caller" arms return `Ok` and do nothing, so anything that
//! fell through to them used to vanish without a trace.

use std::time::Duration;

use serde_json::{json, Value};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::llm::actions::{ActionDefinition, Parameter};
use crate::llm::OllamaClient;
use crate::state::app_state::DueFeedback;
use crate::state::{AppState, ClientId, ServerId};

/// How long an instance is left alone after a feedback batch is taken.
///
/// Leading edge: the first entry after a quiet period is processed at the next tick
/// (within a second), and everything that arrives during a burst is coalesced into the
/// next batch rather than producing an LLM call per entry. A busy server that reports
/// feedback on every request therefore costs at most one model round-trip per window.
pub const FEEDBACK_DEBOUNCE: Duration = Duration::from_secs(30);

/// The one instance a feedback batch is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeedbackTarget {
    Server(ServerId),
    Client(ClientId),
}

impl FeedbackTarget {
    /// The target named by a batch's ids; the server wins if (impossibly) both are set.
    pub fn from_ids(server_id: Option<ServerId>, client_id: Option<ClientId>) -> Option<Self> {
        match (server_id, client_id) {
            (Some(sid), _) => Some(Self::Server(sid)),
            (_, Some(cid)) => Some(Self::Client(cid)),
            _ => None,
        }
    }

    /// `"server"` or `"client"`.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Server(_) => "server",
            Self::Client(_) => "client",
        }
    }

    /// The numeric id.
    pub fn id(&self) -> u32 {
        match self {
            Self::Server(sid) => sid.as_u32(),
            Self::Client(cid) => cid.as_u32(),
        }
    }

    fn server_id(&self) -> Option<ServerId> {
        match self {
            Self::Server(sid) => Some(*sid),
            Self::Client(_) => None,
        }
    }

    fn client_id(&self) -> Option<ClientId> {
        match self {
            Self::Client(cid) => Some(*cid),
            Self::Server(_) => None,
        }
    }

    /// `server #3` / `client #1`, for logs and refusals.
    fn label(&self) -> String {
        format!("{} #{}", self.kind(), self.id())
    }
}

/// The actions a feedback answer for `target` may use.
///
/// Used for the prompt, for the response validator and, by name, for execution, so the three
/// cannot disagree. Definitions are built here rather than taken from `common.rs` because
/// their wording is about *this* instance: the shared ones are written for an operator who
/// can address any instance by id.
pub fn get_feedback_actions(target: FeedbackTarget) -> Vec<ActionDefinition> {
    let kind = target.kind();
    let id = target.id();
    let mut actions = vec![
        ActionDefinition {
            name: "update_instruction".to_string(),
            description: format!(
                "Replace the instruction of the {kind} this prompt is about ({kind} #{id}). The \
                 text you send becomes the WHOLE instruction, so include everything from the \
                 current instruction you want to keep."
            ),
            parameters: vec![Parameter {
                name: "instruction".to_string(),
                type_hint: "string".to_string(),
                description: "Complete new instruction (replaces the current one).".to_string(),
                required: true,
            }],
            example: json!({
                "type": "update_instruction",
                "instruction": "Greet every peer by name, and say goodbye before closing."
            }),
            log_template: None,
        },
        update_instance_action(target),
        ActionDefinition {
            name: "set_memory".to_string(),
            description: format!(
                "Replace this {kind}'s memory with new content. Any existing memory is discarded."
            ),
            parameters: vec![Parameter {
                name: "value".to_string(),
                type_hint: "string".to_string(),
                description: "Complete new memory (replaces the current one).".to_string(),
                required: true,
            }],
            example: json!({"type": "set_memory", "value": "peers_expect_goodbye: true"}),
            log_template: None,
        },
        ActionDefinition {
            name: "append_memory".to_string(),
            description: format!(
                "Add a line to the end of this {kind}'s memory. Existing memory is kept."
            ),
            parameters: vec![Parameter {
                name: "value".to_string(),
                type_hint: "string".to_string(),
                description: "Text to append after a newline.".to_string(),
                required: true,
            }],
            example: json!({"type": "append_memory", "value": "lesson: peers expect a goodbye"}),
            log_template: None,
        },
        ActionDefinition {
            name: "schedule_task".to_string(),
            description: format!(
                "Schedule a task on this {kind} (#{id}): the model is called with the task's \
                 instruction after delay_secs, or every interval_secs when recurring. The task \
                 belongs to this {kind} and ends with it."
            ),
            parameters: vec![
                Parameter {
                    name: "task_id".to_string(),
                    type_hint: "string".to_string(),
                    description: "Name for the task, used to cancel it later.".to_string(),
                    required: true,
                },
                Parameter {
                    name: "recurring".to_string(),
                    type_hint: "boolean".to_string(),
                    description: "true to repeat every interval_secs; false to run once."
                        .to_string(),
                    required: true,
                },
                Parameter {
                    name: "delay_secs".to_string(),
                    type_hint: "number".to_string(),
                    description: "Seconds before the first (or only) run.".to_string(),
                    required: false,
                },
                Parameter {
                    name: "interval_secs".to_string(),
                    type_hint: "number".to_string(),
                    description: "Seconds between runs of a recurring task.".to_string(),
                    required: false,
                },
                Parameter {
                    name: "max_executions".to_string(),
                    type_hint: "number".to_string(),
                    description: "Stop a recurring task after this many runs.".to_string(),
                    required: false,
                },
                Parameter {
                    name: "instruction".to_string(),
                    type_hint: "string".to_string(),
                    description: "What the model should do when the task runs.".to_string(),
                    required: true,
                },
                Parameter {
                    name: "context".to_string(),
                    type_hint: "object".to_string(),
                    description: "Optional data handed to the model with the instruction."
                        .to_string(),
                    required: false,
                },
            ],
            example: json!({
                "type": "schedule_task",
                "task_id": "recheck_timeouts",
                "recurring": false,
                "delay_secs": 300,
                "instruction": "Check whether peers still time out and note it in memory."
            }),
            log_template: None,
        },
        ActionDefinition {
            name: "cancel_task".to_string(),
            description: format!("Cancel a task scheduled on this {kind} (#{id})."),
            parameters: vec![Parameter {
                name: "task_id".to_string(),
                type_hint: "string".to_string(),
                description: "The task_id it was scheduled with.".to_string(),
                required: true,
            }],
            example: json!({"type": "cancel_task", "task_id": "recheck_timeouts"}),
            log_template: None,
        },
        ActionDefinition {
            name: "show_message".to_string(),
            description: "Tell the operator what you changed and why. Not sent to any peer."
                .to_string(),
            parameters: vec![Parameter {
                name: "message".to_string(),
                type_hint: "string".to_string(),
                description: "Message for the operator.".to_string(),
                required: true,
            }],
            example: json!({
                "type": "show_message",
                "message": "Peers kept asking for a goodbye; the instruction now sends one."
            }),
            log_template: None,
        },
    ];
    if matches!(target, FeedbackTarget::Server(_)) {
        actions.push(ActionDefinition {
            name: "append_to_log".to_string(),
            description: "Append a line to one of this server's log files \
                (netget_<output_name>_<time>.log)."
                .to_string(),
            parameters: vec![
                Parameter {
                    name: "output_name".to_string(),
                    type_hint: "string".to_string(),
                    description: "Log name: A-Z, a-z, 0-9, '_' and '-' only (1-64 characters)."
                        .to_string(),
                    required: true,
                },
                Parameter {
                    name: "content".to_string(),
                    type_hint: "string".to_string(),
                    description: "The line to append.".to_string(),
                    required: true,
                },
            ],
            example: json!({
                "type": "append_to_log",
                "output_name": "feedback",
                "content": "instruction now sends a goodbye"
            }),
            log_template: None,
        });
    }
    actions
}

/// `update_server` / `update_client`, pinned to the target and limited to the fields that
/// apply in place.
fn update_instance_action(target: FeedbackTarget) -> ActionDefinition {
    let kind = target.kind();
    let id = target.id();
    let name = format!("update_{kind}");
    let id_param = format!("{kind}_id");
    let mut example = serde_json::Map::new();
    example.insert("type".into(), json!(name));
    example.insert(id_param.clone(), json!(id));
    example.insert(
        "event_handlers".into(),
        json!([
            {"event_pattern": "*", "handler": {"type": "llm", "instruction": "Answer briefly."}}
        ]),
    );
    example.insert("history".into(), json!(10));
    ActionDefinition {
        name,
        description: format!(
            "Change how this {kind} (#{id}) handles events, in place, without dropping \
             connections. Send only the fields you want to change. Its address and startup \
             parameters cannot be changed from here."
        ),
        parameters: vec![
            Parameter {
                name: id_param,
                type_hint: "number".to_string(),
                description: format!("Must be {id}, this {kind}'s id."),
                required: true,
            },
            Parameter {
                name: "event_handlers".to_string(),
                type_hint: "array".to_string(),
                description: format!(
                    "The COMPLETE new handler list; it replaces the current one, so repeat any \
                     current handler you want to keep. Each item is {{\"event_pattern\": \
                     \"<event id>\" or \"*\", \"handler\": {{...}}}}, matched in order, first \
                     match wins. A handler is {{\"type\": \"static\", \"actions\": [...]}} \
                     (fixed actions, no model call), {{\"type\": \"llm\", \"instruction\": \
                     \"...\"}} (the model answers with this instruction) or {{\"type\": \
                     \"manual\"}} (a person answers). An empty list hands every event to this \
                     {kind}'s instruction."
                ),
                required: false,
            },
            Parameter {
                name: "history".to_string(),
                type_hint: "number".to_string(),
                description: "How many earlier exchanges of a connection are shown with each \
                    event; 0 turns history off."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "batching".to_string(),
                type_hint: "boolean".to_string(),
                description: "Deliver events that arrive during a model call together in one \
                    follow-up call. Refused where the protocol cannot batch."
                    .to_string(),
                required: false,
            },
        ],
        example: Value::Object(example),
        log_template: None,
    }
}

/// Fence `text` for a Markdown prompt with a backtick run longer than any inside it, so
/// multi-line content (and content containing a fence) reads back verbatim.
fn fence(text: &str) -> String {
    let mut longest = 0;
    let mut run = 0;
    for c in text.chars() {
        if c == '`' {
            run += 1;
            longest = longest.max(run);
        } else {
            run = 0;
        }
    }
    let ticks = "`".repeat((longest + 1).max(3));
    format!("{ticks}text\n{text}\n{ticks}")
}

/// An event-handler list in the exact shape `update_server`/`update_client` accept.
///
/// `EventPattern` is `#[serde(untagged)]`, so a wildcard serialises as `null`; it is written
/// back as `"*"` here because that is what the model has to send.
fn handlers_as_input(config: Option<&crate::scripting::EventHandlerConfig>) -> Option<String> {
    let handlers = &config?.handlers;
    if handlers.is_empty() {
        return None;
    }
    let list: Vec<Value> = handlers
        .iter()
        .map(|h| {
            let pattern = match &h.event_pattern {
                crate::scripting::EventPattern::Wildcard => "*".to_string(),
                crate::scripting::EventPattern::Specific(id) => id.clone(),
            };
            json!({
                "event_pattern": pattern,
                "handler": serde_json::to_value(&h.handler).unwrap_or(Value::Null),
            })
        })
        .collect();
    serde_json::to_string_pretty(&list).ok()
}

/// What the feedback prompt shows about the instance under review.
///
/// The instruction and memory come from the batch (the snapshot the feedback was taken with);
/// everything else is read live. Each is pre-fenced so the template has no escaping to get
/// wrong. Returns only the instruction and memory when the instance is gone.
pub async fn feedback_instance_view(
    state: &AppState,
    target: Option<FeedbackTarget>,
    instruction: &str,
    memory: &str,
) -> Value {
    let mut view = json!({
        "instruction": fence(instruction),
        "memory": if memory.is_empty() { Value::Null } else { json!(fence(memory)) },
        "kind": null, "id": null, "protocol": null, "address": null, "status": null,
        "event_handlers": null, "history": null, "batching": null,
    });
    let Some(target) = target else {
        return view;
    };
    view["kind"] = json!(target.kind());
    view["id"] = json!(target.id());
    let (protocol, address, status, handlers, history, batching) = match target {
        FeedbackTarget::Server(sid) => match state.get_server(sid).await {
            Some(s) => (
                s.protocol_name,
                match s.local_addr {
                    Some(addr) => format!("listening on {addr}"),
                    None => format!("port {}", s.port),
                },
                s.status.to_string(),
                handlers_as_input(s.event_handler_config.as_ref()),
                s.history_entries,
                s.batching,
            ),
            None => return view,
        },
        FeedbackTarget::Client(cid) => match state.get_client(cid).await {
            Some(c) => (
                c.protocol_name,
                format!("connected to {}", c.remote_addr),
                c.status.to_string(),
                handlers_as_input(c.event_handler_config.as_ref()),
                c.history_entries,
                c.batching,
            ),
            None => return view,
        },
    };
    view["protocol"] = json!(protocol);
    view["address"] = json!(address);
    view["status"] = json!(status);
    view["event_handlers"] = match handlers {
        Some(list) => json!(format!("```json\n{list}\n```")),
        None => Value::Null,
    };
    view["history"] = json!(if history == 0 {
        "off".to_string()
    } else {
        format!("the last {history} exchanges of a connection are shown with each event")
    });
    view["batching"] = json!(if batching { "on" } else { "off" });
    view
}

/// Process every instance whose accumulated feedback is due.
///
/// Each batch is handled in its own task so one slow model call cannot hold up the timer
/// or another instance's feedback.
pub async fn execute_due_feedback(
    state: &AppState,
    llm_client: &OllamaClient,
    status_tx: &mpsc::UnboundedSender<String>,
) {
    let due = state.take_due_feedback(FEEDBACK_DEBOUNCE).await;
    if due.is_empty() {
        return;
    }

    for batch in due {
        let state = state.clone();
        let llm_client = llm_client.clone();
        let status_tx = status_tx.clone();
        tokio::spawn(async move {
            process_feedback_batch(state, llm_client, status_tx, batch).await;
        });
    }
}

/// Run one batch: ask the model what to adjust, then apply it.
async fn process_feedback_batch(
    state: AppState,
    llm_client: OllamaClient,
    status_tx: mpsc::UnboundedSender<String>,
    batch: DueFeedback,
) {
    let Some(target) = FeedbackTarget::from_ids(batch.server_id, batch.client_id) else {
        error!(
            "Feedback batch with neither a server nor a client ({} entries dropped)",
            batch.entries.len()
        );
        return;
    };
    let who = target.label();
    info!(
        "Processing {} feedback entries for {}",
        batch.entries.len(),
        who
    );
    let _ = status_tx.send(format!(
        "[INFO] Processing {} feedback entries for {}",
        batch.entries.len(),
        who
    ));

    let actions = match crate::llm::action_helper::call_llm_for_feedback(
        &llm_client,
        &state,
        batch.server_id,
        batch.client_id,
        &batch.instructions,
        &batch.instruction,
        &batch.memory,
        &batch.entries,
        &status_tx,
    )
    .await
    {
        Ok(actions) => actions,
        Err(e) => {
            // The batch is gone: it was taken out of the buffer under the same lock that
            // stamped the debounce timestamp. Re-queueing it would let one payload the
            // model cannot answer retry forever, so it is dropped — loudly. Feedback is a
            // best-effort signal channel, not a durable queue, and nothing on the wire is
            // waiting on this call.
            error!(
                "Feedback processing failed for {} ({} entries dropped): {}",
                who,
                batch.entries.len(),
                e
            );
            let _ = status_tx.send(format!(
                "[ERROR] Feedback processing failed for {} ({} entries dropped): {}",
                who,
                batch.entries.len(),
                e
            ));
            return;
        }
    };

    if actions.is_empty() {
        debug!("Feedback for {} produced no adjustments", who);
        return;
    }

    apply_feedback_actions(&state, &llm_client, &status_tx, target, actions).await;
}

/// What applying a feedback answer did.
#[derive(Debug, Default, Clone)]
pub struct FeedbackOutcome {
    /// One line per action that took effect.
    pub applied: Vec<String>,
    /// One line per action that was refused or failed, naming the action and why.
    pub failures: Vec<String>,
}

/// Where a single adjustment action has to be executed.
enum Route {
    /// Replace the target's instruction.
    Instruction(String),
    /// `update_server` / `update_client` restricted to in-place fields.
    UpdateServer(crate::cli::management::ServerForm),
    UpdateClient(crate::cli::management::ClientForm),
    /// `schedule_task` with its scope already set to the target.
    Schedule(crate::llm::CommonAction),
    Cancel(String),
    Message(String),
    /// Memory and log actions: the plain executor, with the target's id attached.
    Executor(Value),
    Refused(String),
}

/// Fields of `update_*` that would restart the instance or are owned by another action.
fn forbidden_update_fields(target: FeedbackTarget) -> &'static [(&'static str, &'static str)] {
    const RESTART: &str = "would restart the instance, which feedback may not do";
    const SERVER: &[(&str, &str)] = &[
        ("port", RESTART),
        ("host", RESTART),
        ("interface", RESTART),
        ("mac_address", RESTART),
        ("startup_params", RESTART),
        ("send_first", RESTART),
        ("initial_memory", "use set_memory"),
        ("memory", "use set_memory"),
        ("scheduled_tasks", "use schedule_task"),
        (
            "feedback_instructions",
            "feedback cannot change its own instructions",
        ),
        ("protocol", "the protocol cannot change"),
    ];
    const CLIENT: &[(&str, &str)] = &[
        ("remote_addr", RESTART),
        ("startup_params", RESTART),
        ("initial_memory", "use set_memory"),
        ("memory", "use set_memory"),
        ("scheduled_tasks", "use schedule_task"),
        (
            "feedback_instructions",
            "feedback cannot change its own instructions",
        ),
        ("protocol", "the protocol cannot change"),
    ];
    match target {
        FeedbackTarget::Server(_) => SERVER,
        FeedbackTarget::Client(_) => CLIENT,
    }
}

/// Check an action's `<kind>_id` against the target, filling it in when omitted.
fn pin_id(action: &mut Value, field: &str, target_id: u32, label: &str) -> Result<(), String> {
    match action.get(field) {
        None | Some(Value::Null) => {
            action[field] = json!(target_id);
            Ok(())
        }
        Some(v) => {
            let given = v
                .as_u64()
                .or_else(|| v.as_str().and_then(|s| s.trim().parse().ok()));
            if given == Some(u64::from(target_id)) {
                action[field] = json!(target_id);
                Ok(())
            } else {
                Err(format!(
                    "{field} {v} is not {label}; feedback can only adjust the instance it is about"
                ))
            }
        }
    }
}

/// Decide how one action must be applied, or refuse it.
fn route(mut action: Value, target: FeedbackTarget) -> Route {
    use crate::llm::CommonAction;

    let label = target.label();
    let Some(name) = action
        .get("type")
        .and_then(Value::as_str)
        .map(str::to_owned)
    else {
        return Route::Refused("action has no type".to_string());
    };
    let offered = get_feedback_actions(target).iter().any(|a| a.name == name);
    if !offered {
        return Route::Refused(format!(
            "'{name}' is not a feedback adjustment for {label}; feedback may only use: {}",
            get_feedback_actions(target)
                .iter()
                .map(|a| a.name.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }

    match name.as_str() {
        "update_server" | "update_client" => {
            let id_field = format!("{}_id", target.kind());
            if let Err(e) = pin_id(&mut action, &id_field, target.id(), &label) {
                return Route::Refused(e);
            }
            let present: Vec<String> = forbidden_update_fields(target)
                .iter()
                .filter(|(f, _)| {
                    action
                        .get(*f)
                        .is_some_and(|v| !v.is_null() && *v != Value::Bool(false))
                })
                .map(|(f, why)| format!("{f} ({why})"))
                .collect();
            if !present.is_empty() {
                return Route::Refused(format!(
                    "{name} refused, nothing applied: {}",
                    present.join(", ")
                ));
            }
            match CommonAction::from_json(&action) {
                Ok(CommonAction::UpdateServer {
                    instruction,
                    event_handlers,
                    history,
                    batching,
                    ..
                }) => {
                    if instruction.is_none()
                        && event_handlers.is_none()
                        && history.is_none()
                        && batching.is_none()
                    {
                        return Route::Refused(format!("{name} named nothing to change"));
                    }
                    Route::UpdateServer(crate::cli::management::ServerForm {
                        instruction,
                        event_handlers,
                        history,
                        batching,
                        ..Default::default()
                    })
                }
                Ok(CommonAction::UpdateClient {
                    instruction,
                    event_handlers,
                    history,
                    batching,
                    ..
                }) => {
                    if instruction.is_none()
                        && event_handlers.is_none()
                        && history.is_none()
                        && batching.is_none()
                    {
                        return Route::Refused(format!("{name} named nothing to change"));
                    }
                    Route::UpdateClient(crate::cli::management::ClientForm {
                        instruction,
                        event_handlers,
                        history,
                        batching,
                        ..Default::default()
                    })
                }
                Ok(_) => Route::Refused(format!("{name} did not parse as {name}")),
                Err(e) => Route::Refused(format!("{name} is malformed: {e}")),
            }
        }
        "update_instruction" => match CommonAction::from_json(&action) {
            Ok(CommonAction::UpdateInstruction { instruction }) => Route::Instruction(instruction),
            Ok(_) => Route::Refused("update_instruction did not parse".to_string()),
            Err(e) => Route::Refused(format!("update_instruction is malformed: {e}")),
        },
        "schedule_task" => {
            if action.get("connection_id").is_some_and(|v| !v.is_null()) {
                return Route::Refused(
                    "schedule_task refused: feedback tasks belong to the whole instance, not \
                     one connection"
                        .to_string(),
                );
            }
            for script in ["script_inline", "script_path", "script_runtime"] {
                if action.get(script).is_some_and(|v| !v.is_null()) {
                    return Route::Refused(format!(
                        "schedule_task refused: {script} is not supported for feedback tasks"
                    ));
                }
            }
            let (own, other) = match target {
                FeedbackTarget::Server(_) => ("server_id", "client_id"),
                FeedbackTarget::Client(_) => ("client_id", "server_id"),
            };
            if action.get(other).is_some_and(|v| !v.is_null()) {
                return Route::Refused(format!(
                    "schedule_task refused: {other} names another instance than {label}"
                ));
            }
            if let Err(e) = pin_id(&mut action, own, target.id(), &label) {
                return Route::Refused(format!("schedule_task refused: {e}"));
            }
            match CommonAction::from_json(&action) {
                Ok(task @ CommonAction::ScheduleTask { .. }) => Route::Schedule(task),
                Ok(_) => Route::Refused("schedule_task did not parse".to_string()),
                Err(e) => Route::Refused(format!("schedule_task is malformed: {e}")),
            }
        }
        "cancel_task" => match CommonAction::from_json(&action) {
            Ok(CommonAction::CancelTask { task_id }) => Route::Cancel(task_id),
            Ok(_) => Route::Refused("cancel_task did not parse".to_string()),
            Err(e) => Route::Refused(format!("cancel_task is malformed: {e}")),
        },
        "show_message" => match CommonAction::from_json(&action) {
            Ok(CommonAction::ShowMessage { message }) => Route::Message(message),
            Ok(_) => Route::Refused("show_message did not parse".to_string()),
            Err(e) => Route::Refused(format!("show_message is malformed: {e}")),
        },
        // set_memory, append_memory and (server only) append_to_log.
        _ => Route::Executor(action),
    }
}

/// Whether a scheduled task belongs to the target.
fn task_belongs_to(scope: &crate::state::task::TaskScope, target: FeedbackTarget) -> bool {
    use crate::state::task::TaskScope;
    match (scope, target) {
        (TaskScope::Server(sid), FeedbackTarget::Server(t)) => *sid == t,
        (TaskScope::Connection(sid, _), FeedbackTarget::Server(t)) => *sid == t,
        (TaskScope::Client(cid), FeedbackTarget::Client(t)) => *cid == t,
        _ => false,
    }
}

/// Apply the adjustment actions the model returned, in order, to `target` only.
///
/// Every action that is refused or fails is recorded in the outcome and reported as a
/// `[WARN] Feedback adjustment for … failed` line, so nothing the model asked for disappears
/// silently.
pub async fn apply_feedback_actions(
    state: &AppState,
    llm_client: &OllamaClient,
    status_tx: &mpsc::UnboundedSender<String>,
    target: FeedbackTarget,
    actions: Vec<Value>,
) -> FeedbackOutcome {
    let who = target.label();
    let mut outcome = FeedbackOutcome::default();

    for action in actions {
        let name = action
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or("<untyped>")
            .to_string();
        match route(action, target) {
            Route::Refused(reason) => {
                outcome.failures.push(format!("{name}: {reason}"));
            }
            Route::Instruction(instruction) => {
                match target {
                    FeedbackTarget::Server(sid) => {
                        state.set_instruction(sid, instruction.clone()).await
                    }
                    FeedbackTarget::Client(cid) => {
                        state
                            .set_instruction_for_client(cid, instruction.clone())
                            .await
                    }
                }
                info!("Feedback updated the instruction for {}", who);
                let _ = status_tx.send(format!(
                    "[INFO] Feedback updated the instruction for {}: {}",
                    who,
                    crate::utils::truncate_for_log(&instruction, 120)
                ));
                outcome
                    .applied
                    .push(format!("{name}: instruction replaced"));
            }
            Route::UpdateServer(form) => {
                let sid = target.server_id().expect("routed only for a server target");
                match crate::cli::management::update_server(state, sid, form, status_tx.clone())
                    .await
                {
                    Ok(update) => {
                        let _ = status_tx.send(format!("[INFO] Feedback: {}", update.summary));
                        outcome.applied.push(format!("{name}: {}", update.summary));
                    }
                    Err(e) => outcome.failures.push(format!("{name}: {e}")),
                }
            }
            Route::UpdateClient(form) => {
                let cid = target.client_id().expect("routed only for a client target");
                match crate::cli::management::update_client(
                    state,
                    cid,
                    form,
                    llm_client.clone(),
                    status_tx.clone(),
                )
                .await
                {
                    Ok(update) => {
                        let _ = status_tx.send(format!("[INFO] Feedback: {}", update.summary));
                        outcome.applied.push(format!("{name}: {}", update.summary));
                    }
                    Err(e) => outcome.failures.push(format!("{name}: {e}")),
                }
            }
            Route::Schedule(task) => {
                let mut handler =
                    crate::events::EventHandler::new(state.clone(), llm_client.clone());
                match handler
                    .execute_server_management_action(task, status_tx)
                    .await
                {
                    Ok(()) => outcome.applied.push(format!("{name}: scheduled")),
                    Err(e) => outcome.failures.push(format!("{name}: {e}")),
                }
            }
            Route::Cancel(task_id) => match state.get_task(&task_id).await {
                Some(task) if task_belongs_to(&task.scope, target) => {
                    state.remove_task(task.id).await;
                    let _ = status_tx.send(format!(
                        "[TASK] Feedback cancelled task '{}' on {}",
                        task_id, who
                    ));
                    outcome
                        .applied
                        .push(format!("{name}: '{task_id}' cancelled"));
                }
                Some(_) => outcome
                    .failures
                    .push(format!("{name}: task '{task_id}' does not belong to {who}")),
                None => outcome
                    .failures
                    .push(format!("{name}: no task named '{task_id}'")),
            },
            Route::Message(message) => {
                info!("Feedback for {}: {}", who, message);
                let _ = status_tx.send(format!("[INFO] Feedback for {}: {}", who, message));
                outcome.applied.push(format!("{name}: shown"));
            }
            Route::Executor(value) => {
                match crate::llm::execute_actions(
                    vec![value],
                    state,
                    None,
                    target.server_id(),
                    target.client_id(),
                )
                .await
                {
                    Ok(result) => {
                        let failed = result.failure_summary();
                        for msg in result.messages {
                            let _ = status_tx.send(msg);
                        }
                        match failed {
                            Some(summary) => outcome.failures.push(format!("{name}: {summary}")),
                            None => outcome.applied.push(name),
                        }
                    }
                    Err(e) => outcome.failures.push(format!("{name}: {e}")),
                }
            }
        }
    }

    if !outcome.failures.is_empty() {
        let how = if outcome.applied.is_empty() {
            "failed"
        } else {
            "partly failed"
        };
        let summary = outcome.failures.join("; ");
        warn!("Feedback adjustment for {} {}: {}", who, how, summary);
        let _ = status_tx.send(format!(
            "[WARN] Feedback adjustment for {} {}: {}",
            who, how, summary
        ));
    }
    outcome
}
