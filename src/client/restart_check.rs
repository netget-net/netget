//! Asking before a client starts its instruction over.
//!
//! A client's instruction is usually a script — "send PING, then GET mykey, then stop" — and
//! the model is asked again on every reply. A small model reads each reply as the cue to run
//! the script from the top: measured with llama3.1:8b (31 October and 6 November 2026), a
//! redis client given that instruction answered the reply to PING with PING and GET again, and
//! the reply to those with the same, with both commands listed as already sent in the history
//! directly above the reply. No wording of the history or the system prompt stopped it.
//!
//! What the model cannot be relied on to notice, NetGet can: a restart is an answer to an
//! event that begins where the session began. The client's **opening** is what its first model
//! answer put on the wire, and the restarts measured all start with it — the whole of it
//! (`PING; GET mykey` again) or its first steps (`PING` alone, reply after reply). So:
//!
//! - The opening is recorded from the first model answer of the session that sent anything
//!   (`wait_for_more` sends nothing and does not count). A new instruction starts a new one.
//! - When a later model answer to an event begins with the opening's first action — and then
//!   as many more of its actions, in order, as it repeats — NetGet does not send it yet. It
//!   asks the model one narrow question — the instruction, what was sent at the start, what
//!   just arrived, and the repeat — offering exactly two answers, [`SKIP_REPEAT`] and
//!   [`SEND_AGAIN`]. The question is a model call, debited from the client's budget.
//! - [`SEND_AGAIN`] must name its `trigger`: the word in the latest message that the
//!   instruction says to repeat on (`AGAIN` for "each time the server answers AGAIN, send PING
//!   again"). NetGet checks it rather than the model's say-so: the trigger has to appear, as
//!   whole words, in the instruction *and* in the message's values. Then the answer is sent as
//!   it was. A yes/no question alone was measured not to be enough — llama3.1:8b said "send
//!   again" to a PONG after "Send PING, then GET mykey, then stop".
//! - [`SKIP_REPEAT`], or a [`SEND_AGAIN`] whose trigger is not in both, drops the repeated
//!   actions and sends whatever followed them in the answer. When nothing follows them — the
//!   whole answer was the restart — the model is asked once more for the same event, told
//!   which steps are done ([`continue_instruction`]), and its answer is sent with any restart
//!   at its front dropped unasked. That is what keeps a conversation going: the model has not
//!   answered the message yet, it has only repeated itself.
//! - Anything else — the question failing, an unreadable answer, the budget spent — sends the
//!   answer as it was: a check that cannot be asked changes nothing.
//!
//! Nothing here knows a protocol: the comparison is JSON equality of the actions the client's
//! own model produced. An answer whose first action differs in any field from the opening's
//! (`"ping"` for `"PING"`), or that repeats a later step of the opening without its first
//! (`GET mykey` alone), is not a restart and is never asked about: answering a reply with one
//! of the things already done is what a conversation does, starting from the top is not.
//!
//! So a repeat survives when the instruction names what calls for it and the message carries
//! that — a polling loop, "on AGAIN send PING". A repeat the instruction does not ask for, a
//! retry the model decided on by itself after an error included, is dropped; turn the check
//! off for a client whose instruction relies on that.
//!
//! On by default; `restart_check: false` on a client (`ClientForm`, `open_client`, MCP
//! `start_client` / `update_client`) turns it off.

use anyhow::Result;
use serde_json::{json, Value};
use tokio::sync::mpsc;

use crate::llm::actions::ActionDefinition;
use crate::llm::ollama_client::OllamaClient;
use crate::logging::emit::Log;
use crate::protocol::Event;
use crate::state::app_state::AppState;
use crate::state::ClientId;

/// The event id the question is asked under (`Event: client_restart_check`), so a mock can
/// answer it and a reader of the conversation log can find it.
pub const RESTART_CHECK_EVENT: &str = "client_restart_check";

/// The answer that sends the repeat as the model first wrote it.
pub const SEND_AGAIN: &str = "send_again";

/// The answer that drops the repeated opening and sends what followed it.
pub const SKIP_REPEAT: &str = "skip_repeat";

/// An action that puts nothing on the wire, so it is neither part of an opening nor of a
/// repeat of one.
fn sends_nothing(action: &Value) -> bool {
    matches!(
        action.get("type").and_then(Value::as_str),
        None | Some("wait_for_more")
    )
}

/// The opening a model answer establishes: the actions in it that send something, or `None`
/// when it sends nothing (the opening is then still to come).
pub fn opening_of(actions: &[Value]) -> Option<Vec<Value>> {
    let sent: Vec<Value> = actions
        .iter()
        .filter(|a| !sends_nothing(a))
        .cloned()
        .collect();
    (!sent.is_empty()).then_some(sent)
}

/// How many of the actions that send something `answer` begins with are the opening's own
/// first actions, in order: `0` when the answer does not start the opening over.
pub fn repeated_opening_len(opening: &[Value], answer: &[Value]) -> usize {
    answer
        .iter()
        .filter(|a| !sends_nothing(a))
        .zip(opening)
        .take_while(|(a, b)| a == b)
        .count()
}

/// `answer` without the first `repeated` actions that send something; everything else, in
/// order.
pub fn without_repeated(repeated: usize, answer: Vec<Value>) -> Vec<Value> {
    let mut to_drop = repeated;
    answer
        .into_iter()
        .filter(|action| {
            if to_drop > 0 && !sends_nothing(action) {
                to_drop -= 1;
                false
            } else {
                true
            }
        })
        .collect()
}

fn send_again_action() -> ActionDefinition {
    ActionDefinition {
        name: SEND_AGAIN.to_string(),
        description: "Send them again: the instruction says to repeat them when the server \
            sends something, and the latest message is that something (\"each time the server \
            answers AGAIN, send PING again\" and the latest message is AGAIN)."
            .to_string(),
        parameters: vec![crate::llm::actions::Parameter {
            name: "trigger".to_string(),
            type_hint: "string".to_string(),
            description: "The word or phrase, copied exactly, that appears both in the \
                instruction and in the latest message and makes this repeat due (AGAIN, in \
                the example). If no such word exists, the repeat is not due: answer \
                skip_repeat."
                .to_string(),
            required: true,
        }],
        example: json!({"type": SEND_AGAIN, "trigger": "AGAIN"}),
        log_template: None,
    }
}

fn skip_repeat_action() -> ActionDefinition {
    ActionDefinition {
        name: SKIP_REPEAT.to_string(),
        description: "Do not send them again: they were steps of the instruction, done once \
            already, and nothing in this message calls for doing them again."
            .to_string(),
        parameters: vec![],
        example: json!({"type": SKIP_REPEAT}),
        log_template: None,
    }
}

/// `execute_redis_command {"command":"PING"}` — how an action is named in the question.
fn describe(action: &Value) -> String {
    let name = action
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or("action");
    let rest: serde_json::Map<String, Value> = action
        .as_object()
        .map(|fields| {
            fields
                .iter()
                .filter(|(k, _)| k.as_str() != "type")
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect()
        })
        .unwrap_or_default();
    if rest.is_empty() {
        name.to_string()
    } else {
        format!("{} {}", name, Value::Object(rest))
    }
}

/// What [`check_answer`] decided.
#[derive(Debug, Clone, PartialEq)]
pub struct Checked {
    /// The actions to send.
    pub actions: Vec<Value>,
    /// The repeated steps, described, when the repeat was dropped; `None` when the answer
    /// stands as the model wrote it.
    pub refused: Option<String>,
}

impl Checked {
    fn stands(actions: Vec<Value>) -> Self {
        Self {
            actions,
            refused: None,
        }
    }

    /// Whether the repeat was dropped and nothing that sends anything is left: the model's
    /// whole answer was the restart, so it has not yet answered the message at all.
    pub fn left_nothing(&self) -> bool {
        self.refused.is_some() && opening_of(&self.actions).is_none()
    }
}

/// The instruction for asking again, once, after a refused restart left nothing to send.
///
/// Without it a conversation stalls: measured with llama3.1:8b, a telnet client told to say
/// hello and then answer each question answered the first question with "hello" again; with
/// the repeat dropped and nothing else in the answer, the client said nothing and the server
/// waited for an answer that never came.
pub fn continue_instruction(instruction: &str, refused: &str) -> String {
    format!(
        "{instruction}\n\nAlready done earlier in this session, and not to be sent again: \
         {refused}. Answer the latest message with what your instruction calls for next; if \
         nothing is left to do, answer with no actions."
    )
}

/// `actions` without a restart at its front, decided without asking: for the answer to
/// [`continue_instruction`], where the model has already been told those steps are done.
pub async fn strip_restart(
    state: &AppState,
    client_id: ClientId,
    actions: Vec<Value>,
) -> Vec<Value> {
    match state.client_restart_opening(client_id).await {
        Some(opening) => without_repeated(repeated_opening_len(&opening, &actions), actions),
        None => actions,
    }
}

/// Check `answer`, the model's answer to `event`, against the client's opening, asking the
/// model when it starts the instruction over.
#[allow(clippy::too_many_arguments)]
pub async fn check_answer(
    llm_client: &OllamaClient,
    state: &AppState,
    client_id: ClientId,
    protocol_name: &str,
    instruction: &str,
    event: &Event,
    answer: Vec<Value>,
    private_payloads: bool,
    status_tx: &mpsc::UnboundedSender<String>,
) -> Checked {
    let Some(opening) = state.client_restart_opening(client_id).await else {
        return Checked::stands(answer);
    };
    let n = repeated_opening_len(&opening, &answer);
    if n == 0 {
        return Checked::stands(answer);
    }
    let repeated = opening[..n]
        .iter()
        .map(describe)
        .collect::<Vec<_>>()
        .join("; ");
    let log = Log::to(status_tx);
    if let Err(msg) = state.try_consume_client_llm_call(client_id).await {
        log.warn(format!(
            "client {} repeats its opening ({}) in answer to {}; not asking whether that is \
             meant, and sending it: {}",
            client_id,
            if private_payloads { "…" } else { &repeated },
            event.id(),
            msg
        ));
        return Checked::stands(answer);
    }
    match ask(
        llm_client,
        state,
        client_id,
        protocol_name,
        instruction,
        &opening,
        n,
        event,
        private_payloads,
        status_tx,
    )
    .await
    {
        Ok(Verdict::Due(trigger)) => {
            log.info(format!(
                "client {} repeats its opening in answer to {}; the instruction and the \
                 message share the trigger {:?}, so it is sent",
                client_id,
                event.id(),
                if private_payloads {
                    "…"
                } else {
                    trigger.as_str()
                }
            ));
            Checked::stands(answer)
        }
        Ok(Verdict::Unfounded(trigger)) => {
            log.info(format!(
                "client {} answered {} by starting its instruction over ({}); the model said \
                 to send it again but its trigger {:?} is not in both the instruction and the \
                 message, so the repeat is not sent",
                client_id,
                event.id(),
                if private_payloads { "…" } else { &repeated },
                if private_payloads {
                    "…"
                } else {
                    trigger.as_str()
                }
            ));
            Checked {
                actions: without_repeated(n, answer),
                refused: Some(repeated),
            }
        }
        Ok(Verdict::Done) => {
            log.info(format!(
                "client {} answered {} by starting its instruction over ({}); the model \
                 confirms those steps are done, so the repeat is not sent",
                client_id,
                event.id(),
                if private_payloads { "…" } else { &repeated }
            ));
            Checked {
                actions: without_repeated(n, answer),
                refused: Some(repeated),
            }
        }
        Err(e) => {
            let e = if private_payloads {
                crate::utils::redact::hide_error_details(e)
            } else {
                e
            };
            log.warn(format!(
                "client {} repeats its opening in answer to {}; asking whether that is meant \
                 failed, so it is sent: {}",
                client_id,
                event.id(),
                e
            ));
            Checked::stands(answer)
        }
    }
}

/// The question, and the model's answer to it checked against the instruction and the
/// message.
#[allow(clippy::too_many_arguments)]
async fn ask(
    llm_client: &OllamaClient,
    state: &AppState,
    client_id: ClientId,
    protocol_name: &str,
    instruction: &str,
    opening: &[Value],
    repeated: usize,
    event: &Event,
    private_payloads: bool,
    status_tx: &mpsc::UnboundedSender<String>,
) -> Result<Verdict> {
    let actions = vec![skip_repeat_action(), send_again_action()];
    let system_prompt = format!(
        "You check one answer of a network client ({}) before it is sent.\n\
         The client's instruction: {}\n\n\
         # Response Format\n\
         Return ONE JSON object {{\"actions\": [ ... ]}} holding exactly one action, `{}` or \
         `{}`. JSON only — no prose, no code fences.\n\n\
         # Available actions\n{}",
        protocol_name,
        instruction,
        SKIP_REPEAT,
        SEND_AGAIN,
        actions
            .iter()
            .map(|a| a.to_prompt_text())
            .collect::<Vec<_>>()
            .join("\n\n")
    );
    let sent: Vec<String> = opening.iter().map(describe).collect();
    let data = json!({
        "sent_at_start": sent,
        "latest_message": {"event": event.id(), "data": event.data},
        "answer_repeats": sent[..repeated],
    });
    let user_message = format!(
        "Event: {}\n\
         Description: The client's answer to the latest message from the server begins by \
         sending again, word for word, what it sent at the start of the session \
         (answer_repeats). Those actions were sent once already and the server has been \
         answering them. If they were steps to do once, answer `{}`. Answer `{}` only \
         if the instruction says to send them again when the server sends something, and \
         the latest message contains that something; put the word that appears in both as \
         `trigger`.\n\
         Data: {}",
        RESTART_CHECK_EVENT,
        SKIP_REPEAT,
        SEND_AGAIN,
        serde_json::to_string_pretty(&data).unwrap_or_default()
    );

    let model = crate::llm::model_selection::ensure_state_model(state).await?;
    let rate_limiter = state.get_rate_limiter().await;
    let mut conversation = crate::llm::ConversationHandler::new(
        system_prompt,
        std::sync::Arc::new(llm_client.clone()),
        model,
        rate_limiter,
        crate::llm::RequestSource::Network,
    )
    .with_status_tx(status_tx.clone())
    .with_private_payloads(private_payloads)
    .with_tracking(
        state.clone(),
        crate::state::app_state::ConversationSource::Client { client_id },
        RESTART_CHECK_EVENT.to_string(),
    );
    conversation.add_user_message(user_message);
    let chosen = conversation
        .generate_with_tools_and_retry(None, crate::state::app_state::WebSearchMode::Off, actions)
        .await?;
    let Some(choice) = chosen
        .iter()
        .find(|a| a.get("type").and_then(Value::as_str).is_some())
    else {
        anyhow::bail!("the model chose neither {} nor {}", SEND_AGAIN, SKIP_REPEAT);
    };
    match choice.get("type").and_then(Value::as_str) {
        Some(SKIP_REPEAT) => Ok(Verdict::Done),
        Some(SEND_AGAIN) => {
            let trigger = choice
                .get("trigger")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            if trigger_is_founded(&trigger, instruction, &event.data) {
                Ok(Verdict::Due(trigger))
            } else {
                Ok(Verdict::Unfounded(trigger))
            }
        }
        other => anyhow::bail!(
            "the model answered {:?}, not {} or {}",
            other,
            SEND_AGAIN,
            SKIP_REPEAT
        ),
    }
}

/// What the model's answer to the question comes to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// The repeat is due: the instruction and the latest message share this trigger.
    Due(String),
    /// The repeated steps were done once and are not sent again.
    Done,
    /// The model said to send them again but named a trigger that is not in both the
    /// instruction and the latest message, so nothing it said makes the repeat due.
    Unfounded(String),
}

/// Lower-cased text with every run of non-alphanumeric characters made one space, so a
/// trigger matches however it is quoted or punctuated.
fn normalize(text: &str) -> String {
    let mut out = String::new();
    for word in text
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| !w.is_empty())
    {
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(&word.to_lowercase());
    }
    out
}

/// Every string and number in `value`, keys left out: the part of an event a peer wrote.
fn leaf_text(value: &Value, out: &mut String) {
    match value {
        Value::String(s) => {
            out.push(' ');
            out.push_str(s);
        }
        Value::Number(n) => {
            out.push(' ');
            out.push_str(&n.to_string());
        }
        Value::Array(items) => items.iter().for_each(|v| leaf_text(v, out)),
        Value::Object(fields) => fields.values().for_each(|v| leaf_text(v, out)),
        _ => {}
    }
}

/// Whether `trigger` is a word or phrase (at least two letters or digits) found, as whole
/// words, both in `instruction` and in the values of `event_data`.
pub fn trigger_is_founded(trigger: &str, instruction: &str, event_data: &Value) -> bool {
    let trigger = normalize(trigger);
    if trigger.chars().filter(|c| c.is_alphanumeric()).count() < 2 {
        return false;
    }
    let mut message = String::new();
    leaf_text(event_data, &mut message);
    let within = |text: &str| format!(" {} ", normalize(text)).contains(&format!(" {trigger} "));
    within(instruction) && within(&message)
}
