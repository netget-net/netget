//! Batching pipelined commands on command-reply sessions (SMTP, LMTP, POP3, IMAP, NNTP,
//! ManageSieve).
//!
//! These protocols owe **exactly one reply per command, in command order**. When a client
//! pipelines — sends several commands without waiting — the commands that arrived while the
//! model was answering an earlier one can be answered in one model call
//! (`action_helper::call_llm_batch`), but only if every command still gets its own reply. The
//! generic batch tells the model it may "answer each, some or none"; a command session cannot
//! accept "some", because one reply short shifts every later reply onto the wrong command.
//!
//! So each protocol here batches only commands whose framing it owns completely (a whole
//! command line, nothing the Rust code reads on its own afterwards — no DATA body, literal,
//! SASL exchange or TLS upgrade), marks each batched event with [`mark_pipelined`] so the model
//! is told one reply per command, and accepts the answer only when it holds exactly one reply
//! per command. Anything else is answered with the protocol's own temporary-failure reply for
//! every command in the batch, in order: the session stays in step and nothing is granted.
//!
//! What is here is the shared mechanics — finding lines that are already waiting, and deciding
//! whether a batch would really be answered by one model call. The per-command rules and the
//! reply validation stay in each protocol.

use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncRead, BufReader};

use crate::state::app_state::AppState;
use crate::state::ServerId;

/// The next complete line already in `reader`'s buffer, or readable from the socket without
/// waiting, together with its length including the terminator. Nothing is consumed: the caller
/// decides whether the line joins the batch and calls `reader.consume(len)` if it does, so a
/// line that must be handled on its own stays exactly where the normal read path finds it.
///
/// `None` when no whole line of at most `max_len` bytes is there. A partial line, an over-long
/// one and the end of the stream are all left for the protocol's own bounded read to report.
///
/// The socket is polled only when the buffer is empty, and with a zero deadline: `fill_buf`
/// consumes nothing when it is cancelled, so this never loses a byte and never waits.
pub async fn peek_ready_line<R>(
    reader: &mut BufReader<R>,
    max_len: usize,
) -> Option<(String, usize)>
where
    R: AsyncRead + Unpin,
{
    if reader.buffer().is_empty() {
        match tokio::time::timeout(Duration::ZERO, reader.fill_buf()).await {
            Ok(Ok(buf)) if !buf.is_empty() => {}
            _ => return None,
        }
    }
    let buf = reader.buffer();
    let end = buf.iter().position(|&b| b == b'\n')? + 1;
    if end > max_len {
        return None;
    }
    Some((String::from_utf8_lossy(&buf[..end]).into_owned(), end))
}

/// Whether this instance batches and every one of `event_ids` would be answered by **one**
/// model call — the same test `call_llm_batch` applies before it folds a batch into one call.
///
/// A protocol checks it before collecting, because when `call_llm_batch` falls back to
/// answering events one by one (a script, static or manual rule, an easy-protocol layer,
/// batching switched off) it concatenates their results, and a command session can no longer
/// tell which reply belongs to which command. A command that is not answered by the model is
/// therefore never batched here; it is answered alone, exactly as with batching off.
pub async fn one_model_call_answers(
    state: &AppState,
    server_id: ServerId,
    event_ids: &[&str],
) -> bool {
    let batching = state
        .server_conversation_settings(server_id)
        .await
        .is_some_and(|(_, batching)| batching);
    if !batching || state.get_easy_for_server(server_id).await.is_some() {
        return false;
    }
    let Some(config) = state.get_event_handler_config(server_id).await else {
        return true;
    };
    let mut instruction: Option<Option<String>> = None;
    for id in event_ids {
        let this = match config.find_handler(id) {
            None => None,
            Some(crate::scripting::EventHandlerType::Llm { instruction }) => {
                Some(instruction.clone())
            }
            Some(_) => return false,
        };
        match &instruction {
            None => instruction = Some(this),
            Some(first) if *first != this => return false,
            Some(_) => {}
        }
    }
    true
}

/// Whether batching is switched on for this instance (read per command, so a hot change
/// applies to the next one).
pub async fn batching_on(state: &AppState, server_id: ServerId) -> bool {
    state
        .server_conversation_settings(server_id)
        .await
        .is_some_and(|(_, batching)| batching)
}

/// What a batch's answer puts on the wire, read in the order the model gave it.
#[derive(Debug, Default)]
pub struct BatchReplies {
    /// Every reply the answer writes, in order, `Multiple` flattened.
    pub replies: Vec<Vec<u8>>,
    /// The answer asked to close the connection.
    pub close: bool,
}

impl BatchReplies {
    pub fn from_result(result: &crate::llm::actions::executor::ExecutionResult) -> Self {
        fn walk(results: &[crate::llm::ActionResult], out: &mut BatchReplies) {
            for result in results {
                match result {
                    crate::llm::ActionResult::Output(data) => out.replies.push(data.clone()),
                    crate::llm::ActionResult::CloseConnection => out.close = true,
                    crate::llm::ActionResult::Multiple(inner) => walk(inner, out),
                    _ => {}
                }
            }
        }
        let mut out = Self::default();
        walk(&result.protocol_results, &mut out);
        out
    }
}

/// Tell the model, on each event of a batch, that this command is one of several the client
/// sent without waiting and that every one of them takes exactly one reply, in order.
///
/// The generic batch prompt says the model may answer "each, some or none"; on a command
/// session "some" desynchronises the client, so the protocol says otherwise on the event
/// itself, where a small model reads it.
pub fn mark_pipelined(data: &mut serde_json::Value, position: usize, total: usize) {
    data["pipelined"] = format!(
        "command {position} of {total} the client sent without waiting for replies: answer \
         all {total} with exactly one reply each, in the order they were sent"
    )
    .into();
}
