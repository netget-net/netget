//! Turning a failed run into a *diagnosis*.
//!
//! This is the point of the whole harness. A pass rate says the model could or
//! could not drive the protocol; only the failure mode says whose fault that is.
//! Every rule below keys off a log line netget already writes, and every one
//! carries the model's **actual output** with it — because "the model got it
//! wrong" is not actionable and `{"type":"http_reply","code":200}` is.
//!
//! The ordering is most-specific-first. A model that copies a `{{event.xid}}`
//! placeholder out of an action's own example will *also* trip the executor's
//! rejection rule, and the placeholder is the diagnosis worth reporting.

#![allow(dead_code)]

use super::probe::ProbeOutcome;

/// Log fragments netget emits that name the model's mistake.
const UNKNOWN_ACTION: &str = "LLM returned unknown action(s):";
const MALFORMED_ACTION: &str = "LLM returned malformed action:";
const PARSE_FAILURE: &str = "Failed to parse action response";
const ACTUAL_RESPONSE: &str = "❌ Actual response:";
const MALFORMED_RAW: &str = "Malformed response (raw):";
const EXECUTOR_REJECTED: &str = "failed on protocol";
const NO_PROTOCOL_CONTEXT: &str = "unknown action type and no protocol in context";
const EXECUTING_ACTION: &str = "Executing action";
const LLM_CALL: &str = "LLM call for event";
const FAIL_CLOSED: &str = "decision=fail_closed";
/// The transport's DEBUG line for a completed backend reply.
const LLM_REPLIED: &str = "LLM response:";

/// What went wrong, in the vocabulary a prompt-quality fix would be written in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnosis {
    /// Stable machine-readable mode, e.g. `invented_action_name`.
    pub mode: &'static str,
    /// One sentence naming what to look at.
    pub detail: String,
    /// The lines that prove it — the model's actual output, verbatim.
    pub evidence: Vec<String>,
    /// Action names netget *would* have executed if its response parser
    /// tolerated text after the JSON. Empty unless that is the diagnosis.
    ///
    /// This exists because one defect otherwise hides every other finding. When
    /// the model names the right action with the right parameters and the reply
    /// is discarded whole, the pass rate says 0% and tells you nothing about the
    /// description — which is the thing this harness was built to measure. So
    /// the report carries two numbers: what happens today, and what would happen
    /// if the first value in the reply were taken instead of the whole string.
    pub recovered_actions: Vec<String>,
}

impl Diagnosis {
    fn new(mode: &'static str, detail: impl Into<String>, evidence: Vec<String>) -> Self {
        Self {
            mode,
            detail: detail.into(),
            evidence,
            recovered_actions: Vec::new(),
        }
    }

    fn with_recovered(mut self, recovered: Vec<String>) -> Self {
        self.recovered_actions = recovered;
        self
    }
}

/// Take the first complete JSON value out of a string that may have anything
/// around it, and name the actions in it.
///
/// This is deliberately the *minimum* leniency that would fix the observed
/// failures: `serde_json`'s streaming deserializer reads one value and stops,
/// where `from_str` insists the whole string be consumed. Nothing here guesses,
/// repairs or reformats — if the model did not emit a complete JSON value, this
/// returns nothing and the run is scored as a genuine miss.
fn recover_action_names(text: &str) -> Vec<String> {
    // Try each `{`/`[` in turn rather than only the first. A captured block
    // starts with netget's own marker line and can carry a brace before the
    // model's JSON; anchoring on the first one silently gave up. Bounded so a
    // long log line cannot turn this into a quadratic scan.
    let candidates: Vec<usize> = text
        .char_indices()
        .filter(|(_, c)| *c == '{' || *c == '[')
        .map(|(i, _)| i)
        .take(8)
        .collect();

    for start in candidates {
        let mut stream =
            serde_json::Deserializer::from_str(&text[start..]).into_iter::<serde_json::Value>();
        let value = match stream.next() {
            Some(Ok(v)) => v,
            _ => continue,
        };
        let mut names = Vec::new();
        names_in(&value, &mut names);
        names.dedup();
        if !names.is_empty() {
            return names;
        }
    }
    Vec::new()
}

/// Every `type` in a response value, at any of the nesting levels netget
/// accepts (a bare action, an array of them, or the `{tools, actions}` object).
fn names_in(value: &serde_json::Value, out: &mut Vec<String>) {
    match value {
        serde_json::Value::Array(items) => {
            for item in items {
                names_in(item, out);
            }
        }
        serde_json::Value::Object(map) => {
            if let Some(name) = map.get("type").and_then(|t| t.as_str()) {
                out.push(name.to_string());
            }
            for key in ["actions", "tools"] {
                if let Some(nested) = map.get(key) {
                    names_in(nested, out);
                }
            }
        }
        _ => {}
    }
}

/// Distinctive string values from an action's declared `example` that the model
/// reproduced verbatim and that the operator never asked for.
///
/// This is the shape the `{{event.xid}}` placeholder defect had, wearing better
/// clothes. A placeholder at least *looks* wrong when it reaches the wire; an
/// example full of plausible prose does not, so the model reuses it and the
/// operator's actual instruction loses. Measured: told "serve a menu whose first
/// item is labelled Welcome to NetGet", the model emitted all four items of
/// `send_gopher_menu`'s example — "Welcome to the gopher hole", "About this
/// server", "Files", "Search the archive" — and none of the requested label.
///
/// The second half of the test is what keeps it honest: a value the operator's
/// own instruction contains is not evidence of copying, so anything appearing in
/// the instruction is excluded.
fn copied_example_values(protocol: &str, instruction: &str, log: &[String]) -> Vec<String> {
    // `resolve`, not `get`: the registry is keyed by `protocol_name()` ("SMTP",
    // "Gopher") and a case names its protocol the way `--server` takes it
    // ("smtp"), so an exact-key `get` finds nothing and this check never runs.
    let server = match netget::protocol::server_registry::registry().resolve(protocol) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let examples: std::collections::BTreeMap<String, serde_json::Value> = server
        .get_sync_actions()
        .into_iter()
        .map(|a| (a.name, a.example))
        .collect();
    if examples.is_empty() {
        return Vec::new();
    }

    let instruction_lc = instruction.to_lowercase();
    let mut hits = Vec::new();

    for line in log.iter().filter(|l| l.contains(EXECUTING_ACTION)) {
        let stripped = strip_ansi(line);
        // The executor logs each action with `{:?}`, which for a `serde_json::Value`
        // is its Debug form — `Object {"type": String("send_x"), "k": String("v")}` —
        // and not JSON. Read the name out of that form and search the line itself:
        // a string leaf appears verbatim in both forms. A JSON line still works.
        let (name, rendered) = match debug_action_type(&stripped) {
            Some(n) => (n, stripped.to_lowercase()),
            None => match first_json_value(&stripped) {
                Some(v) => match v.get("type").and_then(|t| t.as_str()) {
                    Some(n) => (n.to_string(), v.to_string().to_lowercase()),
                    None => continue,
                },
                None => continue,
            },
        };
        let example = match examples.get(&name) {
            Some(e) => e,
            None => continue,
        };

        for value in string_leaves(example) {
            // Short values are coincidence, not copying: "GET", "127.0.0.1" and
            // "text/html" are simply the right answer. The example's own `type`
            // is the action's name, which every use of the action contains.
            if value.chars().count() < 10 || value == name {
                continue;
            }
            let value_lc = value.to_lowercase();
            if rendered.contains(&value_lc) && !instruction_lc.contains(&value_lc) {
                hits.push(format!("{}: {:?}", name, value));
            }
        }
    }
    hits.dedup();
    hits
}

/// The action name in an executor line's Debug-formatted action,
/// `… Executing action 0: Object {"type": String("send_x"), …}`. Only the
/// top-level `"type"` counts, which is the key right after the first
/// `Object {` when the model put it first, as it almost always does.
fn debug_action_type(line: &str) -> Option<String> {
    const MARKER: &str = "\"type\": String(\"";
    let object = line.find("Object {")? + "Object {".len();
    let rest = &line[object..];
    let start = if rest.starts_with(MARKER) {
        object + MARKER.len()
    } else {
        line.find(MARKER)? + MARKER.len()
    };
    let len = line[start..].find('"')?;
    Some(line[start..start + len].to_string())
}

/// Every string leaf in a JSON value.
fn string_leaves(value: &serde_json::Value) -> Vec<String> {
    let mut out = Vec::new();
    fn walk(v: &serde_json::Value, out: &mut Vec<String>) {
        match v {
            serde_json::Value::String(s) => out.push(s.clone()),
            serde_json::Value::Array(items) => items.iter().for_each(|i| walk(i, out)),
            serde_json::Value::Object(map) => map.values().for_each(|i| walk(i, out)),
            _ => {}
        }
    }
    walk(value, &mut out);
    out
}

/// The first complete JSON value in a string, whatever surrounds it.
fn first_json_value(text: &str) -> Option<serde_json::Value> {
    let candidates = text
        .char_indices()
        .filter(|(_, c)| *c == '{' || *c == '[')
        .map(|(i, _)| i)
        .take(8);
    for start in candidates {
        if let Some(Ok(v)) = serde_json::Deserializer::from_str(&text[start..])
            .into_iter::<serde_json::Value>()
            .next()
        {
            return Some(v);
        }
    }
    None
}

/// A `{{name` / `{{ name` template opener — the shape a copied placeholder
/// takes. Bare `}}` is not evidence: it is how nested JSON ends.
fn has_template_placeholder(line: &str) -> bool {
    line.match_indices("{{").any(|(i, _)| {
        line[i + 2..]
            .trim_start()
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
    })
}

/// Every distinct mode the classifier can report, with the prose that belongs
/// in the results file next to it.
pub const MODE_GLOSSARY: &[(&str, &str)] = &[
    (
        "invented_action_name",
        "The model named an action that does not exist. Either the vocabulary it \
         needed is not advertised on this event, or a neighbouring description \
         suggested a name the protocol does not have.",
    ),
    (
        "copied_example_placeholder",
        "The model emitted a template placeholder (`{{…}}`) literally. Placeholders \
         are real for static handlers and meaningless in a model's reply, so an \
         action `example` containing one teaches the model to send something its \
         own executor rejects.",
    ),
    (
        "malformed_action_parameters",
        "The action name was right and its parameters would not parse — a missing \
         required field, or a value of the wrong type. Usually the parameter \
         description does not say the field is required, or does not say the type.",
    ),
    (
        "executor_rejected_action",
        "The protocol's own executor refused the action the model built. The \
         description and the executor disagree about what the action accepts.",
    ),
    (
        "valid_actions_rejected_as_unparseable",
        "The model named the right action with the right parameters and the reply was \
         thrown away anyway, because prose or a stray code fence sits around the JSON. \
         **Not a description defect and not a model defect** — `ActionResponse::from_str` \
         (`src/llm/actions/mod.rs`) strips a leading ``` fence and nothing trailing, then \
         hands the remainder to `serde_json::from_str`, which rejects any trailing byte. \
         Small models append an explanation after the JSON constantly, so this one \
         behaviour costs more eval passes than every description problem combined.",
    ),
    (
        "unparseable_response",
        "The model's whole reply was not the action format. Prompting-level, not \
         protocol-level — but a protocol whose actions are hard to express drives \
         models into prose.",
    ),
    (
        "model_answered_with_no_actions",
        "The model was asked and returned no actions at all. The peer gets the \
         protocol default; from the wire this is indistinguishable from an outage.",
    ),
    (
        "client_left_before_model_answered",
        "The model was asked and the client hung up before it answered, so the call \
         was abandoned with the connection. A probe problem — a client whose own \
         timeout is shorter than a model call, or a harness that cut it off — not a \
         prompt problem.",
    ),
    (
        "event_never_reached_model",
        "No model call happened. The request did not reach the LLM path — a \
         harness or protocol wiring problem, not a prompt problem.",
    ),
    (
        "no_wire_response",
        "The model acted but the client got nothing back within the timeout.",
    ),
    (
        "copied_example_content",
        "The model reproduced text out of the action's own `example` and dropped what \
         the operator asked for. Same defect as a `{{…}}` placeholder in an example, but \
         invisible on the wire because the copied text looks plausible. An `example` is \
         the strongest prompt a protocol has: whatever it contains is what a small model \
         will send. Make the values obviously stand-ins, or generic enough that copying \
         them is visibly wrong.",
    ),
    (
        "wrong_content",
        "The model produced a valid, executable action whose content does not \
         satisfy the instruction. This is the honest 'the model did not \
         understand the task' bucket.",
    ),
    (
        "client_error",
        "The third-party client refused the exchange before any content check — \
         a protocol-level handshake failure.",
    ),
];

/// Pull out the lines that show what the model actually said.
///
/// Recorded for passing runs too: a case that passes 2/3 is diagnosed by
/// comparing the action the model built when it worked with the one it built
/// when it did not.
pub fn model_output(log: &[String]) -> Vec<String> {
    log.iter()
        .filter(|l| {
            l.contains(EXECUTING_ACTION)
                || l.contains(UNKNOWN_ACTION)
                || l.contains(MALFORMED_ACTION)
                || l.contains(EXECUTOR_REJECTED)
                || l.contains(PARSE_FAILURE)
                // The two lines that carry the model's reply verbatim. Without
                // them a parse failure reports only that parsing failed, and
                // the whole point is to see what the model actually wrote.
                || l.contains(ACTUAL_RESPONSE)
                || l.contains(MALFORMED_RAW)
                || l.starts_with("{\"actions\"")
                || l.starts_with("{\"tools\"")
        })
        .map(|l| truncate(l, 900))
        .collect()
}

/// Drop the terminal colour codes netget writes, so the evidence in a published
/// artefact is text a person can read rather than `[2m[33m WARN[0m`.
fn strip_ansi(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            // CSI: ESC [ … final-byte in @..~
            if chars.peek() == Some(&'[') {
                chars.next();
                for c in chars.by_ref() {
                    if ('@'..='~').contains(&c) {
                        break;
                    }
                }
            }
            continue;
        }
        out.push(c);
    }
    out
}

fn truncate(line: &str, max: usize) -> String {
    let line = &strip_ansi(line);
    // Char-boundary safe: model output is routinely non-ASCII and byte slicing
    // it is the exact panic `utils::truncate` exists to prevent.
    if line.chars().count() <= max {
        return line.to_string();
    }
    let cut: String = line.chars().take(max).collect();
    format!("{}… (truncated)", cut)
}

fn lines_with<'a>(log: &'a [String], needle: &str) -> Vec<&'a String> {
    log.iter().filter(|l| l.contains(needle)).collect()
}

/// The response dumps netget writes, reassembled.
///
/// `Actual response:` and `Malformed response (raw):` are followed by the
/// model's reply, and the capture stores one log line per entry — so a reply
/// that spans lines is split across several. Looking for the JSON on the marker
/// line alone finds it only when the model happened to answer on one line, which
/// undercounted the recoverable runs in the first validation pass.
fn response_blocks(log: &[String]) -> Vec<String> {
    const FOLLOWING_LINES: usize = 8;
    let mut blocks = Vec::new();
    for (i, line) in log.iter().enumerate() {
        if line.contains(ACTUAL_RESPONSE) || line.contains(MALFORMED_RAW) {
            let end = (i + 1 + FOLLOWING_LINES).min(log.len());
            blocks.push(log[i..end].join("\n"));
        }
    }
    // Some models do answer on one line, and then the JSON is on the marker
    // line itself rather than after it — already covered above — or on a line
    // with no marker at all, which these catch.
    for line in log {
        if line.contains("\"actions\"") || line.contains("\"type\"") {
            blocks.push(line.clone());
        }
    }
    blocks
}

/// Diagnose one failed run.
///
/// `check_error` is what the expectation itself complained about; it is the
/// fallback detail when nothing in the log names a specific mistake.
pub fn classify(
    protocol: &str,
    instruction: &str,
    log: &[String],
    probe: &ProbeOutcome,
    check_error: &str,
) -> Diagnosis {
    let evidence = model_output(log);

    // A harness-level regex mistake must never be scored against the model.
    if check_error.starts_with("HARNESS:") {
        return Diagnosis::new("harness_error", check_error.to_string(), evidence);
    }

    // 1. A placeholder taken literally. Checked first: it also trips the
    //    executor rule below, and it is the diagnosis that names a fixable
    //    description rather than a symptom.
    // `{{` followed by a name, not any `}}`: nested JSON closes with `}}` on
    // every `Executing action` line that carries an object inside an object, and
    // matching that reported IPP attribute groups and HTTP header maps as
    // copied placeholders.
    let placeholder: Vec<String> = log
        .iter()
        .filter(|l| l.contains(EXECUTING_ACTION) || l.contains(EXECUTOR_REJECTED))
        .filter(|l| has_template_placeholder(l))
        .map(|l| truncate(l, 900))
        .collect();
    if !placeholder.is_empty() {
        return Diagnosis::new(
            "copied_example_placeholder",
            "the model emitted a `{{…}}` template placeholder verbatim — check this \
             action's `example` for one",
            placeholder,
        );
    }

    // 2. An action name that does not exist.
    let unknown = lines_with(log, UNKNOWN_ACTION);
    if !unknown.is_empty() {
        return Diagnosis::new(
            "invented_action_name",
            "the model named an action the protocol does not advertise",
            unknown.into_iter().map(|l| truncate(l, 900)).collect(),
        );
    }
    let no_context = lines_with(log, NO_PROTOCOL_CONTEXT);
    if !no_context.is_empty() {
        return Diagnosis::new(
            "invented_action_name",
            "the action was neither a common action nor one this protocol executes",
            no_context.into_iter().map(|l| truncate(l, 900)).collect(),
        );
    }

    // 3. Right name, unusable parameters.
    let malformed = lines_with(log, MALFORMED_ACTION);
    if !malformed.is_empty() {
        return Diagnosis::new(
            "malformed_action_parameters",
            "the action's parameters would not parse — a required field is missing \
             or a value has the wrong type",
            malformed.into_iter().map(|l| truncate(l, 900)).collect(),
        );
    }

    // 4. The protocol's own executor said no.
    let rejected = lines_with(log, EXECUTOR_REJECTED);
    if !rejected.is_empty() {
        return Diagnosis::new(
            "executor_rejected_action",
            "the protocol executor refused the action the model built",
            rejected.into_iter().map(|l| truncate(l, 900)).collect(),
        );
    }

    // 5. The reply would not parse. Two very different diagnoses hide here, and
    //    separating them is the difference between "the model failed" and "a
    //    two-line fix in the response normaliser unblocks this protocol".
    let unparseable = lines_with(log, PARSE_FAILURE);
    if !unparseable.is_empty() {
        // Did the model in fact produce the right action, wrapped in prose or a
        // stray fence? `ActionResponse::from_str` strips a *leading* fence but
        // nothing trailing, so `{"actions":[…]}```Here is why…` is rejected
        // whole even though the JSON in it is correct and complete.
        let blocks = response_blocks(log);
        let mut recovered: Vec<String> = blocks
            .iter()
            .flat_map(|block| recover_action_names(block))
            .collect();
        recovered.dedup();
        let wrapped: Vec<String> = if recovered.is_empty() {
            Vec::new()
        } else {
            blocks.iter().map(|b| truncate(b, 1200)).collect()
        };
        if !wrapped.is_empty() {
            let detail = if recovered.is_empty() {
                "the reply contained action JSON and would not parse".to_string()
            } else {
                format!(
                    "the model produced {} and the reply was discarded anyway, because \
                     text or a stray fence surrounds the JSON",
                    recovered
                        .iter()
                        .map(|n| format!("`{}`", n))
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            };
            return Diagnosis::new("valid_actions_rejected_as_unparseable", detail, wrapped)
                .with_recovered(recovered);
        }
        return Diagnosis::new(
            "unparseable_response",
            "the model's reply was not in the action-response format",
            evidence,
        );
    }

    // 6. Was the model even consulted?
    let calls = lines_with(log, LLM_CALL).len();
    let executions = lines_with(log, EXECUTING_ACTION).len();
    if calls == 0 {
        return Diagnosis::new(
            "event_never_reached_model",
            "no model call was made for this request — the event did not reach the \
             LLM path",
            evidence,
        );
    }
    if executions == 0 && lines_with(log, LLM_REPLIED).is_empty() && !probe.timed_out {
        // Asked, never answered, and the client did not wait out its timeout:
        // the client left mid-call and the server abandoned the model call with
        // the connection. Scoring that as "the model said nothing" blamed the
        // model for the probe's impatience — every ipp run, until it had a name.
        return Diagnosis::new(
            "client_left_before_model_answered",
            format!(
                "the model was asked, the client closed the connection after {:.1}s \
                 without waiting for the answer, and the call was abandoned",
                probe.elapsed.as_secs_f64()
            ),
            evidence,
        );
    }
    if executions == 0 {
        let failed_closed = lines_with(log, FAIL_CLOSED).len();
        let detail = if failed_closed > 0 {
            "the model was asked, produced no usable actions, and the server failed \
             closed"
        } else {
            "the model was asked and answered with no actions at all"
        };
        return Diagnosis::new("model_answered_with_no_actions", detail, evidence);
    }

    // 7. It acted, but nothing reached the client.
    if probe.timed_out || probe.is_silent() {
        return Diagnosis::new(
            "no_wire_response",
            format!(
                "the model executed {} action(s) but the client saw nothing back \
                 ({})",
                executions,
                if probe.timed_out {
                    "client timed out"
                } else {
                    "client exited silently"
                }
            ),
            evidence,
        );
    }

    // 8. A protocol-level refusal from the client itself, before content.
    let lowered = probe.combined().to_lowercase();
    let client_refused = ["connection refused", "protocol error", "could not connect"]
        .iter()
        .any(|m| lowered.contains(m));
    if client_refused {
        return Diagnosis::new(
            "client_error",
            format!("the client refused the exchange: {}", check_error),
            evidence,
        );
    }

    // 9. The actions ran and the content came out of the action's own example
    //    rather than out of the operator's instruction. Checked before the
    //    generic bucket because it names a fixable description; without it this
    //    lands in `wrong_content` and reads as "the model is not very good".
    let copied = copied_example_values(protocol, instruction, log);
    if !copied.is_empty() {
        return Diagnosis::new(
            "copied_example_content",
            format!(
                "the model reproduced its own action's example ({}) instead of what the \
                 instruction asked for",
                copied.join("; ")
            ),
            evidence,
        );
    }

    // 10. Everything worked mechanically and the answer was simply wrong.
    Diagnosis::new(
        "wrong_content",
        format!("valid actions executed, but {}", check_error),
        evidence,
    )
}

/// `copied_example_content` from the line the executor actually writes, for a
/// case that names its protocol the way `--server` takes it. Both halves of that
/// were broken at once — a case-sensitive registry lookup and a JSON parse of a
/// Debug-formatted line — so the diagnosis never fired on any run. The line
/// copies `send_smtp_greeting`'s current example, so this follows the example.
#[test]
fn copied_example_is_found_in_the_executor_debug_line() {
    let line = r#"2026-09-26T21:18:45.444061Z DEBUG Executing action 0: Object {"type": String("send_smtp_greeting"), "hostname": String("mx.example.invalid"), "message": String("ESMTP")}"#.to_string();
    let hits = copied_example_values(
        "smtp",
        "Greet every connection with the banner NetGet Eval Mail.",
        std::slice::from_ref(&line),
    );
    assert!(
        hits.iter().any(|h| h.contains("mx.example.invalid")),
        "the example's greeting host was not recognised as copied: {hits:?}"
    );
    // A value the operator asked for is not copying.
    let hits = copied_example_values(
        "smtp",
        "Greet with the banner ESMTP from mx.example.invalid.",
        &[line],
    );
    assert!(
        hits.is_empty(),
        "instruction values counted as copied: {hits:?}"
    );
}
