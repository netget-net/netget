//! SIP protocol actions implementation

use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::EventType;
use crate::state::app_state::AppState;
use anyhow::{Context, Result};
use serde_json::json;
use std::sync::LazyLock;

pub struct SipProtocol;

impl SipProtocol {
    pub fn new() -> Self {
        Self
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for SipProtocol {
    /// None. SIP has no user-triggered action that does anything.
    ///
    /// `send_sip_invite`, `send_sip_bye` and `update_registration` used to be advertised
    /// here. All three were `Ok(ActionResult::NoAction)` stubs — every parameter they
    /// declared (`to`, `from`, `sdp`, `call_id`, `bindings`) was read by nothing, and neither
    /// the action names nor those fields appear anywhere in `mod.rs`. So a user asking to
    /// place or end a call got silence, and the model was told the capability existed.
    ///
    /// Implementing them needs outbound dialog state this server does not keep (it answers
    /// requests; it does not originate them) and a registration database that outlives a
    /// request. Removed rather than left advertised, as the proxy's six configuration actions
    /// and `ssh_agent/modify_instruction` were: an action that silently does nothing is worse
    /// than an absent one, because the model will choose it.
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            sip_register_action(),
            sip_invite_action(),
            sip_bye_action(),
            sip_ack_action(),
            sip_options_action(),
            sip_cancel_action(),
        ]
    }
    fn protocol_name(&self) -> &'static str {
        "SIP"
    }
    fn get_event_types(&self) -> Vec<EventType> {
        get_sip_event_types()
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>UDP>SIP"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["sip", "voip", "session initiation"]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            .connectionless()
            // Answers on failure: 503 Service Unavailable; nothing reaches a 2xx unless the model
            // names one.
            .answers_on_failure()
            .state(DevelopmentState::Beta)
            .well_known_udp_port(5060)
            // Not rsipstack, and not a compliant stack. `Cargo.toml` declares `sip = []` -
            // there is no SIP dependency at all. `mod.rs` hand-parses the request line and
            // headers and hand-builds the status line. The old claim named a library version
            // this build has never linked, which is exactly the sort of thing an operator
            // reads as evidence of maturity.
            .implementation(
                "Manual line-based parser and response builder (no SIP library; Cargo declares \
                 `sip = []`). Request line + headers + optional SDP body only: no transaction \
                 layer, no retransmissions, no digest auth, no dialog state, UDP only",
            )
            .llm_control("Registration decisions + call routing + SDP generation")
            // Beta since September 2026. This comment used to say the evidence was "a
            // mocked-LLM UDP exchange plus netget's own SIP client - which makes it circular,
            // and is why this stays Experimental". That was true when written; sipsak is now
            // installed and drives the server from outside, which is what changed.
            .e2e_testing(
                "REAL THIRD-PARTY CLIENT: sipsak 0.9.8.1 (the FhG Fokus SER torture-tester, a \
                 C program) in tests/server/sip/real_client_test.rs. NOT #[ignore]d and NOT \
                 skip-gated — the tests FAIL, naming `brew install sipsak`, when the binary is \
                 absent. Not circular: `sip = []` in Cargo.toml, so this server is hand-written \
                 over tokio's UdpSocket with no SIP library at all. Three transactions: an \
                 OPTIONS answered 200 with the model's own allow_methods (sipsak exits 0 only \
                 after matching the reply's Via+branch, Call-ID and CSeq against the request it \
                 sent — the correlation a dissector cannot check, and the thing that decides \
                 whether a real UA accepts a reply or discards it as unmatched); the same \
                 OPTIONS answered 403, where sipsak reports the code and exits non-zero, \
                 proving it reads our status line rather than merely receiving a datagram; and \
                 a REGISTER through usrloc mode, which sipsak reports as 'All usrloc tests \
                 completed successful.' Since build_sip_response is ONE function for every \
                 method, the correlation proven on OPTIONS is the same code every reply uses. \
                 Alongside: the mocked-LLM UDP e2e over the six methods, whose replies are \
                 additionally checked with the Wireshark `sip` dissector, plus a fail-closed \
                 503/ACK-silence test and an RTP interop test. \
                 NOT PROVEN: INVITE and its SDP against a real UA (sipsak's -I mode calls \
                 itself and needs a media stack; no softphone is driven here), so call setup is \
                 covered only by the dissector; digest authentication, which is NOT IMPLEMENTED \
                 and which no action can produce, so no client can be made to authenticate; \
                 TCP and TLS transport (UDP only); dialogs, CANCEL, and multi-Via proxy paths. \
                 Also note sipsak's usrloc mode deactivates Via insertion, so the REGISTER test \
                 contributes the admission decision and NOT correlation evidence.",
            )
            .notes(
                "Scripting candidate, VoIP signaling honeypot. No registration database: the \
                 model decides each REGISTER on its own and nothing is stored between requests \
                 (protocols must not implement storage). REGISTER and INVITE are admission \
                 decisions and fail closed - an LLM error is 503, an action with no \
                 status_code or no SIP response action at all is 500, never a defaulted 200",
            )
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "SIP server for VoIP signaling"
    }
    fn example_prompt(&self) -> &'static str {
        "Start a SIP server on port 5060 for VoIP registration and call signaling"
    }
    fn group_name(&self) -> &'static str {
        "Proxy & Network"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;

        // Deterministic: answer REGISTER, INVITE and OPTIONS each with 200 OK,
        // no LLM call. One script handles all three events.
        let script = r#"import json, sys
data = json.load(sys.stdin)
event = data["event"]
et = data["event_type_id"]
if et == "sip_register":
    actions = [{"type": "sip_register", "status_code": 200}]
elif et == "sip_invite":
    actions = [{"type": "sip_invite", "status_code": 200}]
elif et == "sip_options":
    actions = [{"type": "sip_options", "status_code": 200}]
else:
    actions = []
print(json.dumps({"actions": actions}))"#;

        StartupExamples::new(
            // LLM mode
            json!({
                "type": "open_server",
                "port": 5060,
                "base_stack": "sip",
                "instruction": "SIP VoIP signaling server. Accept REGISTER requests with 200 OK. For INVITE requests, respond with 200 OK and SDP. Log all call setup attempts."
            }),
            // Script mode
            json!({
                "type": "open_server",
                "port": 5060,
                "base_stack": "sip",
                "event_handlers": [{
                    "event_pattern": "sip_register",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": script
                    }
                }, {
                    "event_pattern": "sip_invite",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": script
                    }
                }, {
                    "event_pattern": "sip_options",
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
                "port": 5060,
                "base_stack": "sip",
                "event_handlers": [{
                    "event_pattern": "sip_register",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "sip_register",
                            "status_code": 200,
                            "expires": 3600
                        }]
                    }
                }]
            }),
        )
    }
}

// Implement Server trait (server-specific functionality)
impl Server for SipProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::server::sip::SipServer;
            SipServer::spawn_with_llm_actions(
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
            "sip_register" => self.execute_sip_register(action),
            "sip_invite" => self.execute_sip_invite(action),
            "sip_bye" => self.execute_sip_bye(action),
            "sip_ack" => Ok(ActionResult::NoAction), // ACK doesn't require response
            "sip_options" => self.execute_sip_options(action),
            "sip_cancel" => self.execute_sip_cancel(action),
            _ => Err(anyhow::anyhow!("Unknown SIP action: {}", action_type)),
        }
    }
}

impl SipProtocol {
    /// Execute SIP REGISTER action (network event)
    /// Just validates the action - actual response data comes from action JSON itself
    fn execute_sip_register(&self, _action: serde_json::Value) -> Result<ActionResult> {
        // Validation happens in mod.rs when parsing the action
        Ok(ActionResult::NoAction)
    }

    /// Execute SIP INVITE action (network event)
    fn execute_sip_invite(&self, _action: serde_json::Value) -> Result<ActionResult> {
        Ok(ActionResult::NoAction)
    }

    /// Execute SIP BYE action (network event)
    fn execute_sip_bye(&self, _action: serde_json::Value) -> Result<ActionResult> {
        Ok(ActionResult::NoAction)
    }

    /// Execute SIP OPTIONS action (network event)
    fn execute_sip_options(&self, _action: serde_json::Value) -> Result<ActionResult> {
        Ok(ActionResult::NoAction)
    }

    /// Execute SIP CANCEL action (network event)
    fn execute_sip_cancel(&self, _action: serde_json::Value) -> Result<ActionResult> {
        Ok(ActionResult::NoAction)
    }
}

/// SIP event types
fn get_sip_event_types() -> Vec<EventType> {
    vec![
        SIP_REGISTER_EVENT.clone(),
        SIP_INVITE_EVENT.clone(),
        SIP_BYE_EVENT.clone(),
        SIP_ACK_EVENT.clone(),
        SIP_OPTIONS_EVENT.clone(),
        SIP_CANCEL_EVENT.clone(),
    ]
}

/// SIP REGISTER event
pub static SIP_REGISTER_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "sip_register",
        "A client is registering its location with REGISTER. Answer with sip_register: 200 to \
         accept the binding, 401/403 to challenge or refuse it.",
        json!({
            "type": "sip_register",
            "status_code": 200,
            "expires": 3600
        }),
    )
    // Each SIP event is answered by exactly one action - the reply to a REGISTER is a REGISTER
    // response and nothing else - so every event lists only its own. `call_llm` builds the
    // model's tool list from the event type rather than from get_sync_actions(), so before this
    // the model was offered none of the six and every reply it produced was rejected.
    .with_actions(vec![sip_register_action()])
    .with_log_template(
        LogTemplate::new()
            .with_info("SIP REGISTER")
            .with_debug("SIP REGISTER request")
            .with_trace("SIP: {json_pretty(.)}"),
    )
});

/// SIP INVITE event
pub static SIP_INVITE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "sip_invite",
        "A client is initiating a session with INVITE. Answer with sip_invite carrying the status \
         code and, for a 200, the answering SDP.",
        json!({
            "type": "sip_invite",
            "status_code": 200,
            "sdp": "v=0\no=- 0 0 IN IP4 127.0.0.1\ns=Call\nc=IN IP4 127.0.0.1\nt=0 0\nm=audio 8000 RTP/AVP 0\n"
        }),
    )
    .with_actions(vec![sip_invite_action()])
    .with_log_template(
        LogTemplate::new()
            .with_info("SIP INVITE")
            .with_debug("SIP INVITE request")
            .with_trace("SIP: {json_pretty(.)}"),
    )
});

/// SIP BYE event
pub static SIP_BYE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "sip_bye",
        "The far end is terminating the session with BYE. Answer with sip_bye; 200 acknowledges \
         the teardown.",
        json!({"type": "sip_bye", "status_code": 200}),
    )
    .with_actions(vec![sip_bye_action()])
    .with_log_template(
        LogTemplate::new()
            .with_info("SIP BYE")
            .with_debug("SIP BYE request")
            .with_trace("SIP: {json_pretty(.)}"),
    )
});

/// SIP ACK event
pub static SIP_ACK_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "sip_ack",
        "The client acknowledged an INVITE response. ACK is never answered on the wire, so \
         sip_ack simply records that the dialog is established.",
        json!({"type": "sip_ack"}),
    )
    .with_actions(vec![sip_ack_action()])
    .with_log_template(
        LogTemplate::new()
            .with_info("SIP ACK")
            .with_debug("SIP ACK request")
            .with_trace("SIP: {json_pretty(.)}"),
    )
});

/// The reason phrase RFC 3261 section 21 gives a status code, used when an action names a
/// code and no `reason_phrase`. A class's generic phrase stands in for a code the table does
/// not list, so a 486 is never written "486 OK".
pub fn default_reason_phrase(code: u16) -> &'static str {
    match code {
        100 => "Trying",
        180 => "Ringing",
        181 => "Call Is Being Forwarded",
        182 => "Queued",
        183 => "Session Progress",
        200 => "OK",
        202 => "Accepted",
        300 => "Multiple Choices",
        301 => "Moved Permanently",
        302 => "Moved Temporarily",
        305 => "Use Proxy",
        380 => "Alternative Service",
        400 => "Bad Request",
        401 => "Unauthorized",
        402 => "Payment Required",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        406 => "Not Acceptable",
        407 => "Proxy Authentication Required",
        408 => "Request Timeout",
        410 => "Gone",
        413 => "Request Entity Too Large",
        414 => "Request-URI Too Long",
        415 => "Unsupported Media Type",
        416 => "Unsupported URI Scheme",
        420 => "Bad Extension",
        421 => "Extension Required",
        423 => "Interval Too Brief",
        480 => "Temporarily Unavailable",
        481 => "Call/Transaction Does Not Exist",
        482 => "Loop Detected",
        483 => "Too Many Hops",
        484 => "Address Incomplete",
        485 => "Ambiguous",
        486 => "Busy Here",
        487 => "Request Terminated",
        488 => "Not Acceptable Here",
        491 => "Request Pending",
        493 => "Undecipherable",
        500 => "Server Internal Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Server Time-out",
        505 => "Version Not Supported",
        513 => "Message Too Large",
        600 => "Busy Everywhere",
        603 => "Decline",
        604 => "Does Not Exist Anywhere",
        606 => "Not Acceptable",
        100..=199 => "Session Progress",
        200..=299 => "OK",
        300..=399 => "Redirection",
        400..=499 => "Request Failure",
        500..=599 => "Server Failure",
        _ => "Global Failure",
    }
}

/// The `answer_with` field of `sip_options`.
///
/// The event used to say "answer with sip_options listing the methods you support", and the
/// action's only example is a 200. Told "you are a SIP phone in do-not-disturb mode; tell
/// anyone who checks on you that you are busy", llama3.1:8b answered sipsak's OPTIONS with 200
/// OK five times in five. RFC 3261 section 11.2 makes the OPTIONS status the one an INVITE
/// would get, so the request says so, with the codes that carry each situation.
pub const OPTIONS_ANSWER_WITH: &str = "sip_options with the status an INVITE would get right \
     now: status_code 200 if your instructions say this endpoint is available to take a call; \
     486 (Busy Here) if they say it is busy, on another call or in do-not-disturb; 480 \
     (Temporarily Unavailable) if they say it is offline or away; 603 (Decline) if it refuses \
     every call";

/// SIP OPTIONS event
pub static SIP_OPTIONS_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "sip_options",
        "A client is checking on this endpoint with OPTIONS - whether it is reachable and \
         what it supports. RFC 3261 section 11.2: the status is the one an INVITE would get \
         right now, so 200 only when the endpoint would take a call; answer_with says which \
         code fits which situation.",
        json!({
            "type": "sip_options",
            "status_code": 200,
            "allow_methods": ["INVITE", "ACK", "BYE", "REGISTER", "OPTIONS"]
        }),
    )
    .with_parameters(vec![Parameter {
        name: "answer_with".to_string(),
        type_hint: "string".to_string(),
        description: "Which status this OPTIONS takes: the one an INVITE would get now - 200 \
                      available, 486 busy or do-not-disturb, 480 offline. Present for an \
                      OPTIONS request; absent for a method this server does not recognise"
            .to_string(),
        required: false,
    }])
    .with_actions(vec![sip_options_action()])
    .with_log_template(
        LogTemplate::new()
            .with_info("SIP OPTIONS")
            .with_debug("SIP OPTIONS request")
            .with_trace("SIP: {json_pretty(.)}"),
    )
});

/// SIP CANCEL event
pub static SIP_CANCEL_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "sip_cancel",
        "The client is cancelling a pending INVITE. Answer with sip_cancel; 200 confirms the \
         cancellation.",
        json!({"type": "sip_cancel", "status_code": 200}),
    )
    .with_actions(vec![sip_cancel_action()])
    .with_log_template(
        LogTemplate::new()
            .with_info("SIP CANCEL")
            .with_debug("SIP CANCEL request")
            .with_trace("SIP: {json_pretty(.)}"),
    )
});

// Action definitions
fn sip_register_action() -> ActionDefinition {
    ActionDefinition {
        name: "sip_register".to_string(),
        description: "Respond to SIP REGISTER request".to_string(),
        parameters: vec![
            Parameter {
                name: "status_code".to_string(),
                type_hint: "number".to_string(),
                description: "SIP status code (200=OK, 403=Forbidden, 401=Unauthorized)"
                    .to_string(),
                required: true,
            },
            Parameter {
                name: "reason_phrase".to_string(),
                type_hint: "string".to_string(),
                description: "Optional reason phrase (default based on status code)".to_string(),
                required: false,
            },
            Parameter {
                name: "expires".to_string(),
                type_hint: "number".to_string(),
                description: "Registration expiration in seconds (default 3600)".to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "sip_register",
            "status_code": 200,
            "expires": 3600
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> SIP {status_code} REGISTER")
                .with_debug("SIP sip_register: status={status_code}, expires={expires}"),
        ),
    }
}

fn sip_invite_action() -> ActionDefinition {
    ActionDefinition {
        name: "sip_invite".to_string(),
        description: "Respond to SIP INVITE request".to_string(),
        parameters: vec![
            Parameter {
                name: "status_code".to_string(),
                type_hint: "number".to_string(),
                description: "SIP status code (200=OK, 486=Busy, 603=Decline, 180=Ringing)"
                    .to_string(),
                required: true,
            },
            Parameter {
                name: "reason_phrase".to_string(),
                type_hint: "string".to_string(),
                description: "Optional reason phrase".to_string(),
                required: false,
            },
            Parameter {
                name: "sdp".to_string(),
                type_hint: "string".to_string(),
                description: "Session Description Protocol body (required for 200 OK)".to_string(),
                required: false,
            },
            Parameter {
                name: "rtp_audio".to_string(),
                type_hint: "object".to_string(),
                description: "Optional media to actually stream on a 200 OK: {content, tone_hz, \
                              payload_type, duration_ms}. When NetGet is built with the `rtp` \
                              feature, accepting a call streams this as real RTP to the m=audio \
                              target in the caller's INVITE SDP, so the negotiated session carries \
                              media rather than only promising it. Ignored without the `rtp` feature."
                    .to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "sip_invite",
            "status_code": 200,
            "sdp": "v=0\no=- 0 0 IN IP4 127.0.0.1\ns=Call\nc=IN IP4 127.0.0.1\nt=0 0\nm=audio 8000 RTP/AVP 0\n",
            "rtp_audio": {"content": "tone", "tone_hz": 440, "payload_type": "pcmu", "duration_ms": 2000}
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> SIP {status_code} INVITE")
                .with_debug("SIP sip_invite: status={status_code}"),
        ),
    }
}

fn sip_bye_action() -> ActionDefinition {
    ActionDefinition {
        name: "sip_bye".to_string(),
        description: "Respond to SIP BYE request".to_string(),
        parameters: vec![Parameter {
            name: "status_code".to_string(),
            type_hint: "number".to_string(),
            // Required, and there is no default. `build_sip_response` answers 500 when the
            // field is absent rather than defaulting to 200 - a defaulted 200 would turn a
            // forgotten field into an acceptance. The description used to promise a 200
            // default the executor has never applied.
            description: "SIP status code; 200 acknowledges the teardown. Required - an action \
                          with no status_code is answered 500, not 200"
                .to_string(),
            required: true,
        }],
        example: json!({
            "type": "sip_bye",
            "status_code": 200
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> SIP {status_code} BYE")
                .with_debug("SIP sip_bye: status={status_code}"),
        ),
    }
}

fn sip_ack_action() -> ActionDefinition {
    ActionDefinition {
        name: "sip_ack".to_string(),
        description: "Process SIP ACK (no response needed)".to_string(),
        parameters: vec![],
        example: json!({
            "type": "sip_ack"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> SIP ACK processed")
                .with_debug("SIP sip_ack"),
        ),
    }
}

fn sip_options_action() -> ActionDefinition {
    ActionDefinition {
        name: "sip_options".to_string(),
        description: "Answer an OPTIONS request. Its status is the one an INVITE would get \
                      right now (RFC 3261 section 11.2): 200 when this endpoint is available, \
                      486 Busy Here when it is busy or in do-not-disturb, 480 Temporarily \
                      Unavailable when it is offline, 600 Busy Everywhere or 603 Decline when \
                      it refuses every call."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "status_code".to_string(),
                type_hint: "number".to_string(),
                description: "SIP status code: 200 available, 486 busy / do-not-disturb, 480 \
                              unavailable, 603 decline. Required - an action with no \
                              status_code is answered 500, not 200"
                    .to_string(),
                required: true,
            },
            Parameter {
                name: "allow_methods".to_string(),
                type_hint: "array".to_string(),
                description: "Array of supported SIP methods".to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "sip_options",
            "status_code": 200,
            "allow_methods": ["INVITE", "ACK", "BYE", "REGISTER", "OPTIONS"]
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> SIP {status_code} OPTIONS")
                .with_debug("SIP sip_options: status={status_code}, methods={allow_methods_len}"),
        ),
    }
}

fn sip_cancel_action() -> ActionDefinition {
    ActionDefinition {
        name: "sip_cancel".to_string(),
        description: "Respond to SIP CANCEL request".to_string(),
        parameters: vec![Parameter {
            name: "status_code".to_string(),
            type_hint: "number".to_string(),
            description: "SIP status code; 200 confirms the cancellation. Required - an action \
                          with no status_code is answered 500, not 200"
                .to_string(),
            required: true,
        }],
        example: json!({
            "type": "sip_cancel",
            "status_code": 200
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> SIP {status_code} CANCEL")
                .with_debug("SIP sip_cancel: status={status_code}"),
        ),
    }
}

// User-triggered actions
