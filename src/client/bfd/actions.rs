//! What the model can do as a BFD client: bring a session up with one router (the active
//! role) and steer it — timers, AdminDown, back up — as its state changes.
use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, ParameterDefinition, StartupExamples,
};
use crate::protocol::{ConnectContext, EventType};
use crate::server::bfd::actions::{
    action, admin_down_action, admin_up_action, auth_params, p, set_timers_action, state_params,
    timer_startup_params,
};
use crate::server::bfd::packet;
use crate::state::app_state::AppState;
use anyhow::Result;
use serde_json::{json, Value};
use std::sync::LazyLock;

#[derive(Default)]
pub struct BfdClientProtocol;
impl BfdClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

fn disconnect_action() -> ActionDefinition {
    action(
        "disconnect",
        "End the session: stop sending, so the router's detection timer brings it down.",
        vec![],
        json!({"type":"disconnect"}),
    )
}

pub fn actions() -> Vec<ActionDefinition> {
    vec![
        set_timers_action(),
        admin_down_action(),
        admin_up_action(),
        disconnect_action(),
    ]
}

pub static STARTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "bfd_session_started",
        "The client is sending Control packets to the router; the session comes Up when the router answers.",
        set_timers_action().example.clone(),
    )
    .with_parameters(vec![
        p("peer", "string", "The router's address and BFD port", true),
        p("local", "string", "The address NetGet sends from and listens on", true),
        p("local_discriminator", "number", "This side's discriminator", true),
        p("multihop", "boolean", "Multihop (RFC 5883, port 4784) rather than single-hop (RFC 5881, 3784)", true),
    ])
    .with_actions(actions())
});

pub static STATE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "bfd_session_state",
        "The session with the router changed state. Optionally change timers, take it down, bring it back, or disconnect.",
        set_timers_action().example.clone(),
    )
    .with_parameters(state_params())
    .with_actions(actions())
});

impl Protocol for BfdClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "BFD"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>UDP>BFD"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "bfd",
            "bidirectional forwarding detection",
            "bfd client",
            "bfd session",
        ]
    }
    fn description(&self) -> &'static str {
        "BFD client: brings up a BFD session with a router (BIRD, FRR, a vendor box) in the active role and reports every state change"
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        actions()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![STARTED_EVENT.clone(), STATE_EVENT.clone()]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        let mut params = vec![
            ParameterDefinition {
                name: "local_address".into(),
                type_hint: "string".into(),
                description: "The IP to send from and listen on: the address the router has configured as its neighbour (default: the one the route to the router uses)".into(),
                required: false,
                example: json!("192.0.2.2"),
                default: None,
            },
            ParameterDefinition {
                name: "multihop".into(),
                type_hint: "boolean".into(),
                description: "Multihop BFD (RFC 5883, port 4784): no TTL-255 check. Defaults to true when remote_addr names port 4784".into(),
                required: false,
                example: json!(true),
                default: None,
            },
        ];
        params.extend(timer_startup_params());
        params.extend(auth_params());
        params
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation("The server's RFC 5880 engine (src/server/bfd/) in the active role: one session to remote_addr, sent from a source port in 49152-65535 with TTL 255, received on local_address at the BFD port beside any routing daemon there (SO_REUSEADDR); single-hop packets with a TTL other than 255 are dropped")
            .llm_control("The session's timers, taking it administratively down and back up, and ending it, in reaction to each state change")
            .e2e_testing("tests/client/bfd: BIRD 2 with a static multihop session to NetGet, read back with birdc (Up, timers renegotiated by Poll Sequence, AdminDown and back, keyed MD5)")
            .notes("No Demand mode, no Echo function. Neither side of the session is the model's per packet: the model is asked when the session starts and when its state changes.")
            .max_inbound_bytes(packet::MAX_PACKET)
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Bring up a multihop BFD session with the router at 192.0.2.1 and tell me when it goes down"
    }
    fn get_startup_examples(&self) -> StartupExamples {
        let llm = json!({"type":"open_client","protocol":"bfd","remote_addr":"127.0.0.1:4784",
            "startup_params":{"local_address":"127.0.0.4","desired_min_tx_ms":100,"required_min_rx_ms":100},
            "instruction":"Keep a BFD session up with the router; once it is Up, slow it to 500 ms"});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([
            {"event_pattern":"*","handler":{"type":"static","actions":[]}}
        ]);
        let mut scripted = llm.clone();
        scripted["event_handlers"] = json!([{"event_pattern":"bfd_session_state","handler":{"type":"script","language":"python",
            "code":"import json,sys\ne=json.load(sys.stdin)['event']\nprint(json.dumps({'actions':[{'type':'bfd_set_timers','desired_min_tx_ms':500,'required_min_rx_ms':500}] if e['state']=='Up' and e['required_min_rx_ms']!=500 else []}))"}}]);
        StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Routing"
    }
}

impl Client for BfdClientProtocol {
    fn connect(
        &self,
        ctx: ConnectContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::connect(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ClientActionResult> {
        if v["type"] == "disconnect" {
            return Ok(ClientActionResult::Disconnect);
        }
        crate::server::bfd::runner::check_action(&v)?;
        Ok(ClientActionResult::Custom {
            name: v["type"].as_str().unwrap_or_default().to_string(),
            data: v,
        })
    }
}
