use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, ParameterDefinition, StartupExamples,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::{
    metadata::{DevelopmentState, ProtocolMetadataV2},
    ConnectContext, EventType,
};
use crate::server::netflow_v9::{
    actions::{duration_parameter, parameter},
    codec::{self, Batch},
};
use crate::state::app_state::AppState;
use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;
#[derive(Default)]
pub struct NetflowV9ClientProtocol;
impl NetflowV9ClientProtocol {
    pub fn new() -> Self {
        Self
    }
}
pub fn example_batch() -> Value {
    json!({"source_id":42,"templates":[{"id":256,"fields":[{"element":"source_ipv4"},{"element":"destination_ipv4"},{"element":"in_packets"}]}],"data_sets":[{"template_id":256,"records":[[{"kind":"ipv4","value":"192.0.2.1"},{"kind":"ipv4","value":"198.51.100.2"},{"kind":"unsigned","value":5}]]}]})
}
fn send() -> ActionDefinition {
    ActionDefinition{name:"export_netflow_v9_records".into(),description:"Validate one complete typed v9 UDP packet before emitting; repeats every referenced template, counts all records in Count and advances Source-ID sequence by one packet. Local transport only, no ACK or data retry.".into(),parameters:vec![parameter("batch","object","source_id:u32;optional export_time:u32,sys_uptime_ms:u32;1..32 templates(id>=256,scope_count default0,ordered fields declaring exactly one supported element or scope and optional fixed length);data_sets(template_id,records of aligned {kind,value}). Kinds unsigned/ipv4/ipv6/uptime_milliseconds. Options scopes first(system/interface/line_card/cache/template), followed by options.8192bytes,64flowsets,256data records,32fields,record size>=4; no variable fields or raw bytes.",true)],example:json!({"type":"export_netflow_v9_records","batch":example_batch()}),log_template:Some(LogTemplate::new().with_info("NetFlow v9 export queued for Source ID {batch.source_id}"))}
}
fn disconnect() -> ActionDefinition {
    ActionDefinition {
        name: "disconnect".into(),
        description: "Cancel UDP sends, template refresh, handlers and command handle".into(),
        parameters: vec![],
        example: json!({"type":"disconnect"}),
        log_template: Some(LogTemplate::new().with_info("NetFlow v9 exporter disconnected")),
    }
}
pub static NETFLOW_V9_CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "netflow_v9_connected",
        "UDP exporter ready; collector reception is unconfirmed.",
        send().example,
    )
    .with_parameters(vec![
        parameter("remote_addr", "string", "Collector UDP address", true),
        parameter("local_addr", "string", "Exporter UDP socket", true),
    ])
    .with_actions(vec![send(), disconnect()])
});
pub static NETFLOW_V9_EXPORTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new("netflow_v9_exported","One datagram accepted by the local UDP transport, not an end-to-end receipt or persistence acknowledgment.",send().example).with_parameters(vec![parameter("source_id","number","Observation Source ID",true),parameter("sequence_number","number","Header sequence before increment",true),parameter("record_count","number","Data/options records",true),parameter("header_count","number","All template and data/options records",true),parameter("sys_uptime_ms","number","Export uptime milliseconds",true),parameter("template_count","number","Templates supplied in this packet",true),parameter("byte_count","number","Datagram length",true),parameter("local_transport_only","boolean","Always true; local UDP send does not confirm reception",true)]).with_actions(vec![send(),disconnect()])
});
impl Protocol for NetflowV9ClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "NetFlowV9"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>UDP>NetFlowV9"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["netflow-v9", "netflowv9", "netflow_v9"]
    }
    fn description(&self) -> &'static str {
        "Typed UDP NetFlow v9 exporter with template refresh and per-Source-ID packet sequence"
    }
    fn example_prompt(&self) -> &'static str {
        "Export NETFLOW_V9 records to localhost:2055"
    }
    fn group_name(&self) -> &'static str {
        "Network Management"
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        vec![send(), disconnect()]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            NETFLOW_V9_CONNECTED_EVENT.clone(),
            NETFLOW_V9_EXPORTED_EVENT.clone(),
        ]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![duration_parameter("template_refresh_seconds",super::transport::DEFAULT_REFRESH_SECONDS,"Periodic active-template retransmission,1..3600seconds; every record batch also repeats its templates")]
    }
    fn metadata(&self) -> ProtocolMetadataV2 {
        ProtocolMetadataV2::builder().state(DevelopmentState::Experimental).well_known_udp_port(2055)
        .implementation("Native typed RFC3954 v9 UDP normal/options template and data encoder; owned periodic template refresh")
        .llm_control("Connected/local-export events through common handlers/shared memory; bounded actions and injection independent of parked handlers")
        .e2e_testing("Required actual GoFlow2 2.2.7 service independently decodes exported IPv4/IPv6, counters, uptime and options scopes; native literal/lifecycle/atomic bounds and unmodified softflowd exporter cross-check")
        .notes("Experimental UDP-only selected RFC3954 subset. Count includes templates and data/options records; Source-ID sequence advances once per locally sent packet, including template-only refresh, modulo2^32.32Source IDs,32active templates each; identical definitions allowed, ID redefinition rejected until a new exporter instance. All referenced templates supplied per batch. Periodic time refresh60s configurable1..3600s; no packet-count refresh knob or data retry. sysUpTime defaults to per-source monotonic elapsed time since its first batch; explicit unsigned32 override carried forward for refresh. Unix seconds default system clock or caller unsigned32 override.8192bytes,64flowsets,256data records,32fields,minimum record4bytes;35selected RFC fields,5unsigned scopes, fixed-width data only. One in-flight operation,10sresolve/send,32events/actions,depth8. Refresh candidates commit only after all local sends; failure closes and discards transient state. UDP acceptance does not prove receipt/processing/storage. No ACK, TCP/SCTP/TLS/auth, variable/enterprise extensions, full vendor model, flow capture/store, durability, fuzz or packet-capture evidence.").history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
        .batching(crate::protocol::metadata::BatchingMode::Unsupported)
        .build()
    }
    fn get_startup_examples(&self) -> StartupExamples {
        StartupExamples::new(
            json!({"type":"open_client","base_stack":"netflow_v9","remote_addr":"localhost:2055","instruction":"Export a flow record"}),
            json!({"type":"open_client","base_stack":"netflow_v9","remote_addr":"localhost:2055","event_handlers":[{"event_pattern":"netflow_v9_connected","handler":{"type":"script","language":"python","code":format!("import json,sys\njson.load(sys.stdin)\nprint({:?})",json!({"actions":[send().example]}).to_string())}}]}),
            json!({"type":"open_client","base_stack":"netflow_v9","remote_addr":"localhost:2055","event_handlers":[{"event_pattern":"netflow_v9_connected","handler":{"type":"static","actions":[send().example]}}]}),
        )
    }
}
impl Client for NetflowV9ClientProtocol {
    fn connect(
        &self,
        ctx: ConnectContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::NetflowV9Client::connect(ctx))
    }
    fn execute_action(&self, action: Value) -> Result<ClientActionResult> {
        match action["type"].as_str() {
            Some("export_netflow_v9_records") => {
                let batch: Batch =
                    serde_json::from_value(action.get("batch").context("missing batch")?.clone())?;
                codec::encode(
                    &batch,
                    0,
                    batch.export_time.unwrap_or(0),
                    batch.sys_uptime_ms.unwrap_or(0),
                )?;
                Ok(ClientActionResult::Custom {
                    name: "export_netflow_v9_records".into(),
                    data: serde_json::to_value(batch)?,
                })
            }
            Some("disconnect") => Ok(ClientActionResult::Disconnect),
            _ => bail!("unknown NETFLOW_V9 exporter action"),
        }
    }
}
