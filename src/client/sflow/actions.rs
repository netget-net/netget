use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, StartupExamples,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::{
    metadata::{DevelopmentState, ProtocolMetadataV2},
    ConnectContext, EventType,
};
use crate::server::sflow::{
    actions::parameter,
    codec::{self, Batch},
};
use crate::state::app_state::AppState;
use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

#[derive(Default)]
pub struct SflowClientProtocol;
impl SflowClientProtocol {
    pub fn new() -> Self {
        Self
    }
}
pub fn example_batch() -> Value {
    json!({"agent_address":"192.0.2.1","sub_agent_id":0,"samples":[{
        "kind":"flow","sequence_number":1,"source":{"class":0,"index":3},
        "sampling_rate":1000,"sample_pool":1000,"drops":0,
        "input":{"format":0,"value":3},"output":{"format":0,"value":4},
        "records":[{"kind":"sampled_ipv4","packet_length":64,"protocol":17,
            "source_ip":"192.0.2.2","destination_ip":"198.51.100.2","source_port":53,
            "destination_port":123,"tcp_flags":0,"traffic_class":0}]}]})
}
fn send() -> ActionDefinition {
    ActionDefinition {
        name:"export_sflow_samples".into(),
        description:"Validate a complete typed sFlow v5 batch and send one UDP datagram. Sequence counts locally sent datagrams; transport acceptance does not acknowledge collector reception. Sample sequence/pool/drop counters are supplied by the caller.".into(),
        parameters:vec![parameter("batch","object","agent_address,sub_agent_id,optional uptime_ms,1..32 samples. kind flow/counters; expanded optional(defaultfalse);sequence_number,source(class0..2,index). Flow requires sampling_rate,sample_pool,drops,input/output(format0..2,value),records. Flow records: sampled_ipv4/ipv6 with addresses,packet_length,protocol,ports,tcp_flags,traffic_class; synthesized_header with packet plus frame_length/stripped; ethernet with MACs/ether_type;extended_switch. Counter records: interface(all19fields),ethernet(all13fields),vlan(all6fields).8192bytes,64records/sample,256total; no opaque packet bytes.",true)],
        example:json!({"type":"export_sflow_samples","batch":example_batch()}),
        log_template:Some(LogTemplate::new().with_info("sFlow samples queued for local UDP export")),
    }
}
fn disconnect() -> ActionDefinition {
    ActionDefinition {
        name: "disconnect".into(),
        description: "Cancel the exporter, handlers and command channel".into(),
        parameters: vec![],
        example: json!({"type":"disconnect"}),
        log_template: Some(LogTemplate::new().with_info("sFlow exporter disconnected")),
    }
}
pub static SFLOW_CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "sflow_connected",
        "sFlow v5 UDP exporter is locally ready; reception is unconfirmed.",
        send().example,
    )
    .with_parameters(vec![
        parameter(
            "remote_addr",
            "string",
            "Target collector UDP address and port",
            true,
        ),
        parameter("local_addr", "string", "UDP exporter socket", true),
    ])
    .with_actions(vec![send(), disconnect()])
});
pub static SFLOW_EXPORTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new("sflow_exported","One datagram accepted by local UDP transport, without a receipt or persistence acknowledgment.",send().example)
        .with_parameters(vec![parameter("agent_address","string","Declared monitored agent IPv4 or IPv6 address",true),parameter("sub_agent_id","number","Unsigned identifier of this agent exporter instance",true),
            parameter("sequence_number","number","Datagram sequence before increment",true),parameter("uptime_ms","number","Unsigned32 reported uptime",true),
            parameter("sample_count","number","Number of flow and counter samples in the datagram",true),parameter("record_count","number","Total telemetry records across all samples",true),
            parameter("byte_count","number","Number of encoded bytes accepted by local UDP transport",true),parameter("local_transport_only","boolean","True reports local UDP send acceptance, without collector acknowledgment",true)])
        .with_actions(vec![send(),disconnect()])
});
impl Protocol for SflowClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "sFlow"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>UDP>SFLOW"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["sflow", "sflow-v5"]
    }
    fn description(&self) -> &'static str {
        "Typed bounded sFlow v5 UDP sample exporter"
    }
    fn example_prompt(&self) -> &'static str {
        "Export sFlow samples to localhost:6343"
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
        vec![SFLOW_CONNECTED_EVENT.clone(), SFLOW_EXPORTED_EVENT.clone()]
    }
    fn metadata(&self) -> ProtocolMetadataV2 {
        ProtocolMetadataV2::builder().state(DevelopmentState::Experimental).well_known_udp_port(6343)
            .implementation("Native bounded sFlow v5 XDR encoder with compact/expanded flow and counter samples; no Cargo protocol dependency")
            .llm_control("Typed export actions and transport-only events through common handlers/shared memory; command injection independent of parked handlers")
            .e2e_testing("Required pinned unmodified BSD Cistern exporter/decoder, actual GoFlow2 collector, literal wire/typed goldens and native lifecycle/bounds checks")
            .notes("Experimental manually supplied telemetry subset, not a full sFlow agent: no packet capture, statistical sampler, automatic counter polling, SNMP configuration, aggregation/store, ACK, reliability or authentication. v5 only; four sample formats; selected flow records1/2/3/4/1001 and counters1/2/5. Synthesized raw headers use typed IPv4/IPv6 TCP/UDP summaries; no payload, transport-checksum or capture-integrity claim. 8192bytes/datagram,32samples,64records/sample,256records;32declared agent/sub-agent sequence states, modulo2^32 datagram count starting0. Explicit sample sequence numbers describe caller-owned sFlow instances, not inferred from source alone; uptime optional caller value or elapsed logical client time modulo2^32.10s resolve/write deadlines,oneinflight,32queued events/actions,followup depth8. Required Cistern peer source-ID encoder defect compensated through public arguments; VLAN encoder excluded, evidence uses literal and GoFlow2. No fuzz/pcap/full compliance claim.")
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn get_startup_examples(&self) -> StartupExamples {
        StartupExamples::new(
            json!({"type":"open_client","base_stack":"sflow","remote_addr":"localhost:6343"}),
            json!({"type":"open_client","base_stack":"sflow","remote_addr":"localhost:6343","event_handlers":[{"event_pattern":"sflow_connected","handler":{"type":"script","language":"python","code":format!("import json,sys\njson.load(sys.stdin)\nprint({:?})",json!({"actions":[send().example]}).to_string())}}]}),
            json!({"type":"open_client","base_stack":"sflow","remote_addr":"localhost:6343","event_handlers":[{"event_pattern":"sflow_connected","handler":{"type":"static","actions":[send().example]}}]}),
        )
    }
}
impl Client for SflowClientProtocol {
    fn connect(
        &self,
        ctx: ConnectContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::SflowClient::connect(ctx))
    }
    fn execute_action(&self, action: Value) -> Result<ClientActionResult> {
        match action["type"].as_str() {
            Some("export_sflow_samples") => {
                let batch: Batch =
                    serde_json::from_value(action.get("batch").context("missing batch")?.clone())?;
                codec::encode(&batch, 0, batch.uptime_ms.unwrap_or(0))?;
                Ok(ClientActionResult::Custom {
                    name: "export_sflow_samples".into(),
                    data: serde_json::to_value(batch)?,
                })
            }
            Some("disconnect") => Ok(ClientActionResult::Disconnect),
            _ => bail!("unknown sFlow exporter action"),
        }
    }
}
