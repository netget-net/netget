//! Zabbix trapper actions: what the model is told, and how its answer becomes a response.
//!
//! The model is the Zabbix server's item processing: it sees the values a sender reported and
//! decides how many it accepted. It supplies two counts; [`super::wire::render_result`] writes
//! the response and the `info` string, so the model cannot produce one `zabbix_sender`
//! misreads. The session loop checks that the counts add up to the request's own total.

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

pub struct ZabbixProtocol;

impl ZabbixProtocol {
    pub fn new() -> Self {
        Self
    }
}

impl Default for ZabbixProtocol {
    fn default() -> Self {
        Self::new()
    }
}

impl Protocol for ZabbixProtocol {
    fn get_startup_parameters(&self) -> Vec<crate::llm::actions::ParameterDefinition> {
        vec![
            crate::llm::actions::ParameterDefinition {
                name: "first_byte_timeout_secs".to_string(),
                type_hint: "number".to_string(),
                description: "Seconds a new connection may send nothing before the server \
                              closes it. Default 30: zabbix_sender writes its whole request the \
                              moment it connects."
                    .to_string(),
                required: false,
                example: json!(30),
                default: Some(serde_json::json!(super::FIRST_BYTE_TIMEOUT.as_secs())),
            },
            crate::llm::actions::ParameterDefinition {
                name: "idle_timeout_secs".to_string(),
                type_hint: "number".to_string(),
                description: "Seconds the server waits for the rest of a request that has \
                              started arriving. Default 30."
                    .to_string(),
                required: false,
                example: json!(30),
                default: Some(serde_json::json!(super::IDLE_TIMEOUT.as_secs())),
            },
        ]
    }
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        Vec::new()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![send_result_action(), close_connection_action()]
    }
    fn protocol_name(&self) -> &'static str {
        "Zabbix"
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![ZABBIX_SENDER_DATA_EVENT.clone()]
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>Zabbix"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["zabbix", "zabbix trapper", "zabbix_sender", "trapper"]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{
            DevelopmentState, PrivilegeRequirement, ProtocolMetadataV2,
        };

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Beta)
            .well_known_port(10051)
            // 10051 is unprivileged, and so is every port a test picks.
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation(
                "Hand-written Zabbix protocol framing (ZBXD header, standard and large \
                 lengths) over tokio TCP; the sender-data request parsed with serde_json and \
                 the response and its info string rendered by NetGet",
            )
            .llm_control(
                "Which reported values the trapper accepts: the processed and failed counts \
                 zabbix_sender prints and bases its exit status on",
            )
            .e2e_testing(
                "tests/server/zabbix/real_client_test.rs drives the real zabbix_sender 7.4 \
                 (Homebrew `zabbix`, Ubuntu `zabbix-sender`): a single value with -s/-k/-o and \
                 a batch with -i, asserting on the processed/failed summary it printed and on \
                 its exit status (0 all processed, 2 some failed), with Wireshark's zabbix \
                 dissector reading the captured exchange. It fails, never skips, when the \
                 binary is absent. tests/server/zabbix/e2e_test.rs covers the mocked-model \
                 path on a raw socket.",
            )
            .notes(
                "Implements the trapper side of the Zabbix protocol for the `sender data` \
                 request: one request per connection, answered and closed, as the Zabbix \
                 server does. Other requests (active checks, agent data, zabbix.stats) are \
                 answered `failed` without consulting the model. Compressed packets (flag \
                 0x02) are refused: zabbix_sender 7.4 does not send them. Requests are capped \
                 at 1 MiB (the protocol allows 1 GiB; every byte goes into a model prompt) \
                 and 1000 values, checked against the declared length before allocation. \
                 NetGet stores nothing: the model only says how many values it accepted. On \
                 backend failure or an answer whose counts do not add up to the request, the \
                 sender is told `processed: 0; failed: N` — which makes zabbix_sender exit 2 \
                 — rather than a `failed` response, on which zabbix_sender 7.4 exits 0.",
            )
            .max_inbound_bytes(wire::MAX_DATA_BYTES)
            // A `success` response counting every value as failed: zabbix_sender exits 2.
            .answers_on_failure()
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "Zabbix trapper (zabbix_sender) - the model decides which reported values it accepts"
    }
    fn example_prompt(&self) -> &'static str {
        "Zabbix trapper on port 10051 - accept every value except those for unknown hosts"
    }
    fn group_name(&self) -> &'static str {
        "Application"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        StartupExamples::new(
            json!({
                "type": "open_server",
                "port": 10051,
                "base_stack": "zabbix",
                "instruction": "Zabbix trapper for hosts web1 and db1. Accept every value \
                                reported for those hosts and count values for any other host \
                                as failed."
            }),
            json!({
                "type": "open_server",
                "port": 10051,
                "base_stack": "zabbix",
                "event_handlers": [{
                    "event_pattern": "zabbix_sender_data",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "import json, sys\nitems = json.load(sys.stdin)['event'].get('items', [])\nok = sum(1 for i in items if i.get('host') in ('web1', 'db1'))\nprint(json.dumps({'actions': [{'type': 'send_zabbix_result', 'processed': ok, 'failed': len(items) - ok}]}))"
                    }
                }]
            }),
            json!({
                "type": "open_server",
                "port": 10051,
                "base_stack": "zabbix",
                "event_handlers": [{
                    "event_pattern": "zabbix_sender_data",
                    "handler": {
                        "type": "static",
                        "actions": [{"type": "send_zabbix_result", "processed": 1, "failed": 0}]
                    }
                }]
            }),
        )
    }
}

impl Server for ZabbixProtocol {
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

            crate::server::zabbix::ZabbixServer::spawn_with_llm_actions(
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

        match action_type {
            "send_zabbix_result" => {
                let processed = count(&action, "processed")?.context(
                    "send_zabbix_result needs 'processed', the number of accepted values",
                )?;
                let failed = count(&action, "failed")?.unwrap_or(0);
                let total = processed
                    .checked_add(failed)
                    .context("processed + failed overflows")?;
                // The session loop replaces `seconds spent` with the real figure and checks
                // `total` against the request; an injected result goes out as rendered here.
                Ok(ActionResult::Output(wire::render_result(
                    processed, failed, total, 0.0,
                )))
            }
            "close_connection" => Ok(ActionResult::CloseConnection),
            _ => Err(anyhow!("Unknown Zabbix action: {}", action_type)),
        }
    }
}

fn count(action: &Value, name: &str) -> Result<Option<u64>> {
    match action.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => v
            .as_u64()
            .or_else(|| v.as_str().and_then(|s| s.trim().parse().ok()))
            .map(Some)
            .with_context(|| format!("'{name}' must be a non-negative integer")),
    }
}

fn send_result_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_zabbix_result".to_string(),
        description: "Tell the sender how many of its values were accepted. processed + failed \
                      must equal the number of items in the event (the example is for a \
                      request of 3 values; count yours). A value is processed only when your \
                      instructions accept values for its host (and key); otherwise it failed. \
                      NetGet writes the response zabbix_sender prints (processed: P; failed: F; \
                      total: T; seconds spent: S); zabbix_sender exits 0 when failed is 0 and \
                      2 otherwise."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "processed".to_string(),
                type_hint: "number".to_string(),
                description: "How many values were accepted".to_string(),
                required: true,
            },
            Parameter {
                name: "failed".to_string(),
                type_hint: "number".to_string(),
                description: "How many values were rejected (unknown host, wrong key, bad \
                              value)"
                    .to_string(),
                required: true,
            },
        ],
        example: json!({"type": "send_zabbix_result", "processed": 2, "failed": 1}),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> Zabbix processed {processed}, failed {failed}")
                .with_debug("Zabbix send_zabbix_result: processed={processed} failed={failed}"),
        ),
    }
}

fn close_connection_action() -> ActionDefinition {
    ActionDefinition {
        name: "close_connection".to_string(),
        description: "Close the connection without answering; zabbix_sender reports the send \
                      as failed"
            .to_string(),
        parameters: vec![],
        example: json!({"type": "close_connection"}),
        log_template: Some(
            LogTemplate::new()
                .with_info("Zabbix connection closed")
                .with_debug("Zabbix close_connection"),
        ),
    }
}

/// The `answer_with` field of `zabbix_sender_data`: the hosts to check and the counts that
/// must add up.
///
/// Two misses in the real-model eval (llama3.1:8b, seed 42): told "monitoring only the host
/// web1; values for any other host cannot be stored", the model accepted a value from host
/// mystery-box five runs in five, never comparing `items[].host` with the instruction; and
/// told to accept everything from web1 and db1, it answered a one-value request with
/// `processed: 2` - the example's figure - two runs in five. The request now names each host
/// and how many values it reported, and the total the counts must reach. For a request from a
/// single host - what zabbix_sender sends unless given a batch file - it leads with the lookup
/// and gives both answers as literal actions: worded as a question with a total to reach, the
/// model still accepted mystery-box five runs in five.
pub fn answer_with_for_items<'a>(hosts: impl IntoIterator<Item = &'a str>) -> String {
    let mut per_host: Vec<(&str, u64)> = Vec::new();
    let mut total = 0u64;
    for host in hosts {
        total += 1;
        match per_host.iter_mut().find(|(h, _)| *h == host) {
            Some((_, n)) => *n += 1,
            None => per_host.push((host, 1)),
        }
    }
    let listed = per_host
        .iter()
        .map(|(host, n)| {
            let values = if *n == 1 { "value" } else { "values" };
            format!("{n} {values} from host \"{host}\"")
        })
        .collect::<Vec<_>>()
        .join(", ");
    if let [(host, n)] = per_host.as_slice() {
        // One host: the whole answer is one of two literal actions, so name both.
        return format!(
            "this request carries {listed}. First look in your instructions for the host \
             \"{host}\". If they do not accept values from it - including when they name the \
             hosts they monitor and \"{host}\" is not one of them - answer exactly \
             {{\"type\": \"send_zabbix_result\", \"processed\": 0, \"failed\": {n}}}. \
             Only if they accept values from \"{host}\", answer exactly {{\"type\": \
             \"send_zabbix_result\", \"processed\": {n}, \"failed\": 0}}"
        );
    }
    format!(
        "this request carries {listed}. For each host, first look in your instructions: are \
         values for that host accepted? Count its values as processed if they are and as \
         failed if they are not (a host they do not name is not accepted when they name the \
         hosts they monitor). Then send_zabbix_result where processed + failed = {total}"
    )
}

/// A `sender data` request.
pub static ZABBIX_SENDER_DATA_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "zabbix_sender_data",
        "A sender (zabbix_sender or an application) reported values for trapper items. Decide \
         how many you accept and answer with send_zabbix_result; processed + failed must equal \
         item_count.",
        json!({"type": "send_zabbix_result", "processed": 2, "failed": 0}),
    )
    .with_parameters(vec![
        Parameter {
            name: "items".to_string(),
            type_hint: "array".to_string(),
            description: "The reported values: [{host, key, value, clock?, ns?}], value as \
                          text, clock in Unix seconds when the sender gave one"
                .to_string(),
            required: true,
        },
        Parameter {
            name: "item_count".to_string(),
            type_hint: "number".to_string(),
            description: "How many values the request carries".to_string(),
            required: true,
        },
        Parameter {
            name: "answer_with".to_string(),
            type_hint: "string".to_string(),
            description: "The counts this request takes: the hosts it reports for, and that \
                          processed + failed must add up to item_count"
                .to_string(),
            required: true,
        },
        Parameter {
            name: "clock".to_string(),
            type_hint: "number".to_string(),
            description: "When the sender sent the request (Unix seconds), if it said".to_string(),
            required: false,
        },
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("Zabbix sender data: {item_count} value(s)")
            .with_debug("Zabbix zabbix_sender_data: item_count={item_count}"),
    )
    .with_actions(vec![send_result_action(), close_connection_action()])
    .with_alternative_example(json!({"type": "send_zabbix_result", "processed": 0, "failed": 2}))
});
