//! What the model decides as a LoRaWAN gateway: which configured device sends what, when.
//! NetGet builds and signs every frame from the device's keys and reports every downlink the
//! network server schedules, decrypted when it holds the session.
use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, Parameter, ParameterDefinition, StartupExamples,
};
use crate::protocol::{log_template::LogTemplate, ConnectContext, EventType};
use crate::server::lorawan::actions::{
    check_downlink as check_payload, devices_param, p, payload_params, region_param,
};
use crate::server::lorawan::{region, semtech};
use crate::state::app_state::AppState;
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

pub const SEND_JOIN: &str = "lorawan_send_join_request";
pub const SEND_UPLINK: &str = "lorawan_send_uplink";
pub const DISCONNECT: &str = "disconnect";

pub const DEFAULT_GATEWAY_EUI: &str = "4e65744765740001";
pub const DEFAULT_KEEPALIVE_SECS: u64 = 10;
pub const DEFAULT_STAT_INTERVAL_SECS: u64 = 30;

fn action(
    name: &str,
    description: &str,
    parameters: Vec<Parameter>,
    example: Value,
    log: &str,
) -> ActionDefinition {
    ActionDefinition {
        name: name.into(),
        description: description.into(),
        parameters,
        example,
        log_template: Some(LogTemplate::new().with_info(log)),
    }
}

fn radio_params() -> Vec<Parameter> {
    vec![
        p(
            "frequency_mhz",
            "number",
            "The channel it was heard on (default 868.1; EU868 863..870)",
            false,
        ),
        p(
            "data_rate",
            "string",
            "SF7BW125 (default) .. SF12BW125, or SF7BW250",
            false,
        ),
        p(
            "rssi",
            "number",
            "Signal strength to report, dBm (default -60)",
            false,
        ),
        p("snr", "number", "SNR to report, dB (default 7)", false),
    ]
}

fn device_param() -> Parameter {
    p(
        "device",
        "string",
        "The configured device: its name or its DevEUI",
        true,
    )
}

pub fn join_action() -> ActionDefinition {
    let mut params = vec![device_param()];
    params.extend(radio_params());
    action(
        SEND_JOIN,
        "An OTAA device sends a Join Request through this gateway (a fresh DevNonce, signed with its AppKey). The network's Join Accept arrives as lorawan_join_accepted.",
        params,
        json!({"type": SEND_JOIN, "device": "meter-1"}),
        "-> LoRaWAN Join Request from {device}",
    )
}

pub fn uplink_action() -> ActionDefinition {
    let mut params = vec![device_param()];
    params.extend(payload_params("Application port, 1..223"));
    params.extend([
        p(
            "link_check",
            "boolean",
            "Also ask the network for a LinkCheckAns (default false)",
            false,
        ),
        p(
            "battery",
            "number",
            "Battery level for the DevStatusAns NetGet sends when the network asked for one: 0 external power, 1..254, 255 unknown (default 255)",
            false,
        ),
    ]);
    params.extend(radio_params());
    action(
        SEND_UPLINK,
        "A joined (or ABP) device sends a data uplink through this gateway: NetGet encrypts the payload with its AppSKey, numbers it, signs it with its NwkSKey, acknowledges a confirmed downlink and answers a pending DevStatusReq.",
        params,
        json!({"type": SEND_UPLINK, "device": "meter-1", "f_port": 2, "payload": "21.5C", "confirmed": false}),
        "-> LoRaWAN uplink from {device} port {f_port}",
    )
}

pub fn disconnect_action() -> ActionDefinition {
    action(
        DISCONNECT,
        "Stop being a gateway: no more keepalives, nothing more is forwarded.",
        vec![],
        json!({"type": DISCONNECT}),
        "-> LoRaWAN gateway disconnect",
    )
}

pub fn actions() -> Vec<ActionDefinition> {
    vec![join_action(), uplink_action(), disconnect_action()]
}

pub static CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "lorawan_gateway_connected",
        "The gateway acknowledged by the network server (PULL_ACK): devices can join and send.",
        join_action().example.clone(),
    )
    .with_parameters(vec![
        p("network_server", "string", "The network server's address", true),
        p("gateway_eui", "string", "This gateway's EUI", true),
        p(
            "devices",
            "array",
            "The configured devices: name, dev_eui, activation (otaa or abp) and whether each has a session",
            true,
        ),
    ])
    .with_actions(actions())
});

pub static JOINED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "lorawan_join_accepted",
        "The network sent a Join Accept that decrypted and verified under the device's AppKey; the device now has a session and can send uplinks.",
        uplink_action().example.clone(),
    )
    .with_parameters(vec![
        p("device", "string", "The device's name, or its DevEUI", true),
        p("dev_eui", "string", "The device's EUI", true),
        p("dev_addr", "string", "The DevAddr the network assigned", true),
        p("net_id", "string", "The network's NetID", true),
        p("rx1_dr_offset", "number", "RX1 data-rate offset", true),
        p("rx2_data_rate", "number", "RX2 data rate", true),
        p("rx_delay", "number", "Seconds before RX1", true),
    ])
    .with_actions(actions())
});

pub static DOWNLINK_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "lorawan_downlink",
        "The network scheduled a data downlink to a device with a session here: MIC verified, counter checked, payload decrypted. NetGet answered the gateway's TX_ACK.",
        uplink_action().example.clone(),
    )
    .with_parameters(vec![
        p("device", "string", "The device's name, DevEUI or DevAddr", true),
        p("dev_addr", "string", "Its DevAddr", true),
        p("confirmed", "boolean", "The network asks for an acknowledgement (NetGet sets ACK on the device's next uplink)", true),
        p("f_cnt", "number", "Downlink frame counter", true),
        p("f_port", "number", "Application port; null for MAC commands only", false),
        p("payload", "string", "The decrypted payload, text or hex per payload_encoding", true),
        p("payload_encoding", "string", "utf8 or hex", true),
        p("mac_commands", "array", "MAC commands from the network, decoded (e.g. link_check_ans, dev_status_req)", true),
        p("ack", "boolean", "The network acknowledges the device's last confirmed uplink", true),
        p("f_pending", "boolean", "More downlinks wait for the device's next uplink", true),
        p("frequency_mhz", "number", "Frequency the gateway was asked to transmit on", true),
        p("data_rate", "string", "Data rate of the transmission", true),
        p("immediate", "boolean", "Transmit immediately rather than at tmst", true),
    ])
    .with_actions(actions())
});

/// Radio metadata an uplink action asks for, with defaults: (freq Hz, DR, rssi, snr).
pub fn radio_of(v: &Value) -> Result<(u64, u8, i32, f64)> {
    let freq = match v.get("frequency_mhz").filter(|f| !f.is_null()) {
        None => region::DEFAULT_CHANNELS_HZ[0],
        Some(f) => region::hz(f.as_f64().context("frequency_mhz is a number")?)?,
    };
    ensure!(
        region::in_band(freq),
        "{} MHz is outside EU868's 863..870 MHz",
        region::mhz(freq)
    );
    let dr = match v.get("data_rate").filter(|d| !d.is_null()) {
        None => 5,
        Some(d) => region::data_rate_index(d.as_str().context("data_rate is e.g. SF7BW125")?)?,
    };
    let rssi = match v.get("rssi").filter(|r| !r.is_null()) {
        None => -60,
        Some(r) => {
            let r = r.as_i64().context("rssi is a whole number of dBm")?;
            ensure!((-200..=0).contains(&r), "rssi {r} dBm is not a received level");
            r as i32
        }
    };
    let snr = match v.get("snr").filter(|s| !s.is_null()) {
        None => 7.0,
        Some(s) => {
            let s = s.as_f64().context("snr is a number of dB")?;
            ensure!((-30.0..=20.0).contains(&s), "snr {s} dB is out of range");
            s
        }
    };
    Ok((freq, dr, rssi, snr))
}

pub fn battery_of(v: &Value) -> Result<u8> {
    match v.get("battery").filter(|b| !b.is_null()) {
        None => Ok(255),
        Some(b) => {
            let b = b.as_u64().context("battery is 0..255")?;
            ensure!(b <= 255, "battery is 0..255");
            Ok(b as u8)
        }
    }
}

pub fn check(v: &Value) -> Result<()> {
    match v["type"].as_str().unwrap_or_default() {
        DISCONNECT => {}
        SEND_JOIN => {
            v["device"].as_str().context("device names a configured device")?;
            radio_of(v)?;
        }
        SEND_UPLINK => {
            v["device"].as_str().context("device names a configured device")?;
            check_payload(v)?;
            radio_of(v)?;
            battery_of(v)?;
            if let Some(l) = v.get("link_check").filter(|l| !l.is_null()) {
                l.as_bool().context("link_check is true or false")?;
            }
        }
        _ => bail!("Unknown LoRaWAN client action"),
    }
    Ok(())
}

#[derive(Default)]
pub struct LorawanClientProtocol;
impl LorawanClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

impl Protocol for LorawanClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "LoRaWAN"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>UDP>SEMTECH-UDP>LORAWAN"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "lorawan",
            "lora",
            "lorawan gateway",
            "semtech udp",
            "packet forwarder",
        ]
    }
    fn description(&self) -> &'static str {
        "LoRaWAN gateway (Semtech UDP packet forwarder) for simulated 1.0.x devices: joins and uplinks signed with the devices' keys, downlinks decrypted"
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        actions()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        Vec::new()
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            CONNECTED_EVENT.clone(),
            JOINED_EVENT.clone(),
            DOWNLINK_EVENT.clone(),
        ]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            devices_param(),
            ParameterDefinition {
                name: "gateway_eui".into(),
                type_hint: "string".into(),
                description: "This gateway's EUI-64, hex (the identity the network server knows it by)".into(),
                required: false,
                example: json!("0016c001ff10a235"),
                default: Some(json!(DEFAULT_GATEWAY_EUI)),
            },
            ParameterDefinition {
                name: "keepalive_secs".into(),
                type_hint: "number".into(),
                description: "Seconds between PULL_DATA keepalives, which keep the downlink path open (1..=300)".into(),
                required: false,
                example: json!(10),
                default: Some(json!(DEFAULT_KEEPALIVE_SECS)),
            },
            ParameterDefinition {
                name: "stat_interval_secs".into(),
                type_hint: "number".into(),
                description: "Seconds between stat reports (1..=3600)".into(),
                required: false,
                example: json!(30),
                default: Some(json!(DEFAULT_STAT_INTERVAL_SECS)),
            },
            region_param(),
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation("The server's Semtech UDP and LoRaWAN 1.0.x codecs (src/server/lorawan/) as a packet forwarder: PULL_DATA keepalives, PUSH_DATA with rxpk and stat, TX_ACK with TOO_LATE / TX_FREQ / TX_POWER checked against its own microsecond counter; per device a Join Request with a fresh DevNonce, Join Accept decryption and MIC check, session keys, uplink FCnt, FRMPayload encryption and MIC, downlink MIC, counter and decryption, ACK and DevStatusAns")
            .llm_control("Which configured device joins and sends what (port, payload, confirmed, LinkCheckReq, the radio metadata reported), and what to do with every downlink")
            .e2e_testing("tests/client/lorawan: NetGet's own network server; ChirpStack v4 (network server, with its Gateway Bridge, Mosquitto and Redis) accepting the join, decrypting the uplink into its MQTT application events and sending a queued downlink")
            .notes("Experimental: one independent network server (ChirpStack) and the pair job had not run in CI when it landed. No radio: the devices are simulated and the gateway forwards their frames. EU868, LoRaWAN 1.0.x, class A. A downlink the gateway would refuse (late, off-band, over power) is answered with that TX_ACK error and not delivered. A handler chain stops after 8 follow-ups. Bounds: datagrams ≤ 8 KiB, JSON depth ≤ 8, payloads by data rate, ≤ 256 devices.")
            .max_inbound_bytes(semtech::MAX_DATAGRAM)
            // A gateway's exchange is a session: a Join Request is answered by a Join Accept,
            // an uplink by its downlink, a confirmed downlink by the next uplink's ACK.
            .history(HistoryMode::Last(SESSION_HISTORY_ENTRIES))
            .batching(BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Act as a LoRaWAN gateway to the network server at 127.0.0.1:1700 for meter-1: join, then report 21.5C on port 2"
    }
    fn get_startup_examples(&self) -> StartupExamples {
        let devices = json!([{"name": "meter-1", "dev_eui": "0102030405060708", "app_eui": "0000000000000000", "app_key": "2b7e151628aed2a6abf7158809cf4f3c"}]);
        let llm = json!({"type": "open_client", "protocol": "lorawan", "remote_addr": "127.0.0.1:1700",
            "startup_params": {"devices": devices},
            "instruction": "Join meter-1, then send its reading 21.5C on port 2."});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([
            {"event_pattern": "lorawan_gateway_connected", "handler": {"type": "static", "actions": [{"type": SEND_JOIN, "device": "meter-1"}]}},
            {"event_pattern": "lorawan_join_accepted", "handler": {"type": "static", "actions": [{"type": SEND_UPLINK, "device": "meter-1", "f_port": 2, "payload": "21.5C"}]}}
        ]);
        let mut scripted = llm.clone();
        scripted["event_handlers"] = json!([{"event_pattern": "*", "handler": {"type": "script", "language": "python",
            "code": "import json,sys\ni=json.load(sys.stdin)\nt=i['event_type_id']\nif t=='lorawan_gateway_connected':\n  a=[{'type':'lorawan_send_join_request','device':'meter-1'}]\nelif t=='lorawan_join_accepted':\n  a=[{'type':'lorawan_send_uplink','device':'meter-1','f_port':2,'payload':'21.5C'}]\nelse:\n  a=[]\nprint(json.dumps({'actions':a}))"}}]);
        StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "IoT"
    }
}

impl Client for LorawanClientProtocol {
    fn connect(
        &self,
        ctx: ConnectContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::connect(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ClientActionResult> {
        check(&v)?;
        let name = v["type"].as_str().unwrap_or_default().to_string();
        if name == DISCONNECT {
            return Ok(ClientActionResult::Disconnect);
        }
        Ok(ClientActionResult::Custom { name, data: v })
    }
}
