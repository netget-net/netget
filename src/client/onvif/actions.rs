//! What the model can do as an ONVIF client: ask a device who it is, for its scopes, network
//! interfaces, services and clock, and for its media profiles, video sources and the stream and
//! snapshot URIs of a profile.
use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, ParameterDefinition, StartupExamples,
};
use crate::protocol::{ConnectContext, EventType};
use crate::server::onvif::actions::{action, p};
use crate::state::app_state::AppState;
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

#[derive(Default)]
pub struct OnvifClientProtocol;
impl OnvifClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

/// Action name → ONVIF operation, for the operations that take no arguments.
pub const SIMPLE: &[(&str, &str)] = &[
    ("onvif_get_device_information", "GetDeviceInformation"),
    ("onvif_get_scopes", "GetScopes"),
    ("onvif_get_network_interfaces", "GetNetworkInterfaces"),
    ("onvif_get_capabilities", "GetCapabilities"),
    ("onvif_get_services", "GetServices"),
    ("onvif_get_system_date_and_time", "GetSystemDateAndTime"),
    ("onvif_get_profiles", "GetProfiles"),
    ("onvif_get_video_sources", "GetVideoSources"),
];
pub const STREAM_URI: &str = "onvif_get_stream_uri";
pub const SNAPSHOT_URI: &str = "onvif_get_snapshot_uri";

/// The operation an action calls.
pub fn operation(v: &Value) -> Option<&'static str> {
    let t = v["type"].as_str()?;
    SIMPLE
        .iter()
        .find(|(a, _)| *a == t)
        .map(|(_, op)| *op)
        .or(match t {
            STREAM_URI => Some("GetStreamUri"),
            SNAPSHOT_URI => Some("GetSnapshotUri"),
            _ => None,
        })
}

/// Media operations go to the media service; the rest to the device service.
pub fn is_media(operation: &str) -> bool {
    matches!(
        operation,
        "GetProfiles" | "GetVideoSources" | "GetStreamUri" | "GetSnapshotUri"
    )
}

fn description(op: &str) -> &'static str {
    match op {
        "GetDeviceInformation" => {
            "Ask the device who it is (manufacturer, model, firmware, serial number)."
        }
        "GetScopes" => "Ask for the device's scope URIs (name, location, hardware, profiles).",
        "GetNetworkInterfaces" => {
            "Ask for the device's network interfaces and their IPv4 addresses."
        }
        "GetCapabilities" => "Ask which services the device has and where they live.",
        "GetServices" => {
            "Ask for every service the device exposes, with namespaces, addresses and versions."
        }
        "GetSystemDateAndTime" => {
            "Ask for the device's clock (sent without credentials, as ONVIF allows)."
        }
        "GetProfiles" => {
            "Ask for the media profiles: token, encoding, resolution, frame rate, bitrate."
        }
        _ => "Ask for the device's video inputs.",
    }
}

fn profile_token() -> crate::llm::actions::Parameter {
    p(
        "profile_token",
        "string",
        "A profile token from onvif_get_profiles, e.g. main",
        true,
    )
}

pub fn actions() -> Vec<ActionDefinition> {
    let mut out: Vec<ActionDefinition> = SIMPLE
        .iter()
        .map(|(name, op)| action(name, description(op), vec![], json!({"type": name})))
        .collect();
    out.push(action(
        STREAM_URI,
        "Ask where to stream a profile from (GetStreamUri).",
        vec![
            profile_token(),
            p(
                "stream",
                "string",
                "RTP-Unicast (default) or RTP-Multicast",
                false,
            ),
            p(
                "protocol",
                "string",
                "RTSP (default), HTTP, UDP or TCP",
                false,
            ),
        ],
        json!({"type": STREAM_URI, "profile_token": "main", "protocol": "RTSP"}),
    ));
    out.push(action(
        SNAPSHOT_URI,
        "Ask where to fetch a JPEG snapshot of a profile (GetSnapshotUri).",
        vec![profile_token()],
        json!({"type": SNAPSHOT_URI, "profile_token": "main"}),
    ));
    out.push(action(
        "disconnect",
        "Stop the client.",
        vec![],
        json!({"type": "disconnect"}),
    ));
    out
}

pub static CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "onvif_connected",
        "The client read the device's clock and capabilities and is ready to ask it things.",
        json!({"type": "onvif_get_device_information"}),
    )
    .with_parameters(vec![
        p(
            "device_time",
            "string",
            "The device's UTC clock, or null if it would not say",
            true,
        ),
        p(
            "clock_offset_secs",
            "number",
            "Device clock minus ours; WS-Security timestamps are shifted by it",
            true,
        ),
        p(
            "services",
            "object",
            "Service name to XAddr from GetCapabilities, e.g. {Device, Media}",
            true,
        ),
        p(
            "authenticated",
            "boolean",
            "Requests carry a WS-Security UsernameToken digest",
            true,
        ),
    ])
    .with_actions(actions())
});

pub static RESPONSE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "onvif_response",
        "The device answered an operation, or refused it with a SOAP fault, or could not be reached.",
        json!({"type": STREAM_URI, "profile_token": "main"}),
    )
    .with_parameters(vec![
        p("operation", "string", "The ONVIF operation, e.g. GetProfiles", true),
        p("ok", "boolean", "False for a fault or a transport error", true),
        p("result", "object", "The answer: GetDeviceInformation {manufacturer, model, firmware_version, serial_number, hardware_id}; GetProfiles {profiles: [{token, name, encoding, width, height, framerate, bitrate, video_source_token}]}; GetStreamUri/GetSnapshotUri {uri, timeout}; GetScopes {scopes: [{uri}]}; GetNetworkInterfaces {interfaces}; GetVideoSources {sources}; GetServices {services}; GetCapabilities {services}; GetSystemDateAndTime {utc}", false),
        p("fault", "object", "{code (Sender/Receiver), subcodes (e.g. [NotAuthorized]), reason} when the device refused", false),
        p("error", "string", "Why the device could not be asked (connection, HTTP status, unreadable reply)", false),
        p("request", "object", "The arguments sent, e.g. {profile_token}", true),
    ])
    .with_actions(actions())
});

pub fn check(v: &Value) -> Result<()> {
    let t = v["type"].as_str().unwrap_or_default();
    let Some(op) = operation(v) else {
        bail!("Unknown ONVIF client action {t:?}");
    };
    if op == "GetStreamUri" || op == "GetSnapshotUri" {
        let token = v["profile_token"]
            .as_str()
            .context("profile_token is required")?;
        ensure!(
            !token.is_empty()
                && token.len() <= 64
                && !token.chars().any(char::is_whitespace)
                && !crate::utils::sanitize::has_controls(token),
            "profile_token is a token of 1-64 characters without spaces"
        );
    }
    if op == "GetStreamUri" {
        ensure!(
            matches!(
                v["stream"].as_str(),
                None | Some("RTP-Unicast" | "RTP-Multicast")
            ),
            "stream is RTP-Unicast or RTP-Multicast"
        );
        ensure!(
            matches!(
                v["protocol"].as_str(),
                None | Some("RTSP" | "HTTP" | "UDP" | "TCP")
            ),
            "protocol is RTSP, HTTP, UDP or TCP"
        );
    }
    Ok(())
}

impl Protocol for OnvifClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "ONVIF"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>HTTP>SOAP>ONVIF"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "onvif",
            "ip camera",
            "network camera",
            "nvt",
            "cctv",
            "stream uri",
        ]
    }
    fn description(&self) -> &'static str {
        "ONVIF client: authenticates to an IP camera with a WS-Security digest and asks its Device and Media services for its identity, profiles and stream URIs"
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        actions()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![CONNECTED_EVENT.clone(), RESPONSE_EVENT.clone()]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "username".into(),
                type_hint: "string".into(),
                description: "User to authenticate as (WS-Security UsernameToken, PasswordDigest); without one, requests carry no credentials".into(),
                required: false,
                example: json!("admin"),
                default: None,
            },
            ParameterDefinition {
                name: "password".into(),
                type_hint: "string".into(),
                description: "That user's password".into(),
                required: false,
                example: json!("camera-secret"),
                default: None,
            },
            ParameterDefinition {
                name: "device_path".into(),
                type_hint: "string".into(),
                description: "The device service's path on remote_addr".into(),
                required: false,
                example: json!("/onvif/device_service"),
                default: Some(json!(crate::server::onvif::wire::DEVICE_PATH)),
            },
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation("SOAP 1.2 over HTTP/1.1 (reqwest) with the server's codec: reads the device's clock unauthenticated (GetSystemDateAndTime) and shifts every WS-Security Created by the offset, signs each request with a PasswordDigest UsernameToken (fresh 16-byte nonce), finds the media service through GetCapabilities and keeps the host it connected to, and parses answers and SOAP 1.2/1.1 faults from a bounded tree (1 MiB, depth 32) into structured events")
            .llm_control("Which operations to call, on which profiles, and what to do with each answer; chains are bounded at MAX_FOLLOWUP_DEPTH")
            .e2e_testing("tests/client/onvif: RPOS (the Node.js ONVIF camera, BreeeZe/rpos), which verifies the PasswordDigest itself and refuses a wrong one with ter:NotAuthorized; the model's chosen profile token is asserted in RPOS's own request log")
            .notes("Experimental: one third-party device, nobody has reviewed beyond its test. ver10 Device and Media only; no PTZ, Imaging, Events, Media2 or Set* operations. http only (no TLS) and no HTTP Digest. XAddrs are followed by path on the address the client was given, never to another host.")
            .max_inbound_bytes(crate::server::onvif::wire::MAX_RESPONSE)
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Connect to the ONVIF camera at 192.0.2.10:80 as admin and find its main stream URI"
    }
    fn get_startup_examples(&self) -> StartupExamples {
        let llm = json!({"type":"open_client","protocol":"onvif","remote_addr":"192.0.2.10:80",
            "startup_params":{"username":"admin","password":"secret"},
            "instruction":"Read the camera's device information and profiles, then get the stream URI of its first profile"});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([
            {"event_pattern":"onvif_connected","handler":{"type":"static","actions":[{"type":"onvif_get_profiles"}]}},
            {"event_pattern":"*","handler":{"type":"static","actions":[]}}
        ]);
        let mut scripted = llm.clone();
        scripted["event_handlers"] = json!([{"event_pattern":"*","handler":{"type":"script","language":"python",
            "code":"import json,sys\ni=json.load(sys.stdin); e=i['event']; a=[]\nif i['event_type_id']=='onvif_connected': a=[{'type':'onvif_get_profiles'}]\nelif e.get('operation')=='GetProfiles' and e['ok'] and e['result']['profiles']: a=[{'type':'onvif_get_stream_uri','profile_token':e['result']['profiles'][0]['token']}]\nprint(json.dumps({'actions':a}))"}}]);
        StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Application"
    }
}

impl Client for OnvifClientProtocol {
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
        check(&v)?;
        Ok(ClientActionResult::Custom {
            name: v["type"].as_str().unwrap_or_default().to_string(),
            data: v,
        })
    }
}
