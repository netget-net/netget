//! What the model can do as an ONVIF client: ask a device who it is and for its scopes,
//! interfaces, services and clock; read its media profiles, sources and URIs through Media and
//! Media2; drive its PTZ head (status, moves, stop, presets); subscribe to its events at a pull
//! point and pull, renew and end the subscription, or by Basic Notification, where the device
//! POSTs each event to the client's own consumer endpoint; read and change its imaging settings
//! and focus; and read, search and replay its recordings (Profile G). `ops.rs` holds what each
//! action sends and how each answer is read.
use super::ops::{self, Service, SPECS};
use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, Parameter, ParameterDefinition, StartupExamples,
};
use crate::protocol::{ConnectContext, EventType};
use crate::server::onvif::actions::{action, p};
use crate::state::app_state::AppState;
use anyhow::{bail, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

#[derive(Default)]
pub struct OnvifClientProtocol;
impl OnvifClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

pub const STREAM_URI: &str = "onvif_get_stream_uri";
pub const SNAPSHOT_URI: &str = "onvif_get_snapshot_uri";

/// The operation an action calls, and the service it goes to.
pub fn spec(v: &Value) -> Option<&'static ops::Spec> {
    ops::spec_of(v)
}

fn profile_token() -> Parameter {
    p(
        "profile_token",
        "string",
        "A profile token from onvif_get_profiles or onvif_media2_get_profiles, e.g. main",
        true,
    )
}

fn source_token() -> Parameter {
    p(
        "video_source_token",
        "string",
        "A video source token from onvif_get_video_sources, e.g. video_source",
        true,
    )
}

fn recording_token() -> Parameter {
    p(
        "recording_token",
        "string",
        "A recording token from onvif_get_recordings or a search, e.g. rec_lobby",
        true,
    )
}

fn search_params() -> Vec<Parameter> {
    vec![
        p(
            "search_token",
            "string",
            "The search_token the find action answered",
            true,
        ),
        p(
            "max_results",
            "number",
            "At most this many results now, 1..1000 (optional)",
            false,
        ),
        p(
            "wait_secs",
            "number",
            "How long the device may wait for results, 0..60 seconds (default 0)",
            false,
        ),
    ]
}

fn axes(range: &str) -> Vec<Parameter> {
    vec![
        p(
            "pan",
            "number",
            &format!("Pan (left/right), {range}"),
            false,
        ),
        p("tilt", "number", &format!("Tilt (down/up), {range}"), false),
        p(
            "zoom",
            "number",
            "Zoom (0..1 for a position, -1..1 otherwise)",
            false,
        ),
    ]
}

fn with(mut first: Vec<Parameter>, rest: Vec<Parameter>) -> Vec<Parameter> {
    first.extend(rest);
    first
}

/// The description, parameters and example of each action, in `SPECS` order.
fn definition(name: &'static str) -> (&'static str, Vec<Parameter>, Value) {
    let ex = |extra: Value| {
        let mut v = json!({"type": name});
        if let (Some(o), Some(e)) = (v.as_object_mut(), extra.as_object()) {
            o.extend(e.clone());
        }
        v
    };
    match name {
        "onvif_get_device_information" => ("Ask the device who it is (manufacturer, model, firmware, serial number).", vec![], ex(json!({}))),
        "onvif_get_scopes" => ("Ask for the device's scope URIs (name, location, hardware, profiles).", vec![], ex(json!({}))),
        "onvif_get_network_interfaces" => ("Ask for the device's network interfaces and their IPv4 addresses.", vec![], ex(json!({}))),
        "onvif_get_capabilities" => ("Ask which services the device has and where they live.", vec![], ex(json!({}))),
        "onvif_get_services" => ("Ask for every service the device exposes, with namespaces, addresses and versions.", vec![], ex(json!({}))),
        "onvif_get_system_date_and_time" => ("Ask for the device's clock (sent without credentials, as ONVIF allows).", vec![], ex(json!({}))),
        "onvif_get_profiles" => ("Ask for the media profiles (Media ver10): token, encoding, resolution, frame rate, bitrate.", vec![], ex(json!({}))),
        "onvif_get_video_sources" => ("Ask for the device's video inputs.", vec![], ex(json!({}))),
        STREAM_URI => (
            "Ask where to stream a profile from (Media GetStreamUri).",
            vec![profile_token(), p("stream", "string", "RTP-Unicast (default) or RTP-Multicast", false), p("protocol", "string", "RTSP (default), HTTP, UDP or TCP", false)],
            ex(json!({"profile_token": "main", "protocol": "RTSP"})),
        ),
        SNAPSHOT_URI => ("Ask where to fetch a JPEG snapshot of a profile (Media GetSnapshotUri).", vec![profile_token()], ex(json!({"profile_token": "main"}))),
        "onvif_media2_get_profiles" => ("Ask for the media profiles through Media2 (ver20), with every configuration: token, name, video source, encoding, resolution, PTZ.", vec![], ex(json!({}))),
        "onvif_media2_get_stream_uri" => (
            "Ask Media2 where to stream a profile from.",
            vec![profile_token(), p("protocol", "string", "RtspUnicast (default), RtspMulticast, RTSP or RtspOverHttp", false)],
            ex(json!({"profile_token": "main", "protocol": "RtspUnicast"})),
        ),
        "onvif_media2_get_snapshot_uri" => ("Ask Media2 where to fetch a snapshot of a profile.", vec![profile_token()], ex(json!({"profile_token": "main"}))),
        "onvif_media2_get_video_source_configurations" => (
            "Ask Media2 for the video source configurations, optionally of one profile.",
            vec![p("profile_token", "string", "Only this profile's (optional)", false)],
            ex(json!({})),
        ),
        "onvif_media2_get_video_encoder_configurations" => (
            "Ask Media2 for the video encoder configurations, optionally of one profile.",
            vec![p("profile_token", "string", "Only this profile's (optional)", false)],
            ex(json!({})),
        ),
        "onvif_ptz_get_nodes" => ("Ask for the device's PTZ nodes and what they support.", vec![], ex(json!({}))),
        "onvif_ptz_get_configurations" => ("Ask for the device's PTZ configurations.", vec![], ex(json!({}))),
        "onvif_ptz_get_status" => ("Ask where a profile's PTZ head is and whether it is moving.", vec![profile_token()], ex(json!({"profile_token": "main"}))),
        "onvif_ptz_continuous_move" => (
            "Start moving the PTZ head at a velocity (each axis -1..1) until onvif_ptz_stop or the timeout.",
            with(with(vec![profile_token()], axes("-1..1")), vec![p("timeout_secs", "number", "Stop by itself after this many seconds (optional)", false)]),
            ex(json!({"profile_token": "main", "pan": 0.5, "tilt": 0.0, "timeout_secs": 2})),
        ),
        "onvif_ptz_relative_move" => (
            "Move the PTZ head by a translation (each axis -1..1).",
            with(vec![profile_token()], axes("-1..1")),
            ex(json!({"profile_token": "main", "pan": 0.1, "tilt": -0.1})),
        ),
        "onvif_ptz_absolute_move" => (
            "Move the PTZ head to a position (pan, tilt -1..1; zoom 0..1).",
            with(vec![profile_token()], axes("-1..1")),
            ex(json!({"profile_token": "main", "pan": 0.25, "tilt": 0.0, "zoom": 0.5})),
        ),
        "onvif_ptz_stop" => (
            "Stop the PTZ head.",
            vec![profile_token(), p("pan_tilt", "boolean", "Stop pan and tilt (default true)", false), p("zoom", "boolean", "Stop zoom (default true)", false)],
            ex(json!({"profile_token": "main"})),
        ),
        "onvif_ptz_get_presets" => ("Ask for a profile's PTZ presets.", vec![profile_token()], ex(json!({"profile_token": "main"}))),
        "onvif_ptz_set_preset" => (
            "Save the head's current position as a preset (new, or over preset_token).",
            vec![profile_token(), p("preset_name", "string", "The preset's name", false), p("preset_token", "string", "An existing preset to overwrite (optional)", false)],
            ex(json!({"profile_token": "main", "preset_name": "Door"})),
        ),
        "onvif_ptz_goto_preset" => (
            "Move the PTZ head to a preset.",
            vec![profile_token(), p("preset_token", "string", "The preset's token", true)],
            ex(json!({"profile_token": "main", "preset_token": "1"})),
        ),
        "onvif_ptz_remove_preset" => (
            "Delete a preset.",
            vec![profile_token(), p("preset_token", "string", "The preset's token", true)],
            ex(json!({"profile_token": "main", "preset_token": "1"})),
        ),
        "onvif_ptz_goto_home" => ("Move the PTZ head to its home position.", vec![profile_token()], ex(json!({"profile_token": "main"}))),
        "onvif_get_event_properties" => ("Ask which event topics the device produces.", vec![], ex(json!({}))),
        "onvif_create_pull_point" => (
            "Subscribe to the device's events at a pull point; then onvif_pull_messages reads them.",
            vec![
                p("termination_secs", "number", "How long the subscription lives before it must be renewed (default 60)", false),
                p("topic_filter", "string", "Only these topics, e.g. tns1:VideoSource/MotionAlarm or tns1:RuleEngine//. (optional)", false),
            ],
            ex(json!({"termination_secs": 60})),
        ),
        "onvif_pull_messages" => (
            "Wait for events on the pull point (returns as soon as any arrive).",
            vec![p("timeout_secs", "number", "Wait at most this long, 1..60 (default 10)", false), p("message_limit", "number", "At most this many, 1..100 (default 10)", false)],
            ex(json!({"timeout_secs": 10, "message_limit": 10})),
        ),
        "onvif_renew_subscription" => (
            "Extend the pull-point subscription.",
            vec![p("termination_secs", "number", "Live this much longer (default 60)", false)],
            ex(json!({"termination_secs": 60})),
        ),
        "onvif_unsubscribe" => ("End the pull-point subscription.", vec![], ex(json!({}))),
        "onvif_set_synchronization_point" => ("Ask the device to resend the current value of every property event to the pull point.", vec![], ex(json!({}))),
        "onvif_imaging_get_settings" => ("Ask for a video source's imaging settings.", vec![source_token()], ex(json!({"video_source_token": "video_source"}))),
        "onvif_imaging_set_settings" => (
            "Change a video source's imaging settings; give only the ones to change.",
            vec![
                source_token(),
                p("brightness", "number", "Brightness level, 0..100", false),
                p("color_saturation", "number", "Colour saturation level, 0..100", false),
                p("contrast", "number", "Contrast level, 0..100", false),
                p("sharpness", "number", "Sharpness level, 0..100", false),
                p("ir_cut_filter", "string", "IR-cut filter mode: ON, OFF or AUTO", false),
                p("auto_focus_mode", "string", "Autofocus mode: AUTO or MANUAL", false),
            ],
            ex(json!({"video_source_token": "video_source", "brightness": 60})),
        ),
        "onvif_imaging_get_options" => ("Ask what imaging settings a video source accepts.", vec![source_token()], ex(json!({"video_source_token": "video_source"}))),
        "onvif_imaging_get_move_options" => ("Ask how a video source's focus can be moved.", vec![source_token()], ex(json!({"video_source_token": "video_source"}))),
        "onvif_imaging_move" => (
            "Move a video source's focus.",
            vec![
                source_token(),
                p("kind", "string", "absolute, relative or continuous", true),
                p("position", "number", "For kind absolute: the focus position, 0..1", false),
                p("distance", "number", "For kind relative: how far to move focus, -1..1", false),
                p("speed", "number", "For kind continuous: the focus speed, -1..1", false),
            ],
            ex(json!({"video_source_token": "video_source", "kind": "absolute", "position": 0.4})),
        ),
        "onvif_imaging_get_status" => ("Ask where a video source's focus is and whether it is moving.", vec![source_token()], ex(json!({"video_source_token": "video_source"}))),
        "onvif_imaging_stop" => ("Stop a focus move.", vec![source_token()], ex(json!({"video_source_token": "video_source"}))),
        "onvif_subscribe" => (
            "Subscribe to the device's events by Basic Notification: the device POSTs each one to this client's own consumer endpoint (started on loopback, or notify_bind), and each arrives as an onvif_notification event. Replaces any earlier push subscription the client kept.",
            vec![
                p("termination_secs", "number", "How long the subscription lives before it must be renewed, 1..3600 seconds (default 60)", false),
                p("topic_filter", "string", "Only these topics, e.g. tns1:VideoSource/MotionAlarm or tns1:RuleEngine//. (optional)", false),
            ],
            ex(json!({"termination_secs": 300})),
        ),
        "onvif_renew_push_subscription" => (
            "Extend the Basic Notification subscription onvif_subscribe made.",
            vec![p("termination_secs", "number", "Live this much longer, 1..3600 seconds (default 60)", false)],
            ex(json!({"termination_secs": 300})),
        ),
        "onvif_unsubscribe_push" => ("End the Basic Notification subscription onvif_subscribe made.", vec![], ex(json!({}))),
        "onvif_get_recordings" => ("Ask for the device's recordings: source, content, retention and tracks of each.", vec![], ex(json!({}))),
        "onvif_get_recording_configuration" => (
            "Ask for one recording's configuration (source, content, retention).",
            vec![recording_token()],
            ex(json!({"recording_token": "rec_lobby"})),
        ),
        "onvif_get_recording_jobs" => ("Ask for the device's recording jobs: which recording each records into, its mode and sources.", vec![], ex(json!({}))),
        "onvif_get_recording_summary" => ("Ask the search service how much is recorded: the earliest and latest data and the number of recordings.", vec![], ex(json!({}))),
        "onvif_get_recording_information" => (
            "Ask the search service about one recording: its time range, tracks and status.",
            vec![recording_token()],
            ex(json!({"recording_token": "rec_lobby"})),
        ),
        "onvif_find_recordings" => (
            "Start a search for recordings; read the results with onvif_get_recording_search_results and its search_token.",
            vec![
                p("recording_tokens", "array", "Only these recordings (optional; none is every recording)", false),
                p("max_matches", "number", "Stop after this many, 1..1000 (optional)", false),
                p("keep_alive_secs", "number", "How long the search waits between requests, 1..600 seconds (default 60)", false),
            ],
            ex(json!({"keep_alive_secs": 60})),
        ),
        "onvif_get_recording_search_results" => (
            "Read results of a recording search; search_state Completed means there are no more.",
            search_params(),
            ex(json!({"search_token": "search_0123456789abcdef", "max_results": 10})),
        ),
        "onvif_find_events" => (
            "Start a search for recorded events between two times (an end before the start searches backwards); read the results with onvif_get_event_search_results.",
            vec![
                p("start", "string", "Where the search starts, a UTC time such as 2026-10-24T00:00:00Z", true),
                p("end", "string", "Where it stops, a UTC time (optional; before start searches backwards)", false),
                p("recording_tokens", "array", "Only these recordings (optional)", false),
                p("topic_filter", "string", "Only these topics, e.g. tns1:VideoSource/MotionAlarm (optional)", false),
                p("include_start_state", "boolean", "Also report each property's value at the start (default false)", false),
                p("max_matches", "number", "Stop after this many, 1..1000 (optional)", false),
                p("keep_alive_secs", "number", "How long the search waits between requests, 1..600 seconds (default 60)", false),
            ],
            ex(json!({"start": "2026-10-24T00:00:00Z", "end": "2026-10-25T00:00:00Z", "topic_filter": "tns1:VideoSource/MotionAlarm"})),
        ),
        "onvif_get_event_search_results" => (
            "Read results of an event search; search_state Completed means there are no more.",
            search_params(),
            ex(json!({"search_token": "search_0123456789abcdef", "max_results": 10})),
        ),
        "onvif_end_search" => (
            "End a recording or event search.",
            vec![p("search_token", "string", "The search_token onvif_find_recordings or onvif_find_events answered", true)],
            ex(json!({"search_token": "search_0123456789abcdef"})),
        ),
        "onvif_get_replay_uri" => (
            "Ask where to replay a recording from (an RTSP URI).",
            vec![recording_token(), p("protocol", "string", "RTSP (default), UDP, TCP or HTTP", false)],
            ex(json!({"recording_token": "rec_lobby"})),
        ),
        "onvif_get_replay_configuration" => ("Ask how long an idle replay session lasts.", vec![], ex(json!({}))),
        _ => ("", vec![], ex(json!({}))),
    }
}

pub fn actions() -> Vec<ActionDefinition> {
    let mut out: Vec<ActionDefinition> = SPECS
        .iter()
        .map(|s| {
            let (description, params, example) = definition(s.action);
            action(s.action, description, params, example)
        })
        .collect();
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
        "The client read the device's clock, capabilities and services and is ready to ask it things.",
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
            "Service name to XAddr from GetCapabilities and GetServices, e.g. {Device, Media, Media2, PTZ, Events, Imaging}",
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
        p("service", "string", "device, media, media2, ptz, events, subscription, push_subscription, imaging, recording, search or replay", true),
        p("ok", "boolean", "False for a fault or a transport error", true),
        p("result", "object", "The answer, structured per operation: e.g. GetProfiles {profiles: [...]}; GetStreamUri {uri}; PTZ GetStatus {position: {pan, tilt, zoom}, move_status, utc_time}; GetPresets {presets}; SetPreset {preset_token}; CreatePullPointSubscription {address, termination_time}; PullMessages {notifications: [{topic, utc_time, property_operation, source, data}]}; GetImagingSettings {brightness, ...}; Imaging GetStatus {position, move_status}", false),
        p("fault", "object", "{code (Sender/Receiver), subcodes (e.g. [NotAuthorized]), reason} when the device refused", false),
        p("error", "string", "Why the device could not be asked (connection, HTTP status, unreadable reply, no such service)", false),
        p("request", "object", "The arguments sent, e.g. {profile_token}", true),
    ])
    .with_actions(actions())
});

pub static NOTIFICATION_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "onvif_notification",
        "The device POSTed an event to this client's notification consumer (Basic Notification, after onvif_subscribe).",
        json!({"type": "onvif_get_device_information"}),
    )
    .with_parameters(vec![
        p("topic", "string", "The event's topic, e.g. tns1:VideoSource/MotionAlarm", true),
        p("utc_time", "string", "When it happened, by the device's clock", true),
        p("property_operation", "string", "Initialized, Changed or Deleted (for property events)", true),
        p("source", "object", "The source items, e.g. {Source: video_source}", true),
        p("data", "object", "The data items, e.g. {State: true}", true),
        p("subscription", "string", "The subscription it came through", true),
        p("producer", "string", "The device's address that produced it", true),
    ])
    .with_actions(actions())
});

pub fn check(v: &Value) -> Result<()> {
    let t = v["type"].as_str().unwrap_or_default();
    let Some(s) = spec(v) else {
        bail!("Unknown ONVIF client action {t:?}");
    };
    ops::request_body(s, v).map(|_| ())
}

/// The service's name in the events the model reads.
pub fn service_name(s: Service) -> &'static str {
    match s {
        Service::Device => "device",
        Service::Media => "media",
        Service::Media2 => "media2",
        Service::Ptz => "ptz",
        Service::Events => "events",
        Service::Subscription => "subscription",
        Service::PushSubscription => "push_subscription",
        Service::Imaging => "imaging",
        Service::Recording => "recording",
        Service::Search => "search",
        Service::Replay => "replay",
    }
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
            "ptz",
        ]
    }
    fn description(&self) -> &'static str {
        "ONVIF client: authenticates to an IP camera with a WS-Security digest; reads its identity, Media and Media2 profiles and stream URIs, drives its PTZ head and presets, subscribes to its events at a pull point or by Basic Notification to its own consumer endpoint, reads and sets its imaging, and reads, searches and replays its recordings"
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        actions()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            CONNECTED_EVENT.clone(),
            RESPONSE_EVENT.clone(),
            NOTIFICATION_EVENT.clone(),
        ]
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
            ParameterDefinition {
                name: "notify_bind".into(),
                type_hint: "string".into(),
                description: "The address of this host the Basic Notification consumer listens on, on a port the OS picks (loopback unless a device that refuses loopback consumers must reach it)".into(),
                required: false,
                example: json!("127.0.0.1"),
                default: Some(json!(super::consumer::DEFAULT_BIND)),
            },
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation("SOAP 1.2 over HTTP/1.1 (reqwest) with the server's codec: reads the device's clock unauthenticated (GetSystemDateAndTime) and shifts every WS-Security Created by the offset, signs each request with a PasswordDigest UsernameToken (fresh 16-byte nonce), finds the Media, PTZ, Events and Imaging services (and Recording, Search and Replay in its Extension) through GetCapabilities and Media2 (and the rest) through GetServices, keeping the host it connected to, and parses answers and SOAP 1.2/1.1 faults from a bounded tree (1 MiB, depth 32) into structured events. PTZ: nodes, configurations, status, continuous/relative/absolute moves, stop, presets, home. Events: GetEventProperties and one pull-point subscription (create, pull with a long-poll of up to 60 s, renew, unsubscribe, synchronization point), its notifications as {topic, source, data}; and Basic Notification: onvif_subscribe starts the client's own consumer endpoint (notify_bind, loopback by default, an OS-assigned port, one random 128-bit path; 8 connections, 256 KiB bodies, 64 notifications per Notify, the same bounded tree) and each notification arrives as an onvif_notification event, with renew and unsubscribe of that subscription. Recording, Search and Replay: recordings, a recording's configuration, jobs, the recording summary and information, FindRecordings and FindEvents (time ranges, recordings, a topic filter, IncludeStartState) with their results and EndSearch, the replay URI and configuration. Media2: profiles, stream and snapshot URIs, source and encoder configurations. Imaging: settings, options, focus moves, status")
            .llm_control("Which operations to call, on which profiles and sources, and what to do with each answer; chains are bounded at MAX_FOLLOWUP_DEPTH")
            .e2e_testing("tests/client/onvif: RPOS (the Node.js ONVIF camera, BreeeZe/rpos), which verifies the PasswordDigest itself; the model's profile token is asserted in RPOS's own request log and its PTZ moves and presets in the commands RPOS's rposascii PTZ driver writes; onvif_simple_server (roleoroleo, C, under lighttpd) for Media2 and Events, its pull-point notification raised from a file its notify daemon watches, and Basic Notification: the client subscribes its own consumer (on a non-loopback address of the host, since onvif_simple_server refuses loopback consumers) and the daemon's Initialized and Changed motion alarms arrive as onvif_notification events. No independent device implements Recording, Search or Replay for the client to be tested against; those requests are checked only against a canned device in bounds_test")
            .notes("Experimental: the third-party devices are real and the tests fail without them, but nobody has reviewed beyond them. One pull-point and one Basic Notification subscription at a time, each followed by path on the address the client was given. Recording, Search and Replay are not tested against any independent device (none could be found that implements them and runs in CI). No Device Set* operations, no recording changes (Create/DeleteRecording), no Replay streaming. http only (no TLS) and no HTTP Digest. XAddrs are followed by path on the address the client was given, never to another host.")
            .max_inbound_bytes(crate::server::onvif::wire::MAX_RESPONSE)
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Connect to the ONVIF camera at 192.0.2.10:80 as admin, pan it to the door and watch for motion"
    }
    fn get_startup_examples(&self) -> StartupExamples {
        let llm = json!({"type":"open_client","protocol":"onvif","remote_addr":"192.0.2.10:80",
            "startup_params":{"username":"admin","password":"secret"},
            "instruction":"Read the camera's profiles, pan its PTZ profile a little to the right, then subscribe to its events and report motion"});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([
            {"event_pattern":"onvif_connected","handler":{"type":"static","actions":[{"type":"onvif_get_profiles"}]}},
            {"event_pattern":"*","handler":{"type":"static","actions":[]}}
        ]);
        let mut scripted = llm.clone();
        scripted["event_handlers"] = json!([{"event_pattern":"*","handler":{"type":"script","language":"python",
            "code":"import json,sys\ni=json.load(sys.stdin); e=i['event']; a=[]\nif i['event_type_id']=='onvif_connected': a=[{'type':'onvif_get_profiles'}]\nelif e.get('operation')=='GetProfiles' and e['ok'] and e['result']['profiles']: a=[{'type':'onvif_ptz_relative_move','profile_token':e['result']['profiles'][0]['token'],'pan':0.1}]\nprint(json.dumps({'actions':a}))"}}]);
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
