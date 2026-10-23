//! What the model decides as an ONVIF device: who it says it is, its scopes and network
//! interfaces, its media profiles and video sources, and the stream and snapshot URIs it hands
//! out — or a fault refusing any of them. Rust owns the SOAP envelopes, WS-Security, the clock,
//! the service addresses and every fault the specification defines.
use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter, ParameterDefinition, StartupExamples,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::{EventType, SpawnContext};
use crate::state::app_state::AppState;
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

pub const DEVICE_INFORMATION: &str = "onvif_device_information";
pub const SCOPES: &str = "onvif_scopes";
pub const NETWORK_INTERFACES: &str = "onvif_network_interfaces";
pub const PROFILES: &str = "onvif_profiles";
pub const VIDEO_SOURCES: &str = "onvif_video_sources";
pub const STREAM_URI: &str = "onvif_stream_uri";
pub const SNAPSHOT_URI: &str = "onvif_snapshot_uri";
pub const FAULT: &str = "onvif_fault";
pub const HOSTNAME: &str = "onvif_hostname";
pub const ACCEPT: &str = "onvif_accept";
pub const PTZ_POSITION: &str = "onvif_ptz_position";
pub const FOCUS_POSITION: &str = "onvif_focus_position";
pub const RAISE_EVENT: &str = "onvif_raise_event";
/// A hostname at most, in bytes (RFC 1035).
pub const MAX_HOSTNAME: usize = 253;

/// A string the model supplies, at most.
pub const MAX_TEXT: usize = 256;
/// A URI the model supplies, at most.
pub const MAX_URI: usize = 2048;

#[derive(Default)]
pub struct OnvifProtocol;
impl OnvifProtocol {
    pub fn new() -> Self {
        Self
    }
}

pub fn p(name: &str, kind: &str, description: &str, required: bool) -> Parameter {
    Parameter {
        name: name.into(),
        type_hint: kind.into(),
        description: description.into(),
        required,
    }
}

pub fn action(
    name: &str,
    description: &str,
    parameters: Vec<Parameter>,
    example: Value,
) -> ActionDefinition {
    ActionDefinition {
        name: name.into(),
        description: description.into(),
        parameters,
        example,
        log_template: Some(LogTemplate::new().with_info(format!("-> ONVIF {name}"))),
    }
}

fn fault_action() -> ActionDefinition {
    action(FAULT, "Refuse this request with an ONVIF SOAP fault instead of answering it, e.g. subcode InvalidArgVal with detail NoProfile for a profile token you do not have.",
        vec![
            p("subcode", "string", "The ter: subcode, e.g. InvalidArgVal, ActionNotSupported, NoProfile, NoSource, InvalidStreamSetup", true),
            p("detail", "string", "An optional second, more specific ter: subcode, e.g. NoProfile under InvalidArgVal", false),
            p("reason", "string", "Human-readable reason the client sees", true),
        ],
        json!({"type": FAULT, "subcode": "InvalidArgVal", "detail": "NoProfile", "reason": "No such profile"}))
}

fn device_information_action() -> ActionDefinition {
    action(
        DEVICE_INFORMATION,
        "Answer GetDeviceInformation: who this device says it is.",
        vec![
            p(
                "manufacturer",
                "string",
                "The maker the device names, e.g. Axis",
                true,
            ),
            p("model", "string", "The product model, e.g. P1375", true),
            p(
                "firmware_version",
                "string",
                "The firmware version string, e.g. 10.12.4",
                true,
            ),
            p(
                "serial_number",
                "string",
                "The unit's serial number, e.g. ACCC8E000001",
                true,
            ),
            p(
                "hardware_id",
                "string",
                "The hardware revision identifier, e.g. 7A1",
                true,
            ),
        ],
        json!({"type": DEVICE_INFORMATION, "manufacturer": "NetGet", "model": "Virtual Camera", "firmware_version": "1.0", "serial_number": "NG-0001", "hardware_id": "1"}),
    )
}

fn scopes_action() -> ActionDefinition {
    action(SCOPES, "Answer GetScopes: the device's scope URIs (name, location, hardware, profile).",
        vec![p("scopes", "array", "Scope URIs, e.g. [\"onvif://www.onvif.org/name/Lobby\", \"onvif://www.onvif.org/Profile/Streaming\"]", true)],
        json!({"type": SCOPES, "scopes": ["onvif://www.onvif.org/name/Lobby", "onvif://www.onvif.org/Profile/Streaming"]}))
}

fn network_interfaces_action() -> ActionDefinition {
    action(NETWORK_INTERFACES, "Answer GetNetworkInterfaces: the device's IPv4 interfaces.",
        vec![p("interfaces", "array", "[{token, name, mac (aa:bb:cc:dd:ee:ff), ipv4_address, prefix_length, dhcp, enabled?, mtu?}]", true)],
        json!({"type": NETWORK_INTERFACES, "interfaces": [{"token": "eth0", "name": "eth0", "mac": "02:00:00:00:00:01", "ipv4_address": "192.0.2.10", "prefix_length": 24, "dhcp": false}]}))
}

fn profiles_action() -> ActionDefinition {
    action(PROFILES, "Answer GetProfiles (Media and Media2 alike, and the Media2 configuration lists): the media profiles, each a video source encoded one way. ptz: true gives a profile the device's pan/tilt/zoom head.",
        vec![p("profiles", "array", "[{token, name, encoding (H264, JPEG or MPEG4), width, height, framerate?, bitrate (kbit/s)?, quality?, video_source_token?, ptz?}]", true)],
        json!({"type": PROFILES, "profiles": [{"token": "main", "name": "Main stream", "encoding": "H264", "width": 1920, "height": 1080, "framerate": 25, "bitrate": 4096, "video_source_token": "video_source", "ptz": true}]}))
}

fn hostname_action() -> ActionDefinition {
    action(
        HOSTNAME,
        "Answer GetHostname: the device's host name (once a client's SetHostname is accepted, the device answers with that itself).",
        vec![
            p("name", "string", "The host name, e.g. lobby-cam", true),
            p("from_dhcp", "boolean", "The name came from DHCP (default false)", false),
        ],
        json!({"type": HOSTNAME, "name": "lobby-cam"}),
    )
}

fn accept_action() -> ActionDefinition {
    action(
        ACCEPT,
        "Allow the change or request this event describes; the device applies it exactly as requested (refuse with onvif_fault instead).",
        vec![p(
            "message",
            "string",
            "Optional text the device answers with where the operation has one (SystemReboot's Message)",
            false,
        )],
        json!({"type": ACCEPT}),
    )
}

fn ptz_position_action() -> ActionDefinition {
    action(
        PTZ_POSITION,
        "Accept this PTZ move and say where the camera ends up, in the generic spaces: pan and tilt -1..1, zoom 0..1. The event's proposed position is where plain arithmetic puts it.",
        vec![
            p("pan", "number", "Pan, -1..1", true),
            p("tilt", "number", "Tilt, -1..1", true),
            p("zoom", "number", "Zoom, 0..1", true),
        ],
        json!({"type": PTZ_POSITION, "pan": 0.25, "tilt": -0.1, "zoom": 0.5}),
    )
}

fn focus_position_action() -> ActionDefinition {
    action(
        FOCUS_POSITION,
        "Accept this focus move and say where focus ends up, 0..1. The event's proposed_position is where plain arithmetic puts it.",
        vec![p("position", "number", "Focus position, 0..1", true)],
        json!({"type": FOCUS_POSITION, "position": 0.4}),
    )
}

pub fn raise_event_action() -> ActionDefinition {
    action(
        RAISE_EVENT,
        "Raise an ONVIF event: it goes to every pull-point subscription whose filter matches and is remembered as the property's current value. Topics and their items: tns1:VideoSource/MotionAlarm {source: Source, data: State}; tns1:RuleEngine/CellMotionDetector/Motion {source: VideoSourceConfigurationToken, VideoAnalyticsConfigurationToken, Rule; data: IsMotion}; tns1:RuleEngine/TamperDetector/Tamper {same source; data: IsTamper}; tns1:Device/Trigger/DigitalInput {source: InputToken; data: LogicalState}. Boolean data are true/false.",
        vec![
            p("topic", "string", "One of the topics above, e.g. tns1:VideoSource/MotionAlarm", true),
            p("source", "object", "Every source item the topic carries, e.g. {\"Source\": \"video_source\"}", true),
            p("data", "object", "Every data item the topic carries, e.g. {\"State\": true}", true),
            p("property_operation", "string", "Changed (default), Initialized or Deleted", false),
        ],
        json!({"type": RAISE_EVENT, "topic": "tns1:VideoSource/MotionAlarm", "source": {"Source": "video_source"}, "data": {"State": true}}),
    )
}

fn video_sources_action() -> ActionDefinition {
    action(
        VIDEO_SOURCES,
        "Answer GetVideoSources: the device's video inputs.",
        vec![p(
            "sources",
            "array",
            "[{token, width, height, framerate}]",
            true,
        )],
        json!({"type": VIDEO_SOURCES, "sources": [{"token": "video_source", "width": 1920, "height": 1080, "framerate": 25}]}),
    )
}

fn uri_params(what: &str) -> Vec<Parameter> {
    vec![
        p(
            "uri",
            "string",
            &format!("The {what} URI, e.g. rtsp://192.0.2.10:554/main"),
            true,
        ),
        p(
            "timeout_secs",
            "number",
            "How long the URI stays valid (default 60)",
            false,
        ),
        p(
            "invalid_after_connect",
            "boolean",
            "The URI works only once (default false)",
            false,
        ),
        p(
            "invalid_after_reboot",
            "boolean",
            "The URI stops working after a reboot (default false)",
            false,
        ),
    ]
}

fn stream_uri_action() -> ActionDefinition {
    action(
        STREAM_URI,
        "Answer GetStreamUri: where the client fetches this profile's stream.",
        uri_params("stream"),
        json!({"type": STREAM_URI, "uri": "rtsp://192.0.2.10:554/main"}),
    )
}

fn snapshot_uri_action() -> ActionDefinition {
    action(
        SNAPSHOT_URI,
        "Answer GetSnapshotUri: where the client fetches a JPEG of this profile.",
        uri_params("snapshot"),
        json!({"type": SNAPSHOT_URI, "uri": "http://192.0.2.10/snapshot/main.jpg"}),
    )
}

fn event(
    id: &str,
    description: &str,
    answer: ActionDefinition,
    extra: Vec<Parameter>,
) -> EventType {
    event_with(id, description, vec![answer], extra)
}

/// An event the model answers with one of `answers` or with `onvif_fault`.
fn event_with(
    id: &str,
    description: &str,
    answers: Vec<ActionDefinition>,
    extra: Vec<Parameter>,
) -> EventType {
    let mut params = vec![
        p(
            "operation",
            "string",
            "The ONVIF operation the client called",
            true,
        ),
        p(
            "username",
            "string",
            "The authenticated user, or null when the device requires no credentials",
            true,
        ),
        p(
            "remote_addr",
            "string",
            "The client's address and port",
            true,
        ),
    ];
    params.extend(extra);
    let example = answers[0].example.clone();
    let mut actions = answers;
    actions.push(fault_action());
    EventType::new(id, description, example)
        .with_parameters(params)
        .with_actions(actions)
}

pub static DEVICE_INFORMATION_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event(
        "onvif_get_device_information",
        "A client asked who this device is (GetDeviceInformation).",
        device_information_action(),
        vec![],
    )
});
pub static SCOPES_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event(
        "onvif_get_scopes",
        "A client asked for the device's scopes (GetScopes).",
        scopes_action(),
        vec![],
    )
});
pub static NETWORK_INTERFACES_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event(
        "onvif_get_network_interfaces",
        "A client asked for the device's network interfaces (GetNetworkInterfaces).",
        network_interfaces_action(),
        vec![],
    )
});
pub static PROFILES_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event(
        "onvif_get_profiles",
        "A client asked for the media profiles (GetProfiles).",
        profiles_action(),
        vec![],
    )
});
pub static VIDEO_SOURCES_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event(
        "onvif_get_video_sources",
        "A client asked for the video sources (GetVideoSources).",
        video_sources_action(),
        vec![],
    )
});
pub static STREAM_URI_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event(
        "onvif_get_stream_uri",
        "A client asked where to stream a profile from (GetStreamUri).",
        stream_uri_action(),
        vec![
            p("profile_token", "string", "The profile it wants", true),
            p("stream", "string", "RTP-Unicast or RTP-Multicast", true),
            p(
                "protocol",
                "string",
                "The transport it asked for: RTSP, HTTP, UDP or TCP",
                true,
            ),
            p(
                "service",
                "string",
                "media (ver10) or media2 (ver20; its Protocol is mapped onto stream and protocol)",
                false,
            ),
        ],
    )
});
pub static SNAPSHOT_URI_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event(
        "onvif_get_snapshot_uri",
        "A client asked where to fetch a snapshot of a profile (GetSnapshotUri).",
        snapshot_uri_action(),
        vec![
            p("profile_token", "string", "The profile it wants", true),
            p(
                "service",
                "string",
                "media (ver10) or media2 (ver20)",
                false,
            ),
        ],
    )
});
pub static HOSTNAME_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event(
        "onvif_get_hostname",
        "A client asked for the device's host name (GetHostname) and no SetHostname has been accepted yet.",
        hostname_action(),
        vec![],
    )
});
pub static SET_DATE_TIME_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event(
        "onvif_set_system_date_and_time",
        "A client asks to set the device's clock (SetSystemDateAndTime). Accepted, GetSystemDateAndTime reports it and WS-Security timestamps are checked against it.",
        accept_action(),
        vec![
            p("date_time_type", "string", "Manual or NTP", true),
            p("daylight_savings", "boolean", "Daylight saving in effect", true),
            p("time_zone", "string", "POSIX TZ string, or null to keep the current one", true),
            p("utc_date_time", "string", "The UTC time asked for (Manual), or null", true),
            p("current_utc", "string", "The device's UTC clock now", true),
        ],
    )
});
pub static SET_SCOPES_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event(
        "onvif_set_scopes",
        "A client asks to change the device's configurable scopes (SetScopes replaces them, AddScopes adds, RemoveScopes removes). Accepted, GetScopes reports the change.",
        accept_action(),
        vec![
            p("scopes", "array", "The scope URIs the operation names", true),
            p("configurable", "array", "The configurable scopes before the change", true),
        ],
    )
});
pub static SET_HOSTNAME_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event(
        "onvif_set_hostname",
        "A client asks to rename the device (SetHostname). Accepted, GetHostname reports the new name.",
        accept_action(),
        vec![p("name", "string", "The host name asked for", true)],
    )
});
pub static REBOOT_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event(
        "onvif_system_reboot",
        "A client asks the device to reboot (SystemReboot). Accepting only answers it; nothing reboots.",
        accept_action(),
        vec![],
    )
});
pub static PTZ_MOVE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event(
        "onvif_ptz_move",
        "A client asks the PTZ head to move (ContinuousMove, RelativeMove, AbsoluteMove, GotoPreset, GotoHomePosition). Accept with where it ends up, or refuse with a fault (e.g. InvalidArgVal/InvalidPosition); a refused move changes nothing.",
        ptz_position_action(),
        vec![
            p("profile_token", "string", "The profile the move was sent on", true),
            p("kind", "string", "continuous, relative, absolute, preset or home", true),
            p("velocity", "object", "continuous: {pan, tilt, zoom}, each -1..1 or null", false),
            p("timeout_secs", "number", "continuous: how long the move runs", false),
            p("translation", "object", "relative: {pan, tilt, zoom} to add", false),
            p("target", "object", "absolute: {pan, tilt, zoom}; a null axis stays where it is", false),
            p("preset_token", "string", "preset: the preset's token", false),
            p("preset_name", "string", "preset: the preset's name", false),
            p("speed", "object", "{pan, tilt, zoom} speeds 0..1 the client asked for, or nulls", false),
            p("current", "object", "Where the head is: {pan, tilt, zoom}", true),
            p("proposed", "object", "Where plain arithmetic puts it: {pan, tilt, zoom}", true),
        ],
    )
});
pub static SUBSCRIBE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event_with(
        "onvif_create_subscription",
        "A client asks for a pull-point event subscription (CreatePullPointSubscription). Accept it — optionally raising events it should receive with onvif_raise_event — or refuse with a fault.",
        vec![accept_action(), raise_event_action()],
        vec![
            p("subscription", "string", "The new subscription's id", true),
            p("filter", "array", "The topic expressions it asked for, or null for every topic", true),
            p("termination_time", "string", "When it ends unless renewed", true),
        ],
    )
});
pub static SET_IMAGING_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event(
        "onvif_set_imaging_settings",
        "A client asks to change a video source's imaging settings (SetImagingSettings). Accepted, GetImagingSettings reports them.",
        accept_action(),
        vec![
            p("video_source_token", "string", "The video source", true),
            p("current", "object", "{brightness, color_saturation, contrast, sharpness (0..100), ir_cut_filter, auto_focus_mode}", true),
            p("requested", "object", "The same, as the client asks them to be", true),
        ],
    )
});
pub static IMAGING_MOVE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event(
        "onvif_imaging_move",
        "A client asks to move a video source's focus (Imaging Move). Accept with where focus ends up, or refuse with a fault.",
        focus_position_action(),
        vec![
            p("video_source_token", "string", "The video source", true),
            p("kind", "string", "absolute, relative or continuous", true),
            p("requested", "object", "{position, speed} / {distance, speed} / {speed}", true),
            p("current_position", "number", "Where focus is, 0..1", true),
            p("proposed_position", "number", "Where plain arithmetic puts it", true),
            p("auto_focus_mode", "string", "AUTO or MANUAL", true),
        ],
    )
});

/// Plain text from the model: non-empty, bounded, no control characters.
fn text(v: &Value, key: &str) -> Result<String> {
    let s = v[key]
        .as_str()
        .with_context(|| format!("{key} is required and must be a string"))?;
    ensure!(
        !s.is_empty() && s.len() <= MAX_TEXT && !crate::utils::sanitize::has_controls(s),
        "{key} must be 1-{MAX_TEXT} bytes of text without control characters"
    );
    Ok(s.to_string())
}

/// A ReferenceToken: 1-64 bytes, no whitespace or control characters.
fn token(v: &Value, key: &str, required: bool) -> Result<()> {
    match v.get(key) {
        None | Some(Value::Null) if !required => Ok(()),
        Some(Value::String(s))
            if !s.is_empty()
                && s.len() <= 64
                && !s.chars().any(char::is_whitespace)
                && !crate::utils::sanitize::has_controls(s) =>
        {
            Ok(())
        }
        _ => bail!("{key} must be a token of 1-64 characters without spaces"),
    }
}

fn number(
    v: &Value,
    key: &str,
    range: std::ops::RangeInclusive<u64>,
    required: bool,
) -> Result<()> {
    match v.get(key) {
        None | Some(Value::Null) if !required => Ok(()),
        Some(x) => {
            let n = x
                .as_u64()
                .with_context(|| format!("{key} must be a whole number"))?;
            ensure!(
                range.contains(&n),
                "{key} must be between {} and {}",
                range.start(),
                range.end()
            );
            Ok(())
        }
        None => bail!("{key} is required"),
    }
}

fn flag(v: &Value, key: &str) -> Result<()> {
    ensure!(
        matches!(v.get(key), None | Some(Value::Null) | Some(Value::Bool(_))),
        "{key} must be true or false"
    );
    Ok(())
}

fn list<'a>(v: &'a Value, key: &str) -> Result<&'a Vec<Value>> {
    let a = v[key]
        .as_array()
        .with_context(|| format!("{key} must be a list"))?;
    ensure!(
        a.len() <= super::wire::MAX_ITEMS,
        "{key} may hold at most {} entries",
        super::wire::MAX_ITEMS
    );
    Ok(a)
}

/// A URI with a scheme and no whitespace.
fn uri(v: &Value, key: &str) -> Result<()> {
    let s = v[key]
        .as_str()
        .with_context(|| format!("{key} is required"))?;
    let scheme_ok = s.split_once("://").is_some_and(|(scheme, rest)| {
        !scheme.is_empty()
            && !rest.is_empty()
            && scheme
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "+-.".contains(c))
    });
    ensure!(
        scheme_ok
            && s.len() <= MAX_URI
            && !s.chars().any(char::is_whitespace)
            && !crate::utils::sanitize::has_controls(s),
        "{key} must be an absolute URI such as rtsp://host:554/path"
    );
    Ok(())
}

fn subcode(v: &Value, key: &str, required: bool) -> Result<()> {
    match v.get(key) {
        None | Some(Value::Null) if !required => Ok(()),
        Some(Value::String(s))
            if !s.is_empty() && s.len() <= 64 && s.chars().all(|c| c.is_ascii_alphanumeric()) =>
        {
            Ok(())
        }
        _ => bail!("{key} must be an ONVIF error name such as InvalidArgVal"),
    }
}

/// A host name as RFC 1123 allows: dot-separated labels of letters, digits and inner hyphens.
pub fn hostname(name: &str) -> Result<()> {
    ensure!(
        !name.is_empty()
            && name.len() <= MAX_HOSTNAME
            && name.split('.').all(|l| {
                !l.is_empty()
                    && l.len() <= 63
                    && !l.starts_with('-')
                    && !l.ends_with('-')
                    && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
            }),
        "name must be a host name such as lobby-cam (letters, digits, hyphens; dot-separated labels)"
    );
    Ok(())
}

pub fn check(v: &Value) -> Result<()> {
    match v["type"].as_str().unwrap_or_default() {
        DEVICE_INFORMATION => {
            for k in [
                "manufacturer",
                "model",
                "firmware_version",
                "serial_number",
                "hardware_id",
            ] {
                text(v, k)?;
            }
        }
        SCOPES => {
            for s in list(v, "scopes")? {
                uri(&json!({"u": s}), "u")
                    .context("each scope is a URI such as onvif://www.onvif.org/name/Lobby")?;
            }
        }
        NETWORK_INTERFACES => {
            for i in list(v, "interfaces")? {
                token(i, "token", true)?;
                text(i, "name")?;
                let mac = i["mac"].as_str().context("mac is required")?;
                let parts: Vec<&str> = mac.split([':', '-']).collect();
                ensure!(
                    parts.len() == 6
                        && parts
                            .iter()
                            .all(|p| p.len() == 2 && p.chars().all(|c| c.is_ascii_hexdigit())),
                    "mac must look like 02:00:00:00:00:01"
                );
                i["ipv4_address"]
                    .as_str()
                    .and_then(|a| a.parse::<std::net::Ipv4Addr>().ok())
                    .context("ipv4_address must be an IPv4 address")?;
                number(i, "prefix_length", 0..=32, true)?;
                number(i, "mtu", 68..=65535, false)?;
                flag(i, "dhcp")?;
                flag(i, "enabled")?;
            }
        }
        PROFILES => {
            for pr in list(v, "profiles")? {
                token(pr, "token", true)?;
                token(pr, "video_source_token", false)?;
                if pr.get("name").is_some_and(|n| !n.is_null()) {
                    text(pr, "name")?;
                }
                ensure!(
                    matches!(
                        pr["encoding"].as_str(),
                        None | Some("H264" | "JPEG" | "MPEG4")
                    ),
                    "encoding is H264, JPEG or MPEG4"
                );
                number(pr, "width", 1..=16384, true)?;
                number(pr, "height", 1..=16384, true)?;
                number(pr, "framerate", 1..=240, false)?;
                number(pr, "bitrate", 1..=1_000_000, false)?;
                number(pr, "quality", 0..=100, false)?;
                flag(pr, "ptz")?;
            }
        }
        HOSTNAME => {
            hostname(v["name"].as_str().unwrap_or_default())?;
            flag(v, "from_dhcp")?;
        }
        ACCEPT => {
            if v.get("message").is_some_and(|m| !m.is_null()) {
                text(v, "message")?;
            }
        }
        PTZ_POSITION => {
            super::ptz::Position::from_json(v)
                .context("pan and tilt are numbers in -1..1 and zoom a number in 0..1")?;
        }
        FOCUS_POSITION => {
            ensure!(
                v["position"]
                    .as_f64()
                    .is_some_and(|p| (0.0..=1.0).contains(&p)),
                "position is a number in 0..1"
            );
        }
        RAISE_EVENT => {
            super::events::notification_from_action(v, chrono::Utc::now())?;
        }
        VIDEO_SOURCES => {
            for s in list(v, "sources")? {
                token(s, "token", true)?;
                number(s, "width", 1..=16384, true)?;
                number(s, "height", 1..=16384, true)?;
                number(s, "framerate", 1..=240, false)?;
            }
        }
        STREAM_URI | SNAPSHOT_URI => {
            uri(v, "uri")?;
            number(v, "timeout_secs", 0..=86_400, false)?;
            flag(v, "invalid_after_connect")?;
            flag(v, "invalid_after_reboot")?;
        }
        FAULT => {
            subcode(v, "subcode", true)?;
            subcode(v, "detail", false)?;
            text(v, "reason")?;
        }
        other => bail!("Unknown ONVIF action {other:?}"),
    }
    Ok(())
}

impl Protocol for OnvifProtocol {
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
            "network video transmitter",
            "cctv",
        ]
    }
    fn description(&self) -> &'static str {
        "ONVIF device (IP camera): Device and Media services over SOAP 1.2 with WS-Security digest authentication; the model decides the device's identity, profiles and stream URIs"
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        vec![raise_event_action()]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            device_information_action(),
            scopes_action(),
            network_interfaces_action(),
            profiles_action(),
            video_sources_action(),
            stream_uri_action(),
            snapshot_uri_action(),
            hostname_action(),
            accept_action(),
            ptz_position_action(),
            focus_position_action(),
            raise_event_action(),
            fault_action(),
        ]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            DEVICE_INFORMATION_EVENT.clone(),
            SCOPES_EVENT.clone(),
            NETWORK_INTERFACES_EVENT.clone(),
            PROFILES_EVENT.clone(),
            VIDEO_SOURCES_EVENT.clone(),
            STREAM_URI_EVENT.clone(),
            SNAPSHOT_URI_EVENT.clone(),
            HOSTNAME_EVENT.clone(),
            SET_DATE_TIME_EVENT.clone(),
            SET_SCOPES_EVENT.clone(),
            SET_HOSTNAME_EVENT.clone(),
            REBOOT_EVENT.clone(),
            PTZ_MOVE_EVENT.clone(),
            SUBSCRIBE_EVENT.clone(),
            SET_IMAGING_EVENT.clone(),
            IMAGING_MOVE_EVENT.clone(),
        ]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "username".into(),
                type_hint: "string".into(),
                description: "The one user clients must authenticate as (WS-Security UsernameToken digest). With neither username nor password, every operation is open".into(),
                required: false,
                example: json!("admin"),
                default: None,
            },
            ParameterDefinition {
                name: "password".into(),
                type_hint: "string".into(),
                description: "That user's password; required with username".into(),
                required: false,
                example: json!("camera-secret"),
                default: None,
            },
            ParameterDefinition {
                name: "max_clock_skew_secs".into(),
                type_hint: "number".into(),
                description: "How far a UsernameToken's Created may be from the device's clock, in seconds (1..=86400); clients learn the device's time from GetSystemDateAndTime first".into(),
                required: false,
                example: json!(300),
                default: Some(json!(super::MAX_CLOCK_SKEW.as_secs())),
            },
            ParameterDefinition {
                name: "max_pull_timeout_secs".into(),
                type_hint: "number".into(),
                description: "The longest a PullMessages request is held waiting for an event, in seconds (1..=60); a longer Timeout is cut to it".into(),
                required: false,
                example: json!(60),
                default: Some(json!(super::events::MAX_PULL_TIMEOUT.as_secs())),
            },
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation("hyper HTTP/1.1; SOAP 1.2 envelopes read with quick-xml into a bounded namespace-resolved tree (256 KiB, depth 32, 20000 elements, no DOCTYPE) and written escaped. Device service (ver10): GetSystemDateAndTime (always unauthenticated, from the host clock), GetCapabilities and GetServices (pointing at this server), GetDeviceInformation, GetScopes, GetNetworkInterfaces. Media service (ver10): GetProfiles, GetVideoSources, GetStreamUri, GetSnapshotUri. WS-Security UsernameToken PasswordDigest verified in Rust (SHA-1 over nonce, Created and password; Created within max_clock_skew_secs; nonces remembered so none can be replayed); a refusal is env:Sender/ter:NotAuthorized. Any other operation is env:Receiver/ter:ActionNotSupported")
            .llm_control("The device's identity, scopes and network interfaces, its media profiles and video sources, the stream and snapshot URIs it hands out, and any fault refusing one of those")
            .e2e_testing("tests/server/onvif: two independent ONVIF clients authenticate with digest and read device information, profiles and stream URIs the model supplied — python onvif-zeep-async 4.3.0 (Home Assistant's library, zeep over ONVIF's own WSDL) and Go use-go/onvif v0.0.9 (encoding/xml, its own digest); raw HTTP for the digest, replay, clock, fault, bound and failed-handler paths")
            .notes("Experimental: the two clients are real and the tests fail without them, but nothing above the evidence in tests/server/onvif has been reviewed by a person. Only ver10 Device and Media: no Media2 (ver20; neither client's bundled WSDL has it), no PTZ, Imaging, Events or Recording, no Set* operations. One configured user. No HTTP Digest authentication and no TLS. The device does not stream: the URIs it hands out are whatever the model says. WS-Discovery is the separate wsdiscovery protocol; point its xaddrs at this server's /onvif/device_service to be discovered.")
            .request_only("Every message answers a client's HTTP request")
            .answers_on_failure()
            .max_inbound_bytes(super::wire::MAX_REQUEST)
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "ONVIF camera on port 8080 with user admin/secret, one 1080p H264 profile streaming from rtsp://192.0.2.10:554/main"
    }
    fn get_startup_examples(&self) -> StartupExamples {
        let llm = json!({"type":"open_server","base_stack":"onvif","port":8080,
            "startup_params":{"username":"admin","password":"secret"},
            "instruction":"You are a Lobby camera by NetGet, serial NG-0001, with one 1920x1080 H264 profile 'main' streaming from rtsp://192.0.2.10:554/main"});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([
            {"event_pattern":"onvif_get_device_information","handler":{"type":"static","actions":[device_information_action().example]}},
            {"event_pattern":"onvif_get_profiles","handler":{"type":"static","actions":[profiles_action().example]}},
            {"event_pattern":"onvif_get_stream_uri","handler":{"type":"static","actions":[stream_uri_action().example]}}]);
        let mut scripted = llm.clone();
        scripted["event_handlers"] = json!([{"event_pattern":"onvif_get_stream_uri","handler":{"type":"script","language":"python",
            "code":"import json,sys\ne=json.load(sys.stdin)['event']\nprint(json.dumps({'actions':[{'type':'onvif_stream_uri','uri':'rtsp://192.0.2.10:554/'+e['profile_token']}]}))"}}]);
        StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Application"
    }
}

impl Server for OnvifProtocol {
    fn spawn(
        &self,
        ctx: SpawnContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::spawn(ctx))
    }
    fn execute_action(&self, action: Value) -> Result<ActionResult> {
        check(&action)?;
        Ok(ActionResult::Custom {
            name: action["type"].as_str().unwrap_or_default().to_string(),
            data: action,
        })
    }

    /// `onvif_raise_event` reaches the running device's subscriptions; everything else is an
    /// answer `execute_action` validates.
    fn execute_action_with_state<'a>(
        &'a self,
        action: Value,
        state: AppState,
        server_id: Option<crate::state::ServerId>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<ActionResult>> + Send + 'a>>
    {
        if action["type"].as_str() != Some(RAISE_EVENT) {
            let result = self.execute_action(action);
            return Box::pin(async move { result });
        }
        Box::pin(async move {
            let id = server_id.context("onvif_raise_event needs the running ONVIF device")?;
            let device = state
                .server_handle::<super::Device>(id)
                .await
                .context("this server is not a running ONVIF device")?;
            let delivered = device.raise(&action)?;
            Ok(ActionResult::Custom {
                name: RAISE_EVENT.into(),
                data: json!({"delivered": delivered}),
            })
        })
    }
}
