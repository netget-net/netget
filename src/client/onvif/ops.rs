//! The ONVIF client's operations beyond Device and Media ver10: PTZ, Events (pull point),
//! Media2 and Imaging — what each action sends and how each answer is read back into the JSON
//! the model sees. Every value the model gives is checked here before it is written, and written
//! escaped; every answer is read from the bounded tree `wire::tree` built.
use crate::server::onvif::events::{CONCRETE_SET, MAX_TOPIC_DEPTH};
use crate::server::onvif::ptz;
use crate::server::onvif::wire::{self, esc, Element, MAX_ITEMS};
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Map, Value};

/// Where an operation goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Service {
    Device,
    Media,
    Media2,
    Ptz,
    Events,
    /// The pull-point subscription the last onvif_create_pull_point made.
    Subscription,
    Imaging,
}

pub struct Spec {
    pub action: &'static str,
    pub service: Service,
    pub operation: &'static str,
}

const fn spec(action: &'static str, service: Service, operation: &'static str) -> Spec {
    Spec {
        action,
        service,
        operation,
    }
}

use Service::*;

/// Every action the client has, and the operation it sends.
pub const SPECS: &[Spec] = &[
    spec(
        "onvif_get_device_information",
        Device,
        "GetDeviceInformation",
    ),
    spec("onvif_get_scopes", Device, "GetScopes"),
    spec(
        "onvif_get_network_interfaces",
        Device,
        "GetNetworkInterfaces",
    ),
    spec("onvif_get_capabilities", Device, "GetCapabilities"),
    spec("onvif_get_services", Device, "GetServices"),
    spec(
        "onvif_get_system_date_and_time",
        Device,
        "GetSystemDateAndTime",
    ),
    spec("onvif_get_profiles", Media, "GetProfiles"),
    spec("onvif_get_video_sources", Media, "GetVideoSources"),
    spec("onvif_get_stream_uri", Media, "GetStreamUri"),
    spec("onvif_get_snapshot_uri", Media, "GetSnapshotUri"),
    spec("onvif_media2_get_profiles", Media2, "GetProfiles"),
    spec("onvif_media2_get_stream_uri", Media2, "GetStreamUri"),
    spec("onvif_media2_get_snapshot_uri", Media2, "GetSnapshotUri"),
    spec(
        "onvif_media2_get_video_source_configurations",
        Media2,
        "GetVideoSourceConfigurations",
    ),
    spec(
        "onvif_media2_get_video_encoder_configurations",
        Media2,
        "GetVideoEncoderConfigurations",
    ),
    spec("onvif_ptz_get_nodes", Ptz, "GetNodes"),
    spec("onvif_ptz_get_configurations", Ptz, "GetConfigurations"),
    spec("onvif_ptz_get_status", Ptz, "GetStatus"),
    spec("onvif_ptz_continuous_move", Ptz, "ContinuousMove"),
    spec("onvif_ptz_relative_move", Ptz, "RelativeMove"),
    spec("onvif_ptz_absolute_move", Ptz, "AbsoluteMove"),
    spec("onvif_ptz_stop", Ptz, "Stop"),
    spec("onvif_ptz_get_presets", Ptz, "GetPresets"),
    spec("onvif_ptz_set_preset", Ptz, "SetPreset"),
    spec("onvif_ptz_goto_preset", Ptz, "GotoPreset"),
    spec("onvif_ptz_remove_preset", Ptz, "RemovePreset"),
    spec("onvif_ptz_goto_home", Ptz, "GotoHomePosition"),
    spec("onvif_get_event_properties", Events, "GetEventProperties"),
    spec(
        "onvif_create_pull_point",
        Events,
        "CreatePullPointSubscription",
    ),
    spec("onvif_pull_messages", Subscription, "PullMessages"),
    spec("onvif_renew_subscription", Subscription, "Renew"),
    spec("onvif_unsubscribe", Subscription, "Unsubscribe"),
    spec(
        "onvif_set_synchronization_point",
        Subscription,
        "SetSynchronizationPoint",
    ),
    spec("onvif_imaging_get_settings", Imaging, "GetImagingSettings"),
    spec("onvif_imaging_set_settings", Imaging, "SetImagingSettings"),
    spec("onvif_imaging_get_options", Imaging, "GetOptions"),
    spec("onvif_imaging_get_move_options", Imaging, "GetMoveOptions"),
    spec("onvif_imaging_move", Imaging, "Move"),
    spec("onvif_imaging_get_status", Imaging, "GetStatus"),
    spec("onvif_imaging_stop", Imaging, "Stop"),
];

pub fn spec_of(v: &Value) -> Option<&'static Spec> {
    let t = v["type"].as_str()?;
    SPECS.iter().find(|s| s.action == t)
}

/// The WS-Addressing Action of an Events operation (their bindings are WS-Addressing ones);
/// None for the services whose requests carry no addressing headers.
pub fn action_uri(spec: &Spec) -> Option<&'static str> {
    Some(match spec.operation {
        "GetEventProperties" => {
            "http://www.onvif.org/ver10/events/wsdl/EventPortType/GetEventPropertiesRequest"
        }
        "CreatePullPointSubscription" => {
            "http://www.onvif.org/ver10/events/wsdl/EventPortType/CreatePullPointSubscriptionRequest"
        }
        "PullMessages" => {
            "http://www.onvif.org/ver10/events/wsdl/PullPointSubscription/PullMessagesRequest"
        }
        "SetSynchronizationPoint" => {
            "http://www.onvif.org/ver10/events/wsdl/PullPointSubscription/SetSynchronizationPointRequest"
        }
        "Renew" => "http://docs.oasis-open.org/wsn/bw-2/SubscriptionManager/RenewRequest",
        "Unsubscribe" => "http://docs.oasis-open.org/wsn/bw-2/SubscriptionManager/UnsubscribeRequest",
        _ => return None,
    })
    .filter(|_| matches!(spec.service, Service::Events | Service::Subscription))
}

/// The longest PullMessages wait a client asks for, in seconds.
pub const MAX_PULL_SECS: u64 = 60;
/// The longest subscription lifetime a client asks for, in seconds.
pub const MAX_TERMINATION_SECS: u64 = 3600;

fn token(v: &Value, key: &str) -> Result<String> {
    let t = v[key]
        .as_str()
        .with_context(|| format!("{key} is required"))?;
    ensure!(
        !t.is_empty()
            && t.len() <= 64
            && !t.chars().any(char::is_whitespace)
            && !crate::utils::sanitize::has_controls(t),
        "{key} is a token of 1-64 characters without spaces"
    );
    Ok(esc(t))
}

fn opt_f64(v: &Value, key: &str, lo: f64, hi: f64) -> Result<Option<f64>> {
    match v.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(x) => {
            let f = x
                .as_f64()
                .with_context(|| format!("{key} must be a number"))?;
            ensure!(
                f.is_finite() && (lo..=hi).contains(&f),
                "{key} must be between {lo} and {hi}"
            );
            Ok(Some(f))
        }
    }
}

fn opt_secs(v: &Value, key: &str, max: u64) -> Result<Option<u64>> {
    match v.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(x) => {
            let n = x
                .as_u64()
                .with_context(|| format!("{key} must be a whole number of seconds"))?;
            ensure!((1..=max).contains(&n), "{key} must be between 1 and {max}");
            Ok(Some(n))
        }
    }
}

/// A PTZ vector element: PanTilt when pan or tilt is given (the other defaults to 0), Zoom when
/// zoom is.
fn vector(tag: &str, v: &Value, kind: ptz::Kind) -> Result<String> {
    let (pt_space, z_space, (lo, hi), (zlo, zhi)) = match kind {
        ptz::Kind::Position => (ptz::ABS_PAN_TILT, ptz::ABS_ZOOM, (-1.0, 1.0), (0.0, 1.0)),
        ptz::Kind::Translation => (ptz::REL_PAN_TILT, ptz::REL_ZOOM, (-1.0, 1.0), (-1.0, 1.0)),
        ptz::Kind::Velocity => (ptz::VEL_PAN_TILT, ptz::VEL_ZOOM, (-1.0, 1.0), (-1.0, 1.0)),
        ptz::Kind::Speed => (ptz::SPEED_PAN_TILT, ptz::SPEED_ZOOM, (0.0, 1.0), (0.0, 1.0)),
    };
    let pan = opt_f64(v, "pan", lo, hi)?;
    let tilt = opt_f64(v, "tilt", lo, hi)?;
    let zoom = opt_f64(v, "zoom", zlo, zhi)?;
    ensure!(
        pan.is_some() || tilt.is_some() || zoom.is_some(),
        "give at least one of pan, tilt and zoom"
    );
    let mut out = format!("<tptz:{tag}>");
    if pan.is_some() || tilt.is_some() {
        out.push_str(&format!(
            "<tt:PanTilt x=\"{}\" y=\"{}\" space=\"{pt_space}\"/>",
            pan.unwrap_or(0.0),
            tilt.unwrap_or(0.0)
        ));
    }
    if let Some(z) = zoom {
        out.push_str(&format!("<tt:Zoom x=\"{z}\" space=\"{z_space}\"/>"));
    }
    out.push_str(&format!("</tptz:{tag}>"));
    Ok(out)
}

/// Check an action's arguments and build its request body.
pub fn request_body(spec: &Spec, v: &Value) -> Result<String> {
    let profile = || token(v, "profile_token");
    let source = || token(v, "video_source_token");
    Ok(match (spec.service, spec.operation) {
        (Device | Media, op) => wire::request_body(op, v)?,
        (Media2, "GetProfiles") => {
            "<tr2:GetProfiles><tr2:Type>All</tr2:Type></tr2:GetProfiles>".into()
        }
        (Media2, "GetStreamUri") => {
            let protocol = match v["protocol"].as_str() {
                None => "RtspUnicast",
                Some(p @ ("RtspUnicast" | "RtspMulticast" | "RTSP" | "RtspOverHttp")) => p,
                Some(_) => bail!("protocol is RtspUnicast, RtspMulticast, RTSP or RtspOverHttp"),
            };
            format!(
                "<tr2:GetStreamUri><tr2:Protocol>{protocol}</tr2:Protocol><tr2:ProfileToken>{}</tr2:ProfileToken></tr2:GetStreamUri>",
                profile()?
            )
        }
        (Media2, "GetSnapshotUri") => format!(
            "<tr2:GetSnapshotUri><tr2:ProfileToken>{}</tr2:ProfileToken></tr2:GetSnapshotUri>",
            profile()?
        ),
        (Media2, op) => match v.get("profile_token").filter(|t| !t.is_null()) {
            Some(_) => format!(
                "<tr2:{op}><tr2:ProfileToken>{}</tr2:ProfileToken></tr2:{op}>",
                profile()?
            ),
            None => format!("<tr2:{op}/>"),
        },
        (Ptz, op @ ("GetNodes" | "GetConfigurations")) => format!("<tptz:{op}/>"),
        (Ptz, op @ ("GetStatus" | "GetPresets" | "GotoHomePosition")) => format!(
            "<tptz:{op}><tptz:ProfileToken>{}</tptz:ProfileToken></tptz:{op}>",
            profile()?
        ),
        (Ptz, "ContinuousMove") => {
            let timeout = opt_secs(v, "timeout_secs", ptz::MAX_TIMEOUT.as_secs())?
                .map(|t| format!("<tptz:Timeout>PT{t}S</tptz:Timeout>"))
                .unwrap_or_default();
            format!(
                "<tptz:ContinuousMove><tptz:ProfileToken>{}</tptz:ProfileToken>{}{timeout}</tptz:ContinuousMove>",
                profile()?,
                vector("Velocity", v, ptz::Kind::Velocity)?
            )
        }
        (Ptz, "RelativeMove") => format!(
            "<tptz:RelativeMove><tptz:ProfileToken>{}</tptz:ProfileToken>{}</tptz:RelativeMove>",
            profile()?,
            vector("Translation", v, ptz::Kind::Translation)?
        ),
        (Ptz, "AbsoluteMove") => format!(
            "<tptz:AbsoluteMove><tptz:ProfileToken>{}</tptz:ProfileToken>{}</tptz:AbsoluteMove>",
            profile()?,
            vector("Position", v, ptz::Kind::Position)?
        ),
        (Ptz, "Stop") => {
            let flag = |k: &str| -> Result<bool> {
                match v.get(k) {
                    None | Some(Value::Null) => Ok(true),
                    Some(Value::Bool(b)) => Ok(*b),
                    _ => bail!("{k} is true or false"),
                }
            };
            format!(
                "<tptz:Stop><tptz:ProfileToken>{}</tptz:ProfileToken><tptz:PanTilt>{}</tptz:PanTilt><tptz:Zoom>{}</tptz:Zoom></tptz:Stop>",
                profile()?,
                flag("pan_tilt")?,
                flag("zoom")?
            )
        }
        (Ptz, "SetPreset") => {
            let name = match v.get("preset_name").filter(|n| !n.is_null()) {
                None => String::new(),
                Some(n) => {
                    let n = n.as_str().context("preset_name is text")?;
                    ensure!(
                        !n.is_empty()
                            && n.len() <= ptz::MAX_PRESET_NAME
                            && !crate::utils::sanitize::has_controls(n),
                        "preset_name is 1-{} bytes of text",
                        ptz::MAX_PRESET_NAME
                    );
                    format!("<tptz:PresetName>{}</tptz:PresetName>", esc(n))
                }
            };
            let preset = match v.get("preset_token").filter(|n| !n.is_null()) {
                None => String::new(),
                Some(_) => format!(
                    "<tptz:PresetToken>{}</tptz:PresetToken>",
                    token(v, "preset_token")?
                ),
            };
            format!(
                "<tptz:SetPreset><tptz:ProfileToken>{}</tptz:ProfileToken>{name}{preset}</tptz:SetPreset>",
                profile()?
            )
        }
        (Ptz, op @ ("GotoPreset" | "RemovePreset")) => format!(
            "<tptz:{op}><tptz:ProfileToken>{}</tptz:ProfileToken><tptz:PresetToken>{}</tptz:PresetToken></tptz:{op}>",
            profile()?,
            token(v, "preset_token")?
        ),
        (Events, "GetEventProperties") => "<tev:GetEventProperties/>".into(),
        (Events, "CreatePullPointSubscription") => {
            let filter = match v.get("topic_filter").filter(|f| !f.is_null()) {
                None => String::new(),
                Some(f) => {
                    let f = f.as_str().context("topic_filter is a topic expression")?;
                    // The same parser the device side uses: a filter the client cannot read
                    // itself is not sent.
                    crate::server::onvif::events::parse_topic_filter(CONCRETE_SET, f)
                        .map_err(|e| anyhow::anyhow!("topic_filter: {}", e.reason()))?;
                    format!(
                        "<tev:Filter><wsnt:TopicExpression Dialect=\"{CONCRETE_SET}\">{}</wsnt:TopicExpression></tev:Filter>",
                        esc(f)
                    )
                }
            };
            let secs = opt_secs(v, "termination_secs", MAX_TERMINATION_SECS)?.unwrap_or(60);
            format!(
                "<tev:CreatePullPointSubscription>{filter}<tev:InitialTerminationTime>PT{secs}S</tev:InitialTerminationTime></tev:CreatePullPointSubscription>"
            )
        }
        (Subscription, "PullMessages") => format!(
            "<tev:PullMessages><tev:Timeout>PT{}S</tev:Timeout><tev:MessageLimit>{}</tev:MessageLimit></tev:PullMessages>",
            pull_secs(v)?,
            opt_secs(v, "message_limit", 100)?.unwrap_or(10)
        ),
        (Subscription, "Renew") => format!(
            "<wsnt:Renew><wsnt:TerminationTime>PT{}S</wsnt:TerminationTime></wsnt:Renew>",
            opt_secs(v, "termination_secs", MAX_TERMINATION_SECS)?.unwrap_or(60)
        ),
        (Subscription, "Unsubscribe") => "<wsnt:Unsubscribe/>".into(),
        (Subscription, "SetSynchronizationPoint") => "<tev:SetSynchronizationPoint/>".into(),
        (Imaging, "SetImagingSettings") => {
            let mut settings = String::new();
            let mut any = false;
            for (key, tag) in [
                ("brightness", "Brightness"),
                ("color_saturation", "ColorSaturation"),
                ("contrast", "Contrast"),
            ] {
                if let Some(x) = opt_f64(v, key, 0.0, 100.0)? {
                    settings.push_str(&format!("<tt:{tag}>{x}</tt:{tag}>"));
                    any = true;
                }
            }
            if let Some(m) = v.get("auto_focus_mode").filter(|m| !m.is_null()) {
                let m = m.as_str().unwrap_or_default();
                ensure!(m == "AUTO" || m == "MANUAL", "auto_focus_mode is AUTO or MANUAL");
                settings.push_str(&format!(
                    "<tt:Focus><tt:AutoFocusMode>{m}</tt:AutoFocusMode></tt:Focus>"
                ));
                any = true;
            }
            if let Some(m) = v.get("ir_cut_filter").filter(|m| !m.is_null()) {
                let m = m.as_str().unwrap_or_default();
                ensure!(
                    matches!(m, "ON" | "OFF" | "AUTO"),
                    "ir_cut_filter is ON, OFF or AUTO"
                );
                settings.push_str(&format!("<tt:IrCutFilter>{m}</tt:IrCutFilter>"));
                any = true;
            }
            if let Some(x) = opt_f64(v, "sharpness", 0.0, 100.0)? {
                settings.push_str(&format!("<tt:Sharpness>{x}</tt:Sharpness>"));
                any = true;
            }
            ensure!(any, "give at least one setting to change");
            format!(
                "<timg:SetImagingSettings><timg:VideoSourceToken>{}</timg:VideoSourceToken><timg:ImagingSettings>{settings}</timg:ImagingSettings><timg:ForcePersistence>false</timg:ForcePersistence></timg:SetImagingSettings>",
                source()?
            )
        }
        (Imaging, "Move") => {
            let focus = match v["kind"].as_str() {
                Some("absolute") => format!(
                    "<tt:Absolute><tt:Position>{}</tt:Position></tt:Absolute>",
                    opt_f64(v, "position", 0.0, 1.0)?.context("absolute needs position")?
                ),
                Some("relative") => format!(
                    "<tt:Relative><tt:Distance>{}</tt:Distance></tt:Relative>",
                    opt_f64(v, "distance", -1.0, 1.0)?.context("relative needs distance")?
                ),
                Some("continuous") => format!(
                    "<tt:Continuous><tt:Speed>{}</tt:Speed></tt:Continuous>",
                    opt_f64(v, "speed", -1.0, 1.0)?.context("continuous needs speed")?
                ),
                _ => bail!("kind is absolute, relative or continuous"),
            };
            format!(
                "<timg:Move><timg:VideoSourceToken>{}</timg:VideoSourceToken><timg:Focus>{focus}</timg:Focus></timg:Move>",
                source()?
            )
        }
        (Imaging, op) => format!(
            "<timg:{op}><timg:VideoSourceToken>{}</timg:VideoSourceToken></timg:{op}>",
            source()?
        ),
        (_, op) => bail!("no request body for {op}"),
    })
}

/// A PullMessages wait, in seconds.
pub fn pull_secs(v: &Value) -> Result<u64> {
    Ok(opt_secs(v, "timeout_secs", MAX_PULL_SECS)?.unwrap_or(10))
}

fn opt(e: &Element, path: &[&str]) -> Value {
    e.path(path).map(Value::from).unwrap_or(Value::Null)
}

/// A number at a path: whole numbers as integers, others as floats.
fn num(e: &Element, path: &[&str]) -> Value {
    let Some(t) = e.path(path) else {
        return Value::Null;
    };
    t.parse::<u64>().map(Value::from).unwrap_or_else(|_| {
        t.parse::<f64>()
            .ok()
            .filter(|f| f.is_finite())
            .map(Value::from)
            .unwrap_or(Value::Null)
    })
}

fn attr_num(e: Option<&Element>, name: &str) -> Value {
    e.and_then(|e| e.attr(name))
        .and_then(|t| t.trim().parse::<f64>().ok())
        .filter(|f| f.is_finite())
        .map(Value::from)
        .unwrap_or(Value::Null)
}

fn position(e: Option<&Element>) -> Value {
    json!({
        "pan": attr_num(e.and_then(|e| e.child("PanTilt")), "x"),
        "tilt": attr_num(e.and_then(|e| e.child("PanTilt")), "y"),
        "zoom": attr_num(e.and_then(|e| e.child("Zoom")), "x"),
    })
}

fn items_of(e: &Element) -> Value {
    Value::Object(
        e.children_named("SimpleItem")
            .take(16)
            .filter_map(|i| Some((i.attr("Name")?.to_string(), json!(i.attr("Value")?))))
            .collect::<Map<_, _>>(),
    )
}

/// The leaf topics of a TopicSet, walked without recursion and bounded by depth and count.
fn topics(set: &Element) -> Vec<String> {
    let mut out = Vec::new();
    let mut stack: Vec<(&Element, String, usize)> = set
        .children
        .iter()
        .rev()
        .map(|c| (c, c.name.clone(), 1))
        .collect();
    while let Some((e, path, depth)) = stack.pop() {
        if out.len() >= MAX_ITEMS {
            break;
        }
        if e.attr("topic") == Some("true") {
            out.push(format!("tns1:{path}"));
        }
        if depth < MAX_TOPIC_DEPTH {
            for c in e.children.iter().rev() {
                if c.name != "MessageDescription" && c.name != "Documentation" {
                    stack.push((c, format!("{path}/{}", c.name), depth + 1));
                }
            }
        }
    }
    out
}

/// The text of an address element (`wsa:Address`) under `e`.
pub fn address(e: Option<&Element>) -> Option<String> {
    e.and_then(|e| e.text_of("Address"))
}

/// A device's answer to one of these operations, as the JSON the model reads.
pub fn result_json(spec: &Spec, el: &Element) -> Value {
    match (spec.service, spec.operation) {
        (Device | Media, op) => wire::result_json(op, el),
        (Media2, "GetProfiles") => {
            json!({"profiles": el.children_named("Profiles").take(MAX_ITEMS).map(|p| {
            let c = p.child("Configurations");
            let enc = c.and_then(|c| c.child("VideoEncoder"));
            json!({"token": p.attr("token"), "name": opt(p, &["Name"]),
                   "video_source_token": c.map(|c| opt(c, &["VideoSource", "SourceToken"])).unwrap_or(Value::Null),
                   "encoding": enc.map(|e| opt(e, &["Encoding"])).unwrap_or(Value::Null),
                   "width": enc.map(|e| num(e, &["Resolution", "Width"])).unwrap_or(Value::Null),
                   "height": enc.map(|e| num(e, &["Resolution", "Height"])).unwrap_or(Value::Null),
                   "ptz": c.is_some_and(|c| c.child("PTZ").is_some())})
        }).collect::<Vec<_>>()})
        }
        (Media2, "GetStreamUri" | "GetSnapshotUri") => json!({"uri": opt(el, &["Uri"])}),
        (Media2, "GetVideoSourceConfigurations") => {
            json!({"configurations": el.children_named("Configurations").take(MAX_ITEMS).map(|c| json!({
            "token": c.attr("token"), "source_token": opt(c, &["SourceToken"]),
            "width": c.child("Bounds").and_then(|b| b.attr("width")), "height": c.child("Bounds").and_then(|b| b.attr("height"))})).collect::<Vec<_>>()})
        }
        (Media2, _) => {
            json!({"configurations": el.children_named("Configurations").take(MAX_ITEMS).map(|c| json!({
            "token": c.attr("token"), "encoding": opt(c, &["Encoding"]),
            "width": num(c, &["Resolution", "Width"]), "height": num(c, &["Resolution", "Height"]),
            "framerate": num(c, &["RateControl", "FrameRateLimit"]), "bitrate": num(c, &["RateControl", "BitrateLimit"])})).collect::<Vec<_>>()})
        }
        (Ptz, "GetNodes") => {
            json!({"nodes": el.children_named("PTZNode").take(MAX_ITEMS).map(|n| json!({
            "token": n.attr("token"), "name": opt(n, &["Name"]),
            "max_presets": num(n, &["MaximumNumberOfPresets"]), "home_supported": opt(n, &["HomeSupported"])})).collect::<Vec<_>>()})
        }
        (Ptz, "GetConfigurations") => {
            json!({"configurations": el.children_named("PTZConfiguration").take(MAX_ITEMS).map(|c| json!({
            "token": c.attr("token"), "name": opt(c, &["Name"]), "node_token": opt(c, &["NodeToken"]),
            "default_timeout": opt(c, &["DefaultPTZTimeout"])})).collect::<Vec<_>>()})
        }
        (Ptz, "GetStatus") => {
            let s = el.child("PTZStatus");
            json!({
                "position": position(s.and_then(|s| s.child("Position"))),
                "move_status": {
                    "pan_tilt": s.map(|s| opt(s, &["MoveStatus", "PanTilt"])).unwrap_or(Value::Null),
                    "zoom": s.map(|s| opt(s, &["MoveStatus", "Zoom"])).unwrap_or(Value::Null),
                },
                "utc_time": s.map(|s| opt(s, &["UtcTime"])).unwrap_or(Value::Null),
            })
        }
        (Ptz, "GetPresets") => {
            json!({"presets": el.children_named("Preset").take(MAX_ITEMS).map(|p| json!({
            "token": p.attr("token"), "name": opt(p, &["Name"]), "position": position(p.child("PTZPosition"))})).collect::<Vec<_>>()})
        }
        (Ptz, "SetPreset") => json!({"preset_token": opt(el, &["PresetToken"])}),
        (Events, "GetEventProperties") => {
            json!({"topics": el.child("TopicSet").map(topics).unwrap_or_default()})
        }
        (Events, "CreatePullPointSubscription") => json!({
            "address": address(el.child("SubscriptionReference")),
            "current_time": opt(el, &["CurrentTime"]),
            "termination_time": opt(el, &["TerminationTime"]),
        }),
        (Subscription, "PullMessages") => json!({
            "current_time": opt(el, &["CurrentTime"]),
            "termination_time": opt(el, &["TerminationTime"]),
            "notifications": el.children_named("NotificationMessage").take(MAX_ITEMS).map(|n| {
                let m = n.child("Message").and_then(|m| m.child("Message"));
                json!({
                    "topic": opt(n, &["Topic"]),
                    "utc_time": m.and_then(|m| m.attr("UtcTime")),
                    "property_operation": m.and_then(|m| m.attr("PropertyOperation")),
                    "source": m.and_then(|m| m.child("Source")).map(items_of).unwrap_or(json!({})),
                    "data": m.and_then(|m| m.child("Data")).map(items_of).unwrap_or(json!({})),
                })
            }).collect::<Vec<_>>(),
        }),
        (Subscription, "Renew") => json!({
            "termination_time": opt(el, &["TerminationTime"]),
            "current_time": opt(el, &["CurrentTime"]),
        }),
        (Imaging, "GetImagingSettings") => {
            let s = el.child("ImagingSettings");
            let g = |p: &[&str]| s.map(|s| opt(s, p)).unwrap_or(Value::Null);
            let f = |p: &[&str]| s.map(|s| num(s, p)).unwrap_or(Value::Null);
            json!({"brightness": f(&["Brightness"]), "color_saturation": f(&["ColorSaturation"]),
                   "contrast": f(&["Contrast"]), "sharpness": f(&["Sharpness"]),
                   "ir_cut_filter": g(&["IrCutFilter"]), "auto_focus_mode": g(&["Focus", "AutoFocusMode"])})
        }
        (Imaging, "GetOptions") => {
            let o = el.child("ImagingOptions");
            let r = |k: &str| {
                o.and_then(|o| o.child(k))
                    .map(|r| json!({"min": num(r, &["Min"]), "max": num(r, &["Max"])}))
                    .unwrap_or(Value::Null)
            };
            json!({"brightness": r("Brightness"), "color_saturation": r("ColorSaturation"),
                   "contrast": r("Contrast"), "sharpness": r("Sharpness"),
                   "ir_cut_filter_modes": o.map(|o| o.children_named("IrCutFilterModes").take(8).map(|m| m.text.trim().to_string()).collect::<Vec<_>>()).unwrap_or_default(),
                   "auto_focus_modes": o.and_then(|o| o.child("Focus")).map(|f| f.children_named("AutoFocusModes").take(8).map(|m| m.text.trim().to_string()).collect::<Vec<_>>()).unwrap_or_default()})
        }
        (Imaging, "GetMoveOptions") => {
            let o = el.child("MoveOptions");
            json!({"absolute": o.is_some_and(|o| o.child("Absolute").is_some()),
                   "relative": o.is_some_and(|o| o.child("Relative").is_some()),
                   "continuous": o.is_some_and(|o| o.child("Continuous").is_some())})
        }
        (Imaging, "GetStatus") => {
            let s = el.child("Status").and_then(|s| s.child("FocusStatus20"));
            json!({"position": s.map(|s| num(s, &["Position"])).unwrap_or(Value::Null),
                   "move_status": s.map(|s| opt(s, &["MoveStatus"])).unwrap_or(Value::Null)})
        }
        _ => json!({}),
    }
}

/// The arguments the model sent, for the event that reports the answer.
pub fn request_echo(v: &Value) -> Value {
    let mut out = Map::new();
    if let Some(obj) = v.as_object() {
        for (k, val) in obj.iter().take(16) {
            if k != "type" && !val.is_null() {
                out.insert(k.clone(), val.clone());
            }
        }
    }
    Value::Object(out)
}
