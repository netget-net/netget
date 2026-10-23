//! Every operation the ONVIF device serves, by service, and who answers it.
//!
//! | Service | Rust | The model |
//! |---|---|---|
//! | Device | GetSystemDateAndTime, GetCapabilities, GetServices; GetHostname once a SetHostname was accepted | GetDeviceInformation, GetScopes (its Fixed scopes; Rust adds the configurable ones), GetNetworkInterfaces, GetHostname, and allow/deny on SetSystemDateAndTime, SetScopes, AddScopes, RemoveScopes, SetHostname, SystemReboot |
//! | Media (ver10) | — | GetProfiles, GetVideoSources, GetStreamUri, GetSnapshotUri |
//! | Media2 (ver20) | GetServiceCapabilities | the same events as Media: GetProfiles, GetVideoSourceConfigurations and GetVideoEncoderConfigurations from `onvif_get_profiles`, GetStreamUri and GetSnapshotUri from the URI events |
//! | PTZ (ver20) | GetServiceCapabilities, GetNodes, GetNode, GetConfigurations, GetConfiguration, GetStatus, GetPresets, SetPreset, RemovePreset, Stop | ContinuousMove, RelativeMove, AbsoluteMove, GotoPreset, GotoHomePosition |
//! | Events (ver10) | GetServiceCapabilities, GetEventProperties, PullMessages, Renew, Unsubscribe, SetSynchronizationPoint | CreatePullPointSubscription |
//! | Imaging (ver20) | GetServiceCapabilities, GetImagingSettings, GetOptions, GetMoveOptions, GetStatus, Stop | SetImagingSettings, Move |
//!
//! A PTZ or Imaging request naming a profile or video source the device has not described yet
//! asks the model for its profiles (or sources) once first; after that it costs nothing.
use super::actions as a;
use super::wire::{self, esc, FaultCode};
use super::{
    events, fault, fault_detail, imaging, invalid, lock, media2, ok, ptz, Call, Resp, MAX_SCOPES,
};
use serde_json::{json, Value};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    // Device
    SystemDateAndTime,
    Capabilities,
    Services,
    DeviceInformation,
    Scopes,
    NetworkInterfaces,
    Hostname,
    SetSystemDateAndTime,
    SetScopes,
    AddScopes,
    RemoveScopes,
    SetHostname,
    SystemReboot,
    // Media (ver10)
    Profiles,
    VideoSources,
    StreamUri,
    SnapshotUri,
    // Media2
    Media2Capabilities,
    Profiles2,
    StreamUri2,
    SnapshotUri2,
    VideoSourceConfigurations2,
    VideoEncoderConfigurations2,
    // PTZ
    PtzCapabilities,
    Nodes,
    Node,
    PtzConfigurations,
    PtzConfiguration,
    PtzStatus,
    ContinuousMove,
    RelativeMove,
    AbsoluteMove,
    PtzStop,
    Presets,
    SetPreset,
    GotoPreset,
    RemovePreset,
    GotoHome,
    // Events
    EventsCapabilities,
    EventProperties,
    CreatePullPoint,
    PullMessages,
    Renew,
    Unsubscribe,
    SynchronizationPoint,
    // Imaging
    ImagingCapabilities,
    ImagingSettings,
    SetImagingSettings,
    ImagingOptions,
    MoveOptions,
    ImagingMove,
    ImagingStop,
    ImagingStatus,
}

impl Op {
    pub fn of(ns: &str, name: &str) -> Option<Op> {
        use wire::{TDS, TEV, TIMG, TPTZ, TR2, TRT, WSNT};
        Some(match (ns, name) {
            (TDS, "GetSystemDateAndTime") => Op::SystemDateAndTime,
            (TDS, "GetCapabilities") => Op::Capabilities,
            (TDS, "GetServices") => Op::Services,
            (TDS, "GetDeviceInformation") => Op::DeviceInformation,
            (TDS, "GetScopes") => Op::Scopes,
            (TDS, "GetNetworkInterfaces") => Op::NetworkInterfaces,
            (TDS, "GetHostname") => Op::Hostname,
            (TDS, "SetSystemDateAndTime") => Op::SetSystemDateAndTime,
            (TDS, "SetScopes") => Op::SetScopes,
            (TDS, "AddScopes") => Op::AddScopes,
            (TDS, "RemoveScopes") => Op::RemoveScopes,
            (TDS, "SetHostname") => Op::SetHostname,
            (TDS, "SystemReboot") => Op::SystemReboot,
            (TRT, "GetProfiles") => Op::Profiles,
            (TRT, "GetVideoSources") => Op::VideoSources,
            (TRT, "GetStreamUri") => Op::StreamUri,
            (TRT, "GetSnapshotUri") => Op::SnapshotUri,
            (TR2, "GetServiceCapabilities") => Op::Media2Capabilities,
            (TR2, "GetProfiles") => Op::Profiles2,
            (TR2, "GetStreamUri") => Op::StreamUri2,
            (TR2, "GetSnapshotUri") => Op::SnapshotUri2,
            (TR2, "GetVideoSourceConfigurations") => Op::VideoSourceConfigurations2,
            (TR2, "GetVideoEncoderConfigurations") => Op::VideoEncoderConfigurations2,
            (TPTZ, "GetServiceCapabilities") => Op::PtzCapabilities,
            (TPTZ, "GetNodes") => Op::Nodes,
            (TPTZ, "GetNode") => Op::Node,
            (TPTZ, "GetConfigurations") => Op::PtzConfigurations,
            (TPTZ, "GetConfiguration") => Op::PtzConfiguration,
            (TPTZ, "GetStatus") => Op::PtzStatus,
            (TPTZ, "ContinuousMove") => Op::ContinuousMove,
            (TPTZ, "RelativeMove") => Op::RelativeMove,
            (TPTZ, "AbsoluteMove") => Op::AbsoluteMove,
            (TPTZ, "Stop") => Op::PtzStop,
            (TPTZ, "GetPresets") => Op::Presets,
            (TPTZ, "SetPreset") => Op::SetPreset,
            (TPTZ, "GotoPreset") => Op::GotoPreset,
            (TPTZ, "RemovePreset") => Op::RemovePreset,
            (TPTZ, "GotoHomePosition") => Op::GotoHome,
            (TEV, "GetServiceCapabilities") => Op::EventsCapabilities,
            (TEV, "GetEventProperties") => Op::EventProperties,
            (TEV, "CreatePullPointSubscription") => Op::CreatePullPoint,
            (TEV, "PullMessages") => Op::PullMessages,
            (TEV, "SetSynchronizationPoint") => Op::SynchronizationPoint,
            (WSNT, "Renew") => Op::Renew,
            (WSNT, "Unsubscribe") => Op::Unsubscribe,
            // use-go/onvif's event.Renew and event.Unsubscribe carry no XML name, so they go out
            // unqualified. They only ever reach a subscription (its path names it), so reading
            // them as WS-BaseNotification's is unambiguous.
            ("", "Renew") => Op::Renew,
            ("", "Unsubscribe") => Op::Unsubscribe,
            (TIMG, "GetServiceCapabilities") => Op::ImagingCapabilities,
            (TIMG, "GetImagingSettings") => Op::ImagingSettings,
            (TIMG, "SetImagingSettings") => Op::SetImagingSettings,
            (TIMG, "GetOptions") => Op::ImagingOptions,
            (TIMG, "GetMoveOptions") => Op::MoveOptions,
            (TIMG, "Move") => Op::ImagingMove,
            (TIMG, "Stop") => Op::ImagingStop,
            (TIMG, "GetStatus") => Op::ImagingStatus,
            _ => return None,
        })
    }
}

/// `<prefix:OperationResponse/>`, for the operations whose response carries nothing.
fn empty(prefix: &str, op: &str) -> Resp {
    ok(&format!("<{prefix}:{op}Response/>"))
}

/// Answer one authenticated request.
pub async fn dispatch(call: &Call<'_>, op: Op) -> Resp {
    match op {
        Op::SystemDateAndTime => {
            let c = lock(&call.device.clock);
            let (t, tz, dst) = (c.date_time_type.clone(), c.tz.clone(), c.daylight_savings);
            drop(c);
            ok(&wire::system_date_and_time_as(
                call.device.now(),
                &t,
                &tz,
                dst,
            ))
        }
        Op::Services => ok(&wire::services(&call.base)),
        Op::Capabilities => capabilities(call),
        Op::DeviceInformation => {
            model_answer(call, &a::DEVICE_INFORMATION_EVENT, json!({}), a::DEVICE_INFORMATION)
                .await
                .map(|r| ok(&wire::device_information(&r)))
                .unwrap_or_else(|e| e)
        }
        Op::NetworkInterfaces => {
            model_answer(call, &a::NETWORK_INTERFACES_EVENT, json!({}), a::NETWORK_INTERFACES)
                .await
                .map(|r| ok(&wire::network_interfaces(&r)))
                .unwrap_or_else(|e| e)
        }
        Op::Scopes => scopes(call).await.unwrap_or_else(|e| e),
        Op::Hostname => hostname(call).await.unwrap_or_else(|e| e),
        Op::SetHostname => set_hostname(call).await.unwrap_or_else(|e| e),
        Op::SetSystemDateAndTime => set_date_time(call).await.unwrap_or_else(|e| e),
        Op::SetScopes | Op::AddScopes | Op::RemoveScopes => {
            set_scopes(call, op).await.unwrap_or_else(|e| e)
        }
        Op::SystemReboot => call
            .ask(&a::REBOOT_EVENT, json!({}), a::ACCEPT)
            .await
            .map(|r| {
                ok(&format!(
                    "<tds:SystemRebootResponse><tds:Message>{}</tds:Message></tds:SystemRebootResponse>",
                    esc(r["message"].as_str().unwrap_or("Rebooting"))
                ))
            })
            .unwrap_or_else(|e| e),
        Op::Profiles => profiles_answer(call)
            .await
            .map(|r| ok(&wire::profiles(&r)))
            .unwrap_or_else(|e| e),
        Op::VideoSources => sources_answer(call)
            .await
            .map(|r| ok(&wire::video_sources(&r)))
            .unwrap_or_else(|e| e),
        Op::StreamUri => {
            let b = call.body();
            let extra = json!({
                "profile_token": b.text_of("ProfileToken").unwrap_or_default(),
                "stream": b.path(&["StreamSetup", "Stream"]).unwrap_or_default(),
                "protocol": b.path(&["StreamSetup", "Transport", "Protocol"]).unwrap_or_default(),
                "service": "media",
            });
            model_answer(call, &a::STREAM_URI_EVENT, extra, a::STREAM_URI)
                .await
                .map(|r| ok(&wire::media_uri("GetStreamUri", &r)))
                .unwrap_or_else(|e| e)
        }
        Op::SnapshotUri => {
            let extra = json!({"profile_token": call.body().text_of("ProfileToken").unwrap_or_default(), "service": "media"});
            model_answer(call, &a::SNAPSHOT_URI_EVENT, extra, a::SNAPSHOT_URI)
                .await
                .map(|r| ok(&wire::media_uri("GetSnapshotUri", &r)))
                .unwrap_or_else(|e| e)
        }
        Op::Media2Capabilities => ok(&media2::service_capabilities()),
        Op::Profiles2 => {
            let token = call.body().text_of("Token").filter(|t| !t.is_empty());
            let types = media2::Types::of(call.body());
            profiles_answer(call)
                .await
                .map(|r| ok(&media2::profiles(&r, &types, token.as_deref())))
                .unwrap_or_else(|e| e)
        }
        Op::VideoSourceConfigurations2 => {
            let narrow = media2::Narrow::of(call.body());
            profiles_answer(call)
                .await
                .map(|r| ok(&media2::video_source_configurations(&r, &narrow)))
                .unwrap_or_else(|e| e)
        }
        Op::VideoEncoderConfigurations2 => {
            let narrow = media2::Narrow::of(call.body());
            profiles_answer(call)
                .await
                .map(|r| ok(&media2::video_encoder_configurations(&r, &narrow)))
                .unwrap_or_else(|e| e)
        }
        Op::StreamUri2 => {
            let protocol = call.body().text_of("Protocol").unwrap_or_default();
            let Some((stream, transport)) = media2::stream_setup(&protocol) else {
                return invalid("InvalidStreamSetup", "The device has no such stream protocol");
            };
            let extra = json!({
                "profile_token": call.body().text_of("ProfileToken").unwrap_or_default(),
                "stream": stream, "protocol": transport, "service": "media2",
            });
            model_answer(call, &a::STREAM_URI_EVENT, extra, a::STREAM_URI)
                .await
                .map(|r| ok(&media2::uri("GetStreamUri", &r)))
                .unwrap_or_else(|e| e)
        }
        Op::SnapshotUri2 => {
            let extra = json!({"profile_token": call.body().text_of("ProfileToken").unwrap_or_default(), "service": "media2"});
            model_answer(call, &a::SNAPSHOT_URI_EVENT, extra, a::SNAPSHOT_URI)
                .await
                .map(|r| ok(&media2::uri("GetSnapshotUri", &r)))
                .unwrap_or_else(|e| e)
        }
        Op::PtzCapabilities => ok(&ptz::service_capabilities()),
        Op::Nodes => ok(&format!(
            "<tptz:GetNodesResponse>{}</tptz:GetNodesResponse>",
            ptz::node("tptz:PTZNode")
        )),
        Op::Node => {
            if call.body().text_of("NodeToken").as_deref() != Some(ptz::NODE_TOKEN) {
                return invalid("NoEntity", "No such PTZ node");
            }
            ok(&format!(
                "<tptz:GetNodeResponse>{}</tptz:GetNodeResponse>",
                ptz::node("tptz:PTZNode")
            ))
        }
        Op::PtzConfigurations => ok(&format!(
            "<tptz:GetConfigurationsResponse>{}</tptz:GetConfigurationsResponse>",
            ptz::configuration("tptz:PTZConfiguration")
        )),
        Op::PtzConfiguration => {
            // The schema's element is PTZConfigurationToken; use-go/onvif sends ProfileToken.
            let b = call.body();
            let named = |k: &str| b.text_of(k).as_deref() == Some(ptz::CONFIG_TOKEN);
            if !named("PTZConfigurationToken") && !named("ProfileToken") {
                return invalid("NoConfig", "No such PTZ configuration");
            }
            ok(&format!(
                "<tptz:GetConfigurationResponse>{}</tptz:GetConfigurationResponse>",
                ptz::configuration("tptz:PTZConfiguration")
            ))
        }
        Op::PtzStatus
        | Op::ContinuousMove
        | Op::RelativeMove
        | Op::AbsoluteMove
        | Op::PtzStop
        | Op::Presets
        | Op::SetPreset
        | Op::GotoPreset
        | Op::RemovePreset
        | Op::GotoHome => ptz_op(call, op).await.unwrap_or_else(|e| e),
        Op::EventsCapabilities => ok(&events::service_capabilities()),
        Op::EventProperties => ok(&events::event_properties()),
        Op::CreatePullPoint => create_pull_point(call).await.unwrap_or_else(|e| e),
        Op::PullMessages | Op::Renew | Op::Unsubscribe | Op::SynchronizationPoint => {
            subscription_op(call, op).await.unwrap_or_else(|e| e)
        }
        Op::ImagingCapabilities => ok(&imaging::service_capabilities()),
        Op::ImagingSettings
        | Op::SetImagingSettings
        | Op::ImagingOptions
        | Op::MoveOptions
        | Op::ImagingMove
        | Op::ImagingStop
        | Op::ImagingStatus => imaging_op(call, op).await.unwrap_or_else(|e| e),
    }
}

async fn model_answer(
    call: &Call<'_>,
    event: &'static crate::protocol::EventType,
    extra: Value,
    answer: &str,
) -> Result<Value, Resp> {
    call.ask(event, extra, answer).await
}

fn capabilities(call: &Call<'_>) -> Resp {
    let categories: Vec<String> = call
        .body()
        .children_named("Category")
        .take(16)
        .map(|c| c.text.trim().to_string())
        .collect();
    if !categories
        .iter()
        .all(|c| c == "All" || wire::CATEGORIES.contains(&c.as_str()))
    {
        return fault(
            FaultCode::Receiver,
            &["ActionNotSupported", "NoSuchService"],
            "The device does not have that service",
        );
    }
    let wanted: Vec<&str> = if categories.is_empty() || categories.iter().any(|c| c == "All") {
        wire::CATEGORIES.to_vec()
    } else {
        wire::CATEGORIES
            .iter()
            .copied()
            .filter(|c| categories.iter().any(|x| x == c))
            .collect()
    };
    ok(&wire::capabilities(&call.base, &wanted))
}

// ---- device ---------------------------------------------------------------------------------

async fn scopes(call: &Call<'_>) -> Result<Resp, Resp> {
    let reply = call.ask(&a::SCOPES_EVENT, json!({}), a::SCOPES).await?;
    let mut s = lock(&call.device.scopes);
    s.fixed = wire::items(&reply, "scopes")
        .filter_map(|v| v.as_str().map(str::to_string))
        .collect();
    let configurable = s.configurable.clone();
    drop(s);
    Ok(ok(&wire::scopes_with(&reply, &configurable)))
}

async fn hostname(call: &Call<'_>) -> Result<Resp, Resp> {
    if let Some(name) = lock(&call.device.hostname).clone() {
        return Ok(ok(&wire::hostname(&name, false)));
    }
    let reply = call.ask(&a::HOSTNAME_EVENT, json!({}), a::HOSTNAME).await?;
    Ok(ok(&wire::hostname(
        reply["name"].as_str().unwrap_or_default(),
        reply["from_dhcp"].as_bool().unwrap_or(false),
    )))
}

async fn set_hostname(call: &Call<'_>) -> Result<Resp, Resp> {
    let name = call.body().text_of("Name").unwrap_or_default();
    if a::hostname(&name).is_err() {
        return Err(invalid("InvalidHostname", "The host name is not valid"));
    }
    call.ask(&a::SET_HOSTNAME_EVENT, json!({"name": name}), a::ACCEPT)
        .await?;
    *lock(&call.device.hostname) = Some(name);
    Ok(empty("tds", "SetHostname"))
}

/// A POSIX TZ string: printable, no spaces, bounded.
fn tz_ok(tz: &str) -> bool {
    !tz.is_empty()
        && tz.len() <= 64
        && tz
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || ",.+-:/<>_".contains(c))
}

async fn set_date_time(call: &Call<'_>) -> Result<Resp, Resp> {
    let b = call.body();
    let kind = b.text_of("DateTimeType").unwrap_or_default();
    if kind != "Manual" && kind != "NTP" {
        return Err(invalid("InvalidDateTime", "DateTimeType is Manual or NTP"));
    }
    let dst = b
        .text_of("DaylightSavings")
        .and_then(|t| wire::parse_bool(&t))
        .unwrap_or(false);
    let tz = b.path(&["TimeZone", "TZ"]).filter(|t| !t.is_empty());
    if tz.as_deref().is_some_and(|t| !tz_ok(t)) {
        return Err(invalid(
            "InvalidTimeZone",
            "The time zone is not a POSIX TZ string",
        ));
    }
    let utc = match b.child("UTCDateTime") {
        Some(u) => {
            let wrapper = wire::Element {
                children: vec![u.clone()],
                ..Default::default()
            };
            match wire::utc_of(&wrapper) {
                Some(t) if (1970..=2100).contains(&chrono::Datelike::year(&t)) => Some(t),
                _ => {
                    return Err(invalid(
                        "InvalidDateTime",
                        "The date and time are not valid",
                    ))
                }
            }
        }
        None => None,
    };
    if kind == "Manual" && utc.is_none() {
        return Err(invalid(
            "InvalidDateTime",
            "A Manual clock needs UTCDateTime",
        ));
    }
    call.ask(
        &a::SET_DATE_TIME_EVENT,
        json!({
            "date_time_type": kind, "daylight_savings": dst, "time_zone": tz,
            "utc_date_time": utc.map(wire::format_datetime),
            "current_utc": wire::format_datetime(call.device.now()),
        }),
        a::ACCEPT,
    )
    .await?;
    let mut c = lock(&call.device.clock);
    c.date_time_type = kind.clone();
    c.daylight_savings = dst;
    if let Some(tz) = tz {
        c.tz = tz;
    }
    c.offset = match (kind.as_str(), utc) {
        // An NTP clock is the host's own, which is synchronised.
        ("NTP", _) => chrono::Duration::zero(),
        (_, Some(t)) => t - chrono::Utc::now(),
        _ => c.offset,
    };
    Ok(empty("tds", "SetSystemDateAndTime"))
}

async fn set_scopes(call: &Call<'_>, op: Op) -> Result<Resp, Resp> {
    let element = if op == Op::SetScopes {
        "Scopes"
    } else {
        "ScopeItem"
    };
    let asked: Vec<String> = call
        .body()
        .children_named(element)
        .take(MAX_SCOPES + 1)
        .map(|s| s.text.trim().to_string())
        .collect();
    if asked.len() > MAX_SCOPES {
        return Err(fault(
            FaultCode::Receiver,
            &["Action", "TooManyScopes"],
            "The device holds no more configurable scopes",
        ));
    }
    if asked.is_empty()
        || asked
            .iter()
            .any(|s| a::check(&json!({"type": a::SCOPES, "scopes": [s]})).is_err())
    {
        return Err(invalid("InvalidScope", "Each scope is a URI"));
    }
    let (configurable, fixed) = {
        let s = lock(&call.device.scopes);
        (s.configurable.clone(), s.fixed.clone())
    };
    let after: Vec<String> = match op {
        Op::SetScopes => {
            if asked.iter().any(|s| fixed.contains(s)) {
                return Err(fault(
                    FaultCode::Sender,
                    &["OperationProhibited", "ScopeOverwrite"],
                    "A fixed scope cannot be set",
                ));
            }
            asked.clone()
        }
        Op::AddScopes => {
            let mut all = configurable.clone();
            for s in &asked {
                if !all.contains(s) && !fixed.contains(s) {
                    all.push(s.clone());
                }
            }
            if all.len() > MAX_SCOPES {
                return Err(fault(
                    FaultCode::Receiver,
                    &["Action", "TooManyScopes"],
                    "The device holds no more configurable scopes",
                ));
            }
            all
        }
        _ => {
            for s in &asked {
                if !configurable.contains(s) {
                    return Err(if fixed.contains(s) {
                        fault(
                            FaultCode::Sender,
                            &["OperationProhibited", "FixedScope"],
                            "A fixed scope cannot be removed",
                        )
                    } else {
                        invalid("NoScope", "The device has no such scope")
                    });
                }
            }
            configurable
                .iter()
                .filter(|s| !asked.contains(s))
                .cloned()
                .collect()
        }
    };
    call.ask(
        &a::SET_SCOPES_EVENT,
        json!({"scopes": asked, "configurable": configurable}),
        a::ACCEPT,
    )
    .await?;
    lock(&call.device.scopes).configurable = after;
    Ok(match op {
        Op::RemoveScopes => ok(&format!(
            "<tds:RemoveScopesResponse>{}</tds:RemoveScopesResponse>",
            asked
                .iter()
                .map(|s| format!("<tds:ScopeItem>{}</tds:ScopeItem>", esc(s)))
                .collect::<String>()
        )),
        Op::AddScopes => empty("tds", "AddScopes"),
        _ => empty("tds", "SetScopes"),
    })
}

// ---- media ----------------------------------------------------------------------------------

/// The model's profiles, which the device then knows (for PTZ and Imaging checks).
async fn profiles_answer(call: &Call<'_>) -> Result<Value, Resp> {
    let service = super::service_name(&call.req.ns);
    let reply = call
        .ask(&a::PROFILES_EVENT, json!({"service": service}), a::PROFILES)
        .await?;
    lock(&call.device.catalog).learn_profiles(&reply);
    Ok(reply)
}

async fn sources_answer(call: &Call<'_>) -> Result<Value, Resp> {
    let reply = call
        .ask(&a::VIDEO_SOURCES_EVENT, json!({}), a::VIDEO_SOURCES)
        .await?;
    lock(&call.device.catalog).learn_sources(&reply);
    Ok(reply)
}

// ---- PTZ ------------------------------------------------------------------------------------

/// The ProfileToken a PTZ request names, if it is a profile with the PTZ head.
async fn ptz_profile(call: &Call<'_>) -> Result<String, Resp> {
    let token = call.body().text_of("ProfileToken").unwrap_or_default();
    if token.is_empty() {
        return Err(invalid("NoProfile", "The request names no profile"));
    }
    let mut known = lock(&call.device.catalog).profile(&token);
    if known.is_none() {
        profiles_answer(call).await?;
        known = lock(&call.device.catalog).profile(&token);
    }
    match known {
        None => Err(invalid("NoProfile", "No such profile")),
        Some(false) => Err(invalid(
            "NoPTZProfile",
            "The profile has no PTZ configuration",
        )),
        Some(true) => Ok(token),
    }
}

fn speed(call: &Call<'_>) -> Result<ptz::Axes, Resp> {
    ptz::axes(call.body().child("Speed"), ptz::Kind::Speed)
        .map_err(|d| invalid(d, "The speed is outside the generic speed space"))
}

async fn ptz_op(call: &Call<'_>, op: Op) -> Result<Resp, Resp> {
    let profile = ptz_profile(call).await?;
    let b = call.body();
    let kind = match op {
        Op::PtzStatus => {
            let st = lock(&call.device.ptz);
            return Ok(ok(&ptz::status(&st, call.device.now())));
        }
        Op::Presets => return Ok(ok(&ptz::presets(&lock(&call.device.ptz)))),
        Op::PtzStop => {
            let axis = |k: &str| {
                b.text_of(k)
                    .and_then(|t| wire::parse_bool(&t))
                    .unwrap_or(true)
            };
            lock(&call.device.ptz).stop(axis("PanTilt"), axis("Zoom"));
            return Ok(empty("tptz", "Stop"));
        }
        Op::SetPreset => {
            let t = |k: &str| b.text_of(k).filter(|t| !t.is_empty());
            let (token, name) = (t("PresetToken"), t("PresetName"));
            let r = lock(&call.device.ptz).set_preset(token.as_deref(), name.as_deref());
            return match r {
                Ok(token) => Ok(ok(&format!(
                    "<tptz:SetPresetResponse><tptz:PresetToken>{}</tptz:PresetToken></tptz:SetPresetResponse>",
                    esc(&token)
                ))),
                Err((receiver, subcodes, reason)) => Err(fault(
                    if receiver { FaultCode::Receiver } else { FaultCode::Sender },
                    subcodes,
                    reason,
                )),
            };
        }
        Op::RemovePreset => {
            let token = b.text_of("PresetToken").unwrap_or_default();
            if !lock(&call.device.ptz).remove_preset(&token) {
                return Err(invalid("NoToken", "No such preset token"));
            }
            return Ok(empty("tptz", "RemovePreset"));
        }
        Op::ContinuousMove => {
            let velocity = ptz::axes(b.child("Velocity"), ptz::Kind::Velocity)
                .map_err(|d| invalid(d, "The velocity is outside the generic velocity space"))?;
            let timeout = ptz::timeout(b)
                .map_err(|_| invalid("TimeoutNotSupported", "The timeout is not supported"))?;
            ptz::MoveKind::Continuous { velocity, timeout }
        }
        Op::RelativeMove => ptz::MoveKind::Relative {
            translation: ptz::axes(b.child("Translation"), ptz::Kind::Translation)
                .map_err(|d| invalid(d, "The translation is outside the generic space"))?,
            speed: speed(call)?,
        },
        Op::AbsoluteMove => ptz::MoveKind::Absolute {
            position: ptz::axes(b.child("Position"), ptz::Kind::Position)
                .map_err(|d| invalid(d, "The position is outside the generic space"))?,
            speed: speed(call)?,
        },
        Op::GotoPreset => {
            let token = b.text_of("PresetToken").unwrap_or_default();
            let (name, position) = {
                let st = lock(&call.device.ptz);
                let Some(p) = st.preset(&token) else {
                    return Err(invalid("NoToken", "No such preset token"));
                };
                (p.name.clone(), p.position)
            };
            ptz::MoveKind::Preset {
                token,
                name,
                position,
                speed: speed(call)?,
            }
        }
        _ => ptz::MoveKind::Home {
            speed: speed(call)?,
        },
    };
    // A move: the model accepts it, saying where the head ends up, or refuses it.
    let current = lock(&call.device.ptz).position;
    let proposed = ptz::proposed(current, &kind);
    let mut extra = kind.json();
    extra["profile_token"] = json!(profile);
    extra["kind"] = json!(kind.name());
    extra["current"] = current.json();
    extra["proposed"] = proposed.json();
    let reply = call.ask(&a::PTZ_MOVE_EVENT, extra, a::PTZ_POSITION).await?;
    let Some(to) = ptz::Position::from_json(&reply) else {
        // `check` already refused such an answer; never move on one.
        return Err(super::unavailable(crate::utils::WireFailure::Unavailable));
    };
    let continuous = match &kind {
        ptz::MoveKind::Continuous { velocity, timeout } => Some((velocity, *timeout)),
        _ => None,
    };
    lock(&call.device.ptz).moved(to, continuous);
    Ok(empty("tptz", call.op()))
}

// ---- events ---------------------------------------------------------------------------------

fn resource_unknown() -> Resp {
    fault_detail(
        FaultCode::Sender,
        &["InvalidArgVal"],
        "No such subscription",
        "<wsrf-r:ResourceUnknownFault xmlns:wsrf-r=\"http://docs.oasis-open.org/wsrf/r-2\"/>",
    )
}

fn unacceptable(element: &str) -> Resp {
    fault_detail(
        FaultCode::Sender,
        &["InvalidArgVal"],
        "Unacceptable termination time",
        &format!("<wsnt:{element}/>"),
    )
}

/// A requested termination time, bounded at `MAX_TERMINATION` from now; Err when it is
/// unreadable or not in the future.
fn termination(
    call: &Call<'_>,
    element: &str,
    now: chrono::DateTime<chrono::Utc>,
    fault_name: &str,
) -> Result<chrono::DateTime<chrono::Utc>, Resp> {
    let max = now + chrono::Duration::from_std(events::MAX_TERMINATION).unwrap_or_default();
    match events::time_of(call.body().child(element), now) {
        Err(_) => Err(unacceptable(fault_name)),
        Ok(None) => {
            Ok(now + chrono::Duration::from_std(events::DEFAULT_TERMINATION).unwrap_or_default())
        }
        Ok(Some(t)) if t <= now => Err(unacceptable(fault_name)),
        Ok(Some(t)) => Ok(t.min(max)),
    }
}

async fn create_pull_point(call: &Call<'_>) -> Result<Resp, Resp> {
    let filter = events::filter_of(call.body()).map_err(|e| {
        fault_detail(
            FaultCode::Sender,
            &["InvalidArgVal"],
            e.reason(),
            e.detail(),
        )
    })?;
    let now = call.device.now();
    let until = termination(
        call,
        "InitialTerminationTime",
        now,
        "UnacceptableInitialTerminationTimeFault",
    )?;
    let filter_json = filter.json();
    // The subscription exists while the model is asked, so events it raises in its answer
    // reach it; refused or unanswered, it is removed again.
    let id = call.device.events.create(filter, until, now).map_err(|_| {
        fault_detail(
            FaultCode::Receiver,
            &["Action"],
            "The device holds no more subscriptions",
            "<wsnt:SubscribeCreationFailedFault/>",
        )
    })?;
    let asked = call
        .ask(
            &a::SUBSCRIBE_EVENT,
            json!({"subscription": id, "filter": filter_json, "termination_time": wire::format_datetime(until)}),
            a::ACCEPT,
        )
        .await;
    if let Err(r) = asked {
        call.device.events.remove(&id);
        return Err(r);
    }
    let address = format!("{}{}{id}", call.base, wire::SUBSCRIPTION_PREFIX);
    Ok(ok(&events::create_response(&address, now, until)))
}

/// The subscription a request is for: its path, or failing that its wsa:To.
fn subscription_id(call: &Call<'_>) -> Option<String> {
    let from_path = |p: &str| {
        p.strip_prefix(wire::SUBSCRIPTION_PREFIX)
            .map(|id| id.split(['?', '/']).next().unwrap_or_default().to_string())
            .filter(|id| !id.is_empty())
    };
    from_path(&call.path).or_else(|| {
        call.req
            .to
            .as_deref()
            .and_then(wire::xaddr_path)
            .and_then(|p| from_path(&p))
    })
}

async fn subscription_op(call: &Call<'_>, op: Op) -> Result<Resp, Resp> {
    let id = subscription_id(call).ok_or_else(resource_unknown)?;
    let device = call.device;
    let address = format!("{}{}{id}", call.base, wire::SUBSCRIPTION_PREFIX);
    match op {
        Op::PullMessages => {
            let b = call.body();
            let timeout = match b.text_of("Timeout").filter(|t| !t.is_empty()) {
                None => device.max_pull_timeout,
                Some(t) => wire::parse_duration(&t)
                    .map_err(|_| {
                        fault(
                            FaultCode::Sender,
                            &["InvalidArgVal"],
                            "Timeout is not a duration",
                        )
                    })?
                    .min(device.max_pull_timeout),
            };
            let limit = match b.text_of("MessageLimit").filter(|t| !t.is_empty()) {
                None => events::MAX_MESSAGE_LIMIT,
                Some(t) => usize::try_from(t.parse::<u64>().map_err(|_| {
                    fault(
                        FaultCode::Sender,
                        &["InvalidArgVal"],
                        "MessageLimit is not a number",
                    )
                })?)
                .unwrap_or(usize::MAX)
                .clamp(1, events::MAX_MESSAGE_LIMIT),
            };
            let msgs = device
                .events
                .pull(&id, timeout, limit, || device.now())
                .await
                .map_err(|_| resource_unknown())?;
            let now = device.now();
            let until = device.events.termination(&id, now).unwrap_or(now);
            let producer = format!("{}{}", call.base, wire::EVENTS_PATH);
            Ok(ok(&events::pull_response(
                now, until, &msgs, &address, &producer,
            )))
        }
        Op::Renew => {
            let now = device.now();
            let until = termination(
                call,
                "TerminationTime",
                now,
                "UnacceptableTerminationTimeFault",
            )?;
            device
                .events
                .renew(&id, until, now)
                .map_err(|_| resource_unknown())?;
            Ok(ok(&events::renew_response(until, now)))
        }
        Op::Unsubscribe => {
            if !device.events.remove(&id) {
                return Err(resource_unknown());
            }
            Ok(empty("wsnt", "Unsubscribe"))
        }
        _ => {
            device
                .events
                .synchronization_point(&id, device.now())
                .map_err(|_| resource_unknown())?;
            Ok(empty("tev", "SetSynchronizationPoint"))
        }
    }
}

// ---- imaging --------------------------------------------------------------------------------

/// The VideoSourceToken an Imaging request names, if the device has that source.
async fn video_source(call: &Call<'_>) -> Result<String, Resp> {
    let token = call.body().text_of("VideoSourceToken").unwrap_or_default();
    if token.is_empty() {
        return Err(invalid("NoSource", "The request names no video source"));
    }
    if !lock(&call.device.catalog).has_source(&token) {
        sources_answer(call).await?;
    }
    if !lock(&call.device.catalog).has_source(&token) {
        return Err(invalid("NoSource", "No such video source"));
    }
    Ok(token)
}

fn no_imaging() -> Resp {
    fault(
        FaultCode::Receiver,
        &["ActionNotSupported", "NoImagingForSource"],
        "The device keeps imaging state for no more video sources",
    )
}

async fn imaging_op(call: &Call<'_>, op: Op) -> Result<Resp, Resp> {
    let source = video_source(call).await?;
    let device = call.device;
    // Reads, and the current state a change starts from.
    let (current, focus, auto_focus) = {
        let mut st = lock(&device.imaging);
        let s = st.source(&source).ok_or_else(no_imaging)?;
        match op {
            Op::ImagingSettings => return Ok(ok(&imaging::settings(&s.settings))),
            Op::ImagingStatus => return Ok(ok(&imaging::status(s))),
            Op::ImagingStop => {
                s.stop();
                return Ok(empty("timg", "Stop"));
            }
            Op::ImagingOptions => return Ok(ok(&imaging::options())),
            Op::MoveOptions => return Ok(ok(&imaging::move_options())),
            _ => {}
        }
        (s.settings.clone(), s.focus, s.settings.auto_focus.clone())
    };
    if op == Op::SetImagingSettings {
        let requested = imaging::requested(&current, call.body().child("ImagingSettings"))
            .map_err(|_| invalid("SettingsInvalid", "The settings are outside the options"))?;
        call.ask(
            &a::SET_IMAGING_EVENT,
            json!({"video_source_token": source, "current": current.json(), "requested": requested.json()}),
            a::ACCEPT,
        )
        .await?;
        if let Some(s) = lock(&device.imaging).source(&source) {
            s.settings = requested;
        }
        return Ok(empty("timg", "SetImagingSettings"));
    }
    let (kind, requested, proposed) =
        imaging::focus_move(Some(call.body()), focus).map_err(|_| {
            invalid(
                "SettingsInvalid",
                "The focus move is outside the move options",
            )
        })?;
    let reply = call
        .ask(
            &a::IMAGING_MOVE_EVENT,
            json!({"video_source_token": source, "kind": kind, "requested": requested,
                   "current_position": focus, "proposed_position": proposed, "auto_focus_mode": auto_focus}),
            a::FOCUS_POSITION,
        )
        .await?;
    let Some(to) = reply["position"]
        .as_f64()
        .filter(|p| (0.0..=1.0).contains(p))
    else {
        return Err(super::unavailable(crate::utils::WireFailure::Unavailable));
    };
    if let Some(s) = lock(&device.imaging).source(&source) {
        s.moved(to, kind == "continuous");
    }
    Ok(empty("timg", "Move"))
}
