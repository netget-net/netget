//! Media2 (ver20/media) for the ONVIF device: GetProfiles, GetStreamUri, GetSnapshotUri,
//! GetVideoSourceConfigurations and GetVideoEncoderConfigurations.
//!
//! There is no separate Media2 description: each operation asks the model the same event the
//! ver10 operation does (`onvif_get_profiles`, `onvif_get_stream_uri`, `onvif_get_snapshot_uri`)
//! and renders its answer in Media2's shapes, so a profile, its configuration tokens
//! (`vsc_<source>`, `vec_<profile>`, the one PTZ configuration) and its URIs are the same whichever
//! service a client reads them through.
use super::wire::{self, b, esc, items, n, s, source_of, Element};
use serde_json::Value;

/// Media2's name for an encoding the model gave in ver10 terms.
fn encoding(e: &str) -> &'static str {
    match e {
        "JPEG" => "JPEG",
        "MPEG4" => "MPV4-ES",
        _ => "H264",
    }
}

fn encoder(tag: &str, p: &Value) -> String {
    let token = esc(s(p, "token"));
    let enc = encoding(s(p, "encoding"));
    let fps = n(p, "framerate", 25);
    let attrs = if enc == "H264" {
        format!(" GovLength=\"{fps}\" Profile=\"Main\"")
    } else {
        String::new()
    };
    format!(
        "<{tag} token=\"vec_{token}\"{attrs}><tt:Name>{token}</tt:Name><tt:UseCount>1</tt:UseCount><tt:Encoding>{enc}</tt:Encoding>{}<tt:RateControl ConstantBitRate=\"false\"><tt:FrameRateLimit>{fps}</tt:FrameRateLimit><tt:BitrateLimit>{}</tt:BitrateLimit></tt:RateControl>{}<tt:Quality>{}</tt:Quality></{tag}>",
        wire::resolution(n(p, "width", 1920), n(p, "height", 1080)),
        n(p, "bitrate", 4096),
        wire::MULTICAST,
        n(p, "quality", 5)
    )
}

/// Which configurations a GetProfiles request asked to see. ONVIF: no Type means none, `All`
/// means every one.
pub struct Types(Vec<String>);

impl Types {
    pub fn of(body: &Element) -> Types {
        Types(
            body.children_named("Type")
                .take(16)
                .map(|t| t.text.trim().to_string())
                .collect(),
        )
    }
    fn wants(&self, t: &str) -> bool {
        self.0.iter().any(|x| x == "All" || x == t)
    }
}

pub fn profiles(v: &Value, types: &Types, token: Option<&str>) -> String {
    let mut out = String::from("<tr2:GetProfilesResponse>");
    for p in items(v, "profiles").filter(|p| token.is_none_or(|t| s(p, "token") == t)) {
        let tok = esc(s(p, "token"));
        let (w, h) = (n(p, "width", 1920), n(p, "height", 1080));
        let mut configs = String::new();
        if types.wants("VideoSource") {
            configs.push_str(&wire::video_source_configuration(
                "tr2:VideoSource",
                &source_of(p),
                w,
                h,
            ));
        }
        if types.wants("VideoEncoder") {
            configs.push_str(&encoder("tr2:VideoEncoder", p));
        }
        if types.wants("PTZ") && b(p, "ptz", false) {
            configs.push_str(&super::ptz::configuration("tr2:PTZ"));
        }
        let configs = if configs.is_empty() {
            String::new()
        } else {
            format!("<tr2:Configurations>{configs}</tr2:Configurations>")
        };
        out.push_str(&format!(
            "<tr2:Profiles token=\"{tok}\" fixed=\"true\"><tr2:Name>{}</tr2:Name>{configs}</tr2:Profiles>",
            esc(match s(p, "name") {
                "" => s(p, "token"),
                name => name,
            })
        ));
    }
    out.push_str("</tr2:GetProfilesResponse>");
    out
}

/// The tokens a configuration request narrows to.
pub struct Narrow {
    pub configuration: Option<String>,
    pub profile: Option<String>,
}

impl Narrow {
    pub fn of(body: &Element) -> Narrow {
        let t = |k: &str| body.text_of(k).filter(|t| !t.is_empty());
        Narrow {
            configuration: t("ConfigurationToken"),
            profile: t("ProfileToken"),
        }
    }
}

pub fn video_source_configurations(v: &Value, narrow: &Narrow) -> String {
    let mut out = String::from("<tr2:GetVideoSourceConfigurationsResponse>");
    let mut seen: Vec<String> = Vec::new();
    for p in items(v, "profiles") {
        let source = source_of(p);
        if narrow
            .profile
            .as_deref()
            .is_some_and(|t| s(p, "token") != t)
            || narrow
                .configuration
                .as_deref()
                .is_some_and(|c| esc(c) != format!("vsc_{source}"))
            || seen.contains(&source)
        {
            continue;
        }
        out.push_str(&wire::video_source_configuration(
            "tr2:Configurations",
            &source,
            n(p, "width", 1920),
            n(p, "height", 1080),
        ));
        seen.push(source);
    }
    out.push_str("</tr2:GetVideoSourceConfigurationsResponse>");
    out
}

pub fn video_encoder_configurations(v: &Value, narrow: &Narrow) -> String {
    let mut out = String::from("<tr2:GetVideoEncoderConfigurationsResponse>");
    for p in items(v, "profiles") {
        if narrow
            .profile
            .as_deref()
            .is_some_and(|t| s(p, "token") != t)
            || narrow
                .configuration
                .as_deref()
                .is_some_and(|c| c != format!("vec_{}", s(p, "token")))
        {
            continue;
        }
        out.push_str(&encoder("tr2:Configurations", p));
    }
    out.push_str("</tr2:GetVideoEncoderConfigurationsResponse>");
    out
}

/// GetStreamUriResponse or GetSnapshotUriResponse: Media2 answers with the bare URI.
pub fn uri(operation: &str, v: &Value) -> String {
    format!(
        "<tr2:{operation}Response><tr2:Uri>{}</tr2:Uri></tr2:{operation}Response>",
        esc(s(v, "uri"))
    )
}

/// A Media2 StreamUri request's protocol as ver10's (stream, transport), which is what the
/// model is asked with. Unknown protocols are None.
pub fn stream_setup(protocol: &str) -> Option<(&'static str, &'static str)> {
    Some(match protocol {
        "RtspUnicast" | "RTSP" | "" => ("RTP-Unicast", "RTSP"),
        "RtspMulticast" => ("RTP-Multicast", "RTSP"),
        "RtspOverHttp" => ("RTP-Unicast", "HTTP"),
        // RTSPS (TLS) and anything else: the device has no such stream setup.
        _ => return None,
    })
}

pub fn service_capabilities() -> String {
    "<tr2:GetServiceCapabilitiesResponse><tr2:Capabilities SnapshotUri=\"true\" Rotation=\"false\" VideoSourceMode=\"false\" OSD=\"false\" TemporaryOSDText=\"false\" Mask=\"false\" SourceMask=\"false\"><tr2:ProfileCapabilities MaximumNumberOfProfiles=\"64\"/><tr2:StreamingCapabilities RTSPStreaming=\"true\" RTPMulticast=\"false\" RTP_RTSP_TCP=\"true\" NonAggregateControl=\"false\"/></tr2:Capabilities></tr2:GetServiceCapabilitiesResponse>".into()
}
