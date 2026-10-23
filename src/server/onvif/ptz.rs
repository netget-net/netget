//! PTZ (ver20/ptz) for the ONVIF device: one pan/tilt/zoom node in ONVIF's generic spaces
//! (pan and tilt -1..1, zoom 0..1), its one configuration, its presets and its position.
//!
//! The position, the move status and the presets are the device's own volatile state, held in
//! memory for the life of the server like a real camera's head position — not storage: nothing
//! is written anywhere and a restart forgets it. GetStatus, GetPresets, SetPreset, RemovePreset
//! and Stop are answered from it without the model. Every move (ContinuousMove, RelativeMove,
//! AbsoluteMove, GotoPreset, GotoHomePosition) is the model's to accept — saying where the camera
//! ends up — or refuse with a fault; a refused move changes nothing.
use super::wire::{self, esc, Element};
use crate::utils::clock::Instant;
use serde_json::{json, Value};
use std::time::Duration;

pub const NODE_TOKEN: &str = "ptz_node";
pub const CONFIG_TOKEN: &str = "ptz_config";
/// Presets the node holds at most (`MaximumNumberOfPresets`).
pub const MAX_PRESETS: usize = 32;
/// A preset name at most, in bytes.
pub const MAX_PRESET_NAME: usize = 64;
/// How long a ContinuousMove runs when the request names no Timeout (`DefaultPTZTimeout`).
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);
/// The longest ContinuousMove Timeout accepted.
pub const MAX_TIMEOUT: Duration = Duration::from_secs(600);

pub const ABS_PAN_TILT: &str = "http://www.onvif.org/ver10/tptz/PanTiltSpaces/PositionGenericSpace";
pub const ABS_ZOOM: &str = "http://www.onvif.org/ver10/tptz/ZoomSpaces/PositionGenericSpace";
pub const REL_PAN_TILT: &str =
    "http://www.onvif.org/ver10/tptz/PanTiltSpaces/TranslationGenericSpace";
pub const REL_ZOOM: &str = "http://www.onvif.org/ver10/tptz/ZoomSpaces/TranslationGenericSpace";
pub const VEL_PAN_TILT: &str = "http://www.onvif.org/ver10/tptz/PanTiltSpaces/VelocityGenericSpace";
pub const VEL_ZOOM: &str = "http://www.onvif.org/ver10/tptz/ZoomSpaces/VelocityGenericSpace";
pub const SPEED_PAN_TILT: &str = "http://www.onvif.org/ver10/tptz/PanTiltSpaces/GenericSpeedSpace";
pub const SPEED_ZOOM: &str = "http://www.onvif.org/ver10/tptz/ZoomSpaces/ZoomGenericSpeedSpace";

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Position {
    pub pan: f64,
    pub tilt: f64,
    pub zoom: f64,
}

impl Position {
    pub const HOME: Position = Position {
        pan: 0.0,
        tilt: 0.0,
        zoom: 0.0,
    };
    pub fn json(&self) -> Value {
        json!({"pan": self.pan, "tilt": self.tilt, "zoom": self.zoom})
    }
    /// Clamped into the generic position space.
    fn clamped(self) -> Position {
        Position {
            pan: self.pan.clamp(-1.0, 1.0),
            tilt: self.tilt.clamp(-1.0, 1.0),
            zoom: self.zoom.clamp(0.0, 1.0),
        }
    }
    /// A position the model gave: `{pan, tilt, zoom}` inside the generic spaces.
    pub fn from_json(v: &Value) -> Option<Position> {
        let p = Position {
            pan: v["pan"].as_f64()?,
            tilt: v["tilt"].as_f64()?,
            zoom: v["zoom"].as_f64()?,
        };
        (p.clamped() == p).then_some(p)
    }
}

pub struct Preset {
    pub token: String,
    pub name: String,
    pub position: Position,
}

/// The node's volatile state.
pub struct PtzState {
    pub position: Position,
    pan_tilt_until: Option<Instant>,
    zoom_until: Option<Instant>,
    pub presets: Vec<Preset>,
    next_preset: u64,
}

impl Default for PtzState {
    fn default() -> Self {
        PtzState {
            position: Position::HOME,
            pan_tilt_until: None,
            zoom_until: None,
            presets: Vec::new(),
            next_preset: 1,
        }
    }
}

impl PtzState {
    /// Where the model said an accepted move ends; a continuous move keeps the axes it moves
    /// MOVING until its timeout passes or a Stop arrives.
    pub fn moved(&mut self, to: Position, continuous: Option<(&Axes, Duration)>) {
        self.position = to;
        self.pan_tilt_until = None;
        self.zoom_until = None;
        if let Some((velocity, timeout)) = continuous {
            let until = Instant::now() + timeout;
            if velocity.pan.unwrap_or(0.0) != 0.0 || velocity.tilt.unwrap_or(0.0) != 0.0 {
                self.pan_tilt_until = Some(until);
            }
            if velocity.zoom.unwrap_or(0.0) != 0.0 {
                self.zoom_until = Some(until);
            }
        }
    }

    pub fn stop(&mut self, pan_tilt: bool, zoom: bool) {
        if pan_tilt {
            self.pan_tilt_until = None;
        }
        if zoom {
            self.zoom_until = None;
        }
    }

    fn moving(until: Option<Instant>) -> &'static str {
        match until {
            Some(t) if Instant::now() < t => "MOVING",
            _ => "IDLE",
        }
    }

    pub fn move_status(&self) -> (&'static str, &'static str) {
        (
            Self::moving(self.pan_tilt_until),
            Self::moving(self.zoom_until),
        )
    }

    pub fn preset(&self, token: &str) -> Option<&Preset> {
        self.presets.iter().find(|p| p.token == token)
    }

    /// SetPreset: store the current position under an existing token, or under a new one.
    /// Errors are the `(code is Receiver, subcodes, reason)` of the fault to answer.
    pub fn set_preset(
        &mut self,
        token: Option<&str>,
        name: Option<&str>,
    ) -> Result<String, (bool, &'static [&'static str], &'static str)> {
        if let Some(name) = name {
            if name.len() > MAX_PRESET_NAME
                || name.is_empty()
                || crate::utils::sanitize::has_controls(name)
            {
                return Err((
                    false,
                    &["InvalidArgVal", "InvalidPresetName"],
                    "The preset name is empty, too long or has control characters",
                ));
            }
            if self
                .presets
                .iter()
                .any(|p| p.name == name && Some(p.token.as_str()) != token)
            {
                return Err((
                    false,
                    &["InvalidArgVal", "PresetExist"],
                    "A preset with that name already exists",
                ));
            }
        }
        let position = self.position;
        if let Some(token) = token {
            let Some(p) = self.presets.iter_mut().find(|p| p.token == token) else {
                return Err((false, &["InvalidArgVal", "NoToken"], "No such preset token"));
            };
            p.position = position;
            if let Some(name) = name {
                p.name = name.to_string();
            }
            return Ok(token.to_string());
        }
        if self.presets.len() >= MAX_PRESETS {
            return Err((
                true,
                &["Action", "TooManyPresets"],
                "The node holds no more presets",
            ));
        }
        let token = format!("preset_{}", self.next_preset);
        self.next_preset += 1;
        self.presets.push(Preset {
            name: name.map(str::to_string).unwrap_or_else(|| token.clone()),
            token: token.clone(),
            position,
        });
        Ok(token)
    }

    pub fn remove_preset(&mut self, token: &str) -> bool {
        let before = self.presets.len();
        self.presets.retain(|p| p.token != token);
        self.presets.len() != before
    }
}

/// The axes a PTZVector or PTZSpeed carried; an axis the request left out is None.
#[derive(Debug, Clone, Copy, Default)]
pub struct Axes {
    pub pan: Option<f64>,
    pub tilt: Option<f64>,
    pub zoom: Option<f64>,
}

impl Axes {
    pub fn json(&self) -> Value {
        json!({"pan": self.pan, "tilt": self.tilt, "zoom": self.zoom})
    }
}

/// What a vector in a request means, which decides its spaces, ranges and the fault detail.
#[derive(Debug, Clone, Copy)]
pub enum Kind {
    Position,
    Translation,
    Velocity,
    Speed,
}

impl Kind {
    fn spaces(self) -> (&'static str, &'static str) {
        match self {
            Kind::Position => (ABS_PAN_TILT, ABS_ZOOM),
            Kind::Translation => (REL_PAN_TILT, REL_ZOOM),
            Kind::Velocity => (VEL_PAN_TILT, VEL_ZOOM),
            Kind::Speed => (SPEED_PAN_TILT, SPEED_ZOOM),
        }
    }
    fn ranges(self) -> ((f64, f64), (f64, f64)) {
        match self {
            Kind::Position => ((-1.0, 1.0), (0.0, 1.0)),
            Kind::Translation | Kind::Velocity => ((-1.0, 1.0), (-1.0, 1.0)),
            Kind::Speed => ((0.0, 1.0), (0.0, 1.0)),
        }
    }
    /// The `ter:` detail subcode under InvalidArgVal for a bad vector of this kind.
    pub fn detail(self) -> &'static str {
        match self {
            Kind::Position => "InvalidPosition",
            Kind::Translation => "InvalidTranslation",
            Kind::Velocity => "InvalidVelocity",
            Kind::Speed => "InvalidSpeed",
        }
    }
}

/// The PanTilt (x, y) and Zoom (x) children of `el`, each in its generic space and range.
/// An error is the detail subcode to fault with.
pub fn axes(el: Option<&Element>, kind: Kind) -> Result<Axes, &'static str> {
    let Some(el) = el else {
        return Ok(Axes::default());
    };
    let (pt_space, z_space) = kind.spaces();
    let ((lo, hi), (zlo, zhi)) = kind.ranges();
    let mut out = Axes::default();
    // An empty space attribute is the default space, as an absent one is.
    let space_ok = |e: &Element, want: &str| {
        e.attr("space")
            .is_none_or(|s| s.trim().is_empty() || s.trim() == want)
    };
    if let Some(pt) = el.child("PanTilt") {
        if !space_ok(pt, pt_space) {
            return Err(kind.detail());
        }
        let x = wire::float_attr(pt, "x").map_err(|_| kind.detail())?;
        let y = wire::float_attr(pt, "y").map_err(|_| kind.detail())?;
        let (Some(x), Some(y)) = (x, y) else {
            return Err(kind.detail());
        };
        if !(lo..=hi).contains(&x) || !(lo..=hi).contains(&y) {
            return Err(kind.detail());
        }
        out.pan = Some(x);
        out.tilt = Some(y);
    }
    if let Some(z) = el.child("Zoom") {
        if !space_ok(z, z_space) {
            return Err(kind.detail());
        }
        let x = wire::float_attr(z, "x")
            .map_err(|_| kind.detail())?
            .ok_or(kind.detail())?;
        if !(zlo..=zhi).contains(&x) {
            return Err(kind.detail());
        }
        out.zoom = Some(x);
    }
    Ok(out)
}

/// Where a move would take the camera by plain arithmetic: the model's starting point, which
/// it may accept, change or refuse.
pub fn proposed(current: Position, kind: &MoveKind) -> Position {
    let add = |c: f64, d: Option<f64>| c + d.unwrap_or(0.0);
    match kind {
        MoveKind::Continuous { velocity, timeout } => {
            // Full speed crosses a tenth of the space per second.
            let k = timeout.as_secs_f64() / 10.0;
            Position {
                pan: current.pan + velocity.pan.unwrap_or(0.0) * k,
                tilt: current.tilt + velocity.tilt.unwrap_or(0.0) * k,
                zoom: current.zoom + velocity.zoom.unwrap_or(0.0) * k,
            }
            .clamped()
        }
        MoveKind::Relative { translation, .. } => Position {
            pan: add(current.pan, translation.pan),
            tilt: add(current.tilt, translation.tilt),
            zoom: add(current.zoom, translation.zoom),
        }
        .clamped(),
        MoveKind::Absolute { position, .. } => Position {
            pan: position.pan.unwrap_or(current.pan),
            tilt: position.tilt.unwrap_or(current.tilt),
            zoom: position.zoom.unwrap_or(current.zoom),
        },
        MoveKind::Preset { position, .. } => *position,
        MoveKind::Home { .. } => Position::HOME,
    }
}

/// A move the model is asked about.
pub enum MoveKind {
    Continuous {
        velocity: Axes,
        timeout: Duration,
    },
    Relative {
        translation: Axes,
        speed: Axes,
    },
    Absolute {
        position: Axes,
        speed: Axes,
    },
    Preset {
        token: String,
        name: String,
        position: Position,
        speed: Axes,
    },
    Home {
        speed: Axes,
    },
}

impl MoveKind {
    pub fn name(&self) -> &'static str {
        match self {
            MoveKind::Continuous { .. } => "continuous",
            MoveKind::Relative { .. } => "relative",
            MoveKind::Absolute { .. } => "absolute",
            MoveKind::Preset { .. } => "preset",
            MoveKind::Home { .. } => "home",
        }
    }
    /// What the request asked for, for the model.
    pub fn json(&self) -> Value {
        match self {
            MoveKind::Continuous { velocity, timeout } => {
                json!({"velocity": velocity.json(), "timeout_secs": timeout.as_secs_f64()})
            }
            MoveKind::Relative { translation, speed } => {
                json!({"translation": translation.json(), "speed": speed.json()})
            }
            MoveKind::Absolute { position, speed } => {
                json!({"target": position.json(), "speed": speed.json()})
            }
            MoveKind::Preset {
                token, name, speed, ..
            } => json!({"preset_token": token, "preset_name": name, "speed": speed.json()}),
            MoveKind::Home { speed } => json!({"speed": speed.json()}),
        }
    }
}

fn f(v: f64) -> String {
    // Shortest round-trip form; generic-space values are small and finite.
    format!("{v}")
}

fn space2d(tag: &str, uri: &str, lo: f64, hi: f64) -> String {
    format!(
        "<tt:{tag}><tt:URI>{uri}</tt:URI><tt:XRange><tt:Min>{}</tt:Min><tt:Max>{}</tt:Max></tt:XRange><tt:YRange><tt:Min>{}</tt:Min><tt:Max>{}</tt:Max></tt:YRange></tt:{tag}>",
        f(lo), f(hi), f(lo), f(hi)
    )
}

fn space1d(tag: &str, uri: &str, lo: f64, hi: f64) -> String {
    format!(
        "<tt:{tag}><tt:URI>{uri}</tt:URI><tt:XRange><tt:Min>{}</tt:Min><tt:Max>{}</tt:Max></tt:XRange></tt:{tag}>",
        f(lo),
        f(hi)
    )
}

/// The node, under `tag` (`tptz:PTZNode`).
pub fn node(tag: &str) -> String {
    format!(
        "<{tag} token=\"{NODE_TOKEN}\" FixedHomePosition=\"true\" GeoMove=\"false\"><tt:Name>PTZ</tt:Name><tt:SupportedPTZSpaces>{}{}{}{}{}{}{}{}</tt:SupportedPTZSpaces><tt:MaximumNumberOfPresets>{MAX_PRESETS}</tt:MaximumNumberOfPresets><tt:HomeSupported>true</tt:HomeSupported></{tag}>",
        space2d("AbsolutePanTiltPositionSpace", ABS_PAN_TILT, -1.0, 1.0),
        space1d("AbsoluteZoomPositionSpace", ABS_ZOOM, 0.0, 1.0),
        space2d("RelativePanTiltTranslationSpace", REL_PAN_TILT, -1.0, 1.0),
        space1d("RelativeZoomTranslationSpace", REL_ZOOM, -1.0, 1.0),
        space2d("ContinuousPanTiltVelocitySpace", VEL_PAN_TILT, -1.0, 1.0),
        space1d("ContinuousZoomVelocitySpace", VEL_ZOOM, -1.0, 1.0),
        space1d("PanTiltSpeedSpace", SPEED_PAN_TILT, 0.0, 1.0),
        space1d("ZoomSpeedSpace", SPEED_ZOOM, 0.0, 1.0),
    )
}

/// The device's one PTZ configuration, under `tag` (`tt:PTZConfiguration` inside a profile,
/// `tptz:PTZConfiguration` in a PTZ response).
pub fn configuration(tag: &str) -> String {
    format!(
        "<{tag} token=\"{CONFIG_TOKEN}\"><tt:Name>PTZ</tt:Name><tt:UseCount>1</tt:UseCount><tt:NodeToken>{NODE_TOKEN}</tt:NodeToken><tt:DefaultAbsolutePantTiltPositionSpace>{ABS_PAN_TILT}</tt:DefaultAbsolutePantTiltPositionSpace><tt:DefaultAbsoluteZoomPositionSpace>{ABS_ZOOM}</tt:DefaultAbsoluteZoomPositionSpace><tt:DefaultRelativePanTiltTranslationSpace>{REL_PAN_TILT}</tt:DefaultRelativePanTiltTranslationSpace><tt:DefaultRelativeZoomTranslationSpace>{REL_ZOOM}</tt:DefaultRelativeZoomTranslationSpace><tt:DefaultContinuousPanTiltVelocitySpace>{VEL_PAN_TILT}</tt:DefaultContinuousPanTiltVelocitySpace><tt:DefaultContinuousZoomVelocitySpace>{VEL_ZOOM}</tt:DefaultContinuousZoomVelocitySpace><tt:DefaultPTZSpeed><tt:PanTilt x=\"1\" y=\"1\" space=\"{SPEED_PAN_TILT}\"/><tt:Zoom x=\"1\" space=\"{SPEED_ZOOM}\"/></tt:DefaultPTZSpeed><tt:DefaultPTZTimeout>{}</tt:DefaultPTZTimeout><tt:PanTiltLimits><tt:Range><tt:URI>{ABS_PAN_TILT}</tt:URI><tt:XRange><tt:Min>-1</tt:Min><tt:Max>1</tt:Max></tt:XRange><tt:YRange><tt:Min>-1</tt:Min><tt:Max>1</tt:Max></tt:YRange></tt:Range></tt:PanTiltLimits><tt:ZoomLimits><tt:Range><tt:URI>{ABS_ZOOM}</tt:URI><tt:XRange><tt:Min>0</tt:Min><tt:Max>1</tt:Max></tt:XRange></tt:Range></tt:ZoomLimits></{tag}>",
        wire::format_duration(DEFAULT_TIMEOUT)
    )
}

fn vector(tag: &str, p: Position) -> String {
    format!(
        "<{tag}><tt:PanTilt x=\"{}\" y=\"{}\" space=\"{ABS_PAN_TILT}\"/><tt:Zoom x=\"{}\" space=\"{ABS_ZOOM}\"/></{tag}>",
        f(p.pan),
        f(p.tilt),
        f(p.zoom)
    )
}

pub fn status(state: &PtzState, now: chrono::DateTime<chrono::Utc>) -> String {
    let (pt, z) = state.move_status();
    format!(
        "<tptz:GetStatusResponse><tptz:PTZStatus>{}<tt:MoveStatus><tt:PanTilt>{pt}</tt:PanTilt><tt:Zoom>{z}</tt:Zoom></tt:MoveStatus><tt:UtcTime>{}</tt:UtcTime></tptz:PTZStatus></tptz:GetStatusResponse>",
        vector("tt:Position", state.position),
        wire::format_datetime(now)
    )
}

pub fn presets(state: &PtzState) -> String {
    let mut out = String::from("<tptz:GetPresetsResponse>");
    for p in &state.presets {
        out.push_str(&format!(
            "<tptz:Preset token=\"{}\"><tt:Name>{}</tt:Name>{}</tptz:Preset>",
            esc(&p.token),
            esc(&p.name),
            vector("tt:PTZPosition", p.position)
        ));
    }
    out.push_str("</tptz:GetPresetsResponse>");
    out
}

pub fn service_capabilities() -> String {
    "<tptz:GetServiceCapabilitiesResponse><tptz:Capabilities EFlip=\"false\" Reverse=\"false\" GetCompatibleConfigurations=\"false\" MoveStatus=\"true\" StatusPosition=\"true\"/></tptz:GetServiceCapabilitiesResponse>".into()
}

/// A request's ContinuousMove Timeout, defaulted and bounded. Err is the request being wrong.
pub fn timeout(body: &Element) -> Result<Duration, ()> {
    match body.text_of("Timeout") {
        None => Ok(DEFAULT_TIMEOUT),
        Some(t) if t.is_empty() => Ok(DEFAULT_TIMEOUT),
        Some(t) => match wire::parse_duration(&t) {
            Ok(d) if d <= MAX_TIMEOUT => Ok(d),
            _ => Err(()),
        },
    }
}
