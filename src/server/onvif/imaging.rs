//! Imaging (ver20/imaging) for the ONVIF device: GetImagingSettings, SetImagingSettings,
//! GetOptions, GetMoveOptions, Move, Stop and GetStatus, per video source.
//!
//! Each video source's settings (brightness, colour saturation, contrast, sharpness, IR-cut
//! filter, autofocus mode) and focus position are the device's own volatile state, in memory for
//! the life of the server — not storage. Reads are answered from it; SetImagingSettings and Move
//! are the model's to accept (a Move saying where focus ends up) or refuse, and only an accepted
//! change is applied. The options are fixed: every level 0..100, focus position 0..1.
use super::wire::{self, Element};
use crate::utils::clock::Instant;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::time::Duration;

/// Video sources with imaging state at most.
pub const MAX_SOURCES: usize = super::wire::MAX_ITEMS;
/// A continuous focus move stops by itself after this long (Imaging has no move timeout).
pub const MAX_CONTINUOUS: Duration = Duration::from_secs(60);
pub const LEVELS: [&str; 4] = ["Brightness", "ColorSaturation", "Contrast", "Sharpness"];
pub const IR_CUT_MODES: [&str; 3] = ["ON", "OFF", "AUTO"];
pub const FOCUS_MODES: [&str; 2] = ["AUTO", "MANUAL"];

#[derive(Debug, Clone, PartialEq)]
pub struct Settings {
    /// Brightness, ColorSaturation, Contrast, Sharpness, each 0..100.
    pub levels: [f64; 4],
    pub ir_cut_filter: String,
    pub auto_focus: String,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            levels: [50.0; 4],
            ir_cut_filter: "AUTO".into(),
            auto_focus: "AUTO".into(),
        }
    }
}

impl Settings {
    pub fn json(&self) -> Value {
        json!({"brightness": self.levels[0], "color_saturation": self.levels[1],
               "contrast": self.levels[2], "sharpness": self.levels[3],
               "ir_cut_filter": self.ir_cut_filter, "auto_focus_mode": self.auto_focus})
    }
}

#[derive(Default)]
pub struct Source {
    pub settings: Settings,
    pub focus: f64,
    moving_until: Option<Instant>,
}

#[derive(Default)]
pub struct ImagingState {
    sources: HashMap<String, Source>,
}

impl ImagingState {
    /// A source's state, created at defaults on first use; None once `MAX_SOURCES` are held.
    pub fn source(&mut self, token: &str) -> Option<&mut Source> {
        if !self.sources.contains_key(token) && self.sources.len() >= MAX_SOURCES {
            return None;
        }
        Some(self.sources.entry(token.to_string()).or_default())
    }
}

impl Source {
    pub fn moving(&self) -> &'static str {
        match self.moving_until {
            Some(t) if Instant::now() < t => "MOVING",
            _ => "IDLE",
        }
    }
    pub fn moved(&mut self, to: f64, continuous: bool) {
        self.focus = to;
        self.moving_until = continuous.then(|| Instant::now() + MAX_CONTINUOUS);
    }
    pub fn stop(&mut self) {
        self.moving_until = None;
    }
}

/// The settings a SetImagingSettings asks for, applied over `current`. Err when an element is
/// out of range or one the device does not have.
pub fn requested(current: &Settings, el: Option<&Element>) -> Result<Settings, ()> {
    let el = el.ok_or(())?;
    let mut out = current.clone();
    for c in &el.children {
        match c.name.as_str() {
            "Brightness" | "ColorSaturation" | "Contrast" | "Sharpness" => {
                let v: f64 = c.text.trim().parse().map_err(|_| ())?;
                if !(0.0..=100.0).contains(&v) {
                    return Err(());
                }
                let i = LEVELS.iter().position(|l| *l == c.name).ok_or(())?;
                out.levels[i] = v;
            }
            "IrCutFilter" => {
                let m = c.text.trim();
                out.ir_cut_filter = IR_CUT_MODES
                    .iter()
                    .find(|x| **x == m)
                    .ok_or(())?
                    .to_string();
            }
            "Focus" => {
                if let Some(m) = c.text_of("AutoFocusMode") {
                    out.auto_focus = FOCUS_MODES.iter().find(|x| **x == m).ok_or(())?.to_string();
                }
            }
            "Extension" => {}
            _ => return Err(()),
        }
    }
    Ok(out)
}

/// A Move request's focus: the kind, what it asked for, and where plain arithmetic puts focus.
pub fn focus_move(el: Option<&Element>, current: f64) -> Result<(&'static str, Value, f64), ()> {
    let focus = el.and_then(|e| e.child("Focus")).ok_or(())?;
    let num = |e: &Element, k: &str, lo: f64, hi: f64, required: bool| -> Result<Option<f64>, ()> {
        match e.text_of(k) {
            None if !required => Ok(None),
            None => Err(()),
            Some(t) => {
                let v: f64 = t.parse().map_err(|_| ())?;
                if v.is_finite() && (lo..=hi).contains(&v) {
                    Ok(Some(v))
                } else {
                    Err(())
                }
            }
        }
    };
    if let Some(a) = focus.child("Absolute") {
        let pos = num(a, "Position", 0.0, 1.0, true)?.ok_or(())?;
        let speed = num(a, "Speed", 0.0, 1.0, false)?;
        return Ok(("absolute", json!({"position": pos, "speed": speed}), pos));
    }
    if let Some(r) = focus.child("Relative") {
        let d = num(r, "Distance", -1.0, 1.0, true)?.ok_or(())?;
        let speed = num(r, "Speed", 0.0, 1.0, false)?;
        return Ok((
            "relative",
            json!({"distance": d, "speed": speed}),
            (current + d).clamp(0.0, 1.0),
        ));
    }
    if let Some(c) = focus.child("Continuous") {
        let speed = num(c, "Speed", -1.0, 1.0, true)?.ok_or(())?;
        let to = if speed > 0.0 {
            1.0
        } else if speed < 0.0 {
            0.0
        } else {
            current
        };
        return Ok(("continuous", json!({"speed": speed}), to));
    }
    Err(())
}

fn range(tag: &str, lo: f64, hi: f64) -> String {
    format!("<tt:{tag}><tt:Min>{lo}</tt:Min><tt:Max>{hi}</tt:Max></tt:{tag}>")
}

pub fn settings(s: &Settings) -> String {
    format!(
        "<timg:GetImagingSettingsResponse><timg:ImagingSettings><tt:Brightness>{}</tt:Brightness><tt:ColorSaturation>{}</tt:ColorSaturation><tt:Contrast>{}</tt:Contrast><tt:Focus><tt:AutoFocusMode>{}</tt:AutoFocusMode></tt:Focus><tt:IrCutFilter>{}</tt:IrCutFilter><tt:Sharpness>{}</tt:Sharpness></timg:ImagingSettings></timg:GetImagingSettingsResponse>",
        s.levels[0],
        s.levels[1],
        s.levels[2],
        wire::esc(&s.auto_focus),
        wire::esc(&s.ir_cut_filter),
        s.levels[3]
    )
}

pub fn options() -> String {
    format!(
        "<timg:GetOptionsResponse><timg:ImagingOptions>{}{}{}<tt:Focus>{}</tt:Focus>{}{}</timg:ImagingOptions></timg:GetOptionsResponse>",
        range("Brightness", 0.0, 100.0),
        range("ColorSaturation", 0.0, 100.0),
        range("Contrast", 0.0, 100.0),
        FOCUS_MODES
            .iter()
            .map(|m| format!("<tt:AutoFocusModes>{m}</tt:AutoFocusModes>"))
            .collect::<String>(),
        IR_CUT_MODES
            .iter()
            .map(|m| format!("<tt:IrCutFilterModes>{m}</tt:IrCutFilterModes>"))
            .collect::<String>(),
        range("Sharpness", 0.0, 100.0),
    )
}

pub fn move_options() -> String {
    format!(
        "<timg:GetMoveOptionsResponse><timg:MoveOptions><tt:Absolute>{}{}</tt:Absolute><tt:Relative>{}{}</tt:Relative><tt:Continuous>{}</tt:Continuous></timg:MoveOptions></timg:GetMoveOptionsResponse>",
        range("Position", 0.0, 1.0),
        range("Speed", 0.0, 1.0),
        range("Distance", -1.0, 1.0),
        range("Speed", 0.0, 1.0),
        range("Speed", -1.0, 1.0),
    )
}

pub fn status(s: &Source) -> String {
    format!(
        "<timg:GetStatusResponse><timg:Status><tt:FocusStatus20><tt:Position>{}</tt:Position><tt:MoveStatus>{}</tt:MoveStatus></tt:FocusStatus20></timg:Status></timg:GetStatusResponse>",
        s.focus,
        s.moving()
    )
}

pub fn service_capabilities() -> String {
    "<timg:GetServiceCapabilitiesResponse><timg:Capabilities ImageStabilization=\"false\" Presets=\"false\"/></timg:GetServiceCapabilitiesResponse>".into()
}
