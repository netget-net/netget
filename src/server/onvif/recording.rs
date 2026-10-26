//! Recording (ver10/recording), Search (ver10/search) and Replay (ver10/replay) — ONVIF
//! Profile G — for the ONVIF device.
//!
//! The device stores no media. The model describes its recordings **once** (`onvif_recordings`,
//! asked by the first Recording, Search or Replay request): each recording's source, content,
//! retention, tracks with the time range each holds, the events recorded on it, and the RTSP
//! URI a replay of it is served from; and the recording jobs. Rust validates that description
//! (`archive_from_action`), keeps it as the device's volatile state for the life of the server,
//! and answers GetRecordings, GetRecordingConfiguration, GetRecordingJobs, GetRecordingSummary,
//! GetRecordingInformation, every search and GetReplayUri from it at no model cost.
//! CreateRecording and DeleteRecording are each a model allow/deny and change that state.
//!
//! Searches run to completion when they are started — the description is in memory — and their
//! results wait to be paged out. Every bound is a constant here: recordings, tracks, recorded
//! events and jobs in a description; live searches (`MAX_SEARCHES`); the results a search keeps
//! (`MAX_SEARCH_RESULTS`, below any MaxMatches) and hands out per request (`MAX_RESULTS_PAGE`);
//! a search's keep-alive (`MAX_KEEP_ALIVE`), after which it is gone. The request parsers here
//! (`scope_of`, `event_query`, `recording_query`, `page_size`) are what the fuzz target drives.
use super::events::{self, Filter, Notification};
use super::wire::{self, esc, Element};
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value};
use std::collections::{HashMap, VecDeque};
use std::time::Duration;

/// Recordings the device holds at most (described and created together).
pub const MAX_RECORDINGS: usize = 32;
/// Tracks per recording at most.
pub const MAX_TRACKS: usize = 8;
/// Events recorded on one recording at most.
pub const MAX_RECORDED_EVENTS: usize = 256;
/// Events recorded on all recordings at most.
pub const MAX_ARCHIVE_EVENTS: usize = 1024;
/// Recording jobs at most.
pub const MAX_JOBS: usize = 16;
/// Live searches at most; the next FindRecordings or FindEvents is refused.
pub const MAX_SEARCHES: usize = 8;
/// Results one search keeps at most, whatever its MaxMatches.
pub const MAX_SEARCH_RESULTS: usize = 256;
/// Results one GetRecordingSearchResults or GetEventSearchResults hands out at most.
pub const MAX_RESULTS_PAGE: usize = 100;
/// A search's KeepAliveTime is cut to this.
pub const MAX_KEEP_ALIVE: Duration = Duration::from_secs(300);
/// A search without a KeepAliveTime lives this long between requests.
pub const DEFAULT_KEEP_ALIVE: Duration = Duration::from_secs(60);
/// Recordings or sources one search scope names at most.
pub const MAX_SCOPE_ITEMS: usize = 64;
/// A recording's MaximumRetentionTime at most (ten years), in seconds.
pub const MAX_RETENTION_SECS: u64 = 10 * 365 * 86_400;
/// How long a replay session may stay idle (GetReplayConfiguration).
pub const REPLAY_SESSION_TIMEOUT: Duration = Duration::from_secs(60);
/// A string in a description at most, in bytes.
pub const MAX_TEXT: usize = super::actions::MAX_TEXT;

#[derive(Debug, Clone, PartialEq)]
pub struct Source {
    pub source_id: String,
    pub name: String,
    pub location: String,
    pub description: String,
    pub address: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Track {
    pub token: String,
    /// Video, Audio or Metadata.
    pub kind: &'static str,
    pub description: String,
    pub from: chrono::DateTime<chrono::Utc>,
    pub to: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone)]
pub struct RecordedEvent {
    pub track: String,
    pub notification: Notification,
}

#[derive(Debug, Clone)]
pub struct Recording {
    pub token: String,
    pub source: Source,
    pub content: String,
    pub retention_secs: u64,
    pub tracks: Vec<Track>,
    pub events: Vec<RecordedEvent>,
    pub replay_uri: Option<String>,
}

impl Recording {
    pub fn earliest(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        self.tracks.iter().map(|t| t.from).min()
    }
    pub fn latest(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        self.tracks.iter().map(|t| t.to).max()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Job {
    pub token: String,
    pub recording: String,
    /// Active or Idle.
    pub mode: &'static str,
    pub priority: u64,
    pub source_token: Option<String>,
}

/// Everything the device has recorded, as the model described it and clients changed it.
#[derive(Debug, Clone, Default)]
pub struct Archive {
    pub recordings: Vec<Recording>,
    pub jobs: Vec<Job>,
}

// ---- the model's description ----------------------------------------------------------------

fn opt_text(v: &Value, key: &str) -> Result<String> {
    match v.get(key) {
        None | Some(Value::Null) => Ok(String::new()),
        Some(Value::String(s)) => {
            ensure!(
                s.len() <= MAX_TEXT && !crate::utils::sanitize::has_controls(s),
                "{key} is at most {MAX_TEXT} bytes of text without control characters"
            );
            Ok(s.clone())
        }
        Some(_) => bail!("{key} is text"),
    }
}

/// A ReferenceToken: 1-64 bytes, no whitespace or control characters.
pub fn token_ok(t: &str) -> bool {
    !t.is_empty()
        && t.len() <= 64
        && !t.chars().any(char::is_whitespace)
        && !crate::utils::sanitize::has_controls(t)
}

fn token(v: &Value, key: &str) -> Result<String> {
    let t = v[key]
        .as_str()
        .with_context(|| format!("{key} is required"))?;
    ensure!(
        token_ok(t),
        "{key} is a token of 1-64 characters without spaces"
    );
    Ok(t.to_string())
}

fn time(v: &Value, key: &str) -> Result<chrono::DateTime<chrono::Utc>> {
    let t = v[key]
        .as_str()
        .with_context(|| format!("{key} is required: a UTC time such as 2026-10-24T08:00:00Z"))?;
    let t = wire::parse_datetime(t)
        .with_context(|| format!("{key} is a UTC time such as 2026-10-24T08:00:00Z"))?;
    ensure!(
        (1970..=2100).contains(&chrono::Datelike::year(&t)),
        "{key} is between 1970 and 2100"
    );
    Ok(t)
}

/// A URI with a scheme and no whitespace, as the replay URI must be.
fn uri_ok(s: &str) -> bool {
    s.len() <= super::actions::MAX_URI
        && !s.chars().any(char::is_whitespace)
        && !crate::utils::sanitize::has_controls(s)
        && s.split_once("://").is_some_and(|(scheme, rest)| {
            !scheme.is_empty()
                && !rest.is_empty()
                && scheme
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || "+-.".contains(c))
        })
}

fn track_kind(s: &str) -> Option<&'static str> {
    match s {
        "Video" => Some("Video"),
        "Audio" => Some("Audio"),
        "Metadata" => Some("Metadata"),
        _ => None,
    }
}

fn list<'a>(v: &'a Value, key: &str, max: usize) -> Result<&'a [Value]> {
    match v.get(key) {
        None | Some(Value::Null) => Ok(&[]),
        Some(Value::Array(a)) => {
            ensure!(a.len() <= max, "{key} holds at most {max} entries");
            Ok(a)
        }
        Some(_) => bail!("{key} is a list"),
    }
}

fn recording_from(v: &Value, archive_events: &mut usize) -> Result<Recording> {
    let tok = token(v, "token")?;
    let mut tracks: Vec<Track> = Vec::new();
    for t in list(v, "tracks", MAX_TRACKS)? {
        let tt = token(t, "token").with_context(|| format!("recording {tok}: a track"))?;
        ensure!(
            !tracks.iter().any(|x| x.token == tt),
            "recording {tok}: track {tt} is named twice"
        );
        let kind = t["type"].as_str().and_then(track_kind).with_context(|| {
            format!("recording {tok} track {tt}: type is Video, Audio or Metadata")
        })?;
        let from = time(t, "from").with_context(|| format!("recording {tok} track {tt}"))?;
        let to = time(t, "to").with_context(|| format!("recording {tok} track {tt}"))?;
        ensure!(
            from <= to,
            "recording {tok} track {tt}: from is not after to"
        );
        tracks.push(Track {
            token: tt,
            kind,
            description: opt_text(t, "description")?,
            from,
            to,
        });
    }
    let mut recorded = Vec::new();
    for e in list(v, "events", MAX_RECORDED_EVENTS)? {
        *archive_events += 1;
        ensure!(
            *archive_events <= MAX_ARCHIVE_EVENTS,
            "the recordings hold at most {MAX_ARCHIVE_EVENTS} events between them"
        );
        let at = time(e, "time").with_context(|| format!("recording {tok}: an event"))?;
        let track = match e.get("track").and_then(Value::as_str) {
            Some(t) => {
                ensure!(
                    tracks.iter().any(|x| x.token == t),
                    "recording {tok}: an event names track {t}, which it does not have"
                );
                t.to_string()
            }
            None => tracks
                .iter()
                .find(|t| t.kind == "Video")
                .or(tracks.first())
                .map(|t| t.token.clone())
                .with_context(|| format!("recording {tok} has events but no track"))?,
        };
        let notification = events::notification_from_action(e, at)
            .with_context(|| format!("recording {tok}: an event"))?;
        recorded.push(RecordedEvent {
            track,
            notification,
        });
    }
    let replay_uri = match v.get("replay_uri") {
        None | Some(Value::Null) => None,
        Some(Value::String(u)) if uri_ok(u) => Some(u.clone()),
        Some(_) => bail!("recording {tok}: replay_uri is an absolute URI such as rtsp://192.0.2.10:554/replay/{tok}"),
    };
    let retention_secs = match v.get("retention_secs") {
        None | Some(Value::Null) => 0,
        Some(x) => x
            .as_u64()
            .filter(|n| *n <= MAX_RETENTION_SECS)
            .with_context(|| {
                format!(
                    "recording {tok}: retention_secs is a whole number of seconds up to ten years"
                )
            })?,
    };
    let source_id = match opt_text(v, "source_id")? {
        s if s.is_empty() => "video_source".to_string(),
        s => s,
    };
    let name = match opt_text(v, "name")? {
        s if s.is_empty() => tok.clone(),
        s => s,
    };
    Ok(Recording {
        source: Source {
            source_id,
            name,
            location: opt_text(v, "location")?,
            description: opt_text(v, "description")?,
            address: opt_text(v, "address")?,
        },
        content: opt_text(v, "content")?,
        retention_secs,
        tracks,
        events: recorded,
        replay_uri,
        token: tok,
    })
}

/// The device's recordings and jobs from the model's `onvif_recordings` answer, or why it is not
/// a description the device can serve.
pub fn archive_from_action(v: &Value) -> Result<Archive> {
    let mut archive = Archive::default();
    let mut archive_events = 0usize;
    for r in list(v, "recordings", MAX_RECORDINGS)? {
        let rec = recording_from(r, &mut archive_events)?;
        ensure!(
            !archive.recordings.iter().any(|x| x.token == rec.token),
            "recording {} is named twice",
            rec.token
        );
        archive.recordings.push(rec);
    }
    for j in list(v, "jobs", MAX_JOBS)? {
        let tok = token(j, "token").context("a job")?;
        ensure!(
            !archive.jobs.iter().any(|x| x.token == tok),
            "job {tok} is named twice"
        );
        let recording = token(j, "recording_token").with_context(|| format!("job {tok}"))?;
        ensure!(
            archive.recordings.iter().any(|r| r.token == recording),
            "job {tok} records into {recording}, which is not described"
        );
        let mode = match j["mode"].as_str() {
            None | Some("Active") => "Active",
            Some("Idle") => "Idle",
            Some(_) => bail!("job {tok}: mode is Active or Idle"),
        };
        let priority = match j.get("priority") {
            None | Some(Value::Null) => 1,
            Some(p) => p
                .as_u64()
                .filter(|p| *p <= 1000)
                .with_context(|| format!("job {tok}: priority is a whole number up to 1000"))?,
        };
        let source_token = match j.get("source_token") {
            None | Some(Value::Null) => None,
            Some(_) => Some(token(j, "source_token").with_context(|| format!("job {tok}"))?),
        };
        archive.jobs.push(Job {
            token: tok,
            recording,
            mode,
            priority,
            source_token,
        });
    }
    Ok(archive)
}

impl Archive {
    pub fn recording(&self, token: &str) -> Option<&Recording> {
        self.recordings.iter().find(|r| r.token == token)
    }

    /// Recording, Stopped or Initiated (created and never recorded into), from its jobs.
    pub fn status(&self, r: &Recording) -> &'static str {
        if self
            .jobs
            .iter()
            .any(|j| j.recording == r.token && j.mode == "Active")
        {
            "Recording"
        } else if r.tracks.iter().all(|t| t.from == t.to) {
            "Initiated"
        } else {
            "Stopped"
        }
    }

    /// A token no recording has.
    pub fn new_token(&self) -> String {
        (1..)
            .map(|n| format!("rec_{n}"))
            .find(|t| self.recording(t).is_none())
            .unwrap_or_default()
    }

    /// A recording made by CreateRecording: one empty track of each type.
    pub fn create(
        &mut self,
        configuration: &Configuration,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<String, ()> {
        if self.recordings.len() >= MAX_RECORDINGS {
            return Err(());
        }
        let token = self.new_token();
        let track = |t: &str, kind: &'static str| Track {
            token: t.into(),
            kind,
            description: String::new(),
            from: now,
            to: now,
        };
        self.recordings.push(Recording {
            token: token.clone(),
            source: configuration.source.clone(),
            content: configuration.content.clone(),
            retention_secs: configuration.retention.as_secs(),
            tracks: vec![
                track("VIDEO001", "Video"),
                track("AUDIO001", "Audio"),
                track("META001", "Metadata"),
            ],
            events: Vec::new(),
            replay_uri: None,
        });
        Ok(token)
    }

    /// DeleteRecording: the recording and the jobs that record into it.
    pub fn delete(&mut self, token: &str) -> bool {
        let before = self.recordings.len();
        self.recordings.retain(|r| r.token != token);
        self.jobs.retain(|j| j.recording != token);
        self.recordings.len() != before
    }
}

// ---- requests -------------------------------------------------------------------------------

/// A RecordingConfiguration from CreateRecording, checked.
#[derive(Debug, Clone, PartialEq)]
pub struct Configuration {
    pub source: Source,
    pub content: String,
    pub retention: Duration,
}

fn text_of_bounded(el: &Element, name: &str) -> Result<String, &'static str> {
    let t = el.text_of(name).unwrap_or_default();
    if t.len() > MAX_TEXT || crate::utils::sanitize::has_controls(&t) {
        return Err("InvalidArgVal");
    }
    Ok(t)
}

/// CreateRecording's RecordingConfiguration: every string bounded, the retention a duration.
pub fn configuration_of(body: &Element) -> Result<Configuration, &'static str> {
    let c = body
        .child("RecordingConfiguration")
        .ok_or("BadConfiguration")?;
    let s = c.child("Source").ok_or("BadConfiguration")?;
    let retention = match c.text_of("MaximumRetentionTime").filter(|t| !t.is_empty()) {
        None => Duration::ZERO,
        Some(t) => wire::parse_duration_max(&t, Duration::from_secs(MAX_RETENTION_SECS))
            .map_err(|_| "BadConfiguration")?,
    };
    let source = Source {
        source_id: text_of_bounded(s, "SourceId")?,
        name: text_of_bounded(s, "Name")?,
        location: text_of_bounded(s, "Location")?,
        description: text_of_bounded(s, "Description")?,
        address: text_of_bounded(s, "Address")?,
    };
    Ok(Configuration {
        content: text_of_bounded(c, "Content")?,
        source,
        retention,
    })
}

/// What a search's Scope names: sources (by SourceId) and recordings (by token). Empty is all.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Scope {
    pub sources: Vec<String>,
    pub recordings: Vec<String>,
}

impl Scope {
    pub fn includes(&self, r: &Recording) -> bool {
        (self.sources.is_empty() || self.sources.iter().any(|s| *s == r.source.source_id))
            && (self.recordings.is_empty() || self.recordings.iter().any(|t| *t == r.token))
    }
}

/// A SearchScope. A RecordingInformationFilter (an XPath expression) is refused rather than
/// ignored: the device does not evaluate XPath, and a filter silently not applied answers a
/// different question.
pub fn scope_of(el: Option<&Element>) -> Result<Scope, &'static str> {
    let Some(el) = el else {
        return Ok(Scope::default());
    };
    if el
        .child("RecordingInformationFilter")
        .is_some_and(|f| !f.text.trim().is_empty())
    {
        return Err("InvalidFilterFragment");
    }
    let mut scope = Scope::default();
    for s in el
        .children_named("IncludedSources")
        .take(MAX_SCOPE_ITEMS + 1)
    {
        // A SourceReference carries its token in Token; some clients write the text directly.
        let t = s
            .text_of("Token")
            .unwrap_or_else(|| s.text.trim().to_string());
        if t.len() > MAX_TEXT || crate::utils::sanitize::has_controls(&t) {
            return Err("InvalidArgVal");
        }
        scope.sources.push(t);
    }
    for r in el
        .children_named("IncludedRecordings")
        .take(MAX_SCOPE_ITEMS + 1)
    {
        let t = r.text.trim().to_string();
        if !token_ok(&t) {
            return Err("InvalidArgVal");
        }
        scope.recordings.push(t);
    }
    if scope.sources.len() > MAX_SCOPE_ITEMS || scope.recordings.len() > MAX_SCOPE_ITEMS {
        return Err("InvalidArgVal");
    }
    Ok(scope)
}

/// MaxMatches: absent is as many as the device keeps; anything else is cut to 1..=that.
pub fn max_matches(body: &Element) -> Result<usize, &'static str> {
    match body.text_of("MaxMatches").filter(|t| !t.is_empty()) {
        None => Ok(MAX_SEARCH_RESULTS),
        Some(t) => t
            .parse::<i64>()
            .map(|n| n.clamp(1, MAX_SEARCH_RESULTS as i64) as usize)
            .map_err(|_| "InvalidArgVal"),
    }
}

/// KeepAliveTime, cut to `MAX_KEEP_ALIVE` (and at least a second).
pub fn keep_alive(body: &Element) -> Result<Duration, &'static str> {
    match body.text_of("KeepAliveTime").filter(|t| !t.is_empty()) {
        None => Ok(DEFAULT_KEEP_ALIVE),
        Some(t) => wire::parse_duration(&t)
            .map(|d| d.clamp(Duration::from_secs(1), MAX_KEEP_ALIVE))
            .map_err(|_| "InvalidArgVal"),
    }
}

/// MaxResults of a Get*SearchResults: cut to 1..=`MAX_RESULTS_PAGE`.
pub fn page_size(body: &Element) -> Result<usize, &'static str> {
    match body.text_of("MaxResults").filter(|t| !t.is_empty()) {
        None => Ok(MAX_RESULTS_PAGE),
        Some(t) => t
            .parse::<i64>()
            .map(|n| n.clamp(1, MAX_RESULTS_PAGE as i64) as usize)
            .map_err(|_| "InvalidArgVal"),
    }
}

#[derive(Debug, Clone)]
pub struct RecordingQuery {
    pub scope: Scope,
    pub max_matches: usize,
    pub keep_alive: Duration,
}

pub fn recording_query(body: &Element) -> Result<RecordingQuery, &'static str> {
    Ok(RecordingQuery {
        scope: scope_of(body.child("Scope"))?,
        max_matches: max_matches(body)?,
        keep_alive: keep_alive(body)?,
    })
}

#[derive(Debug, Clone)]
pub struct EventQuery {
    pub start: chrono::DateTime<chrono::Utc>,
    pub end: Option<chrono::DateTime<chrono::Utc>>,
    pub scope: Scope,
    pub filter: Filter,
    pub include_start_state: bool,
    pub max_matches: usize,
    pub keep_alive: Duration,
}

impl EventQuery {
    /// An EndPoint before the StartPoint searches backwards in time.
    pub fn backwards(&self) -> bool {
        self.end.is_some_and(|e| e < self.start)
    }
    /// Whether an event at `t` lies between the start and end points (inclusive).
    pub fn covers(&self, t: chrono::DateTime<chrono::Utc>) -> bool {
        match self.end {
            None => t >= self.start,
            Some(e) if e < self.start => t >= e && t <= self.start,
            Some(e) => t >= self.start && t <= e,
        }
    }
}

/// FindEvents: StartPoint (required), EndPoint, Scope, SearchFilter (a topic expression in any
/// dialect the subscriptions accept; MessageContent refused), IncludeStartState, MaxMatches,
/// KeepAliveTime.
pub fn event_query(body: &Element) -> Result<EventQuery, &'static str> {
    let time = |name: &str| -> Result<Option<chrono::DateTime<chrono::Utc>>, &'static str> {
        match body.text_of(name).filter(|t| !t.is_empty()) {
            None => Ok(None),
            Some(t) => wire::parse_datetime(&t)
                .map(Some)
                .map_err(|_| "InvalidArgVal"),
        }
    };
    let start = time("StartPoint")?.ok_or("InvalidArgVal")?;
    let end = time("EndPoint")?;
    let filter = match body.child("SearchFilter") {
        None => Filter::All,
        Some(f) => {
            if f.child("MessageContent")
                .is_some_and(|m| !m.text.trim().is_empty())
            {
                return Err("InvalidArgVal");
            }
            match f.child("TopicExpression") {
                None => Filter::All,
                Some(t) => {
                    events::parse_topic_filter(t.attr("Dialect").unwrap_or_default(), &t.text)
                        .map_err(|_| "InvalidArgVal")?
                }
            }
        }
    };
    let include_start_state = body
        .text_of("IncludeStartState")
        .and_then(|t| wire::parse_bool(&t))
        .unwrap_or(false);
    Ok(EventQuery {
        start,
        end,
        scope: scope_of(body.child("Scope"))?,
        filter,
        include_start_state,
        max_matches: max_matches(body)?,
        keep_alive: keep_alive(body)?,
    })
}

// ---- running searches -----------------------------------------------------------------------

/// FindRecordings over the archive: the RecordingInformation of each recording in scope.
pub fn find_recordings(archive: &Archive, q: &RecordingQuery) -> Vec<String> {
    archive
        .recordings
        .iter()
        .filter(|r| q.scope.includes(r))
        .take(q.max_matches)
        .map(|r| recording_information("tt:RecordingInformation", archive, r))
        .collect()
}

/// One FindEvents match, rendered.
fn event_result(
    recording: &str,
    track: &str,
    n: &Notification,
    time: chrono::DateTime<chrono::Utc>,
    start_state: bool,
) -> String {
    format!(
        "<tt:Result><tt:RecordingToken>{}</tt:RecordingToken><tt:TrackToken>{}</tt:TrackToken><tt:Time>{}</tt:Time>{}<tt:StartStateEvent>{start_state}</tt:StartStateEvent></tt:Result>",
        esc(recording),
        esc(track),
        wire::format_datetime(time),
        events::message_holder("tt:Event", n, None, None)
    )
}

/// FindEvents over the archive, in time order (backwards when the EndPoint is before the
/// StartPoint): with IncludeStartState, first the state each property was in at the StartPoint.
pub fn find_events(archive: &Archive, q: &EventQuery) -> Vec<String> {
    let mut out = Vec::new();
    let in_scope = archive.recordings.iter().filter(|r| q.scope.includes(r));
    for r in in_scope.filter(|_| q.include_start_state) {
        // The last value of each property before the start (after it, searching backwards).
        let mut state: Vec<&RecordedEvent> = Vec::new();
        for e in &r.events {
            let t = e.notification.utc;
            let before = if q.backwards() {
                t > q.start
            } else {
                t < q.start
            };
            if !before || !q.filter.matches(e.notification.topic.path) {
                continue;
            }
            let key = (e.notification.topic.path, &e.notification.source);
            match state
                .iter_mut()
                .find(|s| (s.notification.topic.path, &s.notification.source) == key)
            {
                Some(s) => {
                    let newer = if q.backwards() {
                        t < s.notification.utc
                    } else {
                        t > s.notification.utc
                    };
                    if newer {
                        *s = e;
                    }
                }
                None => state.push(e),
            }
        }
        for e in state {
            out.push(event_result(
                &r.token,
                &e.track,
                &e.notification,
                q.start,
                true,
            ));
        }
    }
    let mut matches: Vec<(&Recording, &RecordedEvent)> = archive
        .recordings
        .iter()
        .filter(|r| q.scope.includes(r))
        .flat_map(|r| r.events.iter().map(move |e| (r, e)))
        .filter(|(_, e)| {
            q.covers(e.notification.utc) && q.filter.matches(e.notification.topic.path)
        })
        .collect();
    matches.sort_by_key(|(_, e)| e.notification.utc);
    if q.backwards() {
        matches.reverse();
    }
    for (r, e) in matches {
        out.push(event_result(
            &r.token,
            &e.track,
            &e.notification,
            e.notification.utc,
            false,
        ));
    }
    out.truncate(q.max_matches);
    out
}

pub struct Search {
    /// "recordings" or "events": a token is paged out by its own kind of request only.
    kind: &'static str,
    results: VecDeque<String>,
    keep_alive: Duration,
    expires: chrono::DateTime<chrono::Utc>,
    /// The point in time the search reached (EndSearch's Endpoint).
    endpoint: chrono::DateTime<chrono::Utc>,
}

/// The live searches, by token.
#[derive(Default)]
pub struct Searches {
    map: HashMap<String, Search>,
}

#[derive(Debug, PartialEq)]
pub enum SearchError {
    TooMany,
    Unknown,
}

impl Searches {
    fn sweep(&mut self, now: chrono::DateTime<chrono::Utc>) {
        self.map.retain(|_, s| s.expires > now);
    }

    fn deadline(
        now: chrono::DateTime<chrono::Utc>,
        keep_alive: Duration,
    ) -> chrono::DateTime<chrono::Utc> {
        now + chrono::Duration::from_std(keep_alive).unwrap_or_default()
    }

    /// A finished search whose results wait to be paged out; its token.
    pub fn start(
        &mut self,
        kind: &'static str,
        mut results: Vec<String>,
        keep_alive: Duration,
        endpoint: chrono::DateTime<chrono::Utc>,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<String, SearchError> {
        self.sweep(now);
        if self.map.len() >= MAX_SEARCHES {
            return Err(SearchError::TooMany);
        }
        results.truncate(MAX_SEARCH_RESULTS);
        let token = format!("search_{:016x}", rand::random::<u64>());
        self.map.insert(
            token.clone(),
            Search {
                kind,
                results: results.into(),
                keep_alive,
                expires: Self::deadline(now, keep_alive),
                endpoint,
            },
        );
        Ok(token)
    }

    /// Up to `max` results and the state after them: Searching while more wait, then
    /// Completed. Each request keeps the search alive for its keep-alive again.
    pub fn page(
        &mut self,
        kind: &str,
        token: &str,
        max: usize,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<(Vec<String>, &'static str), SearchError> {
        self.sweep(now);
        let s = self
            .map
            .get_mut(token)
            .filter(|s| s.kind == kind)
            .ok_or(SearchError::Unknown)?;
        s.expires = Self::deadline(now, s.keep_alive);
        let n = max.min(MAX_RESULTS_PAGE).min(s.results.len());
        let page: Vec<String> = s.results.drain(..n).collect();
        let state = if s.results.is_empty() {
            "Completed"
        } else {
            "Searching"
        };
        Ok((page, state))
    }

    pub fn state(
        &mut self,
        token: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<&'static str, SearchError> {
        self.sweep(now);
        let s = self.map.get(token).ok_or(SearchError::Unknown)?;
        Ok(if s.results.is_empty() {
            "Completed"
        } else {
            "Searching"
        })
    }

    pub fn end(
        &mut self,
        token: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<chrono::DateTime<chrono::Utc>, SearchError> {
        self.sweep(now);
        self.map
            .remove(token)
            .map(|s| s.endpoint)
            .ok_or(SearchError::Unknown)
    }

    pub fn count(&mut self, now: chrono::DateTime<chrono::Utc>) -> usize {
        self.sweep(now);
        self.map.len()
    }
}

// ---- the wire -------------------------------------------------------------------------------

fn source_xml(s: &Source) -> String {
    format!(
        "<tt:Source><tt:SourceId>{}</tt:SourceId><tt:Name>{}</tt:Name><tt:Location>{}</tt:Location><tt:Description>{}</tt:Description><tt:Address>{}</tt:Address></tt:Source>",
        esc(&s.source_id),
        esc(&s.name),
        esc(&s.location),
        esc(&s.description),
        esc(&s.address)
    )
}

pub fn recording_configuration(tag: &str, r: &Recording) -> String {
    format!(
        "<{tag}>{}<tt:Content>{}</tt:Content><tt:MaximumRetentionTime>PT{}S</tt:MaximumRetentionTime></{tag}>",
        source_xml(&r.source),
        esc(&r.content),
        r.retention_secs
    )
}

pub fn get_recordings(archive: &Archive) -> String {
    let mut out = String::from("<trc:GetRecordingsResponse>");
    for r in &archive.recordings {
        out.push_str(&format!(
            "<trc:RecordingItem><tt:RecordingToken>{}</tt:RecordingToken>{}<tt:Tracks>",
            esc(&r.token),
            recording_configuration("tt:Configuration", r)
        ));
        for t in &r.tracks {
            out.push_str(&format!(
                "<tt:Track><tt:TrackToken>{}</tt:TrackToken><tt:Configuration><tt:TrackType>{}</tt:TrackType><tt:Description>{}</tt:Description></tt:Configuration></tt:Track>",
                esc(&t.token),
                t.kind,
                esc(&t.description)
            ));
        }
        out.push_str("</tt:Tracks></trc:RecordingItem>");
    }
    out.push_str("</trc:GetRecordingsResponse>");
    out
}

pub fn get_recording_jobs(archive: &Archive) -> String {
    let mut out = String::from("<trc:GetRecordingJobsResponse>");
    for j in &archive.jobs {
        let source = j
            .source_token
            .as_ref()
            .map(|s| {
                format!(
                    "<tt:Source><tt:SourceToken Type=\"http://www.onvif.org/ver10/schema/Profile\"><tt:Token>{}</tt:Token></tt:SourceToken></tt:Source>",
                    esc(s)
                )
            })
            .unwrap_or_default();
        out.push_str(&format!(
            "<trc:JobItem><tt:JobToken>{}</tt:JobToken><tt:JobConfiguration><tt:RecordingToken>{}</tt:RecordingToken><tt:Mode>{}</tt:Mode><tt:Priority>{}</tt:Priority>{source}</tt:JobConfiguration></trc:JobItem>",
            esc(&j.token),
            esc(&j.recording),
            j.mode,
            j.priority
        ));
    }
    out.push_str("</trc:GetRecordingJobsResponse>");
    out
}

pub fn recording_information(tag: &str, archive: &Archive, r: &Recording) -> String {
    let mut out = format!(
        "<{tag}><tt:RecordingToken>{}</tt:RecordingToken>{}",
        esc(&r.token),
        source_xml(&r.source)
    );
    if let (Some(from), Some(to)) = (r.earliest(), r.latest()) {
        out.push_str(&format!(
            "<tt:EarliestRecording>{}</tt:EarliestRecording><tt:LatestRecording>{}</tt:LatestRecording>",
            wire::format_datetime(from),
            wire::format_datetime(to)
        ));
    }
    out.push_str(&format!("<tt:Content>{}</tt:Content>", esc(&r.content)));
    for t in &r.tracks {
        out.push_str(&format!(
            "<tt:Track><tt:TrackToken>{}</tt:TrackToken><tt:TrackType>{}</tt:TrackType><tt:Description>{}</tt:Description><tt:DataFrom>{}</tt:DataFrom><tt:DataTo>{}</tt:DataTo></tt:Track>",
            esc(&t.token),
            t.kind,
            esc(&t.description),
            wire::format_datetime(t.from),
            wire::format_datetime(t.to)
        ));
    }
    out.push_str(&format!(
        "<tt:RecordingStatus>{}</tt:RecordingStatus></{tag}>",
        archive.status(r)
    ));
    out
}

pub fn recording_summary(archive: &Archive, now: chrono::DateTime<chrono::Utc>) -> String {
    let from = archive
        .recordings
        .iter()
        .filter_map(Recording::earliest)
        .min()
        .unwrap_or(now);
    let until = archive
        .recordings
        .iter()
        .filter_map(Recording::latest)
        .max()
        .unwrap_or(now);
    format!(
        "<tse:GetRecordingSummaryResponse><tse:Summary><tt:DataFrom>{}</tt:DataFrom><tt:DataUntil>{}</tt:DataUntil><tt:NumberRecordings>{}</tt:NumberRecordings></tse:Summary></tse:GetRecordingSummaryResponse>",
        wire::format_datetime(from),
        wire::format_datetime(until),
        archive.recordings.len()
    )
}

/// GetRecordingSearchResults / GetEventSearchResults.
pub fn results(operation: &str, state: &str, page: &[String]) -> String {
    format!(
        "<tse:{operation}Response><tse:ResultList><tt:SearchState>{state}</tt:SearchState>{}</tse:ResultList></tse:{operation}Response>",
        page.concat()
    )
}

pub fn recording_capabilities() -> String {
    format!(
        "<trc:GetServiceCapabilitiesResponse><trc:Capabilities DynamicRecordings=\"true\" DynamicTracks=\"false\" Encoding=\"H264\" MaxRecordings=\"{MAX_RECORDINGS}\" MaxRecordingJobs=\"{MAX_JOBS}\" Options=\"false\" MetadataRecording=\"false\"/></trc:GetServiceCapabilitiesResponse>"
    )
}

pub fn search_capabilities() -> String {
    "<tse:GetServiceCapabilitiesResponse><tse:Capabilities MetadataSearch=\"false\" GeneralStartEvents=\"false\"/></tse:GetServiceCapabilitiesResponse>".into()
}

pub fn replay_capabilities() -> String {
    format!(
        "<trp:GetServiceCapabilitiesResponse><trp:Capabilities ReversePlayback=\"false\" SessionTimeoutRange=\"{} {}\" RTP_RTSP_TCP=\"true\"/></trp:GetServiceCapabilitiesResponse>",
        REPLAY_SESSION_TIMEOUT.as_secs(),
        REPLAY_SESSION_TIMEOUT.as_secs()
    )
}

pub fn replay_configuration() -> String {
    format!(
        "<trp:GetReplayConfigurationResponse><trp:Configuration><tt:SessionTimeout>{}</tt:SessionTimeout></trp:Configuration></trp:GetReplayConfigurationResponse>",
        wire::format_duration(REPLAY_SESSION_TIMEOUT)
    )
}

/// What the model is told about the archive when a client asks to change it.
pub fn summary_json(archive: &Archive) -> Value {
    json!(archive
        .recordings
        .iter()
        .map(
            |r| json!({"token": r.token, "source_id": r.source.source_id, "content": r.content,
                         "tracks": r.tracks.len(), "events": r.events.len()})
        )
        .collect::<Vec<_>>())
}
