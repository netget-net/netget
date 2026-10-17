//! What the model does as an HLS client: read a playlist (master or media), fetch a segment,
//! or play a stream — pick a variant, follow a live playlist as it slides, fetch every segment
//! — and hear what arrived, summarised. Rust owns URL resolution, playlist parsing, reloads
//! and the MPEG-TS analysis.
use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, Parameter, ParameterDefinition, StartupExamples,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::{ConnectContext, EventType};
use crate::state::app_state::AppState;
use anyhow::{bail, ensure, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

pub const GET_PLAYLIST: &str = "hls_get_playlist";
pub const GET_SEGMENT: &str = "hls_get_segment";
pub const PLAY: &str = "hls_play";

#[derive(Default)]
pub struct HlsClientProtocol;
impl HlsClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

fn p(name: &str, kind: &str, description: &str, required: bool) -> Parameter {
    Parameter {
        name: name.into(),
        type_hint: kind.into(),
        description: description.into(),
        required,
    }
}

fn action(
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
        log_template: Some(LogTemplate::new().with_info(format!("-> HLS {name}"))),
    }
}

pub fn actions() -> Vec<ActionDefinition> {
    vec![
        action(
            GET_PLAYLIST,
            "Fetch and parse a playlist: a master playlist lists its variants, a media playlist its segments.",
            vec![p("uri", "string", "Playlist URI, relative to the stream URL or absolute on the same server (default the stream URL)", false)],
            json!({"type": GET_PLAYLIST}),
        ),
        action(
            GET_SEGMENT,
            "Fetch one media segment and report what it holds (container, streams, codecs, duration by timestamps).",
            vec![p("uri", "string", "Segment URI as the media playlist gave it (resolved against the last media playlist)", true)],
            json!({"type": GET_SEGMENT, "uri": "seg00000.ts"}),
        ),
        action(
            PLAY,
            "Play a stream: choose a variant of a master playlist, fetch its segments in order, reload a live playlist as it slides, and report the whole run.",
            vec![
                p("uri", "string", "Master or media playlist URI (default the stream URL)", false),
                p("variant", "string", "For a master playlist: highest or lowest bandwidth, or a variant's index (default highest)", false),
                p("max_segments", "number", "Segments to fetch at most, 1..=100 (default 10)", false),
            ],
            json!({"type": PLAY, "variant": "highest", "max_segments": 10}),
        ),
        action("disconnect", "Stop this HLS client.", vec![], json!({"type": "disconnect"})),
    ]
}

fn event(id: &str, description: &str, params: Vec<Parameter>) -> EventType {
    EventType::new(id, description, json!({"type": PLAY}))
        .with_parameters(params)
        .with_actions(actions())
}

pub static READY_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event(
        "hls_ready",
        "The client is ready to read the stream at url.",
        vec![p("url", "string", "The stream's playlist URL", true)],
    )
});

pub static PLAYLIST_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event("hls_playlist", "A playlist arrived, parsed (or the reason it could not be read).", vec![
        p("url", "string", "The playlist's URL", true),
        p("status", "number", "HTTP status of the answer", false),
        p("kind", "string", "master or media", false),
        p("variants", "array", "Master: [{index, uri, bandwidth, average_bandwidth, resolution, codecs, frame_rate}]", false),
        p("renditions", "array", "Master: alternative renditions [{type, group_id, name, language, uri}]", false),
        p("target_duration", "number", "Media: EXT-X-TARGETDURATION in seconds", false),
        p("media_sequence", "number", "Media: the first segment's sequence number", false),
        p("playlist_type", "string", "Media: VOD or EVENT when declared", false),
        p("endlist", "boolean", "Media: true when the playlist is complete (no more segments will be added)", false),
        p("segments", "array", "Media: the first 50 segments [{sequence, uri, duration, title}]", false),
        p("segment_count", "number", "Media: how many segments the playlist lists", false),
        p("total_duration", "number", "Media: the sum of the segments' EXTINF durations in seconds", false),
        p("encryption", "string", "Media: the EXT-X-KEY METHOD when it is not NONE (segments are then not analysed)", false),
        p("map", "string", "Media: the EXT-X-MAP initialisation section's URI (fMP4)", false),
        p("error", "string", "Why the playlist could not be read", false),
    ])
});

pub static SEGMENT_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event(
        "hls_segment",
        "A segment arrived and was analysed (or the reason it could not be fetched).",
        vec![
            p("url", "string", "The segment's URL", true),
            p("status", "number", "HTTP status of the answer", false),
            p("bytes", "number", "Segment size in bytes", false),
            p(
                "container",
                "string",
                "mpegts, fmp4, packed (an ID3-led audio segment) or unknown",
                false,
            ),
            p("ts_packets", "number", "MPEG-TS: 188-byte packets", false),
            p(
                "streams",
                "array",
                "MPEG-TS: elementary streams from the PMT [{pid, stream_type, codec}]",
                false,
            ),
            p(
                "duration_ms",
                "number",
                "MPEG-TS: media length by presentation timestamps",
                false,
            ),
            p(
                "continuity_errors",
                "number",
                "MPEG-TS: continuity-counter gaps (lost or reordered packets)",
                false,
            ),
            p(
                "sync_errors",
                "number",
                "MPEG-TS: packets without the 0x47 sync byte, or trailing bytes",
                false,
            ),
            p(
                "error",
                "string",
                "Why the segment could not be fetched",
                false,
            ),
        ],
    )
});

pub static PLAYED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event("hls_played", "A play run ended: what was fetched and what it held.", vec![
        p("url", "string", "The playlist the run started from", true),
        p("variant", "object", "The variant chosen from a master playlist {index, uri, bandwidth, resolution, codecs}", false),
        p("media_playlist", "string", "The media playlist played", false),
        p("segments", "number", "Segments fetched", true),
        p("first_sequence", "number", "Media sequence number of the first segment fetched", false),
        p("last_sequence", "number", "Media sequence number of the last segment fetched", false),
        p("gaps", "number", "Sequence numbers a live playlist slid past before they were fetched", true),
        p("reloads", "number", "Times the media playlist was reloaded", true),
        p("endlist", "boolean", "Whether the playlist was complete when the run ended", true),
        p("bytes", "number", "Bytes of media fetched", true),
        p("duration_ms", "number", "Media length by timestamps, summed over segments", true),
        p("playlist_duration", "number", "The fetched segments' EXTINF durations summed, in seconds", true),
        p("containers", "array", "Containers seen", true),
        p("codecs", "array", "Codecs seen across the segments", true),
        p("continuity_errors", "number", "Continuity-counter gaps within segments", true),
        p("failed", "array", "Segments that could not be fetched [{uri, error}]", true),
        p("error", "string", "Why the run stopped early", false),
    ])
});

pub fn check(v: &Value) -> Result<()> {
    let uri = |required: bool| -> Result<()> {
        match v.get("uri").filter(|x| !x.is_null()) {
            Some(u) => {
                let u = u.as_str().unwrap_or_default();
                ensure!(
                    !u.is_empty() && u.len() <= 2048 && !u.contains(['\r', '\n', ' ']),
                    "uri is a URI from a playlist"
                );
            }
            None => ensure!(!required, "uri is required"),
        }
        Ok(())
    };
    match v["type"].as_str().unwrap_or_default() {
        GET_PLAYLIST => uri(false)?,
        GET_SEGMENT => uri(true)?,
        PLAY => {
            uri(false)?;
            if let Some(var) = v.get("variant").filter(|x| !x.is_null()) {
                let ok = match var {
                    Value::String(s) => {
                        matches!(s.as_str(), "highest" | "lowest") || s.parse::<usize>().is_ok()
                    }
                    Value::Number(n) => n.as_u64().is_some(),
                    _ => false,
                };
                ensure!(ok, "variant is highest, lowest or an index");
            }
            if let Some(n) = v.get("max_segments").filter(|x| !x.is_null()) {
                let n = n.as_u64().unwrap_or(0);
                ensure!(
                    (1..=super::MAX_SEGMENTS_PER_PLAY as u64).contains(&n),
                    "max_segments is 1..={}",
                    super::MAX_SEGMENTS_PER_PLAY
                );
            }
        }
        other => bail!("Unknown HLS client action {other:?}"),
    }
    Ok(())
}

impl Protocol for HlsClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "HLS"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>HTTP>HLS"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "hls client",
            "hls",
            "m3u8",
            "http live streaming",
            "hls player",
        ]
    }
    fn description(&self) -> &'static str {
        "HLS client: reads master and media playlists, plays VOD and live streams segment by segment and reports what the media holds"
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        actions()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            READY_EVENT.clone(),
            PLAYLIST_EVENT.clone(),
            SEGMENT_EVENT.clone(),
            PLAYED_EVENT.clone(),
        ]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![ParameterDefinition {
            name: "timeout_secs".into(),
            type_hint: "number".into(),
            description: "Seconds (1..=120) each playlist or segment request may take".into(),
            required: false,
            example: json!(15),
            default: Some(json!(super::TIMEOUT.as_secs())),
        }]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation("Shared http_fetch client (reqwest natively); RFC 8216 playlist parsing (master variants and renditions, media segments, live reloads at the target duration); MPEG-TS analysis of each segment (PAT/PMT streams and codecs, PES timestamps, continuity counters)")
            .llm_control("Which playlist to read, which variant to play, how much of it, and what to make of the media")
            .e2e_testing("tests/client/hls: an ffmpeg-authored VOD stream with a master playlist and two variants, and a live GStreamer hlssink2 stream whose playlist slides while it is played, both served by Python's http.server")
            .notes("Plays by fetching, not by decoding: no decryption (AES-128 segments are reported, not analysed), no fMP4 sample analysis, no LL-HLS partial segments, one origin. A handler chain stops after 8 follow-ups.")
            .max_inbound_bytes(super::MAX_SEGMENT_BYTES)
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Open http://127.0.0.1:8000/master.m3u8, play its best variant for ten segments and tell me what the stream holds"
    }
    fn get_startup_examples(&self) -> StartupExamples {
        let llm = json!({"type":"open_client","protocol":"hls","remote_addr":"http://127.0.0.1:8000/master.m3u8",
            "instruction":"Play the highest variant and report the codecs"});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([
            {"event_pattern":"hls_ready","handler":{"type":"static","actions":[{"type":PLAY,"variant":"highest","max_segments":5}]}},
            {"event_pattern":"hls_played","handler":{"type":"static","actions":[]}}
        ]);
        let mut scripted = llm.clone();
        scripted["event_handlers"] = json!([{"event_pattern":"*","handler":{"type":"script","language":"python",
            "code":"import json,sys\ni=json.load(sys.stdin); t=i['event_type_id']\na=[{'type':'hls_get_playlist'}] if t=='hls_ready' else ([{'type':'hls_play'}] if t=='hls_playlist' and i['event'].get('kind') else [])\nprint(json.dumps({'actions':a}))"}}]);
        StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Web & File"
    }
}

impl Client for HlsClientProtocol {
    fn connect(
        &self,
        ctx: ConnectContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::connect(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ClientActionResult> {
        let name = v["type"].as_str().unwrap_or_default().to_string();
        if name == "disconnect" {
            return Ok(ClientActionResult::Disconnect);
        }
        check(&v)?;
        Ok(ClientActionResult::Custom { name, data: v })
    }
}
