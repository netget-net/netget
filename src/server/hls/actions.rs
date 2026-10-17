//! HLS protocol actions.
//!
//! The model decides the playlist (structurally or as verbatim m3u8) and each segment's content.
//! HTTP framing is owned by `mod.rs`.

use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::EventType;
use crate::state::app_state::AppState;
use anyhow::{Context, Result};
use serde_json::json;
use std::sync::LazyLock;

pub struct HlsProtocol;

impl HlsProtocol {
    pub fn new() -> Self {
        Self
    }
}

impl Default for HlsProtocol {
    fn default() -> Self {
        Self::new()
    }
}

impl Protocol for HlsProtocol {
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            hls_playlist_response_action(),
            hls_segment_response_action(),
        ]
    }
    fn protocol_name(&self) -> &'static str {
        "HLS"
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![HLS_PLAYLIST_EVENT.clone(), HLS_SEGMENT_EVENT.clone()]
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>HTTP>HLS"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["hls", "http live streaming", "m3u8 playlist", "hls segment"]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            // The request head is all an HLS peer sends that is read; a declared body is
            // refused with 413 unread. Tested in tests/server/hls/inbound_limit_test.rs.
            .max_inbound_bytes(crate::server::hls::MAX_REQUEST_HEAD_BYTES)
            .implementation(
                "Minimal HTTP/1.1 server routing .m3u8 vs segment requests to distinct events; \
                 playlists assembled from structured segment lists or served verbatim",
            )
            .llm_control(
                "The playlist (variants/segment list) and every segment's body (text, or \
                 hex-encoded binary the server decodes)",
            )
            .e2e_testing(
                "curl fetches m3u8 then segments; byte-literal assertions on #EXTM3U structure and \
                 Content-Type (mock LLM)",
            )
            .notes(
                "The server does NOT synthesize MPEG-TS. curl and the m3u8 structure validate fully; \
                 a real media player (ffplay/VLC) needs valid segment bytes, which the model must \
                 supply hex-encoded (e.g. a real .ts). Text segment bodies are for structural tests, \
                 not playback.",
            )
            .request_only("HLS is HTTP request/response; a server cannot send a peer anything unprompted")
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "HLS server serving an m3u8 playlist and media segments over HTTP"
    }
    fn example_prompt(&self) -> &'static str {
        "Start an HLS server on port 8080 serving a 3-segment VOD playlist at /stream.m3u8."
    }
    fn group_name(&self) -> &'static str {
        "Web & File"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;

        // Deterministic: serve a fixed single-segment VOD playlist for every
        // request, no LLM call.
        let script = r##"import json, sys
data = json.load(sys.stdin)
event = data["event"]
if data["event_type_id"] == "hls_playlist_request":
    actions = [{"type": "hls_playlist_response",
                "playlist": "#EXTM3U\n#EXT-X-VERSION:3\n#EXT-X-TARGETDURATION:10\n#EXT-X-MEDIA-SEQUENCE:0\n#EXTINF:10.0,\nsegment0.ts\n#EXT-X-ENDLIST\n"}]
else:
    actions = []
print(json.dumps({"actions": actions}))"##;

        StartupExamples::new(
            json!({
                "type": "open_server",
                "port": 8080,
                "base_stack": "hls",
                "instruction": "Serve an HLS VOD playlist at /stream.m3u8 listing 3 segments (seg0.ts, seg1.ts, seg2.ts), each 6 seconds. For each segment request, return a short text placeholder body."
            }),
            json!({
                "type": "open_server",
                "port": 8080,
                "base_stack": "hls",
                "event_handlers": [{
                    "event_pattern": "hls_playlist_request",
                    "handler": {"type": "script", "language": "python", "code": script}
                }]
            }),
            json!({
                "type": "open_server",
                "port": 8080,
                "base_stack": "hls",
                "event_handlers": [{
                    "event_pattern": "hls_playlist_request",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "hls_playlist_response",
                            "target_duration": 6,
                            "segments": [
                                {"uri": "seg0.ts", "duration": 6.0},
                                {"uri": "seg1.ts", "duration": 6.0}
                            ]
                        }]
                    }
                }]
            }),
        )
    }
}

impl Server for HlsProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::server::hls::HlsServer;
            HlsServer::spawn_with_llm_actions(
                ctx.legacy_listen_addr(),
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.server_id,
            )
            .await
        })
    }

    fn execute_action(&self, action: serde_json::Value) -> Result<ActionResult> {
        // HTTP framing happens in mod.rs from the raw action; validate the type here.
        let action_type = action
            .get("type")
            .and_then(|v| v.as_str())
            .context("Missing 'type' field in action")?;
        match action_type {
            "hls_playlist_response" | "hls_segment_response" => Ok(ActionResult::NoAction),
            _ => Err(anyhow::anyhow!("Unknown HLS action: {}", action_type)),
        }
    }
}

pub static HLS_PLAYLIST_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "hls_playlist_request",
        "A client requested an .m3u8 playlist. Answer with hls_playlist_response, either giving a \
         verbatim `playlist` string or a structured `segments` list the server renders into a \
         valid media playlist.",
        json!({
            "type": "hls_playlist_response",
            "target_duration": 6,
            "segments": [
                {"uri": "seg0.ts", "duration": 6.0},
                {"uri": "seg1.ts", "duration": 6.0}
            ]
        }),
    )
    .with_actions(vec![hls_playlist_response_action()])
    .with_log_template(
        LogTemplate::new()
            .with_info("HLS playlist {path}")
            .with_debug("HLS playlist request {path}")
            .with_trace("HLS: {json_pretty(.)}"),
    )
});

pub static HLS_SEGMENT_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "hls_segment_request",
        "A client requested a media segment (any non-.m3u8 path). Answer with hls_segment_response \
         carrying the segment body — text via `content`, or binary via `data` with encoding=\"hex\".",
        json!({
            "type": "hls_segment_response",
            "content_type": "video/mp2t",
            "content": "<segment placeholder bytes>"
        }),
    )
    .with_actions(vec![hls_segment_response_action()])
    .with_log_template(
        LogTemplate::new()
            .with_info("HLS segment {path}")
            .with_debug("HLS segment request {path}")
            .with_trace("HLS: {json_pretty(.)}"),
    )
});

fn hls_playlist_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "hls_playlist_response".to_string(),
        description: "Serve an HLS .m3u8 playlist. Provide either `playlist` (verbatim m3u8) or \
                      `segments` (structured; the server assembles the playlist)."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "playlist".to_string(),
                type_hint: "string".to_string(),
                description: "Verbatim m3u8 text (starts with #EXTM3U). Overrides `segments`."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "segments".to_string(),
                type_hint: "array".to_string(),
                description: "Array of {uri, duration} objects the server renders into a media \
                              playlist."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "target_duration".to_string(),
                type_hint: "number".to_string(),
                description: "EXT-X-TARGETDURATION seconds. Defaults to the ceil of the longest \
                              segment."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "version".to_string(),
                type_hint: "number".to_string(),
                description: "EXT-X-VERSION (default 3).".to_string(),
                required: false,
            },
            Parameter {
                name: "media_sequence".to_string(),
                type_hint: "number".to_string(),
                description: "EXT-X-MEDIA-SEQUENCE (default 0).".to_string(),
                required: false,
            },
            Parameter {
                name: "ended".to_string(),
                type_hint: "boolean".to_string(),
                description: "Whether to append #EXT-X-ENDLIST (VOD). Default true.".to_string(),
                required: false,
            },
            Parameter {
                name: "status_code".to_string(),
                type_hint: "number".to_string(),
                description: "HTTP status code (default 200).".to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "hls_playlist_response",
            "target_duration": 6,
            "version": 3,
            "segments": [
                {"uri": "seg0.ts", "duration": 6.0},
                {"uri": "seg1.ts", "duration": 6.0},
                {"uri": "seg2.ts", "duration": 4.5}
            ]
        }),
        log_template: Some(LogTemplate::new().with_info("→ HLS playlist {status_code}")),
    }
}

fn hls_segment_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "hls_segment_response".to_string(),
        description: "Serve an HLS media segment body.".to_string(),
        parameters: vec![
            Parameter {
                name: "content".to_string(),
                type_hint: "string".to_string(),
                description: "Segment body as UTF-8 text (for structural/placeholder use)."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "data".to_string(),
                type_hint: "string".to_string(),
                description: "Segment body as binary. Pair with encoding=\"hex\"; the server \
                              hex-decodes it for real (the only sanctioned base-N path, for genuine \
                              MPEG-TS bytes)."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "encoding".to_string(),
                type_hint: "string".to_string(),
                description: "\"utf8\" (default) or \"hex\" — declares how `data` is encoded. Never \
                              sniffed."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "content_type".to_string(),
                type_hint: "string".to_string(),
                description: "MIME type (default video/mp2t; use video/iso.segment for fMP4)."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "status_code".to_string(),
                type_hint: "number".to_string(),
                description: "HTTP status code (default 200; use 404 to reject).".to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "hls_segment_response",
            "content_type": "video/mp2t",
            "encoding": "hex",
            "data": "474000100000b00d0001c100000001f0002ab104b2"
        }),
        log_template: Some(LogTemplate::new().with_info("→ HLS segment {status_code}")),
    }
}
