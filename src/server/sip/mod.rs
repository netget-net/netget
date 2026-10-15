//! SIP server implementation
pub mod actions;

use crate::server::connection::ConnectionId;
use anyhow::Result;
use std::net::SocketAddr;
use std::sync::{Arc, LazyLock};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use crate::llm::action_helper::call_llm;
use crate::llm::ollama_client::OllamaClient;
use crate::logging::emit::Log;
use crate::protocol::Event;
use crate::server::SipProtocol;
use crate::state::app_state::AppState;
use actions::{
    SIP_ACK_EVENT, SIP_BYE_EVENT, SIP_CANCEL_EVENT, SIP_INVITE_EVENT, SIP_OPTIONS_EVENT,
    SIP_REGISTER_EVENT,
};

/// SIP server that handles VoIP signaling
pub struct SipServer;

impl SipServer {
    /// Spawn SIP server with integrated LLM actions
    pub async fn spawn_with_llm_actions(
        listen_addr: SocketAddr,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        server_id: crate::state::ServerId,
    ) -> Result<SocketAddr> {
        let socket = Arc::new(UdpSocket::bind(listen_addr).await?);
        let local_addr = socket.local_addr()?;
        Log::new(Some(&status_tx)).info(format!("SIP server listening on {}", local_addr));

        let protocol = Arc::new(SipProtocol::new());

        let task_registrar = app_state.clone();
        let accept_handle = tokio::spawn(async move {
            let mut buffer = vec![0u8; 65535]; // Max UDP packet size
            let log = Log::new(Some(&status_tx));

            loop {
                match socket.recv_from(&mut buffer).await {
                    Ok((n, peer_addr)) => {
                        let data = buffer[..n].to_vec();
                        let connection_id =
                            ConnectionId::new(app_state.get_next_unified_id().await);

                        // Add connection to ServerInstance
                        use crate::state::server::{
                            ConnectionState as ServerConnectionState, ConnectionStatus,
                            ProtocolConnectionInfo,
                        };
                        let now = crate::utils::clock::Instant::now();
                        let conn_state = ServerConnectionState {
                            id: connection_id,
                            remote_addr: peer_addr,
                            local_addr,
                            bytes_sent: 0,
                            bytes_received: n as u64,
                            packets_sent: 0,
                            packets_received: 1,
                            last_activity: now,
                            status: ConnectionStatus::Active,
                            status_changed_at: now,
                            protocol_info: ProtocolConnectionInfo::empty(),
                        };
                        app_state
                            .add_connection_to_server(server_id, conn_state)
                            .await;
                        let _ = status_tx.send("__UPDATE_UI__".to_string());

                        // Summary + full payload FileOnly: the sip_* event templates
                        // render the equivalent line to the TUI.
                        log.debug(format!("SIP received {} bytes from {}", n, peer_addr));
                        if let Ok(text) = String::from_utf8(data.clone()) {
                            let preview = crate::utils::truncate_for_log(&text, 200);
                            log.trace(format!("SIP message: {}", preview));
                        }

                        let llm_clone = llm_client.clone();
                        let state_clone = app_state.clone();
                        let status_clone = status_tx.clone();
                        let socket_clone = socket.clone();
                        let protocol_clone = protocol.clone();

                        // Tracked, not detached: stop_server must abort this task too.
                        let task_owner = app_state.clone();
                        task_owner
                            .spawn_server_task(server_id, async move {
                                let log = Log::new(Some(&status_clone));
                                // Parse SIP message
                                let sip_message = match Self::parse_sip_message(&data) {
                                    Ok(msg) => msg,
                                    Err(e) => {
                                        log.warn(format!(
                                            "SIP failed to parse message from {}: {}",
                                            peer_addr, e
                                        ));
                                        return;
                                    }
                                };

                                // Request summary FileOnly: the sip_* event template renders
                                // the equivalent line to the TUI.
                                log.debug(format!(
                                    "SIP {} request from {} (Call-ID: {})",
                                    sip_message.method, peer_addr, sip_message.call_id
                                ));

                                // Create event based on SIP method
                                let event = Self::create_event(
                                    &sip_message,
                                    peer_addr,
                                    local_addr,
                                    connection_id,
                                );

                                // Call LLM with SIP event
                                match call_llm(
                                    &llm_clone,
                                    &state_clone,
                                    server_id,
                                    Some(connection_id),
                                    &event,
                                    protocol_clone.as_ref(),
                                )
                                .await
                                {
                                    Ok(execution_result) => {
                                        // ACK takes no response at all (RFC 3261 §17), so the
                                        // whole reply path is skipped for it - including the
                                        // no-answer refusal below. Answering an ACK is a protocol
                                        // violation whatever the model said.
                                        if sip_message.method == "ACK" {
                                            log.debug(format!(
                                            "SIP ACK from {} (Call-ID {}) decision=model_answer; \
                                             ACK takes no response",
                                            peer_addr, sip_message.call_id
                                        ));
                                            return;
                                        }

                                        // Pick the action that is actually a SIP response. The model
                                        // may legitimately return a common action (set_memory,
                                        // schedule_task, ...) alongside - or ahead of - its reply, and
                                        // taking `raw_actions.first()` blindly turned that into a
                                        // fabricated status line while the real answer was ignored.
                                        let response_action = execution_result
                                            .raw_actions
                                            .iter()
                                            .find(|a| is_sip_response_action(a));

                                        let Some(action) = response_action else {
                                            // The model was reachable and produced no SIP response.
                                            // That is not an accept: on REGISTER or INVITE, staying
                                            // silent leaves the UAC retransmitting for 32 seconds and
                                            // tells the operator nothing, so refuse explicitly and
                                            // keep the decision distinguishable from a backend
                                            // failure (radius' decision= shape).
                                            log.warn(format!(
                                            "SIP {} from {} (Call-ID {}) decision=model_silent; \
                                             refusing with 500 (the model returned no SIP \
                                             response action)",
                                            sip_message.method, peer_addr, sip_message.call_id
                                        ));
                                            let refusal = Self::build_sip_response(
                                                &sip_message,
                                                &serde_json::json!({
                                                    "status_code": 500,
                                                    "reason_phrase": "Server Internal Error"
                                                }),
                                            );
                                            if let Err(e) =
                                                socket_clone.send_to(&refusal, peer_addr).await
                                            {
                                                log.error(format!(
                                                    "SIP failed to send 500 to {}: {}",
                                                    peer_addr, e
                                                ));
                                            }
                                            return;
                                        };

                                        // An explicit non-2xx is the model refusing, which must stay
                                        // separable in the log from the silence above and from a
                                        // backend outage below.
                                        let decision = match action
                                            .get("status_code")
                                            .and_then(|v| v.as_u64())
                                        {
                                            Some(code) if !(200..300).contains(&code) => {
                                                "model_reject"
                                            }
                                            Some(_) => "model_answer",
                                            // build_sip_response answers 500 for this; naming it
                                            // here keeps "the model forgot a field" apart from
                                            // "the model chose 500".
                                            None => "fail_closed_malformed_action",
                                        };
                                        log.debug(format!(
                                            "SIP {} from {} (Call-ID {}) decision={}",
                                            sip_message.method,
                                            peer_addr,
                                            sip_message.call_id,
                                            decision
                                        ));

                                        // Build SIP response from action JSON
                                        let response =
                                            Self::build_sip_response(&sip_message, action);

                                        // Send SIP response
                                        match socket_clone.send_to(&response, peer_addr).await {
                                            Ok(sent) => {
                                                // Summary FileOnly: the send action template
                                                // already reports the send to the TUI.
                                                log.debug(format!(
                                                    "SIP sent {} byte response to {}",
                                                    sent, peer_addr
                                                ));
                                            }
                                            Err(e) => {
                                                log.error(format!(
                                                    "SIP failed to send response: {}",
                                                    e
                                                ));
                                            }
                                        }

                                        // Media flow: SIP is signaling only, but when built with
                                        // the `rtp` feature and the accept action carries an
                                        // `rtp_audio` description, we honour the SDP we just
                                        // negotiated by streaming real RTP to the caller's
                                        // advertised media address. This is what makes a SIP INVITE
                                        // result in RTP actually arriving, rather than a 200 OK with
                                        // an SDP that points at nothing.
                                        {
                                            // No `unwrap_or(200)`: a missing status_code was answered
                                            // 500 above, and treating it as 200 here would stream
                                            // media for a call that was never accepted.
                                            let status_code = action
                                                .get("status_code")
                                                .and_then(|v| v.as_u64())
                                                .unwrap_or(0);
                                            if sip_message.method == "INVITE" && status_code == 200
                                            {
                                                if let Some(rtp_audio) = action.get("rtp_audio") {
                                                    Self::stream_invite_media(
                                                        sip_message.body.as_deref(),
                                                        peer_addr,
                                                        rtp_audio.clone(),
                                                        status_clone.clone(),
                                                        state_clone.clone(),
                                                        server_id,
                                                    )
                                                    .await;
                                                }
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        // Non-fatal: a 503 (wire fallback) is built and sent
                                        // below for everything except ACK, so this is WARN.
                                        log.warn(format!(
                                            "SIP LLM error for {} from {} (Call-ID {}): {}",
                                            sip_message.method, peer_addr, sip_message.call_id, e
                                        ));

                                        // ACK is the one method that must never be answered
                                        // (RFC 3261 §17: ACK is not a transaction that takes a
                                        // response), so silence is correct there and only there.
                                        if sip_message.method == "ACK" {
                                            log.debug("SIP ACK needs no response; nothing sent");
                                            return;
                                        }

                                        // Everything else gets a 503 Service Unavailable built
                                        // from the request, so the Via/From/To/Call-ID/CSeq match
                                        // and the client's transaction actually completes. Left
                                        // silent, the UAC retransmits on timers A/E and only gives
                                        // up after Timer B/F (32s).
                                        if crate::llm::is_overload_error(&e) {
                                            log.warn(format!(
                                            "SIP 503 to {} (Call-ID {}): LLM capacity exhausted",
                                            peer_addr, sip_message.call_id
                                        ));
                                        }
                                        let response = Self::build_sip_response(
                                            &sip_message,
                                            &serde_json::json!({
                                                "status_code": 503,
                                                "reason_phrase": "Service Unavailable",
                                                "retry_after": 5
                                            }),
                                        );
                                        match socket_clone.send_to(&response, peer_addr).await {
                                            Ok(sent) => {
                                                log.debug(format!(
                                                    "SIP 503 Service Unavailable to {} ({} bytes)",
                                                    peer_addr, sent
                                                ));
                                            }
                                            Err(send_err) => {
                                                log.error(format!(
                                                    "SIP failed to send 503 to {}: {}",
                                                    peer_addr, send_err
                                                ));
                                            }
                                        }
                                    }
                                }
                            })
                            .await;
                    }
                    Err(e) => {
                        log.error(format!("SIP recv error: {}", e));
                    }
                }
            }
        });

        // Register the accept loop so stop_server can abort it and release the port.
        task_registrar
            .register_server_task(server_id, accept_handle)
            .await;

        Ok(local_addr)
    }

    /// Parse SIP message from bytes
    fn parse_sip_message(data: &[u8]) -> Result<SipMessage> {
        let text = String::from_utf8(data.to_vec())?;
        let lines: Vec<&str> = text.lines().collect();

        if lines.is_empty() {
            anyhow::bail!("Empty SIP message");
        }

        // Parse request line (e.g., "REGISTER sip:example.com SIP/2.0")
        let request_line: Vec<&str> = lines[0].split_whitespace().collect();
        if request_line.len() < 3 {
            anyhow::bail!("Invalid SIP request line");
        }

        let method = request_line[0].to_string();
        let request_uri = request_line[1].to_string();

        // Parse headers
        let mut call_id = String::new();
        let mut from = String::new();
        let mut to = String::new();
        let mut via = Vec::new();
        let mut cseq = String::new();
        let mut contact = None;
        let mut expires = None;
        let mut content_type = None;
        let mut content_length = 0;

        let mut i = 1;
        while i < lines.len() {
            let line = lines[i];
            if line.is_empty() {
                // End of headers
                i += 1;
                break;
            }

            if let Some(colon_pos) = line.find(':') {
                let (header_name, header_value) = line.split_at(colon_pos);
                let header_value = header_value[1..].trim();

                match header_name.to_lowercase().as_str() {
                    "call-id" => call_id = header_value.to_string(),
                    "from" | "f" => from = header_value.to_string(),
                    "to" | "t" => to = header_value.to_string(),
                    "via" | "v" => via.push(header_value.to_string()),
                    "cseq" => cseq = header_value.to_string(),
                    "contact" | "m" => contact = Some(header_value.to_string()),
                    "expires" => expires = header_value.parse().ok(),
                    "content-type" | "c" => content_type = Some(header_value.to_string()),
                    "content-length" | "l" => content_length = header_value.parse().unwrap_or(0),
                    _ => {}
                }
            }

            i += 1;
        }

        // Parse body (SDP)
        let mut body = String::new();
        if content_length > 0 && i < lines.len() {
            body = lines[i..].join("\r\n");
        }

        Ok(SipMessage {
            method,
            request_uri,
            call_id,
            from,
            to,
            via,
            cseq,
            contact,
            expires,
            content_type,
            body: if body.is_empty() { None } else { Some(body) },
        })
    }

    /// Create event from SIP message
    fn create_event(
        sip_message: &SipMessage,
        peer_addr: SocketAddr,
        local_addr: SocketAddr,
        connection_id: ConnectionId,
    ) -> Event {
        let base_data = serde_json::json!({
            "peer_addr": peer_addr.to_string(),
            "local_addr": local_addr.to_string(),
            "connection_id": connection_id.to_string(),
            "call_id": sip_message.call_id,
            "from": sip_message.from,
            "to": sip_message.to,
            "cseq": sip_message.cseq,
        });

        match sip_message.method.as_str() {
            "REGISTER" => {
                let mut data = base_data;
                if let Some(contact) = &sip_message.contact {
                    data["contact"] = serde_json::json!(contact);
                }
                if let Some(expires) = sip_message.expires {
                    data["expires"] = serde_json::json!(expires);
                }
                Event {
                    event_type: &SIP_REGISTER_EVENT,
                    data,
                }
            }
            "INVITE" => {
                let mut data = base_data;
                if let Some(body) = &sip_message.body {
                    data["sdp"] = serde_json::json!(body);
                }
                Event {
                    event_type: &SIP_INVITE_EVENT,
                    data,
                }
            }
            "BYE" => Event {
                event_type: &SIP_BYE_EVENT,
                data: base_data,
            },
            "ACK" => Event {
                event_type: &SIP_ACK_EVENT,
                data: base_data,
            },
            "OPTIONS" => {
                let mut data = base_data;
                data["answer_with"] = serde_json::json!(actions::OPTIONS_ANSWER_WITH);
                Event {
                    event_type: &SIP_OPTIONS_EVENT,
                    data,
                }
            }
            "CANCEL" => Event {
                event_type: &SIP_CANCEL_EVENT,
                data: base_data,
            },
            _ => {
                // Unknown method, treat as OPTIONS event
                Event {
                    event_type: &SIP_OPTIONS_EVENT,
                    data: base_data,
                }
            }
        }
    }

    /// Build SIP response from action JSON
    fn build_sip_response(request: &SipMessage, response_action: &serde_json::Value) -> Vec<u8> {
        // A non-object action used to `.expect(...)` here. That is a panic reachable from the
        // wire - the model's own output, inside a `tokio::spawn` that swallows the panic - so
        // the peer got silence, the log got nothing, and the server went on reporting Running.
        // An empty object routes into the missing-status_code branch below, which is the same
        // fail-closed 500 a malformed action deserves.
        static EMPTY: LazyLock<serde_json::Map<String, serde_json::Value>> =
            LazyLock::new(serde_json::Map::new);
        let response_data = match response_action.as_object() {
            Some(obj) => obj,
            None => {
                tracing::warn!(
                    "SIP action was not a JSON object ({}); answering 500",
                    crate::utils::truncate_for_log(&response_action.to_string(), 120)
                );
                &EMPTY
            }
        };
        // A missing `status_code` is a malformed action, not a decision, so it must not
        // become 200. On REGISTER a defaulted 200 is an accepted registration and on INVITE
        // an accepted call - granted because a field was forgotten. SIP has no default
        // status, so the honest answer is the server's own 500; the model's actual choices
        // (401, 403, 486) are unaffected because they name the field.
        let (status_code, default_reason) =
            match response_data.get("status_code").and_then(|v| v.as_u64()) {
                Some(code) => (code as u16, actions::default_reason_phrase(code as u16)),
                None => {
                    tracing::warn!(
                        "SIP action carried no status_code; answering 500 rather than defaulting \
                     to 200, which would accept the request"
                    );
                    (500u16, "Server Internal Error")
                }
            };

        let reason_phrase = response_data
            .get("reason_phrase")
            .and_then(|v| v.as_str())
            .unwrap_or(default_reason);

        // Build status line
        let mut response = format!("SIP/2.0 {} {}\r\n", status_code, reason_phrase);

        // Add Via headers (copy from request)
        for via in &request.via {
            response.push_str(&format!("Via: {}\r\n", via));
        }

        // Add From header (copy from request)
        response.push_str(&format!("From: {}\r\n", request.from));

        // Add To header (copy from request, add tag if not present)
        let to_header = if request.to.contains(";tag=") {
            request.to.clone()
        } else {
            // Generate a tag for the response
            format!("{};tag={}", request.to, Self::generate_tag())
        };
        response.push_str(&format!("To: {}\r\n", to_header));

        // Add Call-ID header (copy from request)
        response.push_str(&format!("Call-ID: {}\r\n", request.call_id));

        // Add CSeq header (copy from request)
        response.push_str(&format!("CSeq: {}\r\n", request.cseq));

        // Add Contact header for successful REGISTER
        if request.method == "REGISTER" && status_code == 200 {
            if let Some(contact) = &request.contact {
                response.push_str(&format!("Contact: {}\r\n", contact));
            }
        }

        // Add Expires header for REGISTER responses
        if request.method == "REGISTER" {
            let expires = response_data
                .get("expires")
                .and_then(|v| v.as_u64())
                .unwrap_or(3600);
            response.push_str(&format!("Expires: {}\r\n", expires));
        }

        // Add Retry-After when the action asks for one. RFC 3261 §20.33: a 503 SHOULD
        // carry it, so the caller retries after a bounded wait instead of failing over
        // to another proxy or giving up on the URI entirely.
        if let Some(retry_after) = response_data.get("retry_after").and_then(|v| v.as_u64()) {
            response.push_str(&format!("Retry-After: {}\r\n", retry_after));
        }

        // Add Allow header for OPTIONS responses
        if request.method == "OPTIONS" {
            if let Some(allow_methods) = response_data.get("allow_methods") {
                if let Some(methods) = allow_methods.as_array() {
                    let methods_str: Vec<String> = methods
                        .iter()
                        .filter_map(|v| v.as_str())
                        .map(String::from)
                        .collect();
                    response.push_str(&format!("Allow: {}\r\n", methods_str.join(", ")));
                }
            }
        }

        // Add body (SDP) for successful INVITE responses
        let body = if request.method == "INVITE" && status_code == 200 {
            response_data
                .get("sdp")
                .and_then(|v| v.as_str())
                .map(String::from)
        } else {
            None
        };

        // Add Content-Length and body
        if let Some(body_text) = &body {
            response.push_str("Content-Type: application/sdp\r\n");
            response.push_str(&format!("Content-Length: {}\r\n", body_text.len()));
            response.push_str("\r\n");
            response.push_str(body_text);
        } else {
            response.push_str("Content-Length: 0\r\n");
            response.push_str("\r\n");
        }

        response.into_bytes()
    }

    /// Generate a random tag for SIP responses
    fn generate_tag() -> String {
        use rand::Rng;
        let tag: u32 = rand::thread_rng().gen();
        format!("{:x}", tag)
    }

    /// Stream RTP audio to the media address the caller advertised in its INVITE SDP.
    ///
    /// Only compiled with the `rtp` feature. The `rtp_audio` value is the same structured media
    /// description the RTP protocol understands (`content`, `tone_hz`, `payload_type`,
    /// `duration_ms`) — the model describes what the call carries, and the shared media engine
    /// (`crate::server::rtp::media`) owns the samples and RTP framing. A fresh ephemeral UDP
    /// socket is used because RTP must not share the SIP signaling port.
    async fn stream_invite_media(
        caller_sdp: Option<&str>,
        caller_addr: SocketAddr,
        rtp_audio: serde_json::Value,
        status_tx: mpsc::UnboundedSender<String>,
        app_state: Arc<AppState>,
        server_id: crate::state::ServerId,
    ) {
        use crate::server::rtp::media::{self, AudioCodec, RtpPacketizer};

        let Some((ip, port)) = caller_sdp.and_then(parse_sdp_audio_target) else {
            Log::new(Some(&status_tx)).warn(
                "SIP INVITE had rtp_audio but no parseable m=audio target in the caller's SDP",
            );
            return;
        };

        // Refuse to stream anywhere but the source of the INVITE. SIP runs on UDP, so the
        // source address is trivially spoofable and the SDP body names its own destination: an
        // attacker who sends one 400-byte INVITE claiming `c=IN IP4 <victim>` would otherwise
        // have NetGet blast seconds of G.711 at a third party it never heard from. Sending only
        // to the address that actually spoke to us makes the media path unamplifiable, and the
        // legitimate case is unaffected because a real UAC advertises its own address.
        if ip != caller_addr.ip() {
            Log::new(Some(&status_tx)).warn(format!(
                "SIP INVITE decision=refused_media_redirect: SDP asks for media at {} but the \
                 INVITE came from {}; refusing to stream RTP to a third party",
                ip,
                caller_addr.ip()
            ));
            return;
        }
        let target = std::net::SocketAddr::new(ip, port);

        let codec = rtp_audio
            .get("payload_type")
            .and_then(|v| v.as_str())
            .map(AudioCodec::parse)
            .unwrap_or(Ok(AudioCodec::Pcmu))
            .unwrap_or(AudioCodec::Pcmu);
        let content = media::parse_audio_content(&rtp_audio)
            .unwrap_or(media::AudioContent::Tone { hz: 440.0 });
        let duration_ms = rtp_audio
            .get("duration_ms")
            .and_then(|v| v.as_u64())
            .unwrap_or(2000);

        // Tracked, not detached: stop_server must abort this task too.
        let task_owner = app_state.clone();
        task_owner
            .spawn_server_task(server_id, async move {
                let log = Log::new(Some(&status_tx));
                let socket = match tokio::net::UdpSocket::bind(std::net::SocketAddr::from((
                    [0u8, 0, 0, 0],
                    0,
                )))
                .await
                {
                    Ok(s) => s,
                    Err(e) => {
                        log.error(format!("SIP RTP socket bind failed: {}", e));
                        return;
                    }
                };
                let payload = match media::synthesize(codec, &content, duration_ms) {
                    Ok(p) => p,
                    Err(e) => {
                        log.warn(format!("SIP RTP synthesis: {}", e));
                        return;
                    }
                };
                let mut packetizer =
                    RtpPacketizer::new(rand::random(), codec.payload_type(), None, None);
                let packets = packetizer.packetize(&payload, media::G711_SAMPLES_PER_FRAME);
                let mut sent = 0u64;
                for pkt in &packets {
                    if socket.send_to(pkt, target).await.is_err() {
                        break;
                    }
                    sent += 1;
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                }
                log.info(format!(
                    "SIP call media: {} RTP {} packet(s) to {}",
                    sent,
                    codec.rtpmap_name(),
                    target
                ));
            })
            .await;
    }
}

/// True if this action is one of the six SIP response verbs, i.e. something
/// [`SipServer::build_sip_response`] can turn into a status line.
///
/// The reply path selects on this rather than taking the first action the model returned: a
/// common action (`set_memory`, `schedule_task`, …) returned alongside the reply is executed by
/// the shared executor and must not be mistaken for one.
fn is_sip_response_action(action: &serde_json::Value) -> bool {
    matches!(
        action.get("type").and_then(|v| v.as_str()),
        Some("sip_register" | "sip_invite" | "sip_bye" | "sip_ack" | "sip_options" | "sip_cancel")
    )
}

/// Extract the media target (connection IP + audio port) from an SDP offer.
///
/// Reads the `c=IN IP4 <ip>` connection line and the first `m=audio <port> ...` line. Returns
/// None if either is missing or unparseable.
fn parse_sdp_audio_target(sdp: &str) -> Option<(std::net::IpAddr, u16)> {
    let mut ip: Option<std::net::IpAddr> = None;
    let mut port: Option<u16> = None;
    for line in sdp.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("c=IN IP4 ") {
            ip = rest
                .trim()
                .split('/')
                .next()
                .and_then(|s| s.trim().parse().ok());
        } else if let Some(rest) = line.strip_prefix("m=audio ") {
            port = rest.split_whitespace().next().and_then(|s| s.parse().ok());
        }
    }
    Some((ip?, port?))
}

/// Parsed SIP message
#[derive(Debug, Clone)]
struct SipMessage {
    method: String,
    #[allow(dead_code)]
    request_uri: String,
    call_id: String,
    from: String,
    to: String,
    via: Vec<String>,
    cseq: String,
    contact: Option<String>,
    expires: Option<u32>,
    #[allow(dead_code)]
    content_type: Option<String>,
    body: Option<String>,
}
