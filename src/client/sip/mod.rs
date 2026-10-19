//! SIP client implementation
pub mod actions;

pub use actions::SipClientProtocol;

use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex};
use tracing::{error, info, trace, warn};

use crate::client::llm_budget::call_llm_for_client;
use crate::client::sip::actions::{SIP_CLIENT_CONNECTED_EVENT, SIP_CLIENT_RESPONSE_RECEIVED_EVENT};
use crate::llm::ollama_client::OllamaClient;
use crate::llm::ClientLlmResult;
use crate::protocol::Event;
use crate::state::app_state::AppState;
use crate::state::client_handles::{ClientCommand, ClientSendOutcome};
use crate::state::{AccessLogOwner, ClientId, ClientStatus};

/// Per-client data for LLM handling.
///
/// There used to be an `Idle`/`Processing`/`Accumulating` machine and a `queued_data` buffer
/// here, copied from the server side. Nothing could reach the queue: the read loop is one
/// sequential task that calls the model inline, so the state was always `Idle` when a datagram
/// was examined and the `Processing` arm that appended to `queued_data` never ran. Had it run,
/// the drain would have glued every queued datagram into one buffer and parsed it as a single
/// response, delivering the first and dropping the rest. What arrives during a model call
/// waits in the socket's receive buffer instead, one datagram per response, and the loop reads
/// each in turn when the call returns; `tests/client/sip/queued_response_test.rs` pins that.
struct ClientData {
    memory: String,
    call_id: Option<String>,
    from_tag: Option<String>,
    to_tag: Option<String>,
    cseq: u32,
    /// This socket's own address, for Via and Contact. Held here because
    /// `execute_sip_action` is reached from three places (connect, read loop, injected
    /// command) and all three already take the `ClientData` lock to build a request.
    local_addr: SocketAddr,
}

/// SIP client that connects to a remote SIP server
pub struct SipClient;

impl SipClient {
    /// Connect to a SIP server with integrated LLM actions
    pub async fn connect_with_llm_actions(
        remote_addr: String,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        client_id: ClientId,
    ) -> Result<SocketAddr> {
        // Parse remote address
        let remote_sock_addr: SocketAddr = remote_addr
            .parse()
            .context(format!("Invalid SIP server address: {}", remote_addr))?;

        // Bind to local UDP socket (ephemeral port)
        let socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);

        // Connect UDP socket to remote address
        socket.connect(remote_sock_addr).await?;

        // Read the local address *after* connect. Before it, the socket is bound to
        // 0.0.0.0 and `local_addr()` says so; after it, the kernel has picked the outbound
        // interface and reports the address a peer would actually see. This is the address
        // that goes in Via and Contact, so taking it a line too early put a wildcard on the
        // wire.
        let local_addr = socket.local_addr()?;

        info!(
            "SIP client {} connected to {} (local: {})",
            client_id, remote_sock_addr, local_addr
        );

        // Update client state
        app_state
            .update_client_status(client_id, ClientStatus::Connected)
            .await;
        let _ = status_tx.send(format!("[CLIENT] SIP client {} connected", client_id));
        let _ = status_tx.send("__UPDATE_UI__".to_string());

        // Initialize client data
        let client_data = Arc::new(Mutex::new(ClientData {
            memory: String::new(),
            call_id: None,
            from_tag: None,
            to_tag: None,
            cseq: 1,
            local_addr,
        }));

        // Call LLM with initial connected event
        let protocol = Arc::new(crate::client::sip::actions::SipClientProtocol::new());
        let event = Event::new(
            &SIP_CLIENT_CONNECTED_EVENT,
            serde_json::json!({
                "remote_addr": remote_sock_addr.to_string(),
                "local_addr": local_addr.to_string(),
            }),
        );

        // Command channel for injected actions (the dashboard's [ send ]).
        // Registered BEFORE the connected-event LLM call: a manual `*` routing rule can
        // park that call for minutes, and the operator must be able to reach the client
        // while it waits. `recv` is cancellation-safe, so a `select!` arm in the read loop
        // would also be sound - but the read loop can sit inside a multi-minute LLM call,
        // and injected commands must not queue behind it. Hence a separate task; the UDP
        // socket is an `Arc<UdpSocket>` and `send` takes `&self`, so both tasks can write.
        let command_rx =
            crate::client::command_support::register_command_channel(&app_state, client_id).await;
        let cmd_task = tokio::spawn(Self::command_loop(
            command_rx,
            socket.clone(),
            protocol.clone(),
            client_data.clone(),
            client_id,
            app_state.clone(),
            status_tx.clone(),
        ));
        app_state.register_client_task(client_id, cmd_task).await;

        if let Some(instruction) = app_state.get_instruction_for_client(client_id).await {
            // Copy the memory out and drop the guard: passing `&guard.memory` straight into the
            // call would hold the mutex for the whole LLM round-trip, and an injected command
            // (which needs the same mutex for the Call-ID / tag / CSeq state) would queue behind
            // it - defeating the point of running the command loop as its own task.
            let memory = client_data.lock().await.memory.clone();
            match call_llm_for_client(
                &llm_client,
                &app_state,
                client_id.to_string(),
                &instruction,
                &memory,
                Some(&event),
                protocol.as_ref(),
                &status_tx,
            )
            .await
            {
                Ok(ClientLlmResult {
                    actions,
                    memory_updates,
                }) => {
                    // Update memory
                    if let Some(mem) = memory_updates {
                        client_data.lock().await.memory = mem;
                    }

                    // Execute initial actions (e.g., REGISTER)
                    for action in actions {
                        if let Err(e) = Self::execute_sip_action(
                            action,
                            &socket,
                            &protocol,
                            &client_data,
                            client_id,
                            &status_tx,
                        )
                        .await
                        {
                            error!("SIP client {} send error: {}", client_id, e);
                        }
                    }
                }
                Err(e) => {
                    error!("LLM error for SIP client {}: {}", client_id, e);
                }
            }
        }

        // Spawn read loop
        let socket_clone = socket.clone();
        let llm_clone = llm_client.clone();
        let state_clone = app_state.clone();
        let status_clone = status_tx.clone();
        let protocol_clone = protocol.clone();
        let client_data_clone = client_data.clone();

        // Registered with AppState so stop_client can abort this task —
        // dropping a JoinHandle only detaches it in Tokio.
        let task_registrar = app_state.clone();
        let task_handle = tokio::spawn(async move {
            let mut buffer = vec![0u8; 65535]; // Max UDP packet size

            loop {
                match socket_clone.recv(&mut buffer).await {
                    Ok(n) => {
                        trace!("SIP client {} received {} bytes", client_id, n);
                        Self::handle_datagram(
                            &buffer[..n],
                            &llm_clone,
                            &state_clone,
                            &socket_clone,
                            &protocol_clone,
                            &client_data_clone,
                            client_id,
                            &status_clone,
                        )
                        .await;
                    }
                    Err(e) => {
                        error!("SIP client {} recv error: {}", client_id, e);
                        state_clone
                            .update_client_status(client_id, ClientStatus::Error(e.to_string()))
                            .await;
                        let _ = status_clone
                            .send(format!("[CLIENT] SIP client {} error: {}", client_id, e));
                        let _ = status_clone.send("__UPDATE_UI__".to_string());
                        break;
                    }
                }
            }
            // Every exit path lands here: drop the command handle so the dashboard stops
            // offering [ send ] on a dead client. This also closes the command channel,
            // which ends `command_loop`.
            state_clone.remove_client_handle(client_id).await;
            let _ = status_clone.send("__UPDATE_UI__".to_string());
        });
        task_registrar
            .register_client_task(client_id, task_handle)
            .await;

        Ok(local_addr)
    }

    /// Handle one datagram from the server: a final response is acknowledged (when it is an
    /// INVITE's 200) and then put to the model; anything else is logged and dropped.
    ///
    /// The ACK goes out *before* the model is asked. RFC 3261 owes it to the 200 regardless of
    /// what the model decides, and sending it afterwards built it from the dialog's CSeq after
    /// the model's own requests had advanced it, so an answer such as BYE gave the ACK the BYE's
    /// sequence number. It now carries the number from the response's own CSeq.
    #[allow(clippy::too_many_arguments)]
    async fn handle_datagram(
        data: &[u8],
        llm_client: &OllamaClient,
        app_state: &Arc<AppState>,
        socket: &Arc<UdpSocket>,
        protocol: &Arc<SipClientProtocol>,
        client_data: &Arc<Mutex<ClientData>>,
        client_id: ClientId,
        status_tx: &mpsc::UnboundedSender<String>,
    ) {
        let response = match Self::parse_sip_response(data) {
            Ok(resp) => resp,
            Err(e) => {
                warn!("SIP client {} failed to parse response: {}", client_id, e);
                return;
            }
        };

        info!(
            "SIP client {} received {} response (status: {})",
            client_id, response.method, response.status_code
        );

        // Provisional responses (1xx) are reported without a model call.
        if response.status_code >= 100 && response.status_code < 200 {
            info!(
                "SIP client {} received provisional response {} {}, skipping LLM",
                client_id, response.status_code, response.reason_phrase
            );
            let _ = status_tx.send(format!(
                "[CLIENT] SIP {} response: {} {}",
                client_id, response.status_code, response.reason_phrase
            ));
            return;
        }

        if let Some(to_tag) = &response.to_tag {
            client_data.lock().await.to_tag = Some(to_tag.clone());
        }

        // Send automatic ACK for 200 OK response to INVITE (RFC 3261)
        if response.method == "INVITE" && response.status_code == 200 {
            info!(
                "SIP client {} sending automatic ACK for INVITE 200 OK",
                client_id
            );

            // Both of these were `.unwrap()`, and both are `None` until this client has itself
            // sent a request. A datagram whose CSeq says `INVITE` and whose status line says
            // 200 — which any peer can send unprompted — therefore panicked the read loop,
            // inside a `tokio::spawn` that swallows the panic: the client stayed "Connected"
            // and went permanently deaf. There is no dialog to acknowledge in that case, so the
            // honest answer is to log it and send nothing.
            let ack = {
                let d = client_data.lock().await;
                match (d.call_id.as_ref(), d.from_tag.as_ref()) {
                    (Some(call_id), Some(from_tag)) => {
                        // The INVITE's own sequence number, from the response. The saturating
                        // fallback is for a CSeq without one; `cseq` is unsigned and nothing
                        // guarantees a request preceded this.
                        let cseq = response
                            .cseq
                            .split_whitespace()
                            .next()
                            .and_then(|n| n.parse::<u32>().ok())
                            .unwrap_or_else(|| d.cseq.saturating_sub(1));
                        Some(Self::build_ack_request(
                            &response,
                            call_id,
                            from_tag,
                            cseq,
                            d.local_addr,
                        ))
                    }
                    _ => None,
                }
            };
            match ack {
                None => warn!(
                    "SIP client {} got an INVITE 200 OK with no local dialog (no Call-ID or From                      tag yet); this client sent no INVITE, so no ACK is owed",
                    client_id
                ),
                Some(ack_request) => match socket.send(&ack_request).await {
                    Ok(sent) => {
                        info!("SIP client {} sent ACK ({} bytes)", client_id, sent);
                        let _ =
                            status_tx.send(format!("[CLIENT] SIP client {} sent ACK", client_id));
                    }
                    Err(e) => {
                        error!("SIP client {} ACK send error: {}", client_id, e);
                    }
                },
            }
        }

        let Some(instruction) = app_state.get_instruction_for_client(client_id).await else {
            return;
        };
        let event = Event::new(
            &SIP_CLIENT_RESPONSE_RECEIVED_EVENT,
            serde_json::json!({
                "status_code": response.status_code,
                "reason_phrase": response.reason_phrase,
                "method": response.method,
                "call_id": response.call_id,
                "from": response.from,
                "to": response.to,
                "body": response.body,
            }),
        );

        // Copied out so the mutex is not held across the LLM round-trip (see the connect path).
        let memory = client_data.lock().await.memory.clone();
        match call_llm_for_client(
            llm_client,
            app_state,
            client_id.to_string(),
            &instruction,
            &memory,
            Some(&event),
            protocol.as_ref(),
            status_tx,
        )
        .await
        {
            Ok(ClientLlmResult {
                actions,
                memory_updates,
            }) => {
                if let Some(mem) = memory_updates {
                    client_data.lock().await.memory = mem;
                }
                for action in actions {
                    if let Err(e) = Self::execute_sip_action(
                        action,
                        socket,
                        protocol,
                        client_data,
                        client_id,
                        status_tx,
                    )
                    .await
                    {
                        error!("SIP client {} send error: {}", client_id, e);
                    }
                }
            }
            Err(e) => {
                error!("LLM error for SIP client {}: {}", client_id, e);
            }
        }
    }

    /// Drain injected commands until the channel closes (client removed, or the read loop
    /// exited and dropped the handle) or an injected `disconnect` ends the session.
    ///
    /// The generic `command_support::handle_stream_client_command` cannot run this client's
    /// vocabulary - every SIP verb yields `ClientActionResult::Custom` and the request line,
    /// Call-ID, tags and CSeq come from per-client state - so the action goes through
    /// [`Self::execute_sip_action`], the same function the LLM path uses, and the outcome is
    /// recorded and replied exactly the way the generic arm does it.
    async fn command_loop(
        mut command_rx: mpsc::Receiver<ClientCommand>,
        socket: Arc<UdpSocket>,
        protocol: Arc<SipClientProtocol>,
        client_data: Arc<Mutex<ClientData>>,
        client_id: ClientId,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
    ) {
        use crate::llm::actions::protocol_trait::Protocol;

        while let Some(command) = command_rx.recv().await {
            let action = command.action.clone();
            let outcome = Self::execute_sip_action(
                action.clone(),
                &socket,
                &protocol,
                &client_data,
                client_id,
                &status_tx,
            )
            .await;

            let outcome_json = match &outcome {
                Ok(outcome) => serde_json::to_value(outcome).unwrap_or(serde_json::Value::Null),
                Err(e) => serde_json::json!({"error": e.to_string()}),
            };
            app_state
                .record_access_log(
                    AccessLogOwner::Client(client_id.as_u32()),
                    protocol.protocol_name(),
                    None,
                    "injected_action",
                    action,
                    vec![outcome_json],
                )
                .await;

            let disconnect = matches!(outcome, Ok(ClientSendOutcome::Disconnected));
            if let Err(e) = &outcome {
                error!("SIP client {} injected action failed: {}", client_id, e);
                let _ = status_tx.send(format!(
                    "[WARN] Client {} injected action failed: {}",
                    client_id, e
                ));
            }
            let _ = status_tx.send("__UPDATE_UI__".to_string());
            crate::client::command_support::reply(command, outcome);

            if disconnect {
                // SIP over UDP has no connection to close, so the honest end of an injected
                // `disconnect` is: stop accepting commands, drop the handle, and mark the
                // client disconnected. The recv loop's socket is released when the client is
                // removed (`stop_client` aborts both registered tasks).
                app_state.remove_client_handle(client_id).await;
                app_state
                    .update_client_status(client_id, ClientStatus::Disconnected)
                    .await;
                let _ = status_tx.send("__UPDATE_UI__".to_string());
                break;
            }
        }
    }

    /// Execute one SIP action and report what actually reached the wire.
    ///
    /// Shared by the connected-event path, the read loop and injected commands, so the SIP
    /// request encoding (and the Call-ID / tag / CSeq bookkeeping that goes with it) exists
    /// exactly once. `Err` means the datagram could not be sent; the outcome variants are
    /// the truthful report of what happened otherwise.
    async fn execute_sip_action(
        action: serde_json::Value,
        socket: &Arc<UdpSocket>,
        protocol: &Arc<SipClientProtocol>,
        client_data: &Arc<Mutex<ClientData>>,
        client_id: ClientId,
        status_tx: &mpsc::UnboundedSender<String>,
    ) -> Result<ClientSendOutcome> {
        use crate::llm::actions::client_trait::{Client, ClientActionResult};

        let result = match protocol.as_ref().execute_action(action.clone()) {
            Ok(result) => result,
            Err(e) => {
                error!("Action execution error for SIP client {}: {}", client_id, e);
                return Ok(ClientSendOutcome::Rejected {
                    error: e.to_string(),
                });
            }
        };

        match result {
            ClientActionResult::Custom { name, data } => {
                match name.as_str() {
                    "sip_register" | "sip_invite" | "sip_ack" | "sip_bye" | "sip_options"
                    | "sip_cancel" => {
                        // Build and send SIP request
                        let mut client_data_lock = client_data.lock().await;

                        // Generate Call-ID if not set
                        if client_data_lock.call_id.is_none() {
                            client_data_lock.call_id = Some(Self::generate_call_id());
                        }

                        // Generate From tag if not set
                        if client_data_lock.from_tag.is_none() {
                            client_data_lock.from_tag = Some(Self::generate_tag());
                        }

                        // `expect` rather than `unwrap`: both were just filled in above, so
                        // this cannot be reached, and saying so is cheaper than making the
                        // reader prove it.
                        let request = Self::build_sip_request(
                            &name,
                            &data,
                            client_data_lock
                                .call_id
                                .as_ref()
                                .expect("Call-ID generated above"),
                            client_data_lock
                                .from_tag
                                .as_ref()
                                .expect("From tag generated above"),
                            client_data_lock.to_tag.as_ref(),
                            client_data_lock.cseq,
                            client_data_lock.local_addr,
                        );

                        client_data_lock.cseq += 1;
                        drop(client_data_lock);

                        // Send request
                        let sent = socket
                            .send(&request)
                            .await
                            .with_context(|| format!("SIP client {} send failed", client_id))?;
                        info!("SIP client {} sent {} bytes", client_id, sent);
                        let _ = status_tx.send(format!(
                            "[CLIENT] SIP client {} sent {} request",
                            client_id, name
                        ));
                        Ok(ClientSendOutcome::Sent { bytes_sent: sent })
                    }
                    other => Ok(ClientSendOutcome::Executed {
                        detail: format!("custom result '{other}' builds no SIP request"),
                    }),
                }
            }
            ClientActionResult::Disconnect => {
                info!("SIP client {} disconnecting", client_id);
                let _ = status_tx.send(format!("[CLIENT] SIP client {} disconnecting", client_id));
                Ok(ClientSendOutcome::Disconnected)
            }
            ClientActionResult::WaitForMore => {
                trace!("SIP client {} waiting for more data", client_id);
                Ok(ClientSendOutcome::Executed {
                    detail: "wait_for_more".to_string(),
                })
            }
            other => Ok(ClientSendOutcome::Executed {
                detail: format!("{other:?} sends no SIP request"),
            }),
        }
    }

    /// Parse SIP response from bytes
    fn parse_sip_response(data: &[u8]) -> Result<SipResponse> {
        let text = String::from_utf8(data.to_vec())?;
        let lines: Vec<&str> = text.lines().collect();

        if lines.is_empty() {
            anyhow::bail!("Empty SIP response");
        }

        // Parse status line (e.g., "SIP/2.0 200 OK")
        let status_line: Vec<&str> = lines[0].split_whitespace().collect();
        if status_line.len() < 3 {
            anyhow::bail!("Invalid SIP status line");
        }

        let status_code: u16 = status_line[1].parse()?;
        let reason_phrase = status_line[2..].join(" ");

        // Parse headers
        let mut call_id = String::new();
        let mut from = String::new();
        let mut to = String::new();
        let mut cseq = String::new();
        let mut to_tag = None;
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
                    "to" | "t" => {
                        to = header_value.to_string();
                        // Extract tag if present
                        if let Some(tag_start) = header_value.find(";tag=") {
                            to_tag = Some(header_value[tag_start + 5..].to_string());
                        }
                    }
                    "cseq" => cseq = header_value.to_string(),
                    "content-length" | "l" => content_length = header_value.parse().unwrap_or(0),
                    _ => {}
                }
            }

            i += 1;
        }

        // Parse body (SDP or other content)
        let mut body = String::new();
        if content_length > 0 && i < lines.len() {
            body = lines[i..].join("\r\n");
        }

        // Extract method from CSeq
        let method = cseq.split_whitespace().nth(1).unwrap_or("").to_string();

        Ok(SipResponse {
            status_code,
            reason_phrase,
            method,
            call_id,
            from,
            to,
            to_tag,
            cseq,
            body: if body.is_empty() { None } else { Some(body) },
        })
    }

    /// Build SIP request from action data
    fn build_sip_request(
        method: &str,
        data: &serde_json::Value,
        call_id: &str,
        from_tag: &str,
        to_tag: Option<&String>,
        cseq: u32,
        local_addr: SocketAddr,
    ) -> Vec<u8> {
        let from = data["from"].as_str().unwrap_or("sip:user@localhost");
        let to = data["to"].as_str().unwrap_or("sip:server@localhost");
        let request_uri = data["request_uri"]
            .as_str()
            .unwrap_or("sip:server@localhost");

        // Map action name to SIP method
        let sip_method = match method {
            "sip_register" => "REGISTER",
            "sip_invite" => "INVITE",
            "sip_ack" => "ACK",
            "sip_bye" => "BYE",
            "sip_options" => "OPTIONS",
            "sip_cancel" => "CANCEL",
            _ => "OPTIONS",
        };

        // Build request line
        let mut request = format!("{} {} SIP/2.0\r\n", sip_method, request_uri);

        // Add Via header.
        //
        // This is our own address, not the literal `127.0.0.1:5060` it used to be. Via is where
        // an RFC 3261 server sends the response, so a hardcoded loopback address meant every
        // reply from a real server went to port 5060 on the server's own loopback and this
        // client never saw it. It worked only against netget's own SIP server, which answers
        // the datagram's source address instead. `;rport` (RFC 3581) additionally asks the
        // server to reply to the source address and port it actually observed, which is what
        // makes this work from behind NAT.
        request.push_str(&format!(
            "Via: SIP/2.0/UDP {};rport;branch=z9hG4bK-netget-{}\r\n",
            local_addr,
            Self::generate_branch()
        ));

        // Add From header (with tag)
        request.push_str(&format!("From: <{}>;tag={}\r\n", from, from_tag));

        // Add To header (with tag if available)
        if let Some(tag) = to_tag {
            request.push_str(&format!("To: <{}>;tag={}\r\n", to, tag));
        } else {
            request.push_str(&format!("To: <{}>\r\n", to));
        }

        // Add Call-ID header
        request.push_str(&format!("Call-ID: {}\r\n", call_id));

        // Add CSeq header
        request.push_str(&format!("CSeq: {} {}\r\n", cseq, sip_method));

        // Add Contact header (for REGISTER/INVITE)
        if sip_method == "REGISTER" || sip_method == "INVITE" {
            // Default Contact is this socket's own address for the same reason as Via: a
            // server that calls back a hardcoded 127.0.0.1 reaches itself, not us.
            let default_contact = format!("sip:user@{}", local_addr);
            let contact = data["contact"].as_str().unwrap_or(&default_contact);
            request.push_str(&format!("Contact: <{}>\r\n", contact));
        }

        // Add Expires header (for REGISTER)
        if sip_method == "REGISTER" {
            let expires = data["expires"].as_u64().unwrap_or(3600);
            request.push_str(&format!("Expires: {}\r\n", expires));
        }

        // Add body (SDP for INVITE)
        let body = if sip_method == "INVITE" {
            data["sdp"].as_str()
        } else {
            None
        };

        // Add Content-Length and body
        if let Some(body_text) = body {
            request.push_str("Content-Type: application/sdp\r\n");
            request.push_str(&format!("Content-Length: {}\r\n", body_text.len()));
            request.push_str("\r\n");
            request.push_str(body_text);
        } else {
            request.push_str("Content-Length: 0\r\n");
            request.push_str("\r\n");
        }

        request.into_bytes()
    }

    /// Build ACK request for INVITE 3-way handshake (RFC 3261)
    fn build_ack_request(
        response: &SipResponse,
        call_id: &str,
        from_tag: &str,
        cseq: u32,
        local_addr: SocketAddr,
    ) -> Vec<u8> {
        // Extract URIs from response headers
        let from_uri = Self::extract_uri(&response.from).unwrap_or("sip:user@localhost");
        let to_uri = Self::extract_uri(&response.to).unwrap_or("sip:server@localhost");

        // ACK uses same Request-URI as INVITE, which is the To URI
        let request_uri = to_uri;

        // Build request line
        let mut request = format!("ACK {} SIP/2.0\r\n", request_uri);

        // Add Via header.
        //
        // This is our own address, not the literal `127.0.0.1:5060` it used to be. Via is where
        // an RFC 3261 server sends the response, so a hardcoded loopback address meant every
        // reply from a real server went to port 5060 on the server's own loopback and this
        // client never saw it. It worked only against netget's own SIP server, which answers
        // the datagram's source address instead. `;rport` (RFC 3581) additionally asks the
        // server to reply to the source address and port it actually observed, which is what
        // makes this work from behind NAT.
        request.push_str(&format!(
            "Via: SIP/2.0/UDP {};rport;branch=z9hG4bK-netget-{}\r\n",
            local_addr,
            Self::generate_branch()
        ));

        // Add From header (with tag)
        request.push_str(&format!("From: <{}>;tag={}\r\n", from_uri, from_tag));

        // Add To header (with tag from response - ACK must include To tag)
        if let Some(to_tag) = &response.to_tag {
            request.push_str(&format!("To: <{}>;tag={}\r\n", to_uri, to_tag));
        } else {
            request.push_str(&format!("To: <{}>\r\n", to_uri));
        }

        // Add Call-ID header
        request.push_str(&format!("Call-ID: {}\r\n", call_id));

        // Add CSeq header (same number as INVITE, but ACK method)
        request.push_str(&format!("CSeq: {} ACK\r\n", cseq));

        // ACK has no body
        request.push_str("Content-Length: 0\r\n");
        request.push_str("\r\n");

        request.into_bytes()
    }

    /// Extract SIP URI from header value (removes display name and parameters)
    fn extract_uri(header_value: &str) -> Option<&str> {
        // Handle format: "Display Name" <sip:user@host>;tag=xyz
        // or: sip:user@host;tag=xyz
        // or: <sip:user@host>

        let trimmed = header_value.trim();

        // Check for angle brackets.
        //
        // The closing bracket is searched for *after* the opening one. Searching the whole
        // string for '>' independently panicked whenever a '>' appeared first — which a peer
        // can arrange with a display name such as `"a>b" <sip:x@y>` — because `&s[start+1..end]`
        // with `start > end` is a slice whose start is past its end. Remotely triggerable, in
        // the read loop, inside a `tokio::spawn` that swallows the panic.
        if let Some(start) = trimmed.find('<') {
            if let Some(offset) = trimmed[start + 1..].find('>') {
                return Some(&trimmed[start + 1..start + 1 + offset]);
            }
        }

        // No angle brackets, extract until semicolon or end
        if let Some(semicolon) = trimmed.find(';') {
            return Some(&trimmed[..semicolon]);
        }

        Some(trimmed)
    }

    /// Generate a random Call-ID
    fn generate_call_id() -> String {
        use rand::Rng;
        let random: u64 = rand::thread_rng().gen();
        format!("{}@netget-client", random)
    }

    /// Generate a random tag
    fn generate_tag() -> String {
        use rand::Rng;
        let tag: u32 = rand::thread_rng().gen();
        format!("{:x}", tag)
    }

    /// Generate a random branch parameter
    fn generate_branch() -> String {
        use rand::Rng;
        let branch: u32 = rand::thread_rng().gen();
        format!("{:x}", branch)
    }
}

/// Parsed SIP response
#[derive(Debug, Clone)]
struct SipResponse {
    status_code: u16,
    reason_phrase: String,
    method: String, // Extracted from CSeq
    call_id: String,
    from: String,
    to: String,
    to_tag: Option<String>,
    /// Full CSeq header value; its number is the one the automatic ACK repeats.
    cseq: String,
    body: Option<String>,
}
