//! DoT (DNS over TLS) client implementation
pub mod actions;

pub use actions::DotClientProtocol;

use anyhow::{Context, Result};
use hickory_proto::op::{Message as DnsMessage, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RecordType};
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex};
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;
use tracing::{debug, error, info, trace};

use crate::client::dot::actions::{DOT_CLIENT_CONNECTED_EVENT, DOT_CLIENT_RESPONSE_RECEIVED_EVENT};
use crate::client::llm_budget::call_llm_for_client;
use crate::llm::actions::client_trait::{Client as ClientTrait, ClientActionResult};
use crate::llm::ollama_client::OllamaClient;
use crate::llm::ClientLlmResult;
use crate::protocol::Event;
use crate::state::app_state::AppState;
use crate::state::{ClientId, ClientStatus};

/// Connection state for LLM processing
#[derive(Debug, Clone, PartialEq)]
enum ConnectionState {
    Idle,
    Processing,
    Accumulating,
}

/// Per-client data for LLM handling
struct ClientData {
    state: ConnectionState,
    queued_responses: Vec<Vec<u8>>,
    memory: String,
}

/// DoT client that makes DNS queries over TLS
pub struct DotClient;

impl DotClient {
    /// Connect to a DoT server with integrated LLM actions
    pub async fn connect_with_llm_actions(
        remote_addr: String,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        client_id: ClientId,
        startup_params: Option<crate::protocol::StartupParams>,
    ) -> Result<SocketAddr> {
        info!("DoT client {} connecting to {}", client_id, remote_addr);
        let _ = status_tx.send(format!(
            "[CLIENT] DoT client {} connecting to {}",
            client_id, remote_addr
        ));

        // Both parameters are declared in `get_startup_parameters()`; until this pass neither
        // was read, so `verify_tls: false` silently still verified against the Mozilla roots
        // and a NetGet DoT server (self-signed) could never be reached.
        let verify_tls = startup_params
            .as_ref()
            .map(|p| p.get_optional_bool("verify_tls"))
            .transpose()?
            .flatten()
            .unwrap_or(true);
        let server_name_override = startup_params
            .as_ref()
            .map(|p| p.get_optional_string("server_name"))
            .transpose()?
            .flatten();

        // Parse remote address
        let remote_socket_addr: SocketAddr = remote_addr
            .parse()
            .context("Invalid remote address format")?;

        // Extract hostname for SNI (or use IP as fallback)
        let server_name = server_name_override
            .as_deref()
            .unwrap_or_else(|| remote_addr.split(':').next().unwrap_or("dns.server"));

        // Install a rustls CryptoProvider before building the config. Without one,
        // `ClientConfig::builder()` panics rather than returning an error whenever the
        // build has more than one provider feature live, which `all-protocols` does. See
        // the fuller note in `src/client/tls/mod.rs`.
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();

        // Create TLS config with root certificates
        let root_store = RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };

        let config = if verify_tls {
            ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth()
        } else {
            debug!("DoT client {} accepting invalid certificates", client_id);
            ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerification))
                .with_no_client_auth()
        };

        let connector = TlsConnector::from(Arc::new(config));

        // Connect TCP stream
        let tcp_stream = TcpStream::connect(&remote_socket_addr)
            .await
            .context("Failed to connect to DoT server")?;

        let local_addr = tcp_stream.local_addr()?;

        // Perform TLS handshake
        let server_name = match ServerName::try_from(server_name.to_string()) {
            Ok(name) => name,
            Err(_) => {
                debug!("Failed to parse server name, using IP");
                ServerName::try_from(remote_socket_addr.ip().to_string())
                    .map_err(|e| anyhow::anyhow!("Invalid server name: {}", e))?
            }
        };

        let tls_stream = connector
            .connect(server_name, tcp_stream)
            .await
            .context("TLS handshake failed")?;

        info!("DoT client {} connected to {}", client_id, remote_addr);
        let _ = status_tx.send(format!("[CLIENT] DoT client {} connected", client_id));

        // Update status
        app_state
            .update_client_status(client_id, ClientStatus::Connected)
            .await;
        let _ = status_tx.send("__UPDATE_UI__".to_string());

        // Split stream for bidirectional communication
        let (read_half, write_half) = tokio::io::split(tls_stream);
        let write_half_arc = Arc::new(Mutex::new(write_half));

        // Initialize client data
        let client_data = Arc::new(Mutex::new(ClientData {
            state: ConnectionState::Idle,
            queued_responses: Vec::new(),
            memory: String::new(),
        }));

        // Command channel for injected actions (the dashboard's [ send_dns_query ]).
        // Registered BEFORE the connected-event LLM call, which a manual `*` rule can park
        // for minutes - the operator must be able to reach the client while it waits.
        let command_rx =
            crate::client::command_support::register_command_channel(&app_state, client_id).await;

        // The read loop does framed `read_exact` reads, which are not cancellation-safe, so
        // commands are drained by their own task rather than a `select!` arm. Both tasks
        // share the write half.
        let cmd_state = app_state.clone();
        let cmd_tx = status_tx.clone();
        let cmd_write = write_half_arc.clone();
        let cmd_task = tokio::spawn(async move {
            Self::command_loop(command_rx, cmd_write, client_id, cmd_state, cmd_tx).await;
        });
        app_state.register_client_task(client_id, cmd_task).await;

        // Spawn read loop for handling responses
        let write_for_read = write_half_arc.clone();
        let client_data_for_read = client_data.clone();
        let read_app_state = app_state.clone();
        let read_llm_client = llm_client.clone();
        let read_status_tx = status_tx.clone();

        // Registered with AppState so stop_client can abort this task —
        // dropping a JoinHandle only detaches it in Tokio.
        let task_registrar = app_state.clone();
        let task_handle = tokio::spawn(async move {
            if let Err(e) = Self::read_loop(
                read_half,
                write_for_read,
                client_id,
                read_app_state.clone(),
                read_llm_client,
                read_status_tx,
                client_data_for_read,
            )
            .await
            {
                error!("DoT client {} read loop error: {}", client_id, e);
            }
            // Every exit of the read loop (EOF, read error, LLM or injected disconnect) ends
            // here: drop the command handle so the rail stops offering [ send ] on a dead
            // client.
            read_app_state.remove_client_handle(client_id).await;
        });
        task_registrar
            .register_client_task(client_id, task_handle)
            .await;

        // Call LLM with connected event
        if let Some(instruction) = app_state.get_instruction_for_client(client_id).await {
            let protocol = Arc::new(DotClientProtocol::new());
            let event = Event::new(
                &DOT_CLIENT_CONNECTED_EVENT,
                serde_json::json!({
                    "remote_addr": remote_addr,
                }),
            );

            match call_llm_for_client(
                &llm_client,
                &app_state,
                client_id.to_string(),
                &instruction,
                &client_data.lock().await.memory,
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

                    // Execute initial actions
                    for action_json in actions {
                        if let Err(e) = Self::execute_client_action(
                            client_id,
                            action_json,
                            &write_half_arc,
                            &status_tx,
                            &app_state,
                        )
                        .await
                        {
                            error!("DoT client {} action execution failed: {}", client_id, e);
                        }
                    }
                }
                Err(e) => {
                    error!("LLM error for DoT client {}: {}", client_id, e);
                }
            }
        }

        Ok(local_addr)
    }

    /// Read loop for handling DNS responses
    async fn read_loop(
        mut read_half: ReadHalf<TlsStream<TcpStream>>,
        write_half: Arc<Mutex<WriteHalf<TlsStream<TcpStream>>>>,
        client_id: ClientId,
        app_state: Arc<AppState>,
        llm_client: OllamaClient,
        status_tx: mpsc::UnboundedSender<String>,
        client_data: Arc<Mutex<ClientData>>,
    ) -> Result<()> {
        loop {
            // Check client status
            if app_state.get_client(client_id).await.is_none() {
                info!("DoT client {} stopped", client_id);
                break;
            }

            // Read length-prefixed DNS message (2-byte big-endian length)
            let mut len_buf = [0u8; 2];
            match read_half.read_exact(&mut len_buf).await {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    debug!("DoT client {} connection closed by server", client_id);
                    let _ =
                        status_tx.send(format!("[CLIENT] DoT client {} disconnected", client_id));
                    app_state
                        .update_client_status(client_id, ClientStatus::Disconnected)
                        .await;
                    break;
                }
                Err(e) => {
                    error!(
                        "DoT client {} failed to read length prefix: {}",
                        client_id, e
                    );
                    break;
                }
            }

            let dns_len = u16::from_be_bytes(len_buf) as usize;

            if dns_len == 0 || dns_len > 65535 {
                error!(
                    "DoT client {} invalid DNS message length: {}",
                    client_id, dns_len
                );
                break;
            }

            // Read DNS message
            let mut dns_buf = vec![0u8; dns_len];
            if let Err(e) = read_half.read_exact(&mut dns_buf).await {
                error!("DoT client {} failed to read DNS message: {}", client_id, e);
                break;
            }

            debug!("DoT client {} received {} bytes", client_id, dns_len);
            trace!("DoT response hex: {}", hex::encode(&dns_buf));

            // Parse DNS response
            let dns_message = match crate::utils::dns_screen::decode_dns_message(&dns_buf) {
                Ok(msg) => msg,
                Err(e) => {
                    error!(
                        "DoT client {} failed to parse DNS message: {}",
                        client_id, e
                    );
                    continue;
                }
            };

            // Extract response information
            let query_id = dns_message.id();
            let response_code = format!("{:?}", dns_message.response_code());

            let answers: Vec<serde_json::Value> = dns_message
                .answers()
                .iter()
                .map(|record| {
                    let data_str = match record.data() {
                        Some(data) => format!("{}", data),
                        None => "NULL".to_string(),
                    };
                    serde_json::json!({
                        "name": record.name().to_utf8(),
                        "type": format!("{:?}", record.record_type()),
                        "ttl": record.ttl(),
                        "data": data_str,
                    })
                })
                .collect();

            let authorities: Vec<serde_json::Value> = dns_message
                .name_servers()
                .iter()
                .map(|record| {
                    let data_str = match record.data() {
                        Some(data) => format!("{}", data),
                        None => "NULL".to_string(),
                    };
                    serde_json::json!({
                        "name": record.name().to_utf8(),
                        "type": format!("{:?}", record.record_type()),
                        "ttl": record.ttl(),
                        "data": data_str,
                    })
                })
                .collect();

            let additionals: Vec<serde_json::Value> = dns_message
                .additionals()
                .iter()
                .map(|record| {
                    let data_str = match record.data() {
                        Some(data) => format!("{}", data),
                        None => "NULL".to_string(),
                    };
                    serde_json::json!({
                        "name": record.name().to_utf8(),
                        "type": format!("{:?}", record.record_type()),
                        "ttl": record.ttl(),
                        "data": data_str,
                    })
                })
                .collect();

            info!(
                "DoT client {} received response: ID={}, Code={}, Answers={}",
                client_id,
                query_id,
                response_code,
                answers.len()
            );

            // Check state machine
            let mut client_data_lock = client_data.lock().await;

            match client_data_lock.state {
                ConnectionState::Processing => {
                    // Queue this data for later
                    debug!("DoT client {} queuing response (LLM processing)", client_id);
                    client_data_lock.state = ConnectionState::Accumulating;
                    client_data_lock.queued_responses.push(dns_buf);
                    continue;
                }
                ConnectionState::Accumulating => {
                    // Already accumulating, just continue queuing
                    debug!("DoT client {} already accumulating", client_id);
                    client_data_lock.queued_responses.push(dns_buf);
                    continue;
                }
                ConnectionState::Idle => {
                    // Normal processing
                    client_data_lock.state = ConnectionState::Processing;
                    drop(client_data_lock);
                }
            }

            // Call LLM with response
            if let Some(instruction) = app_state.get_instruction_for_client(client_id).await {
                let protocol = Arc::new(DotClientProtocol::new());
                let event = Event::new(
                    &DOT_CLIENT_RESPONSE_RECEIVED_EVENT,
                    serde_json::json!({
                        "query_id": query_id,
                        "response_code": response_code,
                        "answers": answers,
                        "authorities": authorities,
                        "additionals": additionals,
                    }),
                );

                match call_llm_for_client(
                    &llm_client,
                    &app_state,
                    client_id.to_string(),
                    &instruction,
                    &client_data.lock().await.memory,
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

                        // Execute actions
                        for action_json in actions {
                            if let Err(e) = Self::execute_client_action(
                                client_id,
                                action_json,
                                &write_half,
                                &status_tx,
                                &app_state,
                            )
                            .await
                            {
                                error!("DoT client {} action execution failed: {}", client_id, e);
                            }
                        }
                    }
                    Err(e) => {
                        error!("LLM error for DoT client {}: {}", client_id, e);
                    }
                }
            }

            // Set back to Idle and process queued responses
            let mut client_data_lock = client_data.lock().await;
            if !client_data_lock.queued_responses.is_empty() {
                client_data_lock.queued_responses.clear();
            }
            client_data_lock.state = ConnectionState::Idle;
        }

        Ok(())
    }

    /// Drain injected commands until the channel closes (client removed) or an injected
    /// `disconnect` ends the session.
    ///
    /// The generic `command_support::handle_stream_client_command` cannot run this client's
    /// vocabulary because `send_dns_query` yields `ClientActionResult::Custom`, so the action
    /// goes through [`Self::apply_action`] - the same function the LLM path uses, so the DNS
    /// encoding exists exactly once - and the outcome is recorded and replied the way the
    /// generic arm does it.
    async fn command_loop(
        mut command_rx: mpsc::Receiver<crate::state::client_handles::ClientCommand>,
        write_half: Arc<Mutex<WriteHalf<TlsStream<TcpStream>>>>,
        client_id: ClientId,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
    ) {
        use crate::llm::actions::protocol_trait::Protocol;
        use crate::state::client_handles::ClientSendOutcome;
        use crate::state::AccessLogOwner;

        let protocol = DotClientProtocol::new();
        while let Some(command) = command_rx.recv().await {
            let action = command.action.clone();
            let outcome = match protocol.execute_action(action.clone()) {
                Err(e) => Ok(ClientSendOutcome::Rejected {
                    error: e.to_string(),
                }),
                Ok(result) => Self::apply_action(result, &write_half, client_id, &status_tx)
                    .await
                    .map(|applied| match applied {
                        Applied::Disconnect => ClientSendOutcome::Disconnected,
                        Applied::Sent(0) => ClientSendOutcome::Executed {
                            detail: "executed (nothing to write)".to_string(),
                        },
                        Applied::Sent(bytes_sent) => ClientSendOutcome::Sent { bytes_sent },
                    }),
            };

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
                error!("DoT client {} injected action failed: {}", client_id, e);
                let _ = status_tx.send(format!(
                    "[WARN] Client {} injected action failed: {}",
                    client_id, e
                ));
            }
            let _ = status_tx.send("__UPDATE_UI__".to_string());
            crate::client::command_support::reply(command, outcome);

            if disconnect {
                // Half-close: the server reads EOF and closes; the read loop then sees
                // UnexpectedEof and runs its normal disconnect path.
                let _ = write_half.lock().await.shutdown().await;
                break;
            }
        }
    }

    /// Execute a client action produced by the LLM
    async fn execute_client_action(
        client_id: ClientId,
        action_json: serde_json::Value,
        write_half: &Arc<Mutex<WriteHalf<TlsStream<TcpStream>>>>,
        status_tx: &mpsc::UnboundedSender<String>,
        app_state: &Arc<AppState>,
    ) -> Result<()> {
        let protocol = DotClientProtocol::new();
        let action_result = protocol.execute_action(action_json)?;

        if let Applied::Disconnect =
            Self::apply_action(action_result, write_half, client_id, status_tx).await?
        {
            info!("DoT client {} disconnecting", client_id);
            // Remove client from app state, which will cause the read loop to exit
            app_state.remove_client(client_id).await;
            let _ = status_tx.send(format!("[CLIENT] DoT client {} disconnected", client_id));
            let _ = status_tx.send("__UPDATE_UI__".to_string());
        }

        Ok(())
    }

    /// Put one executed action on the wire. Shared by the LLM path and injected commands.
    async fn apply_action(
        action_result: ClientActionResult,
        write_half: &Arc<Mutex<WriteHalf<TlsStream<TcpStream>>>>,
        client_id: ClientId,
        status_tx: &mpsc::UnboundedSender<String>,
    ) -> Result<Applied> {
        match action_result {
            ClientActionResult::Custom { name, data } if name == "dns_query" => {
                let bytes_sent = Self::send_dns_query(
                    client_id,
                    data.get("domain")
                        .and_then(|v| v.as_str())
                        .context("Missing domain")?
                        .to_string(),
                    data.get("query_type")
                        .and_then(|v| v.as_str())
                        .context("Missing query_type")?
                        .to_string(),
                    data.get("recursive")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(true),
                    write_half,
                    status_tx,
                )
                .await?;
                Ok(Applied::Sent(bytes_sent))
            }
            ClientActionResult::Disconnect => Ok(Applied::Disconnect),
            ClientActionResult::WaitForMore => {
                debug!("DoT client {} waiting for more data", client_id);
                Ok(Applied::Sent(0))
            }
            // NoAction, SendData (unused by this vocabulary), other Custom, Multiple.
            _ => Ok(Applied::Sent(0)),
        }
    }

    /// Send a DNS query over TLS
    async fn send_dns_query(
        client_id: ClientId,
        domain: String,
        query_type: String,
        recursive: bool,
        write_half: &Arc<Mutex<WriteHalf<TlsStream<TcpStream>>>>,
        status_tx: &mpsc::UnboundedSender<String>,
    ) -> Result<usize> {
        info!(
            "DoT client {} querying {} {}",
            client_id, domain, query_type
        );
        let _ = status_tx.send(format!("[CLIENT] DoT query: {} {}", domain, query_type));

        // Parse record type
        let record_type = RecordType::from_str(&query_type)
            .context(format!("Invalid query type: {}", query_type))?;

        // Parse domain name
        let name = Name::from_str(&domain).context(format!("Invalid domain name: {}", domain))?;

        // Create DNS query message
        let mut message = DnsMessage::new();
        message.set_id(rand::random());
        message.set_message_type(MessageType::Query);
        message.set_op_code(OpCode::Query);
        message.set_recursion_desired(recursive);

        let query = Query::query(name, record_type);
        message.add_query(query);

        // Encode message
        let dns_bytes = message.to_vec().context("Failed to encode DNS message")?;

        trace!("DoT query hex: {}", hex::encode(&dns_bytes));

        // Length-prefix the message
        let len = u16::try_from(dns_bytes.len()).context("DoT request exceeds u16 frame length")?;
        let mut prefixed_message = len.to_be_bytes().to_vec();
        prefixed_message.extend_from_slice(&dns_bytes);

        // Send via TLS stream
        {
            let mut writer = write_half.lock().await;
            writer
                .write_all(&prefixed_message)
                .await
                .context("Failed to send DNS query over TLS")?;
            writer
                .flush()
                .await
                .context("Failed to flush DNS query over TLS")?;
        }

        debug!(
            "DoT client {} sent DNS query ({} bytes)",
            client_id,
            prefixed_message.len()
        );

        Ok(prefixed_message.len())
    }
}

/// What [`DotClient::apply_action`] did with one action.
enum Applied {
    /// Bytes written (0 when the action produced no wire output).
    Sent(usize),
    /// The action asked to end the session.
    Disconnect,
}

/// Certificate verifier that accepts any certificate. Used only when the declared
/// `verify_tls` startup parameter is `false` (self-signed NetGet DoT servers, tests).
#[derive(Debug)]
struct NoVerification;

impl tokio_rustls::rustls::client::danger::ServerCertVerifier for NoVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[tokio_rustls::rustls::pki_types::CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: tokio_rustls::rustls::pki_types::UnixTime,
    ) -> Result<tokio_rustls::rustls::client::danger::ServerCertVerified, tokio_rustls::rustls::Error>
    {
        Ok(tokio_rustls::rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
        _dss: &tokio_rustls::rustls::DigitallySignedStruct,
    ) -> Result<
        tokio_rustls::rustls::client::danger::HandshakeSignatureValid,
        tokio_rustls::rustls::Error,
    > {
        Ok(tokio_rustls::rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
        _dss: &tokio_rustls::rustls::DigitallySignedStruct,
    ) -> Result<
        tokio_rustls::rustls::client::danger::HandshakeSignatureValid,
        tokio_rustls::rustls::Error,
    > {
        Ok(tokio_rustls::rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<tokio_rustls::rustls::SignatureScheme> {
        tokio_rustls::rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
