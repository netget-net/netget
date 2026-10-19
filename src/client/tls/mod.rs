//! TLS client implementation
//!
//! Provides a generic TLS client that establishes encrypted connections
//! and allows the LLM to implement custom application protocols.

pub mod actions;

pub use actions::TlsClientProtocol;

use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex};
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;
use tracing::{debug, error, info, trace};

use crate::client::llm_budget::call_llm_for_client;
use crate::client::tls::actions::{TLS_CLIENT_CONNECTED_EVENT, TLS_CLIENT_DATA_RECEIVED_EVENT};
use crate::llm::ollama_client::OllamaClient;
use crate::llm::ClientLlmResult;
use crate::logging::patterns;
use crate::protocol::Event;
use crate::state::app_state::AppState;
use crate::state::{ClientId, ClientStatus};

/// How many reads may wait while the model answers an earlier one. Each is at most one
/// 8 KiB read, so at most 256 KiB waits; past it the reader stops reading and TCP holds the
/// server back.
///
/// There used to be an `Idle`/`Processing`/`Accumulating` machine with a `queued_data` buffer
/// here. The read loop awaited every model call inline, so nothing could arrive mid-call and
/// the buffer was only ever filled by `wait_for_more`; that one real use is the `held` prefix
/// in the answering loop now.
const READ_QUEUE_CHUNKS: usize = crate::protocol::metadata::MAX_BATCH_EVENTS;

/// What the reader task hands the answering loop.
enum Inbound {
    Data(Vec<u8>),
    Closed,
    Failed(String),
}

/// TLS client that connects to a remote TLS server
pub struct TlsClient;

impl TlsClient {
    /// Connect to a TLS server with integrated LLM actions
    pub async fn connect_with_llm_actions(
        remote_addr: String,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        client_id: ClientId,
        startup_params: Option<crate::protocol::StartupParams>,
    ) -> Result<SocketAddr> {
        // Extract startup parameters
        let accept_invalid_certs = startup_params
            .as_ref()
            .map(|p| p.get_optional_bool("accept_invalid_certs"))
            .transpose()?
            .flatten()
            .unwrap_or(false);

        let server_name_override = startup_params
            .as_ref()
            .map(|p| p.get_optional_string("server_name"))
            .transpose()?
            .flatten();

        let custom_ca_cert_pem = startup_params
            .as_ref()
            .map(|p| p.get_optional_string("custom_ca_cert_pem"))
            .transpose()?
            .flatten();

        debug!(
            "TLS client {} connecting to {} (accept_invalid_certs: {})",
            client_id, remote_addr, accept_invalid_certs
        );

        // Determine server name for SNI (before connecting)
        let server_name_str = if let Some(override_name) = server_name_override {
            override_name
        } else {
            // Extract hostname from remote_addr (e.g., "example.com:443" -> "example.com")
            remote_addr
                .split(':')
                .next()
                .unwrap_or(&remote_addr)
                .to_string()
        };

        // Make sure rustls has a process-level CryptoProvider before any builder runs.
        //
        // `ClientConfig::builder()` *panics* when it cannot pick one automatically, and it
        // cannot whenever more than one provider feature is live in the build - which is
        // the normal case here, because `all-protocols` pulls in dependencies that enable
        // both `ring` and `aws-lc-rs`. The panic reads "Could not automatically determine
        // the process-level CryptoProvider from Rustls crate features".
        //
        // `src/bin/netget.rs` installs the provider at startup, so the shipped binary was
        // fine and this stayed hidden; anything else using NetGet as a library - every
        // test, and the protocol smoke sweep that found this - reached the builder with no
        // provider installed and took down the connecting task instead of returning `Err`.
        // The servers already guard themselves this way (`src/server/tls_cert_manager.rs`,
        // `src/server/proxy/tls_mitm.rs`); the TLS client did not.
        //
        // Installing is idempotent-by-ignoring: `install_default` returns `Err` if one is
        // already installed, which is exactly the case we want to do nothing about.
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();

        // Create TLS config
        let config = if accept_invalid_certs {
            // Accept any certificate (for testing with self-signed certs)
            debug!("TLS client {} accepting invalid certificates", client_id);
            ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerification))
                .with_no_client_auth()
        } else if let Some(ref ca_pem) = custom_ca_cert_pem {
            // Use custom CA certificate for validation
            debug!("TLS client {} using custom CA certificate", client_id);

            // Parse CA certificate from PEM
            let ca_certs = rustls_pemfile::certs(&mut ca_pem.as_bytes())
                .collect::<Result<Vec<_>, _>>()
                .context("Failed to parse custom CA certificate PEM")?;

            if ca_certs.is_empty() {
                return Err(anyhow::anyhow!(
                    "No certificates found in custom_ca_cert_pem"
                ));
            }

            // Create root store with custom CA
            let mut root_store = RootCertStore::empty();
            for cert in ca_certs {
                root_store
                    .add(cert)
                    .context("Failed to add custom CA certificate to root store")?;
            }

            ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth()
        } else {
            // Use webpki roots for validation
            let root_store = RootCertStore {
                roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
            };
            ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth()
        };

        let connector = TlsConnector::from(Arc::new(config));

        // Connect TCP stream (DNS resolution happens automatically)
        let tcp_stream = TcpStream::connect(&remote_addr)
            .await
            .context(format!("Failed to connect to {}", remote_addr))?;

        let local_addr = tcp_stream.local_addr()?;
        let remote_socket_addr = tcp_stream.peer_addr()?;
        debug!(
            "TLS client {} TCP connected to {} (local: {})",
            client_id, remote_socket_addr, local_addr
        );

        // Perform TLS handshake
        let server_name = ServerName::try_from(server_name_str.clone())
            .map_err(|e| anyhow::anyhow!("Invalid server name '{}': {}", server_name_str, e))?;

        let tls_stream = connector
            .connect(server_name, tcp_stream)
            .await
            .context("TLS handshake failed")?;

        info!(
            "TLS client {} connected to {} (TLS handshake complete)",
            client_id, remote_socket_addr
        );

        // Update client state
        app_state
            .update_client_status(client_id, ClientStatus::Connected)
            .await;
        let _ = status_tx.send(format!("[CLIENT] TLS client {} connected", client_id));
        let _ = status_tx.send("__UPDATE_UI__".to_string());

        // Split stream
        let (mut read_half, write_half) = tokio::io::split(tls_stream);
        let write_half_arc = Arc::new(Mutex::new(write_half));
        let write_half_for_connected = write_half_arc.clone();

        // Call LLM with tls_client_connected event
        if let Some(instruction) = app_state.get_instruction_for_client(client_id).await {
            let event = Event::new(
                &TLS_CLIENT_CONNECTED_EVENT,
                serde_json::json!({
                    "remote_addr": remote_socket_addr.to_string(),
                    "server_name": server_name_str,
                }),
            );

            // The client's memory lives in `AppState`, which is where `set_memory` /
            // `append_memory` write it. This used to read a `ClientData.memory` field that
            // nothing but this file ever wrote, so a model that stored something with
            // `set_memory` was handed an empty memory on its very next turn.
            //
            // Reading it here also keeps the guard out of the call: written inline as an
            // argument, `client_data.lock().await.memory` would create a temporary guard
            // living to the end of the whole `match`, and the arm that writes the memory back
            // would then deadlock on the same non-reentrant mutex. That shape deadlocked the
            // NNTP client's read loop.
            let memory_snapshot = app_state
                .get_memory_for_client(client_id)
                .await
                .unwrap_or_default();

            match call_llm_for_client(
                &llm_client,
                &app_state,
                client_id.to_string(),
                &instruction,
                &memory_snapshot,
                Some(&event),
                &crate::client::tls::actions::TlsClientProtocol,
                &status_tx,
            )
            .await
            {
                Ok(result) => {
                    // Update memory if provided
                    if let Some(new_memory) = result.memory_updates {
                        app_state.set_memory_for_client(client_id, new_memory).await;
                    }

                    // Execute actions from LLM response
                    use crate::llm::actions::client_trait::Client;
                    let protocol = crate::client::tls::actions::TlsClientProtocol::new();
                    for action in result.actions {
                        match protocol.execute_action(action) {
                            Ok(
                                crate::llm::actions::client_trait::ClientActionResult::SendData(
                                    bytes,
                                ),
                            ) => {
                                let mut write_guard = write_half_for_connected.lock().await;
                                if let Err(e) = write_guard.write_all(&bytes).await {
                                    error!("Failed to send data after connect: {}", e);
                                } else if let Err(e) = write_guard.flush().await {
                                    error!("Failed to flush after connect: {}", e);
                                } else {
                                    info!("Sent {} {}", bytes.len(), patterns::TLS_CLIENT_SENT);
                                }
                            }
                            Ok(
                                crate::llm::actions::client_trait::ClientActionResult::Disconnect,
                            ) => {
                                info!("LLM requested disconnect after connect");
                                return Ok(local_addr);
                            }
                            Ok(
                                crate::llm::actions::client_trait::ClientActionResult::WaitForMore,
                            ) => {
                                // Just wait for data
                            }
                            Ok(_) => {
                                // Other action results
                            }
                            Err(e) => {
                                error!("Failed to execute action after connect: {}", e);
                            }
                        }
                    }
                }
                Err(e) => {
                    error!("LLM error on tls_client_connected event: {}", e);
                }
            }
        }

        // Command channel: lets the dashboard inject actions into this loop
        // via AppState::send_to_client (see client/command_support.rs).
        let mut command_rx =
            crate::client::command_support::register_command_channel(&app_state, client_id).await;

        // The reader runs on its own task so that what the server sends while the model is
        // answering keeps its read boundaries in a bounded queue instead of merging in the
        // kernel buffer (or waiting undecrypted inside rustls): with batching on everything
        // waiting is answered together, with it off one read per call. Registered, so
        // stop_client aborts it with the loop.
        let (inbound_tx, mut inbound_rx) = mpsc::channel::<Inbound>(READ_QUEUE_CHUNKS);
        let reader = app_state
            .spawn_client_task(client_id, async move {
                let mut buffer = vec![0u8; 8192];
                loop {
                    let message = match read_half.read(&mut buffer).await {
                        Ok(0) => Inbound::Closed,
                        Ok(n) => Inbound::Data(buffer[..n].to_vec()),
                        Err(e) => Inbound::Failed(e.to_string()),
                    };
                    let last = !matches!(message, Inbound::Data(_));
                    if inbound_tx.send(message).await.is_err() || last {
                        break;
                    }
                }
            })
            .await;

        // Spawn the answering loop.
        // Registered with AppState so stop_client can abort this task —
        // dropping a JoinHandle only detaches it in Tokio.
        let task_registrar = app_state.clone();
        let task_handle = tokio::spawn(async move {
            info!("TLS client {} read loop started", client_id);
            // Bytes the model has seen and answered `wait_for_more` to: the front of the next
            // turn, re-offered with whatever arrives after them.
            let mut held: Vec<u8> = Vec::new();

            'session: loop {
                let inbound = tokio::select! {
                    inbound = inbound_rx.recv() => inbound.unwrap_or(Inbound::Closed),
                    Some(cmd) = command_rx.recv() => {
                        let disconnect = crate::client::command_support::handle_stream_client_command(
                            &crate::client::tls::actions::TlsClientProtocol,
                            &write_half_arc,
                            cmd,
                            client_id,
                            &app_state,
                            &status_tx,
                        )
                        .await;
                        if disconnect {
                            app_state
                                .update_client_status(client_id, ClientStatus::Disconnected)
                                .await;
                            let _ = status_tx.send(format!(
                                "[CLIENT] TLS client {} disconnected (injected action)",
                                client_id
                            ));
                            let _ = status_tx.send("__UPDATE_UI__".to_string());
                            break;
                        }
                        continue;
                    }
                };

                let mut ended: Option<Inbound> = None;
                let mut payload = std::mem::take(&mut held);
                match inbound {
                    Inbound::Data(data) => payload.extend_from_slice(&data),
                    other => ended = Some(other),
                }

                // With batching on, everything else already waiting — what the server sent
                // while the model answered the previous read — joins this payload, as the tcp
                // client does: TLS carries a byte stream, whose read boundaries mean nothing.
                // An end of stream found while sweeping is handled after this turn.
                if ended.is_none()
                    && app_state
                        .client_conversation_settings(client_id)
                        .await
                        .is_some_and(|(_, batching)| batching)
                {
                    while let Ok(more) = inbound_rx.try_recv() {
                        match more {
                            Inbound::Data(more) => payload.extend_from_slice(&more),
                            other => {
                                ended = Some(other);
                                break;
                            }
                        }
                    }
                }

                if !payload.is_empty() {
                    info!(
                        "TLS client {} received {} {}",
                        client_id,
                        payload.len(),
                        patterns::TLS_CLIENT_RECEIVED
                    );
                    if let Some(instruction) = app_state.get_instruction_for_client(client_id).await
                    {
                        let protocol = crate::client::tls::actions::TlsClientProtocol::new();
                        // Try to decode as UTF-8, fallback to hex
                        let data_str = match String::from_utf8(payload.clone()) {
                            Ok(utf8) => utf8,
                            Err(_) => format!("HEX:{}", hex::encode(&payload)),
                        };
                        let event = Event::new(
                            &TLS_CLIENT_DATA_RECEIVED_EVENT,
                            serde_json::json!({
                                "data": data_str,
                                "data_length": payload.len(),
                            }),
                        );

                        // From AppState, for the reasons in the connect path above: that is
                        // where the client's memory actually lives.
                        let memory_snapshot = app_state
                            .get_memory_for_client(client_id)
                            .await
                            .unwrap_or_default();

                        match call_llm_for_client(
                            &llm_client,
                            &app_state,
                            client_id.to_string(),
                            &instruction,
                            &memory_snapshot,
                            Some(&event),
                            &protocol,
                            &status_tx,
                        )
                        .await
                        {
                            Ok(ClientLlmResult {
                                actions,
                                memory_updates,
                            }) => {
                                if let Some(mem) = memory_updates {
                                    app_state.set_memory_for_client(client_id, mem).await;
                                }

                                let mut wait_for_more = false;
                                for action in actions {
                                    use crate::llm::actions::client_trait::Client;
                                    use crate::llm::actions::client_trait::ClientActionResult;
                                    match protocol.execute_action(action) {
                                        Ok(ClientActionResult::SendData(bytes)) => {
                                            let mut write_guard = write_half_arc.lock().await;
                                            if let Err(e) = write_guard.write_all(&bytes).await {
                                                error!(
                                                    "TLS client {} send failed: {}",
                                                    client_id, e
                                                );
                                            } else if let Err(e) = write_guard.flush().await {
                                                error!(
                                                    "TLS client {} flush failed: {}",
                                                    client_id, e
                                                );
                                            } else {
                                                trace!(
                                                    "TLS client {} sent {} bytes",
                                                    client_id,
                                                    bytes.len()
                                                );
                                            }
                                        }
                                        Ok(ClientActionResult::Disconnect) => {
                                            info!("TLS client {} disconnecting", client_id);
                                            let mut write_guard = write_half_arc.lock().await;
                                            let _ = write_guard.shutdown().await;
                                            drop(write_guard);
                                            app_state
                                                .update_client_status(
                                                    client_id,
                                                    ClientStatus::Disconnected,
                                                )
                                                .await;
                                            let _ = status_tx.send(format!(
                                                "[CLIENT] TLS client {} disconnected (model requested)",
                                                client_id
                                            ));
                                            let _ = status_tx.send("__UPDATE_UI__".to_string());
                                            break 'session;
                                        }
                                        Ok(ClientActionResult::WaitForMore) => {
                                            wait_for_more = true;
                                        }
                                        Ok(_) => {}
                                        Err(e) => {
                                            error!(
                                                "TLS client {} could not execute action: {}",
                                                client_id, e
                                            );
                                        }
                                    }
                                }
                                if wait_for_more {
                                    // Keep the bytes the model has already seen: the next
                                    // read is appended to them and the whole is re-offered.
                                    held = payload;
                                }
                            }
                            Err(e) => {
                                error!("LLM error for TLS client {}: {}", client_id, e);
                            }
                        }
                    }
                }

                match ended {
                    Some(Inbound::Closed) => {
                        info!(
                            "TLS client {} {}",
                            client_id,
                            patterns::TLS_CLIENT_DISCONNECTED
                        );
                        app_state
                            .update_client_status(client_id, ClientStatus::Disconnected)
                            .await;
                        let _ = status_tx
                            .send(format!("[CLIENT] TLS client {} disconnected", client_id));
                        let _ = status_tx.send("__UPDATE_UI__".to_string());
                        break;
                    }
                    Some(Inbound::Failed(e)) => {
                        error!("TLS client {} read error: {}", client_id, e);
                        app_state
                            .update_client_status(client_id, ClientStatus::Error(e))
                            .await;
                        let _ = status_tx.send("__UPDATE_UI__".to_string());
                        break;
                    }
                    _ => {}
                }
            }

            reader.abort();
            // The loop owns the only receiver; dropping the registered handle
            // makes later send_to_client calls fail fast instead of timing out.
            app_state.remove_client_handle(client_id).await;
        });
        task_registrar
            .register_client_task(client_id, task_handle)
            .await;

        Ok(local_addr)
    }
}

/// Custom certificate verifier that accepts any certificate
/// Used when accept_invalid_certs is true (for testing self-signed certs)
#[derive(Debug)]
struct NoVerification;

impl tokio_rustls::rustls::client::danger::ServerCertVerifier for NoVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[tokio_rustls::rustls::pki_types::CertificateDer<'_>],
        _server_name: &tokio_rustls::rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: tokio_rustls::rustls::pki_types::UnixTime,
    ) -> Result<tokio_rustls::rustls::client::danger::ServerCertVerified, tokio_rustls::rustls::Error>
    {
        // Accept all certificates
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
        // Accept all signatures
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
        // Accept all signatures
        Ok(tokio_rustls::rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<tokio_rustls::rustls::SignatureScheme> {
        // Support all signature schemes
        vec![
            tokio_rustls::rustls::SignatureScheme::RSA_PKCS1_SHA256,
            tokio_rustls::rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            tokio_rustls::rustls::SignatureScheme::ED25519,
            tokio_rustls::rustls::SignatureScheme::RSA_PSS_SHA256,
        ]
    }
}
