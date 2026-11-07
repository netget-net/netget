//! SMTP client implementation using lettre library
pub mod actions;

pub use actions::SmtpClientProtocol;

use anyhow::{Context, Result};
use lettre::transport::smtp::authentication::Credentials;
use lettre::transport::smtp::client::{Tls, TlsParameters};
use lettre::{SmtpTransport, Transport};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{error, info, trace};

use crate::client::llm_budget::call_llm_for_client;
use crate::client::smtp::actions::SMTP_CLIENT_CONNECTED_EVENT;
use crate::llm::actions::client_trait::{Client, ClientActionResult};
use crate::llm::ollama_client::OllamaClient;
use crate::llm::ClientLlmResult;
use crate::logging::emit::Log;
use crate::protocol::{Event, StartupParams};
use crate::state::app_state::AppState;
use crate::state::{ClientId, ClientStatus};

/// How often the idle task checks whether the client row is still there. The same task
/// drains injected commands, so this is a floor on shutdown latency, not on responsiveness.
const LIVENESS_INTERVAL: Duration = Duration::from_secs(5);

/// The session defaults taken from the declared startup parameters.
///
/// `username`, `password` and `use_tls` are declared in `get_startup_parameters()` and were
/// read by nothing at connect: `deliver` took all three off the *action* instead, so what the
/// caller passed when opening the client was discarded. Nothing failed loudly — a client
/// opened against a plaintext relay simply demanded STARTTLS on every message (the action's
/// own default is `true`) and every delivery was refused, and credentials supplied once at
/// connect had to be repeated by the model on every single `send_email` or no AUTH was sent.
///
/// They arrive on `ConnectContext::startup_params`. `ClientInstance::protocol_data` is not a
/// second source here: `cli/client_startup.rs` leaves it `Value::Null`, and the only keys this
/// client writes there are the ones it derives itself (`smtp_server`, `smtp_port`).
///
/// A value on the action still wins — the model may legitimately authenticate as someone else
/// for one message — so these are defaults, not overrides.
#[derive(Clone, Debug, Default)]
struct SmtpSettings {
    username: Option<String>,
    password: Option<String>,
    /// `None` means the caller said nothing; `deliver` then defaults to STARTTLS.
    use_tls: Option<bool>,
}

impl SmtpSettings {
    /// Read the three declared parameters, propagating a wrong-typed value rather than
    /// unwrapping it: over MCP an `unwrap` here kills the request task and hangs the caller.
    fn from_startup_params(params: Option<&StartupParams>) -> Result<Self> {
        let Some(params) = params else {
            return Ok(Self::default());
        };
        Ok(Self {
            username: params.get_optional_string("username")?,
            password: params.get_optional_string("password")?,
            use_tls: params.get_optional_bool("use_tls")?,
        })
    }
}

/// What one executed SMTP action did.
///
/// SMTP has no persistent socket here: `lettre` opens a connection per message. So an
/// "applied" action is a completed delivery, not bytes on a stream this client owns.
enum SmtpApplied {
    /// A message was accepted by the server.
    Delivered {
        to: Vec<String>,
        subject: String,
        endpoint: String,
    },
    /// The action asked to end the session.
    Disconnect,
    /// The action ran but sent nothing.
    Nothing(String),
}

/// SMTP client that sends emails via SMTP servers
pub struct SmtpClient;

impl SmtpClient {
    /// Connect to an SMTP server with integrated LLM actions
    pub async fn connect_with_llm_actions(
        remote_addr: String,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        client_id: ClientId,
        startup_params: Option<StartupParams>,
    ) -> Result<SocketAddr> {
        info!(
            "SMTP client {} initializing connection to {}",
            client_id, remote_addr
        );

        // Read before anything is registered, so a wrong-typed parameter becomes an `Error`
        // status on a client that never half-started.
        let settings = Arc::new(SmtpSettings::from_startup_params(startup_params.as_ref())?);

        // Parse server address (format: hostname:port or just hostname). The port is kept:
        // without it every message went to whatever `SmtpTransport::relay` defaults to, so a
        // client pointed at `host:2525` silently talked to a different port.
        let (smtp_server, smtp_port) = match remote_addr.rsplit_once(':') {
            Some((host, port)) => (host.to_string(), port.parse::<u16>().ok()),
            None => (remote_addr.clone(), None),
        };

        // Store connection info in protocol data
        app_state
            .with_client_mut(client_id, |client| {
                client
                    .set_protocol_field("smtp_server".to_string(), serde_json::json!(smtp_server));
                client.set_protocol_field("smtp_port".to_string(), serde_json::json!(smtp_port));
                client
                    .set_protocol_field("remote_addr".to_string(), serde_json::json!(remote_addr));
            })
            .await;

        // Update status to connected
        app_state
            .update_client_status(client_id, ClientStatus::Connected)
            .await;
        let _ = status_tx.send(format!(
            "[CLIENT] SMTP client {} ready for {}",
            client_id, remote_addr
        ));
        let _ = status_tx.send("__UPDATE_UI__".to_string());

        // The dashboard's `[ send ]` channel, registered — and drained — BEFORE the
        // connected-event LLM call below. A dashboard-created client defaults to a
        // `*` -> manual rule, so that call can park for minutes waiting for a human; the
        // operator has to be able to reach the client while it waits, which means the
        // draining task must already exist, not just the handle.
        let command_rx =
            crate::client::command_support::register_command_channel(&app_state, client_id).await;
        let command_task = tokio::spawn(Self::idle_and_command_loop(
            command_rx,
            client_id,
            llm_client.clone(),
            app_state.clone(),
            status_tx.clone(),
            settings.clone(),
        ));
        app_state
            .register_client_task(client_id, command_task)
            .await;

        // Call LLM with connected event
        if let Some(instruction) = app_state.get_instruction_for_client(client_id).await {
            let protocol = SmtpClientProtocol::new();
            let event = Event::new(
                &SMTP_CLIENT_CONNECTED_EVENT,
                serde_json::json!({
                    "smtp_server": smtp_server,
                }),
            );

            let memory = app_state
                .get_memory_for_client(client_id)
                .await
                .unwrap_or_default();

            match call_llm_for_client(
                &llm_client,
                &app_state,
                client_id.to_string(),
                &instruction,
                &memory,
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
                    // Update memory
                    if let Some(mem) = memory_updates {
                        app_state.set_memory_for_client(client_id, mem).await;
                    }

                    // Actions used to be discarded here (`actions: _`), which made
                    // `send_email` unreachable from every path: the model could ask for a
                    // message and nothing was ever sent. They go through the same
                    // `apply_action` an injected command uses.
                    for action in actions {
                        match Self::apply_action(client_id, &app_state, action, &settings).await {
                            Ok(applied) => {
                                Self::follow_up(
                                    applied,
                                    client_id,
                                    &llm_client,
                                    &app_state,
                                    &status_tx,
                                    &settings,
                                )
                                .await
                            }
                            Err(e) => {
                                error!(
                                    "SMTP client {} could not execute action after connect: {}",
                                    client_id, e
                                );
                            }
                        }
                    }
                }
                Err(e) => {
                    error!("LLM error for SMTP client {}: {}", client_id, e);
                }
            }
        }

        // Return a dummy local address (SMTP is request-based, not persistent)
        Ok("0.0.0.0:0".parse().unwrap())
    }

    /// Drain injected commands (the dashboard's `[ send ]`) and, on the same task, notice
    /// when the client row goes away.
    ///
    /// This replaced a bare 5-second `sleep` loop that did nothing but the liveness check.
    /// Both futures here are cancellation-safe (`mpsc::Receiver::recv` and `Interval::tick`),
    /// so a `select!` is correct and no separate task is needed.
    ///
    /// Outcome semantics: `lettre` opens its own connection per message and reports no byte
    /// count, so a delivered message is `Executed` naming the recipients and the endpoint,
    /// never `Sent`. A message the server refused is an `Err`.
    async fn idle_and_command_loop(
        mut command_rx: mpsc::Receiver<crate::state::client_handles::ClientCommand>,
        client_id: ClientId,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        settings: Arc<SmtpSettings>,
    ) {
        use crate::llm::actions::protocol_trait::Protocol;
        use crate::state::client_handles::ClientSendOutcome;
        use crate::state::AccessLogOwner;

        let protocol = SmtpClientProtocol::new();
        let mut liveness = tokio::time::interval(LIVENESS_INTERVAL);
        liveness.tick().await; // the first tick completes immediately

        loop {
            let command = tokio::select! {
                _ = liveness.tick() => {
                    if app_state.get_client(client_id).await.is_none() {
                        info!("SMTP client {} stopped", client_id);
                        break;
                    }
                    continue;
                }
                command = command_rx.recv() => match command {
                    Some(command) => command,
                    None => break,
                },
            };

            let action = command.action.clone();
            let mut applied_for_follow_up = None;
            let mut disconnect = false;

            let outcome: Result<ClientSendOutcome> =
                match Self::apply_action(client_id, &app_state, action.clone(), &settings).await {
                    Err(e) => Ok(ClientSendOutcome::Rejected {
                        error: e.to_string(),
                    }),
                    Ok(SmtpApplied::Disconnect) => {
                        disconnect = true;
                        Ok(ClientSendOutcome::Disconnected)
                    }
                    Ok(SmtpApplied::Nothing(detail)) => Ok(ClientSendOutcome::Executed { detail }),
                    Ok(SmtpApplied::Delivered {
                        to,
                        subject,
                        endpoint,
                    }) => {
                        let detail = format!(
                            "send_email '{}': accepted by {} for {} recipient(s)",
                            subject,
                            endpoint,
                            to.len()
                        );
                        applied_for_follow_up = Some(SmtpApplied::Delivered {
                            to,
                            subject,
                            endpoint,
                        });
                        Ok(ClientSendOutcome::Executed { detail })
                    }
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

            if let Err(e) = &outcome {
                Log::to(&status_tx).warn(format!(
                    "SMTP client {} injected action failed: {}",
                    client_id, e
                ));
            }
            let _ = status_tx.send("__UPDATE_UI__".to_string());
            crate::client::command_support::reply(command, outcome);

            if disconnect {
                app_state
                    .update_client_status(client_id, ClientStatus::Disconnected)
                    .await;
                break;
            }

            // The `smtp_email_sent` event goes to the model in its own task: a handler parked
            // for a human must not block the next injected command.
            if let Some(applied) = applied_for_follow_up {
                let llm_client = llm_client.clone();
                let state = app_state.clone();
                let tx = status_tx.clone();
                let settings = settings.clone();
                let handle = tokio::spawn(async move {
                    Self::follow_up(applied, client_id, &llm_client, &state, &tx, &settings).await;
                });
                app_state.register_client_task(client_id, handle).await;
            }
        }

        // Every exit lands here: drop the handle so the rail stops offering `[ send ]` on a
        // client nothing is draining any more.
        app_state.remove_client_handle(client_id).await;
        let _ = status_tx.send("__UPDATE_UI__".to_string());
    }

    /// Execute one action against the configured SMTP server.
    ///
    /// The single place `send_email` is turned into a delivery, shared by the connected-event
    /// path and by injected dashboard commands. It makes no LLM call of its own — that is
    /// [`Self::follow_up`]'s job — so the command loop can reply before the model reacts.
    async fn apply_action(
        client_id: ClientId,
        app_state: &Arc<AppState>,
        action: serde_json::Value,
        settings: &SmtpSettings,
    ) -> Result<SmtpApplied> {
        let protocol = SmtpClientProtocol::new();
        match protocol.execute_action(action)? {
            ClientActionResult::Custom { name, data } if name == "smtp_send_email" => {
                let to: Vec<String> = data
                    .get("to")
                    .and_then(|v| v.as_array())
                    .map(|a| {
                        a.iter()
                            .filter_map(|v| v.as_str().map(|s| s.to_string()))
                            .collect()
                    })
                    .unwrap_or_default();
                let subject = data
                    .get("subject")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string();

                let endpoint = Self::deliver(client_id, app_state, &data, settings).await?;
                Ok(SmtpApplied::Delivered {
                    to,
                    subject,
                    endpoint,
                })
            }
            ClientActionResult::Disconnect => Ok(SmtpApplied::Disconnect),
            ClientActionResult::WaitForMore => {
                Ok(SmtpApplied::Nothing("wait_for_more".to_string()))
            }
            other => Ok(SmtpApplied::Nothing(format!(
                "unsupported action result {other:?}"
            ))),
        }
    }

    /// Build the message and hand it to `lettre`. Returns the `host:port` it was accepted by.
    async fn deliver(
        client_id: ClientId,
        app_state: &Arc<AppState>,
        data: &serde_json::Value,
        settings: &SmtpSettings,
    ) -> Result<String> {
        use lettre::message::Message;

        let (smtp_server, smtp_port) = app_state
            .with_client_mut(client_id, |client| {
                (
                    client
                        .get_protocol_field("smtp_server")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                    client
                        .get_protocol_field("smtp_port")
                        .and_then(|v| v.as_u64())
                        .and_then(|p| u16::try_from(p).ok()),
                )
            })
            .await
            .context("SMTP client is no longer registered")?;
        let smtp_server = smtp_server.context("No SMTP server found")?;

        let from = data
            .get("from")
            .and_then(|v| v.as_str())
            .context("Missing 'from' field")?;
        let to: Vec<String> = data
            .get("to")
            .and_then(|v| v.as_array())
            .context("Missing 'to' field")?
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect();
        let subject = data
            .get("subject")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        let body = data
            .get("body")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        // The action wins where it says something; the startup parameters are the session
        // default; STARTTLS is the default of last resort. `execute_action` deliberately omits
        // a field the action did not carry, so "absent" here really means the model said
        // nothing rather than "the executor filled in `true` for it".
        let username = data
            .get("username")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .or_else(|| settings.username.clone());
        let password = data
            .get("password")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .or_else(|| settings.password.clone());
        let use_tls = data
            .get("use_tls")
            .and_then(|v| v.as_bool())
            .or(settings.use_tls)
            .unwrap_or(true);

        info!("SMTP client {} sending email to {:?}", client_id, to);

        let mut message_builder = Message::builder()
            .from(from.parse().context("Invalid 'from' address")?)
            .subject(subject);
        for recipient in &to {
            message_builder =
                message_builder.to(recipient.parse().context("Invalid 'to' address")?);
        }
        let email = message_builder
            .body(body)
            .context("Failed to build email message")?;

        let mut transport_builder =
            SmtpTransport::relay(&smtp_server).context("Failed to create SMTP transport")?;
        if let Some(port) = smtp_port {
            transport_builder = transport_builder.port(port);
        }

        if let (Some(user), Some(pass)) = (username, password) {
            transport_builder = transport_builder.credentials(Credentials::new(user, pass));
        }

        if use_tls {
            let tls_parameters = TlsParameters::builder(smtp_server.clone())
                .dangerous_accept_invalid_certs(false)
                .build()
                .context("Failed to build TLS parameters")?;
            transport_builder = transport_builder.tls(Tls::Required(tls_parameters));
        } else {
            transport_builder = transport_builder.tls(Tls::None);
        }

        let mailer = transport_builder.build();

        // `lettre`'s SmtpTransport is blocking.
        let response = tokio::task::spawn_blocking(move || mailer.send(&email))
            .await
            .context("Task join error")?
            .context("SMTP server refused the message")?;

        info!(
            "SMTP client {} sent email successfully: {:?}",
            client_id, response
        );

        Ok(match smtp_port {
            Some(port) => format!("{smtp_server}:{port}"),
            None => smtp_server,
        })
    }

    /// Raise `smtp_email_sent` for a delivered message and execute whatever the handler
    /// answers.
    async fn follow_up(
        applied: SmtpApplied,
        client_id: ClientId,
        llm_client: &OllamaClient,
        app_state: &Arc<AppState>,
        status_tx: &mpsc::UnboundedSender<String>,
        settings: &SmtpSettings,
    ) {
        let SmtpApplied::Delivered { to, subject, .. } = applied else {
            match applied {
                SmtpApplied::Disconnect => {
                    info!("SMTP client {} disconnecting", client_id);
                    app_state.remove_client_handle(client_id).await;
                    app_state
                        .update_client_status(client_id, ClientStatus::Disconnected)
                        .await;
                    let _ = status_tx.send("__UPDATE_UI__".to_string());
                }
                SmtpApplied::Nothing(detail) => {
                    trace!("SMTP client {} action sent nothing: {}", client_id, detail);
                }
                SmtpApplied::Delivered { .. } => unreachable!(),
            }
            return;
        };

        let _ = status_tx.send("[CLIENT] SMTP email sent successfully".to_string());

        let Some(instruction) = app_state.get_instruction_for_client(client_id).await else {
            return;
        };
        let protocol = SmtpClientProtocol::new();
        let event = Event::new(
            &crate::client::smtp::actions::SMTP_CLIENT_EMAIL_SENT_EVENT,
            serde_json::json!({
                "to": to,
                "subject": subject,
                "success": true,
            }),
        );

        let memory = app_state
            .get_memory_for_client(client_id)
            .await
            .unwrap_or_default();

        match call_llm_for_client(
            llm_client,
            app_state,
            client_id.to_string(),
            &instruction,
            &memory,
            Some(&event),
            &protocol,
            status_tx,
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
                for action in actions {
                    match Self::apply_action(client_id, app_state, action, settings).await {
                        Ok(applied) => {
                            Box::pin(Self::follow_up(
                                applied, client_id, llm_client, app_state, status_tx, settings,
                            ))
                            .await
                        }
                        Err(e) => {
                            error!("SMTP client {} follow-up action failed: {}", client_id, e)
                        }
                    }
                }
            }
            Err(e) => {
                error!("LLM error for SMTP client {}: {}", client_id, e);
            }
        }
    }
}
