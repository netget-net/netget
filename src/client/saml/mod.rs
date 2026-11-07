//! SAML client implementation
pub mod actions;

pub use actions::SamlClientProtocol;

use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{error, info};

use crate::client::llm_budget::call_llm_for_client;
use crate::client::saml::actions::{
    SAML_CLIENT_CONNECTED_EVENT, SAML_CLIENT_RESPONSE_RECEIVED_EVENT,
};
use crate::llm::actions::client_trait::{Client, ClientActionResult};
use crate::llm::ollama_client::OllamaClient;
use crate::llm::ClientLlmResult;
use crate::logging::emit::Log;
use crate::protocol::{Event, StartupParams};
use crate::state::app_state::AppState;
use crate::state::client_handles::{ClientCommand, ClientSendOutcome};
use crate::state::{AccessLogOwner, ClientId, ClientStatus};

/// What [`SamlClient::apply_action`] did with one executed action. SAML rides on HTTP
/// bindings rather than a socket NetGet owns, so no byte count can honestly be reported.
enum Applied {
    /// The action ran; the string describes the effect.
    Ran(String),
    /// The action asked to end the session.
    Disconnect,
}

/// Whether an event is reported to the LLM inline or from its own task.
///
/// Public because `initiate_sso` / `validate_assertion` are: both are entry points a caller
/// outside this module can drive, and both have to say which way the resulting event goes.
#[derive(Clone, Copy)]
pub enum Dispatch {
    /// Raise it here and now. Used by the connected-event LLM path.
    Inline,
    /// Hand it to a registered task. Used by the injected-command loop, so a manual
    /// (human-answered) routing rule on `saml_response_received` cannot hold up the
    /// command's outcome, or the next injected command.
    Deferred,
}

/// The Service Provider side of the configuration, as the caller declared it.
///
/// `entity_id`, `acs_url` and `binding` are declared startup parameters and arrive on
/// `ConnectContext::startup_params`. They are resolved once, at connect, and written into
/// `protocol_data` -- which is where every later step reads them from, and which
/// `cli/client_startup.rs` leaves `Value::Null` until someone writes it.
struct SamlConfig {
    entity_id: String,
    acs_url: String,
    binding: String,
}

impl SamlConfig {
    /// NetGet's own placeholder SP identity, used when the caller names none.
    const DEFAULT_ENTITY_ID: &'static str = "urn:netget:sp";
    /// Placeholder ACS URL, likewise.
    const DEFAULT_ACS_URL: &'static str = "http://localhost:8080/saml/acs";

    fn resolve(params: Option<&StartupParams>) -> Result<Self> {
        let (entity_id, acs_url, binding) = match params {
            Some(params) => (
                params.get_optional_string("entity_id")?,
                params.get_optional_string("acs_url")?,
                params.get_optional_string("binding")?,
            ),
            None => (None, None, None),
        };

        // Refused rather than silently reinterpreted. `build_sso_request` treats anything that
        // is not exactly "redirect" as HTTP-POST, so "Redirect" or a typo would quietly change
        // the binding -- an advertised knob doing something other than what it says is worse
        // than one that does nothing.
        let binding = match binding {
            None => "redirect".to_string(),
            Some(value) => match value.trim().to_ascii_lowercase().as_str() {
                "redirect" => "redirect".to_string(),
                "post" => "post".to_string(),
                _ => {
                    return Err(anyhow::anyhow!(
                        "startup parameter 'binding' must be \"redirect\" or \"post\", got {:?}",
                        value
                    ))
                }
            },
        };

        Ok(Self {
            entity_id: entity_id.unwrap_or_else(|| Self::DEFAULT_ENTITY_ID.to_string()),
            acs_url: acs_url.unwrap_or_else(|| Self::DEFAULT_ACS_URL.to_string()),
            binding,
        })
    }
}

/// SAML client that authenticates with a SAML Identity Provider
pub struct SamlClient;

impl SamlClient {
    /// Connect to a SAML IdP with integrated LLM actions
    pub async fn connect_with_llm_actions(
        remote_addr: String,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        client_id: ClientId,
        startup_params: Option<StartupParams>,
    ) -> Result<SocketAddr> {
        // For SAML, "connection" is logical - we're preparing to authenticate
        // The actual communication happens via HTTP requests to the IdP

        info!(
            "SAML client {} initialized for IdP: {}",
            client_id, remote_addr
        );

        // The three declared parameters. They used to be written here as *hardcoded*
        // placeholders, under a comment saying they could be "overridden by startup params" --
        // and `ctx.startup_params` was dropped, so nothing could override them. What the
        // caller passed was silently replaced by `urn:netget:sp` and
        // `http://localhost:8080/saml/acs`, which are the SP identity the AuthnRequest claims
        // and the address it asks the IdP to post the assertion to. Errors propagate: a
        // wrong-typed value must name itself, not panic the task that is starting the client.
        let config = SamlConfig::resolve(startup_params.as_ref())?;

        // Store the IdP URL and the resolved SP configuration in protocol_data. Everything
        // downstream (`build_sso_request`) reads it back from there.
        app_state
            .with_client_mut(client_id, |client| {
                client.set_protocol_field(
                    "saml_client".to_string(),
                    serde_json::json!("initialized"),
                );
                client.set_protocol_field("idp_url".to_string(), serde_json::json!(remote_addr));
                client.set_protocol_field(
                    "entity_id".to_string(),
                    serde_json::json!(config.entity_id),
                );
                client.set_protocol_field("acs_url".to_string(), serde_json::json!(config.acs_url));
                client.set_protocol_field("binding".to_string(), serde_json::json!(config.binding));
            })
            .await;

        // Update status
        app_state
            .update_client_status(client_id, ClientStatus::Connected)
            .await;
        let _ = status_tx.send(format!(
            "[CLIENT] SAML client {} ready for IdP: {}",
            client_id, remote_addr
        ));
        let _ = status_tx.send("__UPDATE_UI__".to_string());

        // Command channel for injected actions (the dashboard's [ initiate_sso ] /
        // [ validate_assertion ] / [ disconnect ]). Registered BEFORE the connected-event
        // LLM call below, which is awaited inline and which a manual `*` routing rule can
        // park for minutes - the operator must be able to act while it waits.
        let command_rx =
            crate::client::command_support::register_command_channel(&app_state, client_id).await;
        let cmd_task = tokio::spawn(Self::command_loop(
            command_rx,
            client_id,
            app_state.clone(),
            llm_client.clone(),
            status_tx.clone(),
        ));
        app_state.register_client_task(client_id, cmd_task).await;

        // Call LLM with saml_connected event
        if let Some(instruction) = app_state.get_instruction_for_client(client_id).await {
            let event = Event::new(
                &SAML_CLIENT_CONNECTED_EVENT,
                serde_json::json!({
                    "idp_url": remote_addr.clone(),
                }),
            );

            match call_llm_for_client(
                &llm_client,
                &app_state,
                client_id.to_string(),
                &instruction,
                &String::new(),
                Some(&event),
                &crate::client::saml::actions::SamlClientProtocol,
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

                    // Execute the model's actions through the same path injected commands
                    // use. They used to be dropped on the floor here.
                    let protocol = crate::client::saml::actions::SamlClientProtocol;
                    for action in actions {
                        let result = match protocol.execute_action(action) {
                            Ok(result) => result,
                            Err(e) => {
                                error!("SAML client {} rejected action: {}", client_id, e);
                                continue;
                            }
                        };
                        match Self::apply_action(
                            result,
                            Dispatch::Inline,
                            client_id,
                            &app_state,
                            &llm_client,
                            &status_tx,
                        )
                        .await
                        {
                            Ok(Applied::Ran(detail)) => {
                                info!("SAML client {}: {}", client_id, detail)
                            }
                            Ok(Applied::Disconnect) => {
                                app_state.remove_client_handle(client_id).await;
                                let _ = status_tx.send("__UPDATE_UI__".to_string());
                                return Ok("0.0.0.0:0".parse().unwrap());
                            }
                            Err(e) => {
                                error!("SAML client {} action failed: {}", client_id, e);
                            }
                        }
                    }
                }
                Err(e) => {
                    error!("LLM error on saml_connected event: {}", e);
                }
            }
        }

        // No idle-poll task: the command loop is this client's long-lived task and it ends
        // when the client is removed (`remove_client` drops the command sender).

        // Return a dummy local address (SAML is HTTP-based)
        Ok("0.0.0.0:0".parse().unwrap())
    }

    /// Run one executed action. Shared by the connected-event LLM path and injected
    /// commands so each verb's implementation exists exactly once.
    async fn apply_action(
        result: ClientActionResult,
        dispatch: Dispatch,
        client_id: ClientId,
        app_state: &Arc<AppState>,
        llm_client: &OllamaClient,
        status_tx: &mpsc::UnboundedSender<String>,
    ) -> Result<Applied> {
        match result {
            ClientActionResult::Custom { name, data } if name == "saml_initiate_sso" => {
                let relay_state = data
                    .get("relay_state")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let force_authn = data
                    .get("force_authn")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);

                Self::initiate_sso(
                    client_id,
                    relay_state,
                    force_authn,
                    app_state.clone(),
                    llm_client.clone(),
                    status_tx.clone(),
                    dispatch,
                )
                .await?;

                // The AuthnRequest is carried by the user's browser, not by NetGet: report
                // the URL that was built rather than any byte count.
                let sso_url = app_state
                    .with_client_mut(client_id, |client| {
                        client
                            .get_protocol_field("sso_url")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string())
                    })
                    .await
                    .flatten();
                Ok(Applied::Ran(match sso_url {
                    Some(url) => format!("saml_initiate_sso: AuthnRequest built, SSO URL {}", url),
                    None => "saml_initiate_sso: AuthnRequest built".to_string(),
                }))
            }
            ClientActionResult::Custom { name, data } if name == "saml_validate_assertion" => {
                let saml_response = data
                    .get("saml_response")
                    .and_then(|v| v.as_str())
                    .context("Missing 'saml_response' in saml_validate_assertion")?
                    .to_string();

                Self::validate_assertion(
                    client_id,
                    saml_response,
                    app_state.clone(),
                    llm_client.clone(),
                    status_tx.clone(),
                    dispatch,
                )
                .await?;
                Ok(Applied::Ran(
                    "saml_validate_assertion: response parsed and reported".to_string(),
                ))
            }
            ClientActionResult::Custom { name, data } if name == "saml_parse_assertion" => {
                let response_xml = data
                    .get("response_xml")
                    .and_then(|v| v.as_str())
                    .context("Missing 'response_xml' in saml_parse_assertion")?
                    .to_string();

                let (success, status_code, assertion_data, attributes) =
                    Self::parse_saml_response(&response_xml)?;
                Self::notify_parsed_response(
                    client_id,
                    success,
                    &status_code,
                    assertion_data,
                    attributes,
                    app_state,
                    llm_client,
                    status_tx,
                    dispatch,
                )
                .await;
                Ok(Applied::Ran(format!(
                    "saml_parse_assertion: status {} (success={})",
                    status_code, success
                )))
            }
            ClientActionResult::Disconnect => {
                info!("SAML client {} disconnecting", client_id);
                app_state
                    .update_client_status(client_id, ClientStatus::Disconnected)
                    .await;
                let _ = status_tx.send("__UPDATE_UI__".to_string());
                Ok(Applied::Disconnect)
            }
            ClientActionResult::Custom { name, .. } => Err(anyhow::anyhow!(
                "SAML client cannot execute custom result '{}'",
                name
            )),
            // WaitForMore / NoAction / SendData / nested Multiple: nothing to do.
            _ => Ok(Applied::Ran(
                "no SAML operation performed (action produced no request)".to_string(),
            )),
        }
    }

    /// Drain injected commands until the channel closes (the client was removed) or an
    /// injected `disconnect` ends the session. Each operation is awaited, so the reported
    /// [`ClientSendOutcome`] describes work that really completed; a failure is reported as
    /// an error, never as a success, and nothing here can invent an assertion or a session.
    async fn command_loop(
        mut command_rx: mpsc::Receiver<ClientCommand>,
        client_id: ClientId,
        app_state: Arc<AppState>,
        llm_client: OllamaClient,
        status_tx: mpsc::UnboundedSender<String>,
    ) {
        use crate::llm::actions::protocol_trait::Protocol;

        let protocol = crate::client::saml::actions::SamlClientProtocol;

        while let Some(command) = command_rx.recv().await {
            let action = command.action.clone();
            let outcome = match protocol.execute_action(action.clone()) {
                Err(e) => Ok(ClientSendOutcome::Rejected {
                    error: e.to_string(),
                }),
                Ok(result) => Self::apply_action(
                    result,
                    Dispatch::Deferred,
                    client_id,
                    &app_state,
                    &llm_client,
                    &status_tx,
                )
                .await
                .map(|applied| match applied {
                    Applied::Disconnect => ClientSendOutcome::Disconnected,
                    Applied::Ran(detail) => ClientSendOutcome::Executed { detail },
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
                Log::to(&status_tx).warn(format!(
                    "SAML client {} injected action failed: {}",
                    client_id, e
                ));
            }
            let _ = status_tx.send("__UPDATE_UI__".to_string());
            crate::client::command_support::reply(command, outcome);

            if disconnect {
                break;
            }
        }

        app_state.remove_client_handle(client_id).await;
        let _ = status_tx.send("__UPDATE_UI__".to_string());
        info!("SAML client {} command loop ended", client_id);
    }

    /// Initiate SAML SSO authentication
    #[allow(clippy::too_many_arguments)]
    /// Build the AuthnRequest and SSO URL and store them. Raises no event, calls no LLM.
    ///
    /// Split out so a follow-up action the model returns for a SAML event can run without
    /// re-entering `notify_event`. That path would otherwise be mutually recursive --
    /// notify_event -> apply_action -> initiate_sso -> notify_event -- which rustc rejects
    /// while inferring the async types, quite apart from letting one SSO drive the model
    /// round in circles.
    pub async fn build_sso_request(
        client_id: ClientId,
        relay_state: Option<String>,
        force_authn: bool,
        app_state: &Arc<AppState>,
    ) -> Result<(String, String, String)> {
        info!("SAML client {} initiating SSO", client_id);

        // Get IdP URL and SP configuration from client
        let config_opt = app_state
            .with_client_mut(client_id, |client| {
                let idp = client
                    .get_protocol_field("idp_url")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let entity = client
                    .get_protocol_field("entity_id")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let acs = client
                    .get_protocol_field("acs_url")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let bind = client
                    .get_protocol_field("binding")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                (idp, entity, acs, bind)
            })
            .await;

        let (idp_url, entity_id, acs_url, binding) = config_opt.context("Client not found")?;

        let idp_url = idp_url.context("No IdP URL found")?;
        let entity_id = entity_id.unwrap_or_else(|| SamlConfig::DEFAULT_ENTITY_ID.to_string());
        let acs_url = acs_url.unwrap_or_else(|| SamlConfig::DEFAULT_ACS_URL.to_string());
        let binding = binding.unwrap_or_else(|| "redirect".to_string());

        // Generate SAML AuthnRequest
        let request_id = format!("_{}", uuid::Uuid::new_v4());
        let timestamp = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();

        let authn_request = Self::generate_authn_request(
            &request_id,
            &timestamp,
            &entity_id,
            &acs_url,
            force_authn,
        );

        info!("Generated SAML AuthnRequest with ID: {}", request_id);

        // For HTTP-Redirect binding, we need to deflate and base64 encode
        let encoded_request = if binding == "redirect" {
            Self::encode_request_redirect(&authn_request)?
        } else {
            // HTTP-POST binding uses base64 only
            base64::engine::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                authn_request.as_bytes(),
            )
        };

        // Build SSO URL
        let mut sso_url = format!("{}?SAMLRequest={}", idp_url, encoded_request);
        if let Some(state) = &relay_state {
            sso_url.push_str(&format!("&RelayState={}", urlencoding::encode(state)));
        }

        info!("SAML SSO URL generated: {}", sso_url);

        // Store request ID for validation
        app_state
            .with_client_mut(client_id, |client| {
                client.set_protocol_field("request_id".to_string(), serde_json::json!(request_id));
                client
                    .set_protocol_field("sso_url".to_string(), serde_json::json!(sso_url.clone()));
            })
            .await;

        Ok((idp_url, sso_url, request_id))
    }

    pub async fn initiate_sso(
        client_id: ClientId,
        relay_state: Option<String>,
        force_authn: bool,
        app_state: Arc<AppState>,
        llm_client: OllamaClient,
        status_tx: mpsc::UnboundedSender<String>,
        dispatch: Dispatch,
    ) -> Result<()> {
        let (idp_url, sso_url, request_id) =
            Self::build_sso_request(client_id, relay_state, force_authn, &app_state).await?;

        // Notify LLM about SSO URL
        let event = Event::new(
            &SAML_CLIENT_CONNECTED_EVENT,
            serde_json::json!({
                "idp_url": idp_url,
                "sso_url": sso_url,
                "request_id": request_id,
            }),
        );
        Self::notify_event(
            client_id,
            event,
            dispatch,
            &app_state,
            &llm_client,
            &status_tx,
        )
        .await;

        Ok(())
    }

    /// Validate SAML assertion from IdP response
    pub async fn validate_assertion(
        client_id: ClientId,
        saml_response: String,
        app_state: Arc<AppState>,
        llm_client: OllamaClient,
        status_tx: mpsc::UnboundedSender<String>,
        dispatch: Dispatch,
    ) -> Result<()> {
        info!("SAML client {} validating assertion", client_id);

        // Decode base64 SAML response
        let decoded = base64::engine::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            saml_response.as_bytes(),
        )
        .context("Failed to decode SAML response")?;

        let response_xml =
            String::from_utf8(decoded).context("Failed to parse SAML response as UTF-8")?;

        // Parse SAML response
        let (success, status_code, assertion_data, attributes) =
            Self::parse_saml_response(&response_xml)?;

        info!(
            "SAML response parsed - Success: {}, Status: {}",
            success, status_code
        );

        Self::notify_parsed_response(
            client_id,
            success,
            &status_code,
            assertion_data,
            attributes,
            &app_state,
            &llm_client,
            &status_tx,
            dispatch,
        )
        .await;

        Ok(())
    }

    /// Raise `saml_response_received` for an already-parsed IdP response. Shared by
    /// `validate_assertion` (base64 wrapper) and the `parse_assertion` action (raw XML), so
    /// both report the same event shape.
    #[allow(clippy::too_many_arguments)]
    async fn notify_parsed_response(
        client_id: ClientId,
        success: bool,
        status_code: &str,
        assertion_data: Option<serde_json::Value>,
        attributes: Option<serde_json::Value>,
        app_state: &Arc<AppState>,
        llm_client: &OllamaClient,
        status_tx: &mpsc::UnboundedSender<String>,
        dispatch: Dispatch,
    ) {
        let event = Event::new(
            &SAML_CLIENT_RESPONSE_RECEIVED_EVENT,
            serde_json::json!({
                "success": success,
                "status_code": status_code,
                "assertion": assertion_data,
                "attributes": attributes,
            }),
        );
        Self::notify_event(client_id, event, dispatch, app_state, llm_client, status_tx).await;
    }

    /// Report one event to the LLM, inline or from a registered task.
    async fn notify_event(
        client_id: ClientId,
        event: Event,
        dispatch: Dispatch,
        app_state: &Arc<AppState>,
        llm_client: &OllamaClient,
        status_tx: &mpsc::UnboundedSender<String>,
    ) {
        match dispatch {
            Dispatch::Inline => {
                Self::raise_event(
                    client_id,
                    event,
                    app_state.clone(),
                    llm_client.clone(),
                    status_tx.clone(),
                )
                .await
            }
            Dispatch::Deferred => {
                let handle = tokio::spawn(Self::raise_event(
                    client_id,
                    event,
                    app_state.clone(),
                    llm_client.clone(),
                    status_tx.clone(),
                ));
                // Registered so stop_client aborts an in-flight LLM call for this event.
                app_state.register_client_task(client_id, handle).await;
            }
        }
    }

    /// The event -> LLM round-trip itself.
    async fn raise_event(
        client_id: ClientId,
        event: Event,
        app_state: Arc<AppState>,
        llm_client: OllamaClient,
        status_tx: mpsc::UnboundedSender<String>,
    ) {
        let Some(instruction) = app_state.get_instruction_for_client(client_id).await else {
            return;
        };

        let protocol = Arc::new(crate::client::saml::actions::SamlClientProtocol::new());
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
            protocol.as_ref(),
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

                // Execute what the model asked for. These were discarded, so answering a
                // SAML event did nothing -- a model that read an IdP response and wanted
                // to start a fresh AuthnRequest (a re-authentication, which is exactly
                // what force_authn exists for) was silently ignored.
                //
                // Dispatch goes through `build_sso_request`, which does the work and
                // raises no event. Calling `initiate_sso` here instead would be mutually
                // recursive -- notify_event -> apply_action -> initiate_sso ->
                // notify_event -- which rustc rejects while inferring the async types,
                // quite apart from letting one SSO drive the model round in circles.
                use crate::llm::actions::client_trait::{Client, ClientActionResult};
                for action in actions {
                    let Ok(ClientActionResult::Custom { name, data }) =
                        protocol.execute_action(action.clone())
                    else {
                        continue;
                    };
                    if name != "saml_initiate_sso" {
                        info!(
                            "SAML client {} follow-up '{}' has no non-notifying path; skipped",
                            client_id, name
                        );
                        continue;
                    }
                    let relay_state = data
                        .get("relay_state")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    let force_authn = data
                        .get("force_authn")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    match Self::build_sso_request(client_id, relay_state, force_authn, &app_state)
                        .await
                    {
                        Ok((_, sso_url, _)) => info!(
                            "SAML client {} follow-up built SSO URL {}",
                            client_id, sso_url
                        ),
                        Err(e) => error!(
                            "SAML client {} follow-up saml_initiate_sso failed: {}",
                            client_id, e
                        ),
                    }
                }
            }
            Err(e) => {
                error!("LLM error for SAML client {}: {}", client_id, e);
            }
        }
    }

    /// Generate SAML AuthnRequest XML
    fn generate_authn_request(
        request_id: &str,
        timestamp: &str,
        issuer: &str,
        acs_url: &str,
        force_authn: bool,
    ) -> String {
        format!(
            r#"<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{}" Version="2.0" IssueInstant="{}" ForceAuthn="{}" IsPassive="false" AssertionConsumerServiceURL="{}">
  <saml:Issuer>{}</saml:Issuer>
  <samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified" AllowCreate="true"/>
</samlp:AuthnRequest>"#,
            request_id, timestamp, force_authn, acs_url, issuer
        )
    }

    /// Encode SAML request for HTTP-Redirect binding
    fn encode_request_redirect(request: &str) -> Result<String> {
        use flate2::write::DeflateEncoder;
        use flate2::Compression;
        use std::io::Write;

        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
        encoder
            .write_all(request.as_bytes())
            .context("Failed to deflate SAML request")?;
        let deflated = encoder.finish().context("Failed to finish deflation")?;

        let encoded =
            base64::engine::Engine::encode(&base64::engine::general_purpose::STANDARD, deflated);

        Ok(urlencoding::encode(&encoded).to_string())
    }

    /// Parse SAML response XML
    fn parse_saml_response(
        response_xml: &str,
    ) -> Result<(
        bool,
        String,
        Option<serde_json::Value>,
        Option<serde_json::Value>,
    )> {
        use quick_xml::events::Event;
        use quick_xml::Reader;

        let mut reader = Reader::from_str(response_xml);
        reader.config_mut().trim_text(true);

        let mut status_code = "urn:oasis:names:tc:SAML:2.0:status:Unknown".to_string();
        // The only value that means the IdP authenticated the subject (SAML 2.0 Core 3.2.2.2).
        const STATUS_SUCCESS: &str = "urn:oasis:names:tc:SAML:2.0:status:Success";
        let mut subject = None;
        let mut attributes = serde_json::Map::new();
        let mut in_attribute = false;
        let mut current_attr_name = None;

        let mut buf = Vec::new();
        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(ref e)) => {
                    // `local_name()` strips the namespace prefix. Matching the raw qualified
                    // name only recognised the `saml:` prefix, so a document using `saml2:`
                    // or `sa:` - both perfectly conforming, and `saml2:` is what ADFS and
                    // Shibboleth emit - parsed as if it had no subject and no attributes.
                    match e.local_name().as_ref() {
                        b"Attribute" => {
                            in_attribute = true;
                            // Extract attribute name
                            for attr in e.attributes() {
                                if let Ok(attr) = attr {
                                    if attr.key.as_ref() == b"Name" {
                                        if let Ok(value) =
                                            attr.decode_and_unescape_value(reader.decoder())
                                        {
                                            current_attr_name = Some(value.to_string());
                                        }
                                    }
                                }
                            }
                        }
                        b"NameID" => {
                            // Read subject
                            if let Ok(Event::Text(e)) = reader.read_event_into(&mut buf) {
                                if let Ok(text) = e.unescape() {
                                    subject = Some(text.to_string());
                                }
                            }
                        }
                        _ => {}
                    }
                }
                Ok(Event::Empty(ref e)) => {
                    if e.local_name().as_ref() == b"StatusCode" {
                        // Extract status code
                        for attr in e.attributes() {
                            if let Ok(attr) = attr {
                                if attr.key.as_ref() == b"Value" {
                                    if let Ok(value) =
                                        attr.decode_and_unescape_value(reader.decoder())
                                    {
                                        status_code = value.to_string();
                                    }
                                }
                            }
                        }
                    }
                }
                Ok(Event::End(ref e)) => match e.local_name().as_ref() {
                    b"Attribute" => {
                        in_attribute = false;
                        current_attr_name = None;
                    }
                    _ => {}
                },
                Ok(Event::Text(e)) => {
                    if in_attribute {
                        if let Some(name) = &current_attr_name {
                            if let Ok(text) = e.unescape() {
                                attributes
                                    .insert(name.clone(), serde_json::json!(text.to_string()));
                            }
                        }
                    }
                }
                Ok(Event::Eof) => break,
                Err(e) => return Err(anyhow::anyhow!("XML parse error: {}", e)),
                _ => {}
            }
            buf.clear();
        }

        // Exact match, not `status_code.contains("Success")`.
        //
        // The StatusCode Value is chosen by whoever sent the response - which on this path is
        // an unauthenticated peer, since nothing here verifies a signature. `contains` is
        // satisfied by `...:status:NotSuccess`, by `Success-denied`, by any string with those
        // seven characters anywhere in it. The model reads `success` to decide whether to
        // treat the subject as signed in, so a substring test on an attacker-controlled field
        // was an affirmative default on the one field that matters.
        //
        // SAML 2.0 Core 3.2.2.2 defines exactly one success value; a nested second-level
        // StatusCode never carries it.
        let success = status_code == STATUS_SUCCESS;

        let assertion_data = if success {
            Some(serde_json::json!({
                "subject": subject,
                "status_code": status_code.clone(),
            }))
        } else {
            None
        };

        let attrs = if !attributes.is_empty() {
            Some(serde_json::Value::Object(attributes))
        } else {
            None
        };

        Ok((success, status_code, assertion_data, attrs))
    }
}
