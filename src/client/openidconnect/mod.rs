//! OpenID Connect client implementation
pub mod actions;

pub use actions::OpenIdConnectClientProtocol;

use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{error, info};
use urlencoding;

use crate::client::http_fetch::FetchClient;
use crate::client::llm_budget::call_llm_for_client;
use crate::client::openidconnect::actions::{
    OIDC_CLIENT_DISCOVERED_EVENT, OIDC_CLIENT_TOKEN_RECEIVED_EVENT,
    OIDC_CLIENT_USERINFO_RECEIVED_EVENT,
};
use crate::llm::actions::client_trait::ClientActionResult;
use crate::llm::ollama_client::OllamaClient;
use crate::llm::ClientLlmResult;
use crate::logging::emit::Log;
use crate::protocol::Event;
use crate::state::app_state::AppState;
use crate::state::client_handles::{ClientCommand, ClientSendOutcome};
use crate::state::{AccessLogOwner, ClientId, ClientStatus};

/// The HTTP function the `openidconnect` crate is handed for every request it makes. Natively it is
/// the crate's own reqwest `async_http_client`, unchanged.
#[cfg(not(target_arch = "wasm32"))]
use openidconnect::reqwest::async_http_client as http_hook;

/// The HTTP function the `openidconnect` crate is handed in the browser build. The crate's own
/// `async_http_client` is reqwest's `fetch` backend there, which cannot reach the page's virtual
/// loopback, so each request goes through the shared hyper transport
/// ([`crate::client::http_fetch`]) instead: 30 seconds an exchange, 8 MiB of body, no redirects
/// (the crate's own client follows none either), and `https://` refused with the reason.
#[cfg(target_arch = "wasm32")]
async fn http_hook(
    request: openidconnect::HttpRequest,
) -> std::result::Result<openidconnect::HttpResponse, crate::client::http_fetch::FetchError> {
    let client = FetchClient::transport(std::time::Duration::from_secs(30));
    let headers = request
        .headers
        .iter()
        .map(|(name, value)| (name.as_str().to_string(), value.as_bytes().to_vec()))
        .collect();
    let (status, headers, body) = crate::client::http_fetch::round_trip_parts(
        &client,
        request.method.as_str(),
        request.url.as_str(),
        headers,
        request.body,
    )
    .await?;
    let mut map = openidconnect::http::HeaderMap::new();
    for (name, value) in headers {
        if let (Ok(name), Ok(value)) = (
            openidconnect::http::header::HeaderName::from_bytes(name.as_bytes()),
            openidconnect::http::HeaderValue::from_bytes(&value),
        ) {
            map.append(name, value);
        }
    }
    let status_code = openidconnect::http::StatusCode::from_u16(status).map_err(|e| {
        crate::client::http_fetch::FetchError(anyhow::anyhow!("status {status}: {e}"))
    })?;
    Ok(openidconnect::HttpResponse {
        status_code,
        headers: map,
        body: body.to_vec(),
    })
}

/// The HTTP client for the requests this client writes itself (device-code polling, the
/// authorization-code callback's exchange): a fresh reqwest client natively, as before, and the
/// shared hyper transport in the browser build, bounded at 30 seconds.
fn plain_http_client() -> FetchClient {
    #[cfg(not(target_arch = "wasm32"))]
    let client = FetchClient::from_reqwest(reqwest::Client::new());
    #[cfg(target_arch = "wasm32")]
    let client = FetchClient::transport(std::time::Duration::from_secs(30));
    client
}

use openidconnect::{
    core::{CoreClient, CoreProviderMetadata, CoreTokenResponse, CoreUserInfoClaims},
    ClientId as OidcClientId, ClientSecret, IssuerUrl, OAuth2TokenResponse, ResourceOwnerPassword,
    ResourceOwnerUsername, Scope,
};

/// What [`OpenIdConnectClient::apply_action`] did with one executed action.
///
/// Every OIDC flow is HTTPS request/response through the `openidconnect` crate, so NetGet
/// owns no socket whose byte count could be reported. The description is built from what is
/// observably true afterwards - in particular whether a token was actually stored - so a
/// flow that failed can never read as a success, and nothing here can invent a token.
enum Applied {
    /// The action ran; the string describes the effect.
    Ran(String),
    /// The action asked to end the session.
    Disconnect,
}

/// Whether an event is reported to the LLM inline or from its own task.
#[derive(Clone, Copy)]
enum Dispatch {
    /// Raise it here and now. Used by the LLM path and by the flows' own spawned tasks.
    Inline,
    /// Hand it to a registered task. Used by the injected-command loop, so a manual
    /// (human-answered) routing rule on `oidc_token_received` / `oidc_userinfo_received`
    /// cannot hold up the command's outcome, or the next injected command.
    Deferred,
}

/// OpenID Connect client that handles OAuth2/OIDC authentication flows
pub struct OpenIdConnectClient;

impl OpenIdConnectClient {
    /// Connect to an OpenID Connect provider with integrated LLM actions
    pub async fn connect_with_llm_actions(
        remote_addr: String,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        client_id: ClientId,
        startup_params: Option<crate::protocol::StartupParams>,
    ) -> Result<SocketAddr> {
        info!(
            "OpenID Connect client {} initializing for {}",
            client_id, remote_addr
        );

        // `flow` names the OAuth2/OIDC flow to run, and nothing read it: the flow was
        // whichever action the model happened to choose, so an operator who asked for
        // `client_credentials` could get a device-code prompt instead. It is resolved here
        // into the action that runs once discovery has completed.
        //
        // `password` is refused rather than silently ignored: it needs a username and a
        // password, which are per-action parameters this client deliberately does not
        // declare at startup, so there is no value of `flow` alone that could start it.
        let (flow, startup_scopes) = match &startup_params {
            Some(params) => (
                params.get_optional_string("flow")?,
                params.get_optional_string("scopes")?,
            ),
            None => (None, None),
        };
        let flow_action = match flow.as_deref() {
            None => None,
            Some("device_code") => Some(serde_json::json!({
                "type": "start_device_flow", "scopes": startup_scopes })),
            Some("authorization_code") => Some(serde_json::json!({
                "type": "start_authorization_code_flow", "scopes": startup_scopes })),
            Some("client_credentials") => Some(serde_json::json!({
                "type": "exchange_client_credentials", "scopes": startup_scopes })),
            Some("password") => {
                return Err(anyhow::anyhow!(
                    "OpenID Connect client: `flow: \"password\"` cannot be started from \
                     startup parameters - the resource-owner password flow needs a username \
                     and a password, and this client only accepts those on the \
                     `exchange_password` action. Drive it with that action (the dashboard's \
                     [ exchange_password ] row, or an instruction telling the model to use \
                     it) and leave `flow` unset."
                ));
            }
            Some(other) => {
                return Err(anyhow::anyhow!(
                    "OpenID Connect client: unknown `flow` value '{other}'. Expected one of \
                     device_code, authorization_code, client_credentials (password is \
                     action-driven; see the error for flow=\"password\")."
                ));
            }
        };

        // In the browser build the transport has no TLS: an `https://` provider is refused here,
        // with the reason, rather than inside discovery.
        crate::client::http_fetch::check_url(&remote_addr)?;

        // Store provider URL in protocol_data, and seed the startup params alongside it.
        // Every OIDC flow reads `client_id` / `client_secret` out of `protocol_data`, but
        // the generic creation path (dashboard form, MCP, `open_client`) only stores the
        // validated startup params on the client and leaves `protocol_data` empty - so a
        // client created that way arrived here unconfigured.
        app_state
            .with_client_mut(client_id, |client| {
                if let Some(serde_json::Value::Object(params)) = client.startup_params.clone() {
                    for (key, value) in params {
                        if client.get_protocol_field(&key).is_none() {
                            client.set_protocol_field(key, value);
                        }
                    }
                }
                client
                    .set_protocol_field("provider_url".to_string(), serde_json::json!(remote_addr));
            })
            .await;

        // Update status
        app_state
            .update_client_status(client_id, ClientStatus::Connected)
            .await;
        Log::new(Some(&status_tx)).info(format!(
            "OpenID Connect client {} ready for {}",
            client_id, remote_addr
        ));
        let _ = status_tx.send("__UPDATE_UI__".to_string());

        // Command channel for injected actions (the dashboard's [ exchange_password ],
        // [ fetch_userinfo ], ...). Registered BEFORE the discovery + connected-event LLM
        // call below, which is awaited inline and which a manual `*` routing rule can park
        // for minutes - the operator must be able to drive the flow while it waits.
        //
        // This task also replaces the old "poll get_client() every 5s" idle task: the loop
        // ends when the client is removed, because `remove_client` drops the sender.
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

        // Trigger initial discovery
        if let Some(instruction) = app_state.get_instruction_for_client(client_id).await {
            let protocol = Arc::new(OpenIdConnectClientProtocol::new());

            // Auto-discover configuration
            if let Err(e) = Self::discover_and_call_llm(
                &remote_addr,
                client_id,
                &llm_client,
                &app_state,
                &status_tx,
                &instruction,
                protocol,
            )
            .await
            {
                Log::new(Some(&status_tx))
                    .error(format!("Failed to discover OIDC configuration: {}", e));
            }
        }

        // Start the flow the operator asked for.
        //
        // From its own registered task, not inline: the device flow's polling and the
        // authorization-code flow's callback server both outlive `connect()`, which must
        // return promptly. It runs through `execute_llm_action`, the same entry point the
        // model's own flow actions use, so an operator-selected flow and a model-selected
        // one are the same code path.
        if let Some(action) = flow_action {
            let flow_state = app_state.clone();
            let flow_llm = llm_client.clone();
            let flow_status = status_tx.clone();
            let flow_task = tokio::spawn(async move {
                let protocol = Arc::new(OpenIdConnectClientProtocol::new());
                if let Err(e) = Self::execute_llm_action(
                    action,
                    client_id,
                    &flow_llm,
                    &flow_state,
                    &flow_status,
                    protocol,
                )
                .await
                {
                    Log::new(Some(&flow_status)).error(format!(
                        "OpenID Connect client {}: the `flow` startup parameter's flow failed: {}",
                        client_id, e
                    ));
                }
            });
            app_state.register_client_task(client_id, flow_task).await;
        }

        // Return a dummy local address (OIDC is HTTP-based, connectionless)
        Ok("0.0.0.0:0".parse().unwrap())
    }

    /// Discover OpenID Connect provider configuration and call LLM
    async fn discover_and_call_llm(
        provider_url: &str,
        client_id: ClientId,
        llm_client: &OllamaClient,
        app_state: &Arc<AppState>,
        status_tx: &mpsc::UnboundedSender<String>,
        instruction: &str,
        protocol: Arc<OpenIdConnectClientProtocol>,
    ) -> Result<()> {
        info!("Discovering OIDC configuration for {}", provider_url);

        // Discover provider metadata
        let issuer_url = IssuerUrl::new(provider_url.to_string()).context("Invalid issuer URL")?;

        let provider_metadata = CoreProviderMetadata::discover_async(issuer_url.clone(), http_hook)
            .await
            .context("Failed to discover OIDC provider metadata")?;

        Log::new(Some(status_tx))
            .info(format!("Discovered OIDC provider: {}", issuer_url.as_str()));

        // Store provider metadata
        app_state
            .with_client_mut(client_id, |client| {
                client.set_protocol_field(
                "provider_metadata".to_string(),
                serde_json::json!({
                    "issuer": issuer_url.as_str(),
                    "authorization_endpoint": provider_metadata.authorization_endpoint().as_str(),
                    "token_endpoint": provider_metadata.token_endpoint().map(|u| u.as_str()),
                    "userinfo_endpoint": provider_metadata.userinfo_endpoint().map(|u| u.as_str()),
                }),
            );
            })
            .await;

        // Call LLM with discovered event
        let event = Event::new(
            &OIDC_CLIENT_DISCOVERED_EVENT,
            serde_json::json!({
                "issuer": issuer_url.as_str(),
                "authorization_endpoint": provider_metadata.authorization_endpoint().as_str(),
                "token_endpoint": provider_metadata.token_endpoint().map(|u| u.as_str()),
                "userinfo_endpoint": provider_metadata.userinfo_endpoint().map(|u| u.as_str()),
                "supported_scopes": provider_metadata.scopes_supported()
                    .map(|scopes| scopes.iter().map(|s| s.as_str()).collect::<Vec<_>>()),
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
            instruction,
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
                // Update memory
                if let Some(mem) = memory_updates {
                    app_state.set_memory_for_client(client_id, mem).await;
                }

                // Execute actions
                for action in actions {
                    if let Err(e) = Self::execute_llm_action(
                        action,
                        client_id,
                        llm_client,
                        app_state,
                        status_tx,
                        protocol.clone(),
                    )
                    .await
                    {
                        Log::new(Some(status_tx))
                            .error(format!("Failed to execute OIDC action: {}", e));
                    }
                }
            }
            Err(e) => {
                error!("LLM error for OIDC client {}: {}", client_id, e);
            }
        }

        Ok(())
    }

    /// Execute an LLM-generated action: the model's path into [`Self::apply_action`].
    ///
    /// Kept as a separate entry point because the follow-up actions the model returns from
    /// a token/userinfo event come back here, and that recursion needs a boxed future.
    fn execute_llm_action<'a>(
        action: serde_json::Value,
        client_id: ClientId,
        llm_client: &'a OllamaClient,
        app_state: &'a Arc<AppState>,
        status_tx: &'a mpsc::UnboundedSender<String>,
        protocol: Arc<OpenIdConnectClientProtocol>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move {
            use crate::llm::actions::Client;

            let result = protocol.execute_action(action.clone())?;
            match Self::apply_action(
                result,
                Dispatch::Inline,
                client_id,
                llm_client,
                app_state,
                status_tx,
                protocol,
            )
            .await?
            {
                Applied::Ran(detail) => info!("OIDC client {}: {}", client_id, detail),
                Applied::Disconnect => {
                    // The model asking to disconnect tears the client down, as it always
                    // has. An *injected* disconnect only marks it Disconnected - removing
                    // the client from under the command loop would abort the very task
                    // that owes the dashboard a reply.
                    app_state.remove_client(client_id).await;
                }
            }
            Ok(())
        })
    }

    /// Run one executed action. Shared by the LLM path and injected commands, so a flow is
    /// driven by exactly one implementation whoever asked for it.
    #[allow(clippy::too_many_arguments)]
    fn apply_action<'a>(
        result: ClientActionResult,
        dispatch: Dispatch,
        client_id: ClientId,
        llm_client: &'a OllamaClient,
        app_state: &'a Arc<AppState>,
        status_tx: &'a mpsc::UnboundedSender<String>,
        protocol: Arc<OpenIdConnectClientProtocol>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Applied>> + Send + 'a>> {
        Box::pin(async move {
            match result {
                ClientActionResult::Custom { name, data } => match name.as_str() {
                    "oidc_discover" => {
                        let provider_url = app_state
                            .with_client_mut(client_id, |client| {
                                client
                                    .get_protocol_field("provider_url")
                                    .and_then(|v| v.as_str())
                                    .map(|s| s.to_string())
                            })
                            .await
                            .flatten()
                            .context("No provider URL found")?;
                        let instruction = app_state
                            .get_instruction_for_client(client_id)
                            .await
                            .unwrap_or_default();
                        Self::discover_and_call_llm(
                            &provider_url,
                            client_id,
                            llm_client,
                            app_state,
                            status_tx,
                            &instruction,
                            protocol,
                        )
                        .await?;
                        Ok(Applied::Ran(format!(
                            "oidc_discover: provider metadata fetched from {provider_url}"
                        )))
                    }
                    "oidc_device_flow" => {
                        Self::start_device_flow(
                            client_id, data, llm_client, app_state, status_tx, protocol,
                        )
                        .await?;
                        Ok(Applied::Ran(
                            "oidc_device_flow: device code issued, polling started".to_string(),
                        ))
                    }
                    "oidc_authorization_code" => {
                        Self::start_authorization_code_flow(
                            client_id, data, llm_client, app_state, status_tx, protocol,
                        )
                        .await?;
                        Ok(Applied::Ran(
                            "oidc_authorization_code: authorization URL built, callback server \
                             waiting"
                                .to_string(),
                        ))
                    }
                    "oidc_password_flow" => {
                        Self::exchange_password(
                            client_id, data, llm_client, app_state, status_tx, protocol, dispatch,
                        )
                        .await?;
                        Ok(Applied::Ran(
                            Self::token_state_detail("oidc_password_flow", client_id, app_state)
                                .await,
                        ))
                    }
                    "oidc_client_credentials" => {
                        Self::exchange_client_credentials(
                            client_id, data, llm_client, app_state, status_tx, protocol, dispatch,
                        )
                        .await?;
                        Ok(Applied::Ran(
                            Self::token_state_detail(
                                "oidc_client_credentials",
                                client_id,
                                app_state,
                            )
                            .await,
                        ))
                    }
                    "oidc_refresh_token" => {
                        Self::refresh_token(
                            client_id, llm_client, app_state, status_tx, protocol, dispatch,
                        )
                        .await?;
                        Ok(Applied::Ran(
                            Self::token_state_detail("oidc_refresh_token", client_id, app_state)
                                .await,
                        ))
                    }
                    "oidc_fetch_userinfo" => {
                        Self::fetch_userinfo(
                            client_id, llm_client, app_state, status_tx, protocol, dispatch,
                        )
                        .await?;
                        Ok(Applied::Ran(
                            "oidc_fetch_userinfo: UserInfo endpoint answered".to_string(),
                        ))
                    }
                    other => Err(anyhow::anyhow!("Unknown OIDC action: {}", other)),
                },
                ClientActionResult::Disconnect => {
                    info!("OIDC client {} disconnecting", client_id);
                    app_state
                        .update_client_status(client_id, ClientStatus::Disconnected)
                        .await;
                    let _ = status_tx.send("__UPDATE_UI__".to_string());
                    Ok(Applied::Disconnect)
                }
                _ => Err(anyhow::anyhow!("Unsupported action result type")),
            }
        })
    }

    /// Describe a token flow by what it left behind - never by assuming it worked.
    async fn token_state_detail(
        name: &str,
        client_id: ClientId,
        app_state: &Arc<AppState>,
    ) -> String {
        let has_token = app_state
            .with_client_mut(client_id, |client| {
                client.get_protocol_field("access_token").is_some()
            })
            .await
            .unwrap_or(false);
        if has_token {
            format!("{name}: completed, an access token is stored")
        } else {
            format!(
                "{name}: completed but no access token was stored - the provider did not \
                 issue one (see netget.log)"
            )
        }
    }

    /// Drain injected commands until the channel closes (the client was removed) or an
    /// injected `disconnect` ends the session.
    ///
    /// The flow itself is awaited, so the reported [`ClientSendOutcome`] describes what the
    /// provider actually did; only the resulting token/userinfo event is handed to its own
    /// task, so a manual routing rule waiting on a human cannot hold up the reply.
    async fn command_loop(
        mut command_rx: mpsc::Receiver<ClientCommand>,
        client_id: ClientId,
        app_state: Arc<AppState>,
        llm_client: OllamaClient,
        status_tx: mpsc::UnboundedSender<String>,
    ) {
        use crate::llm::actions::protocol_trait::Protocol;
        use crate::llm::actions::Client;

        let protocol = Arc::new(OpenIdConnectClientProtocol::new());

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
                    &llm_client,
                    &app_state,
                    &status_tx,
                    protocol.clone(),
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
                    "OIDC client {} injected action failed: {}",
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
        info!("OIDC client {} command loop ended", client_id);
    }

    /// Start device code flow (RFC 8628)
    async fn start_device_flow(
        client_id: ClientId,
        data: serde_json::Value,
        llm_client: &OllamaClient,
        app_state: &Arc<AppState>,
        status_tx: &mpsc::UnboundedSender<String>,
        protocol: Arc<OpenIdConnectClientProtocol>,
    ) -> Result<()> {
        Log::new(Some(status_tx)).info(format!(
            "Starting device code flow for client {}",
            client_id
        ));

        // Get provider metadata and client config
        let (provider_url, oidc_client_id, oidc_client_secret) = app_state
            .with_client_mut(client_id, |client| {
                let provider = client
                    .get_protocol_field("provider_url")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())?;
                let client_id_str = client
                    .get_protocol_field("client_id")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "default-client-id".to_string());
                let client_secret_str = client
                    .get_protocol_field("client_secret")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                Some((provider, client_id_str, client_secret_str))
            })
            .await
            .flatten()
            .context("No provider URL found")?;

        let scopes = data
            .get("scopes")
            .and_then(|v| v.as_str())
            .unwrap_or("openid");

        let issuer_url = IssuerUrl::new(provider_url)?;
        let provider_metadata =
            CoreProviderMetadata::discover_async(issuer_url.clone(), http_hook).await?;

        // Construct device authorization endpoint URL (typically /device/code or /device/authorize)
        let device_auth_url = format!("{}/device/code", issuer_url.as_str().trim_end_matches('/'));
        Log::new(Some(status_tx)).info(format!(
            "Device authorization endpoint: {}",
            device_auth_url
        ));

        // Build request body
        let mut params = vec![("client_id", oidc_client_id.as_str()), ("scope", scopes)];

        if let Some(ref secret) = oidc_client_secret {
            params.push(("client_secret", secret.as_str()));
        }

        // Make device authorization request
        let http_client = plain_http_client();
        let response = http_client
            .post(&device_auth_url)
            .form(&params)
            .send()
            .await
            .context("Failed to send device authorization request")?;

        if !response.status().is_success() {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            return Err(anyhow::anyhow!(
                "Device authorization failed: {}",
                error_text
            ));
        }

        let device_response: serde_json::Value = response
            .json()
            .await
            .context("Failed to parse device authorization response")?;

        // Extract device code response fields
        let device_code = device_response
            .get("device_code")
            .and_then(|v| v.as_str())
            .context("Missing device_code in response")?
            .to_string();

        let user_code = device_response
            .get("user_code")
            .and_then(|v| v.as_str())
            .context("Missing user_code in response")?
            .to_string();

        let verification_uri = device_response
            .get("verification_uri")
            .and_then(|v| v.as_str())
            .context("Missing verification_uri in response")?
            .to_string();

        let verification_uri_complete = device_response
            .get("verification_uri_complete")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let interval = device_response
            .get("interval")
            .and_then(|v| v.as_u64())
            .unwrap_or(5);

        let expires_in = device_response
            .get("expires_in")
            .and_then(|v| v.as_u64())
            .unwrap_or(300);

        // Display device code and verification URL to user
        let log = Log::new(Some(status_tx));
        let _ = status_tx.send("========================================".to_string());
        log.info("Device Code Flow - User Action Required".to_string());
        let _ = status_tx.send("========================================".to_string());
        log.info("1. Open this URL in your browser:".to_string());
        log.info(format!("   {}", verification_uri));
        if let Some(complete_uri) = verification_uri_complete {
            log.info(format!("   Or use this direct link: {}", complete_uri));
        }
        log.info(format!("2. Enter this code: {}", user_code));
        let _ = status_tx.send("========================================".to_string());
        log.info("Waiting for authorization...".to_string());

        // Get token endpoint
        let token_endpoint = provider_metadata
            .token_endpoint()
            .context("No token endpoint in provider metadata")?
            .as_str()
            .to_string();

        // Spawn polling task
        let app_state_clone = app_state.clone();
        let llm_client_clone = llm_client.clone();
        let status_tx_clone = status_tx.clone();
        let protocol_clone = protocol.clone();
        let oidc_client_id_clone = oidc_client_id.clone();
        let oidc_client_secret_clone = oidc_client_secret.clone();

        // Registered with AppState so stop_client can abort this task —
        // dropping a JoinHandle only detaches it in Tokio.
        let task_registrar = app_state.clone();
        let task_handle = tokio::spawn(async move {
            let start_time = crate::utils::clock::Instant::now();
            let mut poll_count = 0;
            let interval_duration = std::time::Duration::from_secs(interval);
            let expires_duration = std::time::Duration::from_secs(expires_in);
            let log = Log::new(Some(&status_tx_clone));

            loop {
                // Check if expired
                if start_time.elapsed() > expires_duration {
                    log.error("Device code expired. Please try again.".to_string());
                    break;
                }

                // Wait for interval
                tokio::time::sleep(interval_duration).await;
                poll_count += 1;

                log.info(format!(
                    "Polling for authorization (attempt {})...",
                    poll_count
                ));

                // Build token request
                let mut token_params = vec![
                    ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                    ("device_code", device_code.as_str()),
                    ("client_id", oidc_client_id_clone.as_str()),
                ];

                if let Some(ref secret) = oidc_client_secret_clone {
                    token_params.push(("client_secret", secret.as_str()));
                }

                // Poll token endpoint
                let http_client = plain_http_client();
                match http_client
                    .post(&token_endpoint)
                    .form(&token_params)
                    .send()
                    .await
                {
                    Ok(response) => {
                        if response.status().is_success() {
                            // Success - parse tokens
                            match response.json::<serde_json::Value>().await {
                                Ok(token_json) => {
                                    log.info(
                                        "Authorization successful! Received tokens.".to_string(),
                                    );

                                    // Convert JSON to CoreTokenResponse manually
                                    if let Err(e) = Self::store_tokens_from_json(
                                        client_id,
                                        &token_json,
                                        &llm_client_clone,
                                        &app_state_clone,
                                        &status_tx_clone,
                                        protocol_clone,
                                    )
                                    .await
                                    {
                                        log.error(format!("Failed to store tokens: {}", e));
                                    }
                                    break;
                                }
                                Err(e) => {
                                    log.error(format!("Failed to parse token response: {}", e));
                                    break;
                                }
                            }
                        } else {
                            // Check error response
                            match response.json::<serde_json::Value>().await {
                                Ok(error_json) => {
                                    let error_code = error_json
                                        .get("error")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("unknown");

                                    match error_code {
                                        "authorization_pending" => {
                                            // User hasn't authorized yet, continue polling
                                            continue;
                                        }
                                        "slow_down" => {
                                            // Slow down polling
                                            log.info("Slowing down polling rate...".to_string());
                                            tokio::time::sleep(interval_duration).await;
                                            continue;
                                        }
                                        "expired_token" => {
                                            log.error("Device code expired.".to_string());
                                            break;
                                        }
                                        "access_denied" => {
                                            log.error("User denied authorization.".to_string());
                                            break;
                                        }
                                        _ => {
                                            log.error(format!(
                                                "Authorization error: {}",
                                                error_code
                                            ));
                                            break;
                                        }
                                    }
                                }
                                Err(_) => {
                                    log.error("Failed to parse error response".to_string());
                                    break;
                                }
                            }
                        }
                    }
                    Err(e) => {
                        log.error(format!("Polling failed: {}", e));
                        break;
                    }
                }
            }
        });
        task_registrar
            .register_client_task(client_id, task_handle)
            .await;

        Ok(())
    }

    /// Store tokens from JSON response (helper for device code flow)
    async fn store_tokens_from_json(
        client_id: ClientId,
        token_json: &serde_json::Value,
        llm_client: &OllamaClient,
        app_state: &Arc<AppState>,
        status_tx: &mpsc::UnboundedSender<String>,
        protocol: Arc<OpenIdConnectClientProtocol>,
    ) -> Result<()> {
        let access_token = token_json
            .get("access_token")
            .and_then(|v| v.as_str())
            .context("Missing access_token")?;
        let id_token = token_json
            .get("id_token")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let refresh_token = token_json
            .get("refresh_token")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let expires_in = token_json.get("expires_in").and_then(|v| v.as_u64());
        let token_type = token_json
            .get("token_type")
            .and_then(|v| v.as_str())
            .unwrap_or("Bearer");

        Log::new(Some(status_tx)).info(format!("Received tokens (expires_in: {:?}s)", expires_in));

        // Store tokens
        app_state
            .with_client_mut(client_id, |client| {
                client.set_protocol_field(
                    "access_token".to_string(),
                    serde_json::json!(access_token),
                );
                if let Some(id) = &id_token {
                    client.set_protocol_field("id_token".to_string(), serde_json::json!(id));
                }
                if let Some(refresh) = &refresh_token {
                    client.set_protocol_field(
                        "refresh_token".to_string(),
                        serde_json::json!(refresh),
                    );
                }
            })
            .await;

        // Call LLM with token received event. This helper is only reached from the device
        // and authorization-code flows' own spawned tasks, which are already off any
        // command loop's critical path, so the event is raised inline there.
        // The tokens are stored above and every action that needs one
        // (`fetch_userinfo`, `refresh_token`, `validate_token`) reads it back out of
        // `protocol_data`. The model therefore never needs the secret itself, and putting it
        // in the event copied a live bearer token, a refresh token and an id_token into the
        // LLM prompt — which goes to whatever backend is configured, is written to
        // `netget.log`, and is echoed onto the status stream. The sibling `oauth2` client has
        // always redacted these; this one did not. Report presence and metadata instead.
        let event = Event::new(
            &OIDC_CLIENT_TOKEN_RECEIVED_EVENT,
            serde_json::json!({
                "access_token": "[REDACTED]",
                "id_token": if id_token.is_some() { "[REDACTED]" } else { "" },
                "refresh_token": if refresh_token.is_some() { "[REDACTED]" } else { "" },
                "expires_in": expires_in,
                "token_type": token_type,
            }),
        );
        Self::notify_event(
            client_id,
            event,
            Dispatch::Inline,
            llm_client,
            app_state,
            status_tx,
            protocol,
        )
        .await;

        Ok(())
    }

    /// Start authorization code flow with local callback server
    async fn start_authorization_code_flow(
        client_id: ClientId,
        data: serde_json::Value,
        llm_client: &OllamaClient,
        app_state: &Arc<AppState>,
        status_tx: &mpsc::UnboundedSender<String>,
        protocol: Arc<OpenIdConnectClientProtocol>,
    ) -> Result<()> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        Log::new(Some(status_tx)).info(format!(
            "Starting authorization code flow for client {}",
            client_id
        ));

        // Get provider metadata and client config
        let (provider_url, oidc_client_id, oidc_client_secret) = app_state
            .with_client_mut(client_id, |client| {
                let provider = client
                    .get_protocol_field("provider_url")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())?;
                let client_id_str = client
                    .get_protocol_field("client_id")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "default-client-id".to_string());
                let client_secret_str = client
                    .get_protocol_field("client_secret")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                Some((provider, client_id_str, client_secret_str))
            })
            .await
            .flatten()
            .context("No provider URL found")?;

        let scopes = data
            .get("scopes")
            .and_then(|v| v.as_str())
            .unwrap_or("openid profile email");

        let callback_port = crate::client::wire_values::number::<u16>(&data, "port", 8080)?;

        let issuer_url = IssuerUrl::new(provider_url)?;
        let provider_metadata = CoreProviderMetadata::discover_async(issuer_url, http_hook).await?;

        // Get authorization endpoint
        let auth_endpoint = provider_metadata.authorization_endpoint().as_str();

        // Generate state for CSRF protection
        use rand::Rng;
        let state: String = rand::thread_rng()
            .sample_iter(&rand::distributions::Alphanumeric)
            .take(32)
            .map(char::from)
            .collect();

        // Build redirect URI
        let redirect_uri = format!("http://localhost:{}/callback", callback_port);

        // Build authorization URL
        let auth_url = format!(
            "{}?response_type=code&client_id={}&redirect_uri={}&scope={}&state={}",
            auth_endpoint,
            urlencoding::encode(&oidc_client_id),
            urlencoding::encode(&redirect_uri),
            urlencoding::encode(scopes),
            urlencoding::encode(&state)
        );

        // Display authorization URL
        let log = Log::new(Some(status_tx));
        let _ = status_tx.send("========================================".to_string());
        log.info("Authorization Code Flow - User Action Required".to_string());
        let _ = status_tx.send("========================================".to_string());
        log.info("1. Open this URL in your browser:".to_string());
        log.info(format!("   {}", auth_url));
        log.info(format!(
            "2. After authorization, the browser will redirect to localhost:{}",
            callback_port
        ));
        let _ = status_tx.send("========================================".to_string());
        log.info(format!(
            "Starting local callback server on port {}...",
            callback_port
        ));

        // Start local HTTP server
        let listener = TcpListener::bind(format!("127.0.0.1:{}", callback_port))
            .await
            .context(format!(
                "Failed to bind to port {}. Port may be in use.",
                callback_port
            ))?;

        log.info(format!(
            "Callback server listening on http://127.0.0.1:{}/callback",
            callback_port
        ));
        log.info("Waiting for authorization...".to_string());

        // Get token endpoint
        let token_endpoint = provider_metadata
            .token_endpoint()
            .context("No token endpoint in provider metadata")?
            .as_str()
            .to_string();

        // Spawn server task
        let app_state_clone = app_state.clone();
        let llm_client_clone = llm_client.clone();
        let status_tx_clone = status_tx.clone();
        let protocol_clone = protocol.clone();
        let state_clone = state.clone();

        // Registered with AppState so stop_client can abort this task —
        // dropping a JoinHandle only detaches it in Tokio.
        let task_registrar = app_state.clone();
        let task_handle = tokio::spawn(async move {
            let log = Log::new(Some(&status_tx_clone));
            // Accept one connection
            match listener.accept().await {
                Ok((mut socket, _addr)) => {
                    log.info("Received callback request...".to_string());

                    // Read HTTP request
                    let mut buffer = vec![0u8; 4096];
                    match socket.read(&mut buffer).await {
                        Ok(n) => {
                            let request = String::from_utf8_lossy(&buffer[..n]);

                            // Parse query parameters
                            if let Some(query_line) = request.lines().next() {
                                if let Some(query_str) = query_line.split_whitespace().nth(1) {
                                    if let Some(query_params) = query_str.split('?').nth(1) {
                                        let mut code = None;
                                        let mut returned_state = None;
                                        let mut error = None;

                                        for param in query_params.split('&') {
                                            let parts: Vec<&str> = param.split('=').collect();
                                            if parts.len() == 2 {
                                                match parts[0] {
                                                    "code" => code = Some(parts[1].to_string()),
                                                    "state" => {
                                                        returned_state = Some(parts[1].to_string())
                                                    }
                                                    "error" => error = Some(parts[1].to_string()),
                                                    _ => {}
                                                }
                                            }
                                        }

                                        // Send response to browser
                                        let response = if error.is_some() {
                                            "HTTP/1.1 400 Bad Request\r\nContent-Type: text/html\r\n\r\n<html><body><h1>Authorization Failed</h1><p>An error occurred during authorization. You can close this window.</p></body></html>"
                                        } else if code.is_some() {
                                            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><body><h1>Authorization Successful!</h1><p>You can close this window and return to the terminal.</p></body></html>"
                                        } else {
                                            "HTTP/1.1 400 Bad Request\r\nContent-Type: text/html\r\n\r\n<html><body><h1>Invalid Request</h1><p>Missing authorization code. You can close this window.</p></body></html>"
                                        };

                                        let _ = socket.write_all(response.as_bytes()).await;

                                        // Process authorization code
                                        if let Some(error_msg) = error {
                                            log.error(format!(
                                                "Authorization failed: {}",
                                                error_msg
                                            ));
                                            return;
                                        }

                                        if let Some(auth_code) = code {
                                            // Verify state
                                            if returned_state.as_deref()
                                                != Some(state_clone.as_str())
                                            {
                                                log.error(
                                                    "State mismatch - possible CSRF attack"
                                                        .to_string(),
                                                );
                                                return;
                                            }

                                            log.info("Authorization code received, exchanging for tokens...".to_string());

                                            // Exchange authorization code for tokens
                                            let mut token_params = vec![
                                                ("grant_type", "authorization_code"),
                                                ("code", auth_code.as_str()),
                                                ("redirect_uri", redirect_uri.as_str()),
                                                ("client_id", oidc_client_id.as_str()),
                                            ];

                                            if let Some(ref secret) = oidc_client_secret {
                                                token_params
                                                    .push(("client_secret", secret.as_str()));
                                            }

                                            let http_client = plain_http_client();
                                            match http_client
                                                .post(&token_endpoint)
                                                .form(&token_params)
                                                .send()
                                                .await
                                            {
                                                Ok(response) => {
                                                    if response.status().is_success() {
                                                        match response
                                                            .json::<serde_json::Value>()
                                                            .await
                                                        {
                                                            Ok(token_json) => {
                                                                log.info("Successfully exchanged code for tokens!".to_string());

                                                                if let Err(e) =
                                                                    Self::store_tokens_from_json(
                                                                        client_id,
                                                                        &token_json,
                                                                        &llm_client_clone,
                                                                        &app_state_clone,
                                                                        &status_tx_clone,
                                                                        protocol_clone,
                                                                    )
                                                                    .await
                                                                {
                                                                    log.error(format!("Failed to store tokens: {}", e));
                                                                }
                                                            }
                                                            Err(e) => {
                                                                log.error(format!("Failed to parse token response: {}", e));
                                                            }
                                                        }
                                                    } else {
                                                        let error_text =
                                                            response.text().await.unwrap_or_else(
                                                                |_| "Unknown error".to_string(),
                                                            );
                                                        log.error(format!(
                                                            "Token exchange failed: {}",
                                                            error_text
                                                        ));
                                                    }
                                                }
                                                Err(e) => {
                                                    log.error(format!(
                                                        "Failed to exchange code: {}",
                                                        e
                                                    ));
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            log.error(format!("Failed to read request: {}", e));
                        }
                    }
                }
                Err(e) => {
                    log.error(format!("Failed to accept connection: {}", e));
                }
            }
        });
        task_registrar
            .register_client_task(client_id, task_handle)
            .await;

        Ok(())
    }

    /// Exchange username/password for tokens
    #[allow(clippy::too_many_arguments)]
    async fn exchange_password(
        client_id: ClientId,
        data: serde_json::Value,
        llm_client: &OllamaClient,
        app_state: &Arc<AppState>,
        status_tx: &mpsc::UnboundedSender<String>,
        protocol: Arc<OpenIdConnectClientProtocol>,
        dispatch: Dispatch,
    ) -> Result<()> {
        let username = data
            .get("username")
            .and_then(|v| v.as_str())
            .context("Missing username")?;
        let password = data
            .get("password")
            .and_then(|v| v.as_str())
            .context("Missing password")?;
        let scopes = data
            .get("scopes")
            .and_then(|v| v.as_str())
            .unwrap_or("openid");

        Log::new(Some(status_tx)).info(format!(
            "Exchanging password for tokens (user: {})",
            username
        ));

        // Get client config and provider metadata
        let (oidc_client_id, oidc_client_secret, provider_url) = app_state
            .with_client_mut(client_id, |client| {
                let client_id_str = client
                    .get_protocol_field("client_id")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "default-client-id".to_string());
                let client_secret_str = client
                    .get_protocol_field("client_secret")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let provider = client
                    .get_protocol_field("provider_url")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                    .unwrap_or_default();
                (client_id_str, client_secret_str, provider)
            })
            .await
            .unwrap_or_else(|| ("default-client-id".to_string(), None, String::new()));

        let issuer_url = IssuerUrl::new(provider_url)?;
        let provider_metadata = CoreProviderMetadata::discover_async(issuer_url, http_hook).await?;

        let client = if let Some(secret) = oidc_client_secret {
            CoreClient::from_provider_metadata(
                provider_metadata,
                OidcClientId::new(oidc_client_id),
                Some(ClientSecret::new(secret)),
            )
        } else {
            CoreClient::from_provider_metadata(
                provider_metadata,
                OidcClientId::new(oidc_client_id),
                None,
            )
        };

        // Exchange password for tokens
        let username_param = ResourceOwnerUsername::new(username.to_string());
        let password_param = ResourceOwnerPassword::new(password.to_string());
        let mut token_request = client.exchange_password(&username_param, &password_param);

        // Add scopes
        for scope in scopes.split_whitespace() {
            token_request = token_request.add_scope(Scope::new(scope.to_string()));
        }

        let token_response = token_request
            .request_async(http_hook)
            .await
            .context("Failed to exchange password for tokens")?;

        // Store tokens
        Self::store_and_notify_tokens(
            client_id,
            &token_response,
            llm_client,
            app_state,
            status_tx,
            protocol,
            dispatch,
        )
        .await?;

        Ok(())
    }

    /// Exchange client credentials for access token
    #[allow(clippy::too_many_arguments)]
    async fn exchange_client_credentials(
        client_id: ClientId,
        data: serde_json::Value,
        llm_client: &OllamaClient,
        app_state: &Arc<AppState>,
        status_tx: &mpsc::UnboundedSender<String>,
        protocol: Arc<OpenIdConnectClientProtocol>,
        dispatch: Dispatch,
    ) -> Result<()> {
        let scopes = data.get("scopes").and_then(|v| v.as_str()).unwrap_or("");

        Log::new(Some(status_tx))
            .info("Exchanging client credentials for access token".to_string());

        // Get client config and provider metadata
        let (oidc_client_id, oidc_client_secret, provider_url) = app_state
            .with_client_mut(client_id, |client| {
                let client_id_str = client
                    .get_protocol_field("client_id")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                    .context("Missing client_id")
                    .ok()?;
                let client_secret_str = client
                    .get_protocol_field("client_secret")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                    .context("Missing client_secret for confidential client")
                    .ok()?;
                let provider = client
                    .get_protocol_field("provider_url")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())?;
                Some((client_id_str, client_secret_str, provider))
            })
            .await
            .flatten()
            .context("Missing client configuration")?;

        let issuer_url = IssuerUrl::new(provider_url)?;
        let provider_metadata = CoreProviderMetadata::discover_async(issuer_url, http_hook).await?;

        let client = CoreClient::from_provider_metadata(
            provider_metadata,
            OidcClientId::new(oidc_client_id),
            Some(ClientSecret::new(oidc_client_secret)),
        );

        // Exchange client credentials
        let mut token_request = client.exchange_client_credentials();

        // Add scopes
        for scope in scopes.split_whitespace() {
            if !scope.is_empty() {
                token_request = token_request.add_scope(Scope::new(scope.to_string()));
            }
        }

        let token_response = token_request
            .request_async(http_hook)
            .await
            .context("Failed to exchange client credentials")?;

        // Store tokens
        Self::store_and_notify_tokens(
            client_id,
            &token_response,
            llm_client,
            app_state,
            status_tx,
            protocol,
            dispatch,
        )
        .await?;

        Ok(())
    }

    /// Refresh access token
    async fn refresh_token(
        client_id: ClientId,
        llm_client: &OllamaClient,
        app_state: &Arc<AppState>,
        status_tx: &mpsc::UnboundedSender<String>,
        protocol: Arc<OpenIdConnectClientProtocol>,
        dispatch: Dispatch,
    ) -> Result<()> {
        Log::new(Some(status_tx)).info("Refreshing access token".to_string());

        // Get refresh token and client config
        let (refresh_token_str, oidc_client_id, oidc_client_secret, provider_url) = app_state
            .with_client_mut(client_id, |client| {
                let refresh = client
                    .get_protocol_field("refresh_token")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                    .context("No refresh token available")
                    .ok()?;
                let client_id_str = client
                    .get_protocol_field("client_id")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())?;
                let client_secret_str = client
                    .get_protocol_field("client_secret")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let provider = client
                    .get_protocol_field("provider_url")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())?;
                Some((refresh, client_id_str, client_secret_str, provider))
            })
            .await
            .flatten()
            .context("Missing refresh token or client configuration")?;

        let issuer_url = IssuerUrl::new(provider_url)?;
        let provider_metadata = CoreProviderMetadata::discover_async(issuer_url, http_hook).await?;

        let client = if let Some(secret) = oidc_client_secret {
            CoreClient::from_provider_metadata(
                provider_metadata,
                OidcClientId::new(oidc_client_id),
                Some(ClientSecret::new(secret)),
            )
        } else {
            CoreClient::from_provider_metadata(
                provider_metadata,
                OidcClientId::new(oidc_client_id),
                None,
            )
        };

        use openidconnect::RefreshToken;
        let token_response = client
            .exchange_refresh_token(&RefreshToken::new(refresh_token_str))
            .request_async(http_hook)
            .await
            .context("Failed to refresh token")?;

        // Store new tokens
        Self::store_and_notify_tokens(
            client_id,
            &token_response,
            llm_client,
            app_state,
            status_tx,
            protocol,
            dispatch,
        )
        .await?;

        Ok(())
    }

    /// Fetch UserInfo
    async fn fetch_userinfo(
        client_id: ClientId,
        llm_client: &OllamaClient,
        app_state: &Arc<AppState>,
        status_tx: &mpsc::UnboundedSender<String>,
        protocol: Arc<OpenIdConnectClientProtocol>,
        dispatch: Dispatch,
    ) -> Result<()> {
        Log::new(Some(status_tx)).info("Fetching UserInfo".to_string());

        // Get access token and provider metadata
        let (access_token_str, oidc_client_id, oidc_client_secret, provider_url) = app_state
            .with_client_mut(client_id, |client| {
                let access = client
                    .get_protocol_field("access_token")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                    .context("No access token available")
                    .ok()?;
                let client_id_str = client
                    .get_protocol_field("client_id")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())?;
                let client_secret_str = client
                    .get_protocol_field("client_secret")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let provider = client
                    .get_protocol_field("provider_url")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())?;
                Some((access, client_id_str, client_secret_str, provider))
            })
            .await
            .flatten()
            .context("Missing access token or client configuration")?;

        let issuer_url = IssuerUrl::new(provider_url)?;
        let provider_metadata = CoreProviderMetadata::discover_async(issuer_url, http_hook).await?;

        let client = if let Some(secret) = oidc_client_secret {
            CoreClient::from_provider_metadata(
                provider_metadata,
                OidcClientId::new(oidc_client_id),
                Some(ClientSecret::new(secret)),
            )
        } else {
            CoreClient::from_provider_metadata(
                provider_metadata,
                OidcClientId::new(oidc_client_id),
                None,
            )
        };

        use openidconnect::AccessToken;
        let userinfo: CoreUserInfoClaims = client
            .user_info(AccessToken::new(access_token_str), None)
            .context("UserInfo endpoint not available")?
            .request_async(http_hook)
            .await
            .context("Failed to fetch UserInfo")?;

        Log::new(Some(status_tx)).info(format!(
            "Received UserInfo for subject: {:?}",
            userinfo.subject()
        ));

        // Call LLM with userinfo event
        let event = Event::new(
            &OIDC_CLIENT_USERINFO_RECEIVED_EVENT,
            serde_json::json!({
                "sub": userinfo.subject().as_str(),
                "claims": serde_json::to_value(&userinfo).unwrap_or(serde_json::json!({})),
            }),
        );
        Self::notify_event(
            client_id, event, dispatch, llm_client, app_state, status_tx, protocol,
        )
        .await;

        Ok(())
    }

    /// Store tokens and notify LLM
    #[allow(clippy::too_many_arguments)]
    async fn store_and_notify_tokens(
        client_id: ClientId,
        token_response: &CoreTokenResponse,
        llm_client: &OllamaClient,
        app_state: &Arc<AppState>,
        status_tx: &mpsc::UnboundedSender<String>,
        protocol: Arc<OpenIdConnectClientProtocol>,
        dispatch: Dispatch,
    ) -> Result<()> {
        let access_token = token_response.access_token().secret();
        let id_token = token_response
            .extra_fields()
            .id_token()
            .map(|t| t.to_string());
        let refresh_token = token_response
            .refresh_token()
            .map(|t| t.secret().to_string());
        let expires_in = token_response.expires_in().map(|d| d.as_secs());
        let token_type = token_response.token_type().as_ref();

        Log::new(Some(status_tx)).info(format!("Received tokens (expires_in: {:?}s)", expires_in));

        // Store tokens
        app_state
            .with_client_mut(client_id, |client| {
                client.set_protocol_field(
                    "access_token".to_string(),
                    serde_json::json!(access_token),
                );
                if let Some(id) = &id_token {
                    client.set_protocol_field("id_token".to_string(), serde_json::json!(id));
                }
                if let Some(refresh) = &refresh_token {
                    client.set_protocol_field(
                        "refresh_token".to_string(),
                        serde_json::json!(refresh),
                    );
                }
            })
            .await;

        // Call LLM with token received event.
        // The tokens are stored above and every action that needs one
        // (`fetch_userinfo`, `refresh_token`, `validate_token`) reads it back out of
        // `protocol_data`. The model therefore never needs the secret itself, and putting it
        // in the event copied a live bearer token, a refresh token and an id_token into the
        // LLM prompt — which goes to whatever backend is configured, is written to
        // `netget.log`, and is echoed onto the status stream. The sibling `oauth2` client has
        // always redacted these; this one did not. Report presence and metadata instead.
        let event = Event::new(
            &OIDC_CLIENT_TOKEN_RECEIVED_EVENT,
            serde_json::json!({
                "access_token": "[REDACTED]",
                "id_token": if id_token.is_some() { "[REDACTED]" } else { "" },
                "refresh_token": if refresh_token.is_some() { "[REDACTED]" } else { "" },
                "expires_in": expires_in,
                "token_type": token_type,
            }),
        );
        Self::notify_event(
            client_id, event, dispatch, llm_client, app_state, status_tx, protocol,
        )
        .await;

        Ok(())
    }

    /// Report one event to the LLM, inline or from a registered task.
    #[allow(clippy::too_many_arguments)]
    async fn notify_event(
        client_id: ClientId,
        event: Event,
        dispatch: Dispatch,
        llm_client: &OllamaClient,
        app_state: &Arc<AppState>,
        status_tx: &mpsc::UnboundedSender<String>,
        protocol: Arc<OpenIdConnectClientProtocol>,
    ) {
        match dispatch {
            Dispatch::Inline => {
                Self::raise_event(
                    client_id,
                    event,
                    llm_client.clone(),
                    app_state.clone(),
                    status_tx.clone(),
                    protocol,
                )
                .await
            }
            Dispatch::Deferred => {
                let handle = tokio::spawn(Self::raise_event(
                    client_id,
                    event,
                    llm_client.clone(),
                    app_state.clone(),
                    status_tx.clone(),
                    protocol,
                ));
                // Registered so stop_client aborts an in-flight LLM call for this event.
                app_state.register_client_task(client_id, handle).await;
            }
        }
    }

    /// The event -> LLM round-trip itself, plus whatever follow-up actions it answers with.
    async fn raise_event(
        client_id: ClientId,
        event: Event,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        protocol: Arc<OpenIdConnectClientProtocol>,
    ) {
        let Some(instruction) = app_state.get_instruction_for_client(client_id).await else {
            return;
        };
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

                // Execute follow-up actions
                for action in actions {
                    if let Err(e) = Self::execute_llm_action(
                        action,
                        client_id,
                        &llm_client,
                        &app_state,
                        &status_tx,
                        protocol.clone(),
                    )
                    .await
                    {
                        error!("Failed to execute follow-up action: {}", e);
                    }
                }
            }
            Err(e) => {
                error!("LLM error for OIDC client {}: {}", client_id, e);
            }
        }
    }
}
