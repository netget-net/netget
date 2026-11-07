//! OAuth2 client implementation
pub mod actions;

pub use actions::OAuth2ClientProtocol;

use anyhow::{Context, Result};
use oauth2::{
    basic::{BasicClient, BasicTokenType},
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, DeviceAuthorizationUrl,
    EmptyExtraDeviceAuthorizationFields, EmptyExtraTokenFields, PkceCodeChallenge, RedirectUrl,
    RefreshToken, ResourceOwnerPassword, ResourceOwnerUsername, Scope, StandardTokenResponse,
    TokenResponse, TokenUrl,
};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{error, info};

use crate::client::http_fetch::FetchClient;
use crate::client::llm_budget::call_llm_for_client;
use crate::client::oauth2::actions::{
    OAUTH2_CLIENT_CONNECTED_EVENT, OAUTH2_DEVICE_CODE_EVENT, OAUTH2_ERROR_EVENT,
    OAUTH2_TOKEN_OBTAINED_EVENT,
};
use crate::llm::actions::client_trait::ClientActionResult;
use crate::llm::ollama_client::OllamaClient;
use crate::llm::ClientLlmResult;
use crate::logging::emit::Log;
use crate::protocol::Event;
use crate::state::app_state::AppState;
use crate::state::client_handles::{ClientCommand, ClientSendOutcome};
use crate::state::{AccessLogOwner, ClientId as NetGetClientId, ClientStatus};

/// The HTTP function the `oauth2` crate is handed for every request it makes. Natively it is
/// the crate's own reqwest `async_http_client`, unchanged.
#[cfg(not(target_arch = "wasm32"))]
use oauth2::reqwest::async_http_client as http_hook;

/// The HTTP function the `oauth2` crate is handed in the browser build. The crate's own
/// `async_http_client` is reqwest's `fetch` backend there, which cannot reach the page's virtual
/// loopback, so each request goes through the shared hyper transport
/// ([`crate::client::http_fetch`]) instead: 30 seconds an exchange, 8 MiB of body, no redirects
/// (the crate's own client follows none either), and `https://` refused with the reason.
#[cfg(target_arch = "wasm32")]
async fn http_hook(
    request: oauth2::HttpRequest,
) -> std::result::Result<oauth2::HttpResponse, crate::client::http_fetch::FetchError> {
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
    let mut map = oauth2::http::HeaderMap::new();
    for (name, value) in headers {
        if let (Ok(name), Ok(value)) = (
            oauth2::http::header::HeaderName::from_bytes(name.as_bytes()),
            oauth2::http::HeaderValue::from_bytes(&value),
        ) {
            map.append(name, value);
        }
    }
    let status_code = oauth2::http::StatusCode::from_u16(status).map_err(|e| {
        crate::client::http_fetch::FetchError(anyhow::anyhow!("status {status}: {e}"))
    })?;
    Ok(oauth2::HttpResponse {
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

type TokenResponseType = StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>;

/// What [`OAuth2Client::apply_action`] did with one executed action.
///
/// OAuth2 flows are HTTPS request/response through the `oauth2` crate, so NetGet owns no
/// socket whose byte count could be reported. The description is deliberately built from
/// what is *observably* true afterwards - in particular whether a token was actually
/// stored - so a flow that failed can never read as a success. Nothing on this path may
/// invent a code or a token; only a provider response can produce one.
enum Applied {
    /// The action ran; the string describes the effect.
    Ran(String),
    /// The action asked to end the session.
    Disconnect,
}

/// Whether an event is reported to the LLM inline or from its own task.
#[derive(Clone, Copy)]
enum Dispatch {
    /// Raise it here and now. Used by the connected-event LLM path.
    Inline,
    /// Do the work and raise nothing at all.
    ///
    /// Used for a flow the model asks for in answer to `oauth2_token_obtained` or
    /// `oauth2_error`. Without it a refresh answered on a token event would raise another
    /// token event, whose answer could refresh again -- an unbounded credential loop, on
    /// the one client in this tree where that matters most.
    Silent,
    /// Hand it to a registered task. Used by the injected-command loop, so a manual
    /// (human-answered) routing rule on `oauth2_token_obtained` / `oauth2_error` cannot
    /// hold up the command's outcome, or the next injected command.
    Deferred,
}

/// OAuth2 client for authentication flows
pub struct OAuth2Client;

impl OAuth2Client {
    /// Connect to an OAuth2 provider with integrated LLM actions
    pub async fn connect_with_llm_actions(
        remote_addr: String,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        client_id: NetGetClientId,
    ) -> Result<SocketAddr> {
        info!(
            "OAuth2 client {} initializing for {}",
            client_id, remote_addr
        );

        // Every OAuth2 flow reads its configuration out of `protocol_data`, but the generic
        // creation path (dashboard form, MCP, `open_client`) only stores the validated
        // startup params on the client and leaves `protocol_data` empty - so a client
        // created that way arrived here unconfigured. Seed the fields once, without
        // overwriting anything a caller already put there.
        app_state
            .with_client_mut(client_id, |client| {
                if let Some(serde_json::Value::Object(params)) = client.startup_params.clone() {
                    for (key, value) in params {
                        if client.get_protocol_field(&key).is_none() {
                            client.set_protocol_field(key, value);
                        }
                    }
                }
            })
            .await;

        // Get startup parameters from protocol data
        let (oauth_client_id, oauth_client_secret, auth_url_opt, token_url, scopes_opt) = app_state
            .with_client_mut(client_id, |client| {
                let client_id_val = client
                    .get_protocol_field("client_id")
                    .and_then(|v| v.as_str())
                    .context("Missing OAuth2 client_id startup parameter")?;

                let client_secret_val = client
                    .get_protocol_field("client_secret")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());

                let auth_url = client
                    .get_protocol_field("auth_url")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());

                let token_url_val = client
                    .get_protocol_field("token_url")
                    .and_then(|v| v.as_str())
                    .context("Missing OAuth2 token_url startup parameter")?;

                let scopes = client
                    .get_protocol_field("scopes")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());

                Ok::<_, anyhow::Error>((
                    client_id_val.to_string(),
                    client_secret_val,
                    auth_url,
                    token_url_val.to_string(),
                    scopes,
                ))
            })
            .await
            .context("Client not found")??;

        // In the browser build the transport has no TLS: an `https://` token endpoint is refused
        // here, with the reason, rather than on the first token request.
        crate::client::http_fetch::check_url(&token_url)?;

        // Build OAuth2 client
        let client_id_obj = ClientId::new(oauth_client_id);
        let client_secret_obj = oauth_client_secret.map(ClientSecret::new);

        let token_url_obj = TokenUrl::new(token_url.clone()).context("Invalid token URL")?;

        // If auth_url is not provided, use token_url as placeholder (won't be used for flows that don't need it)
        let auth_url_obj = if let Some(auth_url_str) = auth_url_opt.clone() {
            AuthUrl::new(auth_url_str).context("Invalid auth URL")?
        } else {
            AuthUrl::new(token_url.clone()).context("Invalid token URL for auth placeholder")?
        };

        let _oauth_client = BasicClient::new(
            client_id_obj,
            client_secret_obj.clone(),
            auth_url_obj,
            Some(token_url_obj),
        );

        // Note: Device authorization URL would be set here if needed for device code flow
        // Format: DeviceAuthorizationUrl::new(format!("{}/device/code", remote_addr))
        // OAuth client is constructed here to validate configuration but not used yet

        // Store OAuth2 client configuration in protocol data
        app_state
            .with_client_mut(client_id, |client| {
                client
                    .set_protocol_field("oauth2_initialized".to_string(), serde_json::json!(true));
                client.set_protocol_field("token_url".to_string(), serde_json::json!(token_url));
                if let Some(auth_url) = &auth_url_opt {
                    client.set_protocol_field("auth_url".to_string(), serde_json::json!(auth_url));
                }
                if let Some(scopes) = &scopes_opt {
                    client.set_protocol_field(
                        "default_scopes".to_string(),
                        serde_json::json!(scopes),
                    );
                }
            })
            .await;

        // Update status
        app_state
            .update_client_status(client_id, ClientStatus::Connected)
            .await;
        Log::new(Some(&status_tx)).info(format!(
            "OAuth2 client {} ready for {}",
            client_id, remote_addr
        ));
        let _ = status_tx.send("__UPDATE_UI__".to_string());

        // Command channel for injected actions (the dashboard's [ exchange_password ],
        // [ refresh_token ], ...). Registered BEFORE the connected-event LLM call below,
        // which is awaited inline and which a manual `*` routing rule can park for minutes
        // - the operator must be able to drive the flow while it waits.
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

        // Call LLM with connected event
        if let Some(instruction) = app_state.get_instruction_for_client(client_id).await {
            let protocol = Arc::new(OAuth2ClientProtocol::new());
            let event = Event::new(
                &OAUTH2_CLIENT_CONNECTED_EVENT,
                serde_json::json!({
                    "token_url": token_url,
                    "auth_url": auth_url_opt,
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
                        app_state.set_memory_for_client(client_id, mem).await;
                    }

                    // Execute actions through the same path injected commands use.
                    for action in actions {
                        use crate::llm::actions::client_trait::Client;
                        let result = match protocol.execute_action(action) {
                            Ok(result) => result,
                            Err(e) => {
                                error!("OAuth2 client {} rejected action: {}", client_id, e);
                                continue;
                            }
                        };
                        match Self::apply_action(
                            result,
                            Dispatch::Inline,
                            client_id,
                            app_state.clone(),
                            llm_client.clone(),
                            status_tx.clone(),
                        )
                        .await
                        {
                            Ok(Applied::Ran(detail)) => {
                                info!("OAuth2 client {}: {}", client_id, detail)
                            }
                            Ok(Applied::Disconnect) => break,
                            Err(e) => error!("Failed to execute OAuth2 action: {}", e),
                        }
                    }
                }
                Err(e) => {
                    error!("LLM error for OAuth2 client {}: {}", client_id, e);
                }
            }
        }

        // No idle-poll task: the command loop is this client's long-lived task and it ends
        // when the client is removed (`remove_client` drops the command sender). The old
        // poll was also never registered, so stop_client could not abort it.

        // Return dummy local address (OAuth2 is HTTP-based)
        Ok("0.0.0.0:0".parse().unwrap())
    }

    /// Run one executed action. Shared by the connected-event LLM path and by injected
    /// commands, so a flow is driven by exactly one implementation whoever asked for it.
    ///
    /// The description returned by [`Applied::Ran`] is built from what is observably true
    /// *after* the flow ran - crucially, whether the provider's answer actually produced a
    /// stored access token. Nothing here can mint a code or a token on its own: a failed
    /// exchange reports the failure, it never reads as a success.
    async fn apply_action(
        action_result: ClientActionResult,
        dispatch: Dispatch,
        client_id: NetGetClientId,
        app_state: Arc<AppState>,
        llm_client: OllamaClient,
        status_tx: mpsc::UnboundedSender<String>,
    ) -> Result<Applied> {
        match action_result {
            ClientActionResult::Custom { name, data } => match name.as_str() {
                "oauth2_exchange_password" => {
                    Self::exchange_password(
                        client_id,
                        data,
                        app_state.clone(),
                        llm_client,
                        status_tx,
                        dispatch,
                    )
                    .await?;
                    Ok(Applied::Ran(
                        Self::token_state_detail(&name, client_id, &app_state).await,
                    ))
                }
                "oauth2_exchange_client_credentials" => {
                    Self::exchange_client_credentials(
                        client_id,
                        data,
                        app_state.clone(),
                        llm_client,
                        status_tx,
                        dispatch,
                    )
                    .await?;
                    Ok(Applied::Ran(
                        Self::token_state_detail(&name, client_id, &app_state).await,
                    ))
                }
                "oauth2_start_device_code" => {
                    Self::start_device_code_flow(
                        client_id,
                        data,
                        app_state.clone(),
                        llm_client,
                        status_tx,
                        dispatch,
                    )
                    .await?;
                    let has_code = app_state
                        .with_client_mut(client_id, |client| {
                            client.get_protocol_field("device_code").is_some()
                        })
                        .await
                        .unwrap_or(false);
                    Ok(Applied::Ran(if has_code {
                        "oauth2_start_device_code: device code issued, polling started".to_string()
                    } else {
                        "oauth2_start_device_code: provider issued no device code".to_string()
                    }))
                }
                "oauth2_poll_device_code" => {
                    Self::poll_device_code(
                        client_id,
                        app_state.clone(),
                        llm_client,
                        status_tx,
                        dispatch,
                    )
                    .await?;
                    Ok(Applied::Ran(
                        Self::token_state_detail(&name, client_id, &app_state).await,
                    ))
                }
                "oauth2_refresh_token" => {
                    Self::refresh_token(
                        client_id,
                        app_state.clone(),
                        llm_client,
                        status_tx,
                        dispatch,
                    )
                    .await?;
                    Ok(Applied::Ran(
                        Self::token_state_detail(&name, client_id, &app_state).await,
                    ))
                }
                "oauth2_generate_auth_url" => {
                    Self::generate_auth_url(client_id, data, app_state, status_tx).await?;
                    Ok(Applied::Ran(
                        "oauth2_generate_auth_url: authorization URL built (nothing sent; the \
                         user's browser carries it)"
                            .to_string(),
                    ))
                }
                "oauth2_exchange_code" => {
                    Self::exchange_code(
                        client_id,
                        data,
                        app_state.clone(),
                        llm_client,
                        status_tx,
                        dispatch,
                    )
                    .await?;
                    Ok(Applied::Ran(
                        Self::token_state_detail(&name, client_id, &app_state).await,
                    ))
                }
                other => Err(anyhow::anyhow!(
                    "OAuth2 client cannot execute custom result '{}'",
                    other
                )),
            },
            ClientActionResult::Disconnect => {
                info!("OAuth2 client {} disconnecting", client_id);
                app_state
                    .update_client_status(client_id, ClientStatus::Disconnected)
                    .await;
                let _ = status_tx.send("__UPDATE_UI__".to_string());
                Ok(Applied::Disconnect)
            }
            // WaitForMore / NoAction / SendData / nested Multiple: OAuth2 has no socket of
            // its own, so none of these produce a flow.
            _ => Ok(Applied::Ran(
                "no OAuth2 flow run (action produced no request)".to_string(),
            )),
        }
    }

    /// Describe a token flow by what it left behind - never by assuming it worked.
    async fn token_state_detail(
        name: &str,
        client_id: NetGetClientId,
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
                 issue one (see the oauth2_error event and netget.log)"
            )
        }
    }

    /// Build OAuth2 client from stored config
    fn build_oauth_client(
        oauth_client_id: String,
        oauth_client_secret: Option<String>,
        auth_url_opt: Option<String>,
        token_url: String,
        device_auth_url_opt: Option<String>,
    ) -> Result<BasicClient> {
        let client_id_obj = ClientId::new(oauth_client_id);
        let client_secret_obj = oauth_client_secret.map(ClientSecret::new);
        let token_url_obj = TokenUrl::new(token_url.clone())?;

        // If auth_url is not provided, use token_url as placeholder (won't be used for flows that don't need it)
        let auth_url_obj = if let Some(auth_url_str) = auth_url_opt {
            AuthUrl::new(auth_url_str)?
        } else {
            AuthUrl::new(token_url)?
        };

        let mut oauth_client = BasicClient::new(
            client_id_obj,
            client_secret_obj,
            auth_url_obj,
            Some(token_url_obj),
        );

        if let Some(device_url_str) = device_auth_url_opt {
            oauth_client = oauth_client
                .set_device_authorization_url(DeviceAuthorizationUrl::new(device_url_str)?);
        }

        Ok(oauth_client)
    }

    /// Exchange username/password for access token
    async fn exchange_password(
        client_id: NetGetClientId,
        data: serde_json::Value,
        app_state: Arc<AppState>,
        llm_client: OllamaClient,
        status_tx: mpsc::UnboundedSender<String>,
        dispatch: Dispatch,
    ) -> Result<()> {
        let username = data["username"]
            .as_str()
            .context("Missing username")?
            .to_string();
        let password = data["password"]
            .as_str()
            .context("Missing password")?
            .to_string();
        let scopes_str = data["scopes"].as_str().map(|s| s.to_string());

        info!("OAuth2 client {} exchanging password for token", client_id);

        // Get OAuth2 client config
        let (oauth_client_id, oauth_client_secret, auth_url, token_url, _) = app_state
            .with_client_mut(client_id, |client| {
                let cid = client
                    .get_protocol_field("client_id")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                    .context("Missing client_id")?;
                let csecret = client
                    .get_protocol_field("client_secret")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let aurl = client
                    .get_protocol_field("auth_url")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let turl = client
                    .get_protocol_field("token_url")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                    .context("Missing token_url")?;
                let dscopes = client
                    .get_protocol_field("default_scopes")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                Ok::<_, anyhow::Error>((cid, csecret, aurl, turl, dscopes))
            })
            .await
            .context("Client not found")??;

        let oauth_client = Self::build_oauth_client(
            oauth_client_id,
            oauth_client_secret,
            auth_url,
            token_url,
            None,
        )?;

        // Build token request
        let username_obj = ResourceOwnerUsername::new(username);
        let password_obj = ResourceOwnerPassword::new(password);
        let mut token_request = oauth_client.exchange_password(&username_obj, &password_obj);

        // Add scopes
        if let Some(scopes) = scopes_str {
            for scope in scopes.split_whitespace() {
                token_request = token_request.add_scope(Scope::new(scope.to_string()));
            }
        }

        // Execute token exchange
        match token_request.request_async(http_hook).await {
            Ok(token_response) => {
                Self::handle_token_response(
                    client_id,
                    token_response,
                    app_state,
                    llm_client,
                    status_tx,
                    dispatch,
                )
                .await?;
            }
            Err(e) => {
                Self::handle_oauth_error(
                    client_id,
                    format!("password_exchange_failed: {}", e),
                    app_state,
                    llm_client,
                    status_tx,
                    dispatch,
                )
                .await?;
            }
        }

        Ok(())
    }

    /// Exchange client credentials for access token
    async fn exchange_client_credentials(
        client_id: NetGetClientId,
        data: serde_json::Value,
        app_state: Arc<AppState>,
        llm_client: OllamaClient,
        status_tx: mpsc::UnboundedSender<String>,
        dispatch: Dispatch,
    ) -> Result<()> {
        let scopes_str = data["scopes"].as_str().map(|s| s.to_string());

        info!(
            "OAuth2 client {} exchanging client credentials for token",
            client_id
        );

        // Get OAuth2 client config
        let (oauth_client_id, oauth_client_secret, auth_url, token_url, _) = app_state
            .with_client_mut(client_id, |client| {
                let cid = client
                    .get_protocol_field("client_id")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                    .context("Missing client_id")?;
                let csecret = client
                    .get_protocol_field("client_secret")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let aurl = client
                    .get_protocol_field("auth_url")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let turl = client
                    .get_protocol_field("token_url")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                    .context("Missing token_url")?;
                let dscopes = client
                    .get_protocol_field("default_scopes")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                Ok::<_, anyhow::Error>((cid, csecret, aurl, turl, dscopes))
            })
            .await
            .context("Client not found")??;

        let oauth_client = Self::build_oauth_client(
            oauth_client_id,
            oauth_client_secret,
            auth_url,
            token_url,
            None,
        )?;

        // Build token request
        let mut token_request = oauth_client.exchange_client_credentials();

        // Add scopes
        if let Some(scopes) = scopes_str {
            for scope in scopes.split_whitespace() {
                token_request = token_request.add_scope(Scope::new(scope.to_string()));
            }
        }

        // Execute token exchange
        match token_request.request_async(http_hook).await {
            Ok(token_response) => {
                Self::handle_token_response(
                    client_id,
                    token_response,
                    app_state,
                    llm_client,
                    status_tx,
                    dispatch,
                )
                .await?;
            }
            Err(e) => {
                Self::handle_oauth_error(
                    client_id,
                    format!("client_credentials_exchange_failed: {}", e),
                    app_state,
                    llm_client,
                    status_tx,
                    dispatch,
                )
                .await?;
            }
        }

        Ok(())
    }

    /// Start device code flow
    async fn start_device_code_flow(
        client_id: NetGetClientId,
        data: serde_json::Value,
        app_state: Arc<AppState>,
        llm_client: OllamaClient,
        status_tx: mpsc::UnboundedSender<String>,
        dispatch: Dispatch,
    ) -> Result<()> {
        let scopes_str = data["scopes"].as_str().map(|s| s.to_string());

        info!("OAuth2 client {} starting device code flow", client_id);

        // Get OAuth2 client config
        let (oauth_client_id, oauth_client_secret, auth_url, token_url, device_auth_url) =
            app_state
                .with_client_mut(client_id, |client| {
                    let cid = client
                        .get_protocol_field("client_id")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string())
                        .context("Missing client_id")?;
                    let csecret = client
                        .get_protocol_field("client_secret")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    let aurl = client
                        .get_protocol_field("auth_url")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    let turl = client
                        .get_protocol_field("token_url")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string())
                        .context("Missing token_url")?;
                    let durl = client
                        .get_protocol_field("device_auth_url")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    Ok::<_, anyhow::Error>((cid, csecret, aurl, turl, durl))
                })
                .await
                .context("Client not found")??;

        let oauth_client = Self::build_oauth_client(
            oauth_client_id,
            oauth_client_secret,
            auth_url,
            token_url,
            device_auth_url,
        )?;

        // Build device authorization request
        let mut device_auth_request = oauth_client
            .exchange_device_code()
            .context("Device authorization URL not configured")?;

        // Add scopes
        if let Some(scopes) = scopes_str {
            for scope in scopes.split_whitespace() {
                device_auth_request = device_auth_request.add_scope(Scope::new(scope.to_string()));
            }
        }

        // Execute device authorization request
        match device_auth_request
            .request_async::<_, _, _, EmptyExtraDeviceAuthorizationFields>(http_hook)
            .await
        {
            Ok(device_response) => {
                let verification_uri = device_response.verification_uri().to_string();
                let user_code = device_response.user_code().secret().to_string();
                let device_code = device_response.device_code().secret().to_string();
                let interval = device_response.interval().as_secs();

                info!(
                    "OAuth2 client {} device code flow: visit {} and enter code {}",
                    client_id, verification_uri, user_code
                );

                // Store device code for polling
                app_state
                    .with_client_mut(client_id, |client| {
                        client.set_protocol_field(
                            "device_code".to_string(),
                            serde_json::json!(device_code),
                        );
                        client.set_protocol_field(
                            "polling_interval".to_string(),
                            serde_json::json!(interval),
                        );
                    })
                    .await;

                // Call LLM with device code event
                let event = Event::new(
                    &OAUTH2_DEVICE_CODE_EVENT,
                    serde_json::json!({
                        "verification_uri": verification_uri,
                        "user_code": user_code,
                        "device_code": "[REDACTED]",
                        "interval": interval,
                    }),
                );
                Self::notify_event(
                    client_id,
                    event,
                    app_state.clone(),
                    llm_client.clone(),
                    status_tx.clone(),
                    dispatch,
                )
                .await;

                // Spawn polling task
                let app_state_clone = app_state.clone();
                let llm_client_clone = llm_client.clone();
                let status_tx_clone = status_tx.clone();
                // Tracked, not detached: stop_client must abort this task too.
                let task_owner = app_state.clone();
                task_owner
                    .spawn_client_task(client_id, async move {
                        for _ in 0..60 {
                            // Poll for up to 5 minutes
                            tokio::time::sleep(std::time::Duration::from_secs(interval)).await;

                            if let Err(e) = Self::poll_device_code(
                                client_id,
                                app_state_clone.clone(),
                                llm_client_clone.clone(),
                                status_tx_clone.clone(),
                                // The polling task is nobody's injected command: report its
                                // token event inline, in its own task.
                                Dispatch::Inline,
                            )
                            .await
                            {
                                error!("Device code polling error: {}", e);
                                break;
                            }

                            // Check if token was obtained
                            let has_token = app_state_clone
                                .with_client_mut(client_id, |client| {
                                    client.get_protocol_field("access_token").is_some()
                                })
                                .await
                                .unwrap_or(false);

                            if has_token {
                                break;
                            }
                        }
                    })
                    .await;
            }
            Err(e) => {
                Self::handle_oauth_error(
                    client_id,
                    format!("device_code_failed: {}", e),
                    app_state,
                    llm_client,
                    status_tx,
                    dispatch,
                )
                .await?;
            }
        }

        Ok(())
    }

    /// Poll device code for completion
    async fn poll_device_code(
        client_id: NetGetClientId,
        app_state: Arc<AppState>,
        llm_client: OllamaClient,
        status_tx: mpsc::UnboundedSender<String>,
        dispatch: Dispatch,
    ) -> Result<()> {
        // Get device code and OAuth client config
        let (device_code_str, oauth_client_id, oauth_client_secret, _auth_url, token_url) =
            app_state
                .with_client_mut(client_id, |client| {
                    let dc = client
                        .get_protocol_field("device_code")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string())
                        .context("Missing device_code")?;
                    let cid = client
                        .get_protocol_field("client_id")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string())
                        .context("Missing client_id")?;
                    let csecret = client
                        .get_protocol_field("client_secret")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    let aurl = client
                        .get_protocol_field("auth_url")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    let turl = client
                        .get_protocol_field("token_url")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string())
                        .context("Missing token_url")?;
                    Ok::<_, anyhow::Error>((dc, cid, csecret, aurl, turl))
                })
                .await
                .context("Client not found")??;

        // Make direct HTTP request to token endpoint for device code polling
        // This is a workaround since we can't reconstruct DeviceAuthorizationResponse
        let client = plain_http_client();
        let mut params = vec![
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ("device_code", device_code_str.as_str()),
            ("client_id", oauth_client_id.as_str()),
        ];

        // Add client secret if present
        let client_secret_param;
        if let Some(ref secret) = oauth_client_secret {
            client_secret_param = secret.clone();
            params.push(("client_secret", client_secret_param.as_str()));
        }

        match client.post(&token_url).form(&params).send().await {
            Ok(response) => {
                let status = response.status();
                let body: serde_json::Value = response.json().await?;

                if status.is_success() {
                    // Token obtained successfully
                    if let Some(access_token) = body.get("access_token").and_then(|v| v.as_str()) {
                        let token_type = body
                            .get("token_type")
                            .and_then(|v| v.as_str())
                            .unwrap_or("Bearer");
                        let expires_in = body
                            .get("expires_in")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(3600);
                        let refresh_token = body
                            .get("refresh_token")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string());
                        let scope = body.get("scope").and_then(|v| v.as_str()).unwrap_or("");

                        // Store tokens
                        app_state
                            .with_client_mut(client_id, |client| {
                                client.set_protocol_field(
                                    "access_token".to_string(),
                                    serde_json::json!(access_token),
                                );
                                client.set_protocol_field(
                                    "token_type".to_string(),
                                    serde_json::json!(token_type),
                                );
                                client.set_protocol_field(
                                    "expires_in".to_string(),
                                    serde_json::json!(expires_in),
                                );
                                if let Some(rt) = &refresh_token {
                                    client.set_protocol_field(
                                        "refresh_token".to_string(),
                                        serde_json::json!(rt),
                                    );
                                }
                                if !scope.is_empty() {
                                    client.set_protocol_field(
                                        "scopes".to_string(),
                                        serde_json::json!(scope),
                                    );
                                }
                            })
                            .await;

                        info!("OAuth2 client {} device code token obtained", client_id);

                        // Call LLM with token obtained event
                        let event = Event::new(
                            &OAUTH2_TOKEN_OBTAINED_EVENT,
                            serde_json::json!({
                                "access_token": "[REDACTED]",
                                "token_type": token_type,
                                "expires_in": expires_in,
                                "refresh_token": if refresh_token.is_some() { "[REDACTED]" } else { "" },
                                "scope": scope,
                            }),
                        );
                        Self::notify_event(
                            client_id,
                            event,
                            app_state.clone(),
                            llm_client.clone(),
                            status_tx.clone(),
                            dispatch,
                        )
                        .await;
                    }
                } else {
                    // Check for authorization_pending error
                    let error = body
                        .get("error")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown");
                    if error != "authorization_pending" && error != "slow_down" {
                        error!("Device code polling error: {}", error);
                    }
                }
            }
            Err(e) => {
                error!("Device code polling HTTP error: {}", e);
            }
        }

        Ok(())
    }

    /// Refresh access token using refresh token
    async fn refresh_token(
        client_id: NetGetClientId,
        app_state: Arc<AppState>,
        llm_client: OllamaClient,
        status_tx: mpsc::UnboundedSender<String>,
        dispatch: Dispatch,
    ) -> Result<()> {
        info!("OAuth2 client {} refreshing token", client_id);

        // Get refresh token and OAuth client config
        let (refresh_token_str, oauth_client_id, oauth_client_secret, auth_url, token_url) =
            app_state
                .with_client_mut(client_id, |client| {
                    let rt = client
                        .get_protocol_field("refresh_token")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string())
                        .context("No refresh token available")?;
                    let cid = client
                        .get_protocol_field("client_id")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string())
                        .context("Missing client_id")?;
                    let csecret = client
                        .get_protocol_field("client_secret")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    let aurl = client
                        .get_protocol_field("auth_url")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    let turl = client
                        .get_protocol_field("token_url")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string())
                        .context("Missing token_url")?;
                    Ok::<_, anyhow::Error>((rt, cid, csecret, aurl, turl))
                })
                .await
                .context("Client not found")??;

        let oauth_client = Self::build_oauth_client(
            oauth_client_id,
            oauth_client_secret,
            auth_url,
            token_url,
            None,
        )?;

        // Execute token refresh
        match oauth_client
            .exchange_refresh_token(&RefreshToken::new(refresh_token_str))
            .request_async(http_hook)
            .await
        {
            Ok(token_response) => {
                Self::handle_token_response(
                    client_id,
                    token_response,
                    app_state,
                    llm_client,
                    status_tx,
                    dispatch,
                )
                .await?;
            }
            Err(e) => {
                Self::handle_oauth_error(
                    client_id,
                    format!("token_refresh_failed: {}", e),
                    app_state,
                    llm_client,
                    status_tx,
                    dispatch,
                )
                .await?;
            }
        }

        Ok(())
    }

    /// Generate authorization URL for authorization code flow
    async fn generate_auth_url(
        client_id: NetGetClientId,
        data: serde_json::Value,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
    ) -> Result<()> {
        let scopes_str = data["scopes"].as_str().map(|s| s.to_string());
        let redirect_uri_str = data["redirect_uri"]
            .as_str()
            .unwrap_or("http://localhost:8080/callback");

        info!("OAuth2 client {} generating auth URL", client_id);

        // Get OAuth client config
        let (oauth_client_id, oauth_client_secret, auth_url, token_url, _) = app_state
            .with_client_mut(client_id, |client| {
                let cid = client
                    .get_protocol_field("client_id")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                    .context("Missing client_id")?;
                let csecret = client
                    .get_protocol_field("client_secret")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let aurl = client
                    .get_protocol_field("auth_url")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                    .context("Missing auth_url for authorization code flow")?;
                let turl = client
                    .get_protocol_field("token_url")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                    .context("Missing token_url")?;
                let dscopes = client
                    .get_protocol_field("default_scopes")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                Ok::<_, anyhow::Error>((cid, csecret, Some(aurl), turl, dscopes))
            })
            .await
            .context("Client not found")??;

        let mut oauth_client = Self::build_oauth_client(
            oauth_client_id,
            oauth_client_secret,
            auth_url,
            token_url,
            None,
        )?;

        // Set redirect URI
        oauth_client =
            oauth_client.set_redirect_uri(RedirectUrl::new(redirect_uri_str.to_string())?);

        // Generate PKCE challenge
        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

        // Build authorization URL
        let mut auth_request = oauth_client
            .authorize_url(CsrfToken::new_random)
            .set_pkce_challenge(pkce_challenge);

        // Add scopes
        if let Some(scopes) = scopes_str {
            for scope in scopes.split_whitespace() {
                auth_request = auth_request.add_scope(Scope::new(scope.to_string()));
            }
        }

        let (auth_url_result, csrf_token) = auth_request.url();

        // Store PKCE verifier and CSRF token for later
        app_state
            .with_client_mut(client_id, |client| {
                client.set_protocol_field(
                    "pkce_verifier".to_string(),
                    serde_json::json!(pkce_verifier.secret()),
                );
                client.set_protocol_field(
                    "csrf_token".to_string(),
                    serde_json::json!(csrf_token.secret()),
                );
                client.set_protocol_field(
                    "redirect_uri".to_string(),
                    serde_json::json!(redirect_uri_str),
                );
            })
            .await;

        let log = Log::new(Some(&status_tx));
        log.info(format!("OAuth2 authorization URL: {}", auth_url_result));
        log.info("Visit the URL above to authorize, then paste the code".to_string());

        Ok(())
    }

    /// Exchange authorization code for access token
    async fn exchange_code(
        client_id: NetGetClientId,
        data: serde_json::Value,
        app_state: Arc<AppState>,
        llm_client: OllamaClient,
        status_tx: mpsc::UnboundedSender<String>,
        dispatch: Dispatch,
    ) -> Result<()> {
        let code = data["code"].as_str().context("Missing code")?.to_string();

        info!("OAuth2 client {} exchanging authorization code", client_id);

        // Get OAuth client config and PKCE verifier
        let (
            pkce_verifier_str,
            redirect_uri,
            oauth_client_id,
            oauth_client_secret,
            auth_url,
            token_url,
        ) = app_state
            .with_client_mut(client_id, |client| {
                let pkce = client
                    .get_protocol_field("pkce_verifier")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                    .context("Missing PKCE verifier")?;
                let redir = client
                    .get_protocol_field("redirect_uri")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                    .context("Missing redirect_uri")?;
                let cid = client
                    .get_protocol_field("client_id")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                    .context("Missing client_id")?;
                let csecret = client
                    .get_protocol_field("client_secret")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let aurl = client
                    .get_protocol_field("auth_url")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let turl = client
                    .get_protocol_field("token_url")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                    .context("Missing token_url")?;
                Ok::<_, anyhow::Error>((pkce, redir, cid, csecret, aurl, turl))
            })
            .await
            .context("Client not found")??;

        let mut oauth_client = Self::build_oauth_client(
            oauth_client_id,
            oauth_client_secret,
            auth_url,
            token_url,
            None,
        )?;

        oauth_client = oauth_client.set_redirect_uri(RedirectUrl::new(redirect_uri)?);

        // Exchange code for token
        let token_request = oauth_client
            .exchange_code(AuthorizationCode::new(code))
            .set_pkce_verifier(oauth2::PkceCodeVerifier::new(pkce_verifier_str));

        match token_request.request_async(http_hook).await {
            Ok(token_response) => {
                Self::handle_token_response(
                    client_id,
                    token_response,
                    app_state,
                    llm_client,
                    status_tx,
                    dispatch,
                )
                .await?;
            }
            Err(e) => {
                Self::handle_oauth_error(
                    client_id,
                    format!("code_exchange_failed: {}", e),
                    app_state,
                    llm_client,
                    status_tx,
                    dispatch,
                )
                .await?;
            }
        }

        Ok(())
    }

    /// Handle successful token response
    async fn handle_token_response(
        client_id: NetGetClientId,
        token_response: TokenResponseType,
        app_state: Arc<AppState>,
        llm_client: OllamaClient,
        status_tx: mpsc::UnboundedSender<String>,
        dispatch: Dispatch,
    ) -> Result<()> {
        let access_token = token_response.access_token().secret().to_string();
        let token_type = token_response.token_type().as_ref().to_string();
        let expires_in = token_response
            .expires_in()
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let refresh_token = token_response
            .refresh_token()
            .map(|rt| rt.secret().to_string());
        let scopes = token_response
            .scopes()
            .map(|s| {
                s.iter()
                    .map(|scope| scope.to_string())
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .unwrap_or_default();

        info!(
            "OAuth2 client {} obtained access token (expires in {}s)",
            client_id, expires_in
        );

        // Store tokens
        app_state
            .with_client_mut(client_id, |client| {
                client.set_protocol_field(
                    "access_token".to_string(),
                    serde_json::json!(access_token),
                );
                client.set_protocol_field("token_type".to_string(), serde_json::json!(token_type));
                client.set_protocol_field("expires_in".to_string(), serde_json::json!(expires_in));
                if let Some(rt) = &refresh_token {
                    client.set_protocol_field("refresh_token".to_string(), serde_json::json!(rt));
                }
                if !scopes.is_empty() {
                    client.set_protocol_field("scopes".to_string(), serde_json::json!(scopes));
                }
            })
            .await;

        // Call LLM with token obtained event
        let event = Event::new(
            &OAUTH2_TOKEN_OBTAINED_EVENT,
            serde_json::json!({
                "access_token": "[REDACTED]",
                "token_type": token_type,
                "expires_in": expires_in,
                "refresh_token": if refresh_token.is_some() { "[REDACTED]" } else { "" },
                "scope": scopes,
            }),
        );
        Self::notify_event(client_id, event, app_state, llm_client, status_tx, dispatch).await;

        Ok(())
    }

    /// Handle OAuth error
    async fn handle_oauth_error(
        client_id: NetGetClientId,
        error: String,
        app_state: Arc<AppState>,
        llm_client: OllamaClient,
        status_tx: mpsc::UnboundedSender<String>,
        dispatch: Dispatch,
    ) -> Result<()> {
        Log::new(Some(&status_tx)).error(format!("OAuth2 client {} error: {}", client_id, error));

        // Call LLM with error event
        let event = Event::new(
            &OAUTH2_ERROR_EVENT,
            serde_json::json!({
                "error": error,
                "error_description": "",
            }),
        );
        Self::notify_event(client_id, event, app_state, llm_client, status_tx, dispatch).await;

        Ok(())
    }

    /// Report one event to the LLM, inline or from a registered task.
    async fn notify_event(
        client_id: NetGetClientId,
        event: Event,
        app_state: Arc<AppState>,
        llm_client: OllamaClient,
        status_tx: mpsc::UnboundedSender<String>,
        dispatch: Dispatch,
    ) {
        match dispatch {
            // Deliberately nothing: see `Dispatch::Silent`.
            Dispatch::Silent => {}
            Dispatch::Inline => {
                Self::raise_event(client_id, event, app_state, llm_client, status_tx).await
            }
            Dispatch::Deferred => {
                let registrar = app_state.clone();
                let handle = tokio::spawn(Self::raise_event(
                    client_id, event, app_state, llm_client, status_tx,
                ));
                // Registered so stop_client aborts an in-flight LLM call for this event.
                registrar.register_client_task(client_id, handle).await;
            }
        }
    }

    /// The event -> LLM round-trip itself, plus whatever the model answers.
    ///
    /// Returns a boxed future rather than being a plain `async fn`. Executing the answer
    /// closes a cycle -- raise_event -> apply_action -> a token flow -> notify_event ->
    /// raise_event -- and rustc cannot infer the type of a self-referential chain of
    /// `async fn`s. Boxing one member of the cycle turns that edge into an ordinary
    /// dynamic call.
    fn raise_event(
        client_id: NetGetClientId,
        event: Event,
        app_state: Arc<AppState>,
        llm_client: OllamaClient,
        status_tx: mpsc::UnboundedSender<String>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> {
        Box::pin(async move {
            let protocol = Arc::new(OAuth2ClientProtocol::new());
            let instruction = app_state
                .get_instruction_for_client(client_id)
                .await
                .unwrap_or_default();
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

                    // Do what the model asked for. This was discarded, so answering
                    // oauth2_token_obtained or oauth2_error did nothing -- a model that saw a
                    // token expire and wanted to refresh it, or saw an error and wanted to
                    // fall back to another grant, was ignored on the only events that report
                    // either.
                    //
                    // Every flow runs with Dispatch::Silent, so it raises no further event.
                    // That bound is not optional here: a refresh answered on a token event
                    // would raise another token event, whose answer could refresh again.
                    use crate::llm::actions::client_trait::Client;
                    for action in actions {
                        match protocol.execute_action(action.clone()) {
                            Ok(result) => {
                                if let Err(e) = Self::apply_action(
                                    result,
                                    Dispatch::Silent,
                                    client_id,
                                    app_state.clone(),
                                    llm_client.clone(),
                                    status_tx.clone(),
                                )
                                .await
                                {
                                    error!(
                                        "OAuth2 client {} follow-up action failed: {}",
                                        client_id, e
                                    );
                                }
                            }
                            Err(e) => error!(
                                "OAuth2 client {} rejected its own follow-up action: {}",
                                client_id, e
                            ),
                        }
                    }
                }
                Err(e) => {
                    error!("LLM error for OAuth2 client {}: {}", client_id, e);
                }
            }
        })
    }

    /// Drain injected commands until the channel closes (the client was removed) or an
    /// injected `disconnect` ends the session.
    ///
    /// The flow itself is awaited, so the reported [`ClientSendOutcome`] describes what the
    /// provider actually did; only the resulting `oauth2_token_obtained` / `oauth2_error`
    /// event is handed to its own task, so a manual routing rule waiting on a human cannot
    /// hold up the reply. An action the protocol rejects is reported as `Rejected` and an
    /// action that ran without producing a token says so - there is no path here that can
    /// report success for a flow that did not complete.
    async fn command_loop(
        mut command_rx: mpsc::Receiver<ClientCommand>,
        client_id: NetGetClientId,
        app_state: Arc<AppState>,
        llm_client: OllamaClient,
        status_tx: mpsc::UnboundedSender<String>,
    ) {
        use crate::llm::actions::client_trait::Client;
        use crate::llm::actions::protocol_trait::Protocol;

        let protocol = OAuth2ClientProtocol::new();

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
                    app_state.clone(),
                    llm_client.clone(),
                    status_tx.clone(),
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
                    "OAuth2 client {} injected action failed: {}",
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
        info!("OAuth2 client {} command loop ended", client_id);
    }
}
