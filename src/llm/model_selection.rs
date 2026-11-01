//! Model selection utilities for Ollama
//!
//! This module provides functions to query available models from Ollama
//! and select the best one based on size and recency.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

/// Information about an Ollama model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelInfo {
    pub name: String,
    pub size: u64,
    pub modified_at: String,
}

/// Query Ollama for available models and return detailed information
pub async fn query_available_models(ollama_url: &str) -> Result<Vec<ModelInfo>> {
    #[cfg(target_arch = "wasm32")]
    {
        let _ = ollama_url;
        anyhow::bail!("the browser build has no Ollama to query; models come from the page");
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        // Built through the shared helper, not `Client::new()`: this call has a 5-second timeout,
        // and pointing it at a literal IP used to spend all five inside `getaddrinfo("127.0.0.1")`
        // under load. It surfaced as `bluetooth_read_request` handlers "answering" in exactly
        // 5.003s with zero calls reaching the backend — the read failed closed on a timeout that
        // was pure name resolution. See `crate::llm::ollama_client::client_for_endpoint`.
        let client = crate::llm::ollama_client::client_for_endpoint(ollama_url);
        let url = format!("{}/api/tags", ollama_url);
        let response = client
            .get(&url)
            .timeout(std::time::Duration::from_secs(5))
            .send()
            .await
            .context("Failed to connect to Ollama API. Is Ollama running?")?;

        if !response.status().is_success() {
            anyhow::bail!("Ollama API returned error status: {}", response.status());
        }

        let body = crate::client::http_fetch::read_response_text(response, 8 * 1024 * 1024)
            .await
            .context("Failed to read response from Ollama")?;

        // Parse the response
        let json: serde_json::Value =
            serde_json::from_str(&body).context("Failed to parse Ollama API response")?;

        let models = json
            .get("models")
            .and_then(|m| m.as_array())
            .context("Ollama API response missing 'models' array")?;

        let mut result = Vec::new();
        for model in models {
            let name = model
                .get("name")
                .and_then(|n| n.as_str())
                .unwrap_or("")
                .to_string();
            let size = model.get("size").and_then(|s| s.as_u64()).unwrap_or(0);
            let modified_at = model
                .get("modified_at")
                .and_then(|m| m.as_str())
                .unwrap_or("")
                .to_string();

            if !name.is_empty() {
                result.push(ModelInfo {
                    name,
                    size,
                    modified_at,
                });
            }
        }

        Ok(result)
    }
}

/// Select the best model from available models
/// Prioritizes: largest size, then most recent modification
pub fn select_best_model(models: &[ModelInfo]) -> Option<String> {
    if models.is_empty() {
        return None;
    }

    // Sort by size (descending), then by modified_at (descending)
    let mut sorted = models.to_vec();
    sorted.sort_by(|a, b| {
        // First compare by size (larger is better)
        match b.size.cmp(&a.size) {
            std::cmp::Ordering::Equal => {
                // If sizes are equal, compare by modified_at (more recent is better)
                b.modified_at.cmp(&a.modified_at)
            }
            other => other,
        }
    });

    debug!(
        "Available models sorted by size: {:?}",
        sorted
            .iter()
            .map(|m| format!("{} ({} bytes)", m.name, m.size))
            .collect::<Vec<_>>()
    );

    Some(sorted[0].name.clone())
}

/// Check if Ollama is available and return available models
pub async fn check_ollama_availability(ollama_url: &str) -> Result<Vec<ModelInfo>> {
    query_available_models(ollama_url)
        .await
        .context("Ollama is not available")
}

/// Select or validate a model for use
///
/// # Arguments
/// * `configured_model` - Model from settings/args (None = auto-select)
/// * `interactive` - Whether running in interactive mode (affects error handling)
/// * `ollama_url` - URL of the Ollama server
///
/// # Returns
/// * `Ok(Some(model))` - Model selected and ready to use
/// * `Ok(None)` - No model available but should continue (interactive mode only)
/// * `Err(_)` - Critical error, should exit
pub async fn select_or_validate_model(
    configured_model: Option<String>,
    interactive: bool,
    ollama_url: &str,
) -> Result<Option<String>> {
    // Query Ollama for available models
    let models = match check_ollama_availability(ollama_url).await {
        Ok(models) => models,
        Err(e) => {
            // Name the endpoint. "Ollama is not available" without a host is unactionable
            // precisely when it matters most — the failure this function had was that it
            // asked a *different* host than the operator configured, and a message that
            // omits the host cannot show that.
            let error_msg = format!(
                "✗  Ollama is not available at {}: {}\n   Please ensure Ollama is running there: https://ollama.ai\n   Use `/model` to list and select a model once Ollama is running.",
                ollama_url, e
            );

            if interactive {
                // In interactive mode, show warning but allow continuing
                warn!("{}", error_msg);
                return Ok(None);
            } else {
                // In non-interactive mode, this is a critical error
                anyhow::bail!("{}", error_msg);
            }
        }
    };

    if models.is_empty() {
        let error_msg = "✗  No models available in Ollama.\n   Please pull a model first: ollama pull qwen2.5-coder:32b\n   Use `/model` to list and select a model.";

        if interactive {
            warn!("{}", error_msg);
            return Ok(None);
        } else {
            anyhow::bail!("{}", error_msg);
        }
    }

    // If a model is configured, validate it exists
    if let Some(ref model_name) = configured_model {
        let names: Vec<String> = models.iter().map(|m| m.name.clone()).collect();
        let model_exists = model_is_listed(model_name, &names);

        if !model_exists {
            let available_models = models
                .iter()
                .map(|m| m.name.as_str())
                .collect::<Vec<_>>()
                .join(", ");

            let error_msg = format!(
                "✗  Configured model '{}' is not installed at Ollama {}.\n   Installed models: {}\n   Use `/model` to select a different model.",
                model_name, ollama_url, available_models
            );

            if interactive {
                warn!("{}", error_msg);
                // Try to auto-select a different model
                if let Some(best_model) = select_best_model(&models) {
                    warn!("⚠  Auto-selecting model: {}", best_model);
                    return Ok(Some(best_model));
                }
                return Ok(None);
            } else {
                anyhow::bail!("{}", error_msg);
            }
        }

        info!("✓  Using configured model: {}", model_name);
        return Ok(Some(model_name.clone()));
    }

    // No model configured, auto-select the best one
    if let Some(best_model) = select_best_model(&models) {
        warn!(
            "⚠  No model configured, auto-selected: {} (largest/most recent)",
            best_model
        );
        info!("   To set a different model, use: /model or edit ~/.netget settings");
        Ok(Some(best_model))
    } else {
        // This shouldn't happen since we checked models.is_empty() above
        Ok(None)
    }
}

/// Ensure we have a model for LLM calls.
///
/// If no model is set, auto-selects one from the LLM endpoint **this process was pointed
/// at** — `llm_endpoint`, which every caller reads from `AppState::get_ollama_url()`.
/// Returns an error if that endpoint is unreachable or advertises no models.
///
/// The endpoint is a parameter rather than a constant because it used to be
/// `"http://localhost:11434"`, hardcoded, with a comment claiming this function is "typically
/// called from interactive TUI mode where ollama_url should already be validated during
/// startup". That was false for three shipped paths, each of which sets the model only
/// `if let Some(model) = configured_model`: `--mcp`/`--mcp-http`, `netget --client … --connect …`
/// (`run_client`, which deliberately skips `select_or_validate_model`), and the dashboard,
/// which stores `None` when `resolve_startup_model` comes back empty. On any of them,
/// `netget --mcp --ollama-url http://gpu-box:11434` with no `--model` auto-selected against
/// **localhost** — so it either failed closed with "Failed to ensure model is selected" while a
/// perfectly good backend sat waiting, or, worse, picked a model name off a local Ollama and
/// sent it to the remote endpoint, which does not have it.
///
/// The symptom is the giveaway and is worth recognising: the endpoint the operator configured
/// receives **no request at all**, not even a failing one. `tests/model_selection_endpoint_test.rs`
/// pins this by counting `/api/tags` hits on a mock, which is the only thing that can tell
/// "asked the right host and it said no" apart from "asked a different host".
pub async fn ensure_model_selected(
    current_model: Option<String>,
    llm_endpoint: &str,
) -> Result<String> {
    if let Some(model) = current_model {
        // Model already set
        debug!("Model already selected: {}", model);
        return Ok(model);
    }

    // No model set, try to auto-select one from the configured endpoint.
    warn!(
        "⚠  No model selected, attempting to auto-select from models available at {}...",
        llm_endpoint
    );

    match select_or_validate_model(None, false, llm_endpoint).await {
        Ok(Some(model)) => {
            info!("✓  Auto-selected model: {}", model);
            warn!(
                "⚠  Auto-selected model: {} (no model was configured)",
                model
            );
            Ok(model)
        }
        Ok(None) => {
            anyhow::bail!(
                "✗  No model available at {}.\n   Please:\n   1. Ensure Ollama is running there: https://ollama.ai\n   2. Pull a model: ollama pull qwen2.5-coder:32b\n   3. Use `/model` to select a model",
                llm_endpoint
            )
        }
        Err(e) => Err(e),
    }
}

/// Whether `model` is one of `names` the way the backend resolves a model name: exactly, or —
/// for an untagged name — as `<name>:latest`, which is what Ollama completes it to.
pub fn model_is_listed(model: &str, names: &[String]) -> bool {
    let model = model.trim();
    names.iter().any(|name| {
        name == model || (!model.contains(':') && name.strip_suffix(":latest") == Some(model))
    })
}

/// How long a model listing may take before it is reported as "could not check". The listing
/// sits on `get_status`, `set_model` and MCP startup, none of which should wait on a request
/// timeout meant for generation.
pub const MODEL_LISTING_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// What the backend says about one model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModelAvailability {
    /// The endpoint lists it.
    Installed,
    /// The endpoint lists models and this is not one of them.
    NotInstalled { installed: Vec<String> },
    /// The endpoint could not be asked (unreachable, or it does not list models).
    Unknown { reason: String },
    /// The backend has no models of its own to check against: the calling agent
    /// (`--llm-agent`) or the browser host bridge answers whatever the name.
    NotApplicable,
}

/// The models `client`'s endpoint lists, with their sizes where the backend reports them
/// (Ollama does, OpenAI-compatible endpoints do not). `None` for a backend with no models of
/// its own to list (the agent queue, the host bridge).
pub async fn listed_models(client: &crate::llm::OllamaClient) -> Option<Result<Vec<ModelInfo>>> {
    match client.backend_type() {
        "ollama" => {
            let endpoint = client.backend_url();
            Some(query_available_models(endpoint.trim_end_matches('/')).await)
        }
        "openai" => Some(
            match tokio::time::timeout(MODEL_LISTING_TIMEOUT, client.list_models()).await {
                Ok(Ok(names)) => Ok(names
                    .into_iter()
                    .map(|name| ModelInfo {
                        name,
                        size: 0,
                        modified_at: String::new(),
                    })
                    .collect()),
                Ok(Err(e)) => Err(e),
                Err(_) => Err(anyhow::anyhow!(
                    "listing models timed out after {:?}",
                    MODEL_LISTING_TIMEOUT
                )),
            },
        ),
        _ => None,
    }
}

/// `"Ollama http://host:11434"` / `"OpenAI-compatible endpoint https://…"`, for messages.
pub fn describe_endpoint(client: &crate::llm::OllamaClient) -> String {
    let backend = match client.backend_type() {
        "ollama" => crate::llm::backend_error::OLLAMA,
        "openai" => crate::llm::backend_error::OPENAI,
        other => other,
    };
    format!("{} {}", backend, client.backend_url().trim_end_matches('/'))
}

/// Ask `client`'s endpoint whether it has `model`.
pub async fn check_model(client: &crate::llm::OllamaClient, model: &str) -> ModelAvailability {
    match listed_models(client).await {
        None => ModelAvailability::NotApplicable,
        Some(Err(e)) => ModelAvailability::Unknown {
            reason: format!("{e:#}"),
        },
        Some(Ok(models)) => {
            let installed: Vec<String> = models.into_iter().map(|m| m.name).collect();
            if model_is_listed(model, &installed) {
                ModelAvailability::Installed
            } else {
                ModelAvailability::NotInstalled { installed }
            }
        }
    }
}

/// A short list of model names for a message: all of them up to ten, then a count.
pub fn summarize_models(names: &[String]) -> String {
    if names.is_empty() {
        return "none".to_string();
    }
    const SHOWN: usize = 10;
    let mut out = names
        .iter()
        .take(SHOWN)
        .cloned()
        .collect::<Vec<_>>()
        .join(", ");
    if names.len() > SHOWN {
        out.push_str(&format!(" and {} more", names.len() - SHOWN));
    }
    out
}

/// The model a headless process (MCP) should use, and what to say about how it was chosen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedModel {
    /// The model to store in `AppState` (`None` = auto-select at the first request).
    pub model: Option<String>,
    /// Said in the log and in `get_status` whenever the model in use is not simply the
    /// configured one, or could not be verified.
    pub notice: Option<String>,
}

/// Validate a configured model against `client`'s endpoint before anything uses it.
///
/// - Listed, or no model configured, or a backend with no models of its own: unchanged.
/// - Ollama lists models and this is not one: the best installed model is used instead —
///   the same choice the interactive dashboard makes — and the notice names both and the
///   endpoint. Using the configured name anyway would fail every request in milliseconds.
/// - An OpenAI-compatible endpoint lists models and this is not one: kept, with a notice.
///   Such endpoints often accept names they do not list (aliases, routed models), and they
///   report no sizes to choose a replacement by.
/// - The endpoint cannot be asked: kept, with a notice that it is unverified, so a backend
///   that comes up after NetGet still gets the model the operator chose.
pub async fn resolve_configured_model(
    client: &crate::llm::OllamaClient,
    configured: Option<String>,
) -> ResolvedModel {
    let Some(model) = configured else {
        return ResolvedModel {
            model: None,
            notice: None,
        };
    };
    let endpoint = describe_endpoint(client);
    let unchanged = |notice: Option<String>| ResolvedModel {
        model: Some(model.clone()),
        notice,
    };
    match listed_models(client).await {
        None => unchanged(None),
        Some(Err(e)) => unchanged(Some(format!(
            "could not list the models at {endpoint} ({e:#}); using the configured model \
             '{model}' unverified"
        ))),
        Some(Ok(models)) => {
            let names: Vec<String> = models.iter().map(|m| m.name.clone()).collect();
            if model_is_listed(&model, &names) {
                return unchanged(None);
            }
            if client.backend_type() != "ollama" {
                return unchanged(Some(format!(
                    "the configured model '{model}' is not listed by {endpoint} (it lists: {}); \
                     using it anyway — requests fail if the endpoint does not serve it",
                    summarize_models(&names)
                )));
            }
            match select_best_model(&models) {
                Some(best) => ResolvedModel {
                    notice: Some(format!(
                        "the configured model '{model}' is not installed at {endpoint} \
                         (installed: {}); using '{best}' instead",
                        summarize_models(&names)
                    )),
                    model: Some(best),
                },
                None => unchanged(Some(format!(
                    "the configured model '{model}' is not installed at {endpoint}, which has \
                     no models installed; every request will fail until one is pulled"
                ))),
            }
        }
    }
}

/// The model for an LLM call, auto-selected and **stored** when none is set.
///
/// [`ensure_model_selected`] returns the auto-selected model without recording it, so every
/// request re-asked the endpoint and `get_status` kept saying "(auto-select)" while requests
/// went to a model it never named. This records the choice in `state` the first time it is
/// made, with a notice saying how it was made.
pub async fn ensure_state_model(state: &crate::state::AppState) -> Result<String> {
    if let Some(model) = state.get_ollama_model().await {
        return Ok(model);
    }
    let endpoint = state.get_ollama_url().await;
    let model = ensure_model_selected(None, &endpoint).await?;
    if state.set_ollama_model_if_unset(model.clone()).await {
        state.set_model_notice(Some(format!(
            "no model was configured; auto-selected '{model}' (largest installed) at {endpoint}"
        )));
        Ok(model)
    } else {
        // Someone set one meanwhile (set_model, another request's auto-selection): use theirs.
        Ok(state.get_ollama_model().await.unwrap_or(model))
    }
}
