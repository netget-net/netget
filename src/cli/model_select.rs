//! Startup model resolution shared by the interactive UIs (rolling TUI and
//! full-screen dashboard): decide which model to use from args/settings,
//! validate or auto-select it, and produce the human-readable lines the UI
//! should show about the outcome.

use anyhow::Result;
use tracing::{error, info, warn};

use crate::settings::Settings;

/// Outcome of startup model resolution.
pub struct StartupModel {
    /// Base URL of the model backend (Ollama or OpenAI-compatible).
    pub base_url: String,
    /// The selected model; empty string when none is available (interactive
    /// mode continues and the user picks one later).
    pub model: String,
    /// Lines the UI should surface about how the model was chosen.
    pub messages: Vec<String>,
}

/// Resolve the startup model exactly as the rolling TUI always has: args
/// override settings; OpenAI mode trusts the pre-validated model; Ollama mode
/// validates or auto-selects, tolerating an unavailable Ollama.
pub async fn resolve_startup_model(
    args: &super::Args,
    settings: &Settings,
) -> Result<StartupModel> {
    let configured_model = args.model.clone().or(settings.model.clone());

    let base_url = args
        .openai_url
        .as_deref()
        .or(args.ollama_url.as_deref())
        .unwrap_or("http://localhost:11434")
        .to_string();

    if args.openai_url.is_some() {
        // OpenAI mode: model was already validated as required in create_llm_client
        let model = configured_model.unwrap_or_default();
        let messages = vec![format!("✓  Using OpenAI-compatible backend: {}", base_url)];
        return Ok(StartupModel {
            base_url,
            model,
            messages,
        });
    }

    match crate::llm::select_or_validate_model(configured_model.clone(), true, &base_url).await {
        Ok(Some(model)) => {
            info!("✓  Using model: {}", model);
            let messages = if let Some(ref config_model) = configured_model {
                if config_model == &model {
                    info!("✓  Using configured model: {}", model);
                    vec![]
                } else {
                    let line = format!(
                        "⚠  Configured model '{}' is not installed at Ollama {}; using '{}' instead",
                        config_model, base_url, model
                    );
                    warn!("{}", line);
                    vec![line]
                }
            } else {
                vec![
                    format!(
                        "⚠  No model configured, auto-selected: {} (largest/most recent)",
                        model
                    ),
                    "   To set a different model, use: /model or edit ~/.netget settings"
                        .to_string(),
                ]
            };
            Ok(StartupModel {
                base_url,
                model,
                messages,
            })
        }
        Ok(None) => {
            warn!("⚠  No model selected. Use /model command to select one.");
            let messages = vec![
                "✗  Ollama is not available or no models found.".to_string(),
                "   Please ensure Ollama is running: https://ollama.ai".to_string(),
                "   Use `/model` to list and select a model once Ollama is running.".to_string(),
            ];
            Ok(StartupModel {
                base_url,
                model: String::new(),
                messages,
            })
        }
        Err(e) => {
            error!("Failed to initialize model: {}", e);
            eprintln!("✗  Failed to initialize model: {}", e);
            Err(e)
        }
    }
}
