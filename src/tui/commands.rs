//! Chat submit path: history, `UserCommand` parsing, LLM dispatch.
//!
//! Slash commands keep working because `UserCommand::parse` is reused
//! verbatim; the dashboard surfaces the same capabilities through the rail and
//! status bar as well (see `modal::help`).

use tokio::sync::mpsc;

use crate::events::{EventHandler, UserCommand};
use crate::state::app_state::AppState;
use crate::tui::app::DashboardApp;
use crate::tui::chat::EntryKind;
use crate::tui::modal::{Modal, PendingAction};

/// Handle one submitted line of chat input.
pub async fn submit(
    app: &mut DashboardApp,
    text: String,
    state: &AppState,
    event_handler: &EventHandler,
    status_tx: &mpsc::UnboundedSender<String>,
) {
    let trimmed = text.trim().to_string();
    if trimmed.is_empty() {
        return;
    }
    app.core.add_to_history(trimmed.clone());
    app.push_chat(EntryKind::User, trimmed.clone());
    app.activity.scroll_to_follow();
    app.dirty = true;

    match UserCommand::parse(&trimmed) {
        UserCommand::Interpret { input } => {
            // Fire-and-forget, exactly as the rolling TUI does: output streams
            // back through the status channel.
            if state.get_ollama_model().await.is_none() {
                app.push_error(
                    "No model is configured, so there is nothing to interpret that. \
                     /model <name> picks one — or drive instances directly: a starts a \
                     server, and every event can be answered by a rule or by you.",
                );
                app.dirty = true;
                return;
            }
            let mut handler = event_handler.clone();
            let tx = status_tx.clone();
            tokio::spawn(async move {
                if let Err(e) = handler
                    .handle_interpret_with_actions(input, tx.clone(), None)
                    .await
                {
                    crate::logging::emit::Log::to(&tx).error(format!("LLM request failed: {e}"));
                }
            });
        }
        UserCommand::Quit => {
            app.modals.push(Modal::Confirm {
                message: "Quit NetGet? Running servers and clients will stop.".to_string(),
                action: PendingAction::Quit,
            });
        }
        UserCommand::StopAll => {
            app.modals.push(Modal::Confirm {
                message: "Stop every running server and client?".to_string(),
                action: PendingAction::StopAll,
            });
        }
        UserCommand::StopById { id } => {
            stop_by_unified_id(app, state, id).await;
        }
        UserCommand::ShowLogLevel => {
            app.push_system(format!("Log level: {}", app.core.log_level.as_str()));
        }
        UserCommand::ChangeLogLevel { level } => match crate::ui::app::LogLevel::parse(&level) {
            Some(parsed) => {
                app.core.set_log_level(parsed);
                app.push_system(format!("Log level set to {}", parsed.as_str()));
            }
            None => app.push_system(format!(
                "Unknown log level '{level}' (error|warn|info|debug|trace)"
            )),
        },
        UserCommand::ShowModel => {
            // `/model` with no argument should show what you can switch TO,
            // not just repeat what is already on the status bar.
            let current = state.get_ollama_model().await.unwrap_or_default();
            let llm = app.llm_client.clone();
            let ui_tx = app.ui_tx.clone();
            app.push_system("Listing available models…");
            tokio::spawn(async move {
                let message = match llm.list_models().await {
                    Ok(models) if models.is_empty() => {
                        "No models available from the backend.".to_string()
                    }
                    Ok(models) => {
                        let mut lines =
                            vec!["Available models (/model <name> to switch):".to_string()];
                        for model in models {
                            let marker = if model == current { "→" } else { " " };
                            lines.push(format!("  {marker} {model}"));
                        }
                        lines.join("\n")
                    }
                    Err(e) => format!(
                        "Could not list models: {e}\nCurrent model: {}",
                        if current.is_empty() {
                            "(none)"
                        } else {
                            &current
                        }
                    ),
                };
                let _ = ui_tx.send(crate::tui::uimsg::UiMsg::Chat(message));
            });
        }
        UserCommand::ChangeModel { model } => {
            state.set_ollama_model(Some(model.clone())).await;
            app.status.model = model.clone();
            app.push_system(format!("Model set to {model}"));

            // Verify in the background: a model the backend does not have
            // fails on first use, far from the command that chose it.
            let llm = app.llm_client.clone();
            let ui_tx = app.ui_tx.clone();
            tokio::spawn(async move {
                if let Ok(models) = llm.list_models().await {
                    if !models.iter().any(|m| m == &model) {
                        let _ = ui_tx.send(crate::tui::uimsg::UiMsg::Chat(format!(
                            "⚠ '{model}' is not one of the backend's models. Available: {}",
                            models.join(", ")
                        )));
                    }
                }
            });
        }
        UserCommand::UnknownSlashCommand { command } => {
            app.push_error(format!(
                "Unknown command: /{command} — press F1 for what the dashboard offers"
            ));
        }
        other => {
            // Everything else is handled by the shared command executor, whose
            // output lines arrive on the status channel.
            let rendered = crate::tui::command_exec::execute(other, state, status_tx).await;
            for line in rendered {
                app.push_system(line);
            }
        }
    }
    app.dirty = true;
}

/// `/stop <id>`: unified id may name a server or a client. Immediate — the
/// user typed the id; a confirmation would only repeat it back.
async fn stop_by_unified_id(app: &mut DashboardApp, state: &AppState, id: u32) {
    let server_id = crate::state::ServerId::new(id);
    if state.get_server(server_id).await.is_some() {
        let line =
            crate::tui::modal::confirm::execute(&PendingAction::StopServer(server_id), state).await;
        app.push_system(line);
        return;
    }
    let client_id = crate::state::ClientId::new(id);
    if state.get_client(client_id).await.is_some() {
        let line =
            crate::tui::modal::confirm::execute(&PendingAction::StopClient(client_id), state).await;
        app.push_system(line);
        return;
    }
    app.push_system(format!("No server or client with id {id}"));
}
