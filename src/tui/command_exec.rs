//! Sink-based execution of the remaining `UserCommand` variants.
//!
//! The read-only reports are derived from `AppState` and the registries as
//! plain lines; the state-changing ones route through the same APIs the rest
//! of the dashboard uses.

use tokio::sync::mpsc;

use crate::events::UserCommand;
use crate::state::app_state::AppState;

/// Execute a command, returning lines for the chat pane.
pub async fn execute(
    command: UserCommand,
    state: &AppState,
    status_tx: &mpsc::UnboundedSender<String>,
) -> Vec<String> {
    match command {
        UserCommand::Status => status_report(state).await,
        UserCommand::Manage => {
            let mut lines = vec![
                "The list on the left is the management surface (Tab reaches it):".to_string(),
                "  a  start a server      A  start a client     e  edit config".to_string(),
                "  r  rules               m  cycle the driver   x  stop / remove".to_string(),
                "  c  connect a client to a server              n  send through a client"
                    .to_string(),
            ];
            lines.extend(status_report(state).await);
            lines
        }
        UserCommand::ShowStability => crate::protocol::stability_report(None),
        UserCommand::ShowUsage => {
            let (input, output, calls) = state.get_llm_stats().await;
            vec![
                format!("LLM calls:     {calls}"),
                format!("Input tokens:  {input}"),
                format!("Output tokens: {output}"),
            ]
        }
        UserCommand::ShowEnvironment => environment_report(state).await,
        UserCommand::ShowWebSearch => {
            vec![format!(
                "Web search: {:?}",
                state.get_web_search_mode().await
            )]
        }
        UserCommand::SetWebSearch { mode } => {
            state.set_web_search_mode(mode).await;
            vec![format!("Web search set to {mode:?}")]
        }
        UserCommand::ShowEventHandler => {
            vec![format!(
                "Handler mode: {:?}",
                state.get_event_handler_mode().await
            )]
        }
        UserCommand::SetEventHandler { mode } => {
            state.set_event_handler_mode(mode).await;
            vec![format!("Handler mode set to {mode:?}")]
        }
        UserCommand::ShowDocs { protocol } => match protocol {
            Some(name) => match crate::protocol::server_registry::registry().resolve(&name) {
                Ok(proto) => vec![
                    format!("{} — {}", proto.protocol_name(), proto.description()),
                    format!("maturity: {}", proto.metadata().summary()),
                ],
                Err(e) => vec![format!("{e}")],
            },
            None => vec!["Usage: /docs <protocol> — or press d on an instance".to_string()],
        },
        UserCommand::ShowBackend => {
            vec![format!("Backend URL: {}", state.get_ollama_url().await)]
        }
        UserCommand::TestOutput { count } => {
            // Synthetic lines that exercise the activity feed, not events: they go to the
            // status channel only, never to netget.log.
            for i in 1..=count {
                let _ = status_tx.send(format!("[INFO] test output line {i}/{count}"));
            }
            Vec::new()
        }
        UserCommand::SetFooterStatus { message } => match message {
            Some(m) => vec![format!("Status note: {m}")],
            None => vec!["Status note cleared".to_string()],
        },
        other => vec![format!("'{other:?}' is not available in the dashboard yet")],
    }
}

async fn status_report(state: &AppState) -> Vec<String> {
    let servers = state.get_all_servers().await;
    let clients = state.get_all_clients().await;
    let mut lines = vec![format!(
        "{} server(s), {} client(s)",
        servers.len(),
        clients.len()
    )];
    for s in servers {
        lines.push(format!(
            "  server #{} {} :{} {} — {} conn",
            s.id.as_u32(),
            s.protocol_name,
            s.port,
            s.status,
            s.connections.len()
        ));
    }
    for c in clients {
        lines.push(format!(
            "  client #{} {} → {} {}",
            c.id.as_u32(),
            c.protocol_name,
            c.remote_addr,
            c.status
        ));
    }
    lines
}

async fn environment_report(state: &AppState) -> Vec<String> {
    let env = state.get_scripting_env().await;
    let caps = state.get_system_capabilities().await;
    let mut lines = vec!["Scripting interpreters:".to_string()];
    for language in [
        crate::scripting::ScriptLanguage::Python,
        crate::scripting::ScriptLanguage::JavaScript,
        crate::scripting::ScriptLanguage::Go,
        crate::scripting::ScriptLanguage::Perl,
    ] {
        lines.push(format!(
            "  {:<11} {}",
            language.as_str(),
            if env.is_available(language) {
                "available"
            } else {
                "not installed"
            }
        ));
    }
    lines.push(String::new());
    lines.push("Privileges:".to_string());
    lines.push(format!("  root:            {}", caps.is_root));
    lines.push(format!(
        "  privileged port: {}",
        caps.can_bind_privileged_ports
    ));
    lines.push(format!("  raw sockets:     {}", caps.has_raw_socket_access));
    lines.push(format!(
        "  packet capture:  {}",
        caps.has_packet_capture_access
    ));
    lines
}
