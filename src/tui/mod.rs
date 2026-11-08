//! Full-screen ratatui dashboard — the default interactive UI.
//!
//! Management on the left: every server and client as a card with its
//! buttons and sections, always visible. On the right, one stream of what is
//! happening and of the conversation, with the input box at the bottom. See
//! `src/tui/AGENTS.md` for the design.
//!

pub mod actions;
pub mod activity;
pub mod app;
pub mod cards;
pub mod chat;
pub mod command_exec;
pub mod commands;
pub mod driver;
pub mod event_loop;
pub mod hit;
pub mod keymap;
pub mod llm_activity;
pub mod metrics;
pub mod modal;
pub mod modal_keys;
pub mod projection;
pub mod rail;
pub mod render;
pub mod theme;
pub mod uimsg;
pub mod wireshark;
pub mod wrap;

use std::sync::Arc;

use anyhow::Result;
use tokio::sync::{mpsc, Mutex};

use crate::cli::theme::ColorPalette;
use crate::events::EventHandler;
use crate::llm::OllamaClient;
use crate::settings::Settings;
use crate::state::app_state::AppState;
use crate::ui::App;

use app::DashboardApp;
use event_loop::LoopContext;
use theme::Styles;

/// Entry point: the interactive UI.
#[cfg(not(target_arch = "wasm32"))]
pub async fn run_dashboard(
    state: AppState,
    core: App,
    event_handler: EventHandler,
    llm_client: OllamaClient,
    settings: Settings,
    args: &crate::cli::Args,
    palette: ColorPalette,
) -> Result<()> {
    let (app, ctx) = prepare_dashboard(
        state,
        core,
        event_handler,
        llm_client,
        settings,
        args,
        palette,
    )
    .await?;
    event_loop::run(app, ctx).await
}

/// Channels a hosted page uses to report status and request dashboard forms.
pub type DashboardReady =
    Box<dyn FnOnce(mpsc::UnboundedSender<String>, mpsc::UnboundedSender<uimsg::UiMsg>)>;

/// The dashboard on a caller-supplied terminal and input stream: the browser
/// build's entry point (`crates/netget-web`), where the terminal is xterm.js
/// and the events come from the DOM. Same construction as [`run_dashboard`];
/// `on_ready` receives the status and UI channels once the loop is about to start.
#[allow(clippy::too_many_arguments)]
pub async fn run_dashboard_on<B, S>(
    terminal: &mut ratatui::Terminal<B>,
    events: S,
    state: AppState,
    core: App,
    event_handler: EventHandler,
    llm_client: OllamaClient,
    settings: Settings,
    args: &crate::cli::Args,
    palette: ColorPalette,
    on_ready: Option<DashboardReady>,
) -> Result<()>
where
    B: ratatui::backend::Backend,
    S: futures::Stream<Item = std::io::Result<crossterm::event::Event>> + Unpin,
{
    let (app, ctx) = prepare_dashboard(
        state,
        core,
        event_handler,
        llm_client,
        settings,
        args,
        palette,
    )
    .await?;
    // The caller gets the dashboard's own status channel, so anything it starts on the
    // side (the page's quick-start buttons go through `ServerForm::create`) logs into the
    // same stream and repaints the same cards.
    if let Some(ready) = on_ready {
        ready(ctx.status_tx.clone(), app.ui_tx.clone());
    }
    event_loop::run_loop(terminal, events, app, ctx).await
}

/// Everything `run_dashboard` does before the loop: resolve the model, wire
/// the channels, build the `DashboardApp`.
async fn prepare_dashboard(
    state: AppState,
    mut core: App,
    event_handler: EventHandler,
    llm_client: OllamaClient,
    settings: Settings,
    args: &crate::cli::Args,
    palette: ColorPalette,
) -> Result<(DashboardApp, LoopContext)> {
    let settings = Arc::new(Mutex::new(settings));

    // Resolve the model exactly as the legacy TUI does (shared module).
    let resolved = {
        let guard = settings.lock().await;
        crate::cli::model_select::resolve_startup_model(args, &guard).await?
    };
    state
        .set_ollama_model(if resolved.model.is_empty() {
            None
        } else {
            Some(resolved.model.clone())
        })
        .await;
    core.connection_info.model = resolved.model.clone();

    // Web-search mode from settings, and the CLI handler-mode override.
    let web_search_mode = settings.lock().await.get_web_search_mode();
    state.set_web_search_mode(web_search_mode).await;
    if let Ok(Some(handler_mode)) = args.parse_event_handler_mode() {
        state.set_event_handler_mode(handler_mode).await;
    }

    let (status_tx, status_rx) = mpsc::unbounded_channel::<String>();
    let (web_approval_tx, web_approval_rx) = mpsc::unbounded_channel();
    let (ui_tx, ui_rx) = mpsc::unbounded_channel::<uimsg::UiMsg>();
    state.set_web_approval_channel(web_approval_tx).await;

    let styles = Styles::from_palette(&palette);
    let mut app = DashboardApp::new(core, styles, status_tx.clone(), ui_tx, llm_client.clone());

    app.push_system("NetGet — a starts a server or client, Tab reaches them, F1 lists every key");
    for message in resolved.messages {
        app.push_system(message);
    }

    // ASCII banner streams into chat like any other status output.
    #[cfg(not(target_arch = "wasm32"))]
    if args.show_art {
        let base_url = resolved.base_url.clone();
        let model = resolved.model.clone();
        let tx = status_tx.clone();
        tokio::spawn(async move {
            let _ =
                crate::cli::banner::generate_and_stream_ascii_banner(&base_url, &model, tx).await;
        });
    }

    let ctx = LoopContext {
        state,
        event_handler,
        llm_client,
        settings,
        status_tx,
        status_rx,
        web_approval_rx,
        ui_rx,
    };

    Ok((app, ctx))
}
