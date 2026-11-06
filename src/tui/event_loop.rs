//! Terminal lifecycle and the main select loop.
//!
//! All four legacy tick cadences are preserved: 100ms UI, 1s scheduled
//! tasks + feedback, 1s stats/projection, 5s state reapers. The task tick in
//! particular is load-bearing — without it scheduled tasks never fire.
//!
//! The loop itself ([`run_loop`]) is generic over the ratatui backend it draws
//! to and the stream of input events it reads, and owns no terminal. [`run`]
//! is the native front: raw mode, alternate screen, `CrosstermBackend` on
//! stdout and crossterm's `EventStream`. The browser build
//! (`crates/netget-web`) calls `run_loop` with a backend that emits ANSI into
//! xterm.js and a channel of events built from DOM `KeyboardEvent`s, and the
//! dashboard cannot tell the difference.

#[cfg(not(target_arch = "wasm32"))]
use std::io::{stdout, Stdout};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
#[cfg(not(target_arch = "wasm32"))]
use crossterm::event::{DisableMouseCapture, EnableMouseCapture, EventStream};
use crossterm::event::{Event, KeyEventKind};
#[cfg(not(target_arch = "wasm32"))]
use crossterm::execute;
#[cfg(not(target_arch = "wasm32"))]
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use futures::{Stream, StreamExt};
use ratatui::backend::Backend;
#[cfg(not(target_arch = "wasm32"))]
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use tokio::sync::{mpsc, Mutex};
use tokio::time::interval;
use tracing::{debug, info};

use crate::events::EventHandler;
use crate::llm::OllamaClient;
use crate::settings::Settings;
use crate::state::app_state::AppState;
use crate::tui::app::DashboardApp;
use crate::tui::chat::DRAIN_CAP_PER_FRAME;
use crate::tui::keymap::{self, Outcome};
use crate::tui::modal::Modal;
use crate::tui::{projection, render};

const CLEANUP_INTERVAL_SECS: u64 = 5;
const SERVER_CLEANUP_TIMEOUT_SECS: u64 = 30;
const CONNECTION_CLEANUP_TIMEOUT_SECS: u64 = 10;
const CONNECTIONLESS_CLEANUP_TIMEOUT_SECS: u64 = 10;

/// Restores the terminal on drop, so a panic cannot leave it wedged.
#[cfg(not(target_arch = "wasm32"))]
struct TerminalGuard;

#[cfg(not(target_arch = "wasm32"))]
impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = execute!(stdout(), DisableMouseCapture, LeaveAlternateScreen);
        let _ = disable_raw_mode();
    }
}

pub struct LoopContext {
    pub state: AppState,
    pub event_handler: EventHandler,
    pub llm_client: OllamaClient,
    pub settings: Arc<Mutex<Settings>>,
    pub status_tx: mpsc::UnboundedSender<String>,
    pub status_rx: mpsc::UnboundedReceiver<String>,
    pub web_approval_rx: mpsc::UnboundedReceiver<crate::state::app_state::WebApprovalRequest>,
    /// Results of spawned create/update/send actions.
    pub ui_rx: mpsc::UnboundedReceiver<crate::tui::uimsg::UiMsg>,
}

/// Run the dashboard on the process's own terminal.
#[cfg(not(target_arch = "wasm32"))]
pub async fn run(app: DashboardApp, ctx: LoopContext) -> Result<()> {
    // Arm the native-crash restorer BEFORE raw mode, with the extra bytes that
    // leave the alternate screen and mouse capture.
    crate::cli::crash_restore::install(crate::cli::crash_restore::ALT_SCREEN_EXTRA);

    enable_raw_mode()?;
    let _guard = TerminalGuard;
    execute!(stdout(), EnterAlternateScreen, EnableMouseCapture)?;

    // A panic must restore the terminal before the message is printed, or the
    // backtrace lands in the alternate screen and vanishes.
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = execute!(stdout(), DisableMouseCapture, LeaveAlternateScreen);
        let _ = disable_raw_mode();
        default_hook(info);
    }));

    let backend = CrosstermBackend::new(stdout());
    let mut terminal: Terminal<CrosstermBackend<Stdout>> = Terminal::new(backend)?;
    terminal.clear()?;

    let event_stream = EventStream::new();
    run_loop(&mut terminal, event_stream, app, ctx).await
}

/// The dashboard loop over any backend and any source of input events.
///
/// Returns when the user quits or `events` ends. The caller owns the terminal
/// and whatever it took to set it up.
pub async fn run_loop<B, S>(
    terminal: &mut Terminal<B>,
    mut events: S,
    mut app: DashboardApp,
    mut ctx: LoopContext,
) -> Result<()>
where
    B: Backend,
    S: Stream<Item = std::io::Result<Event>> + Unpin,
{
    let mut ui_tick = interval(Duration::from_millis(100));
    let mut task_tick = interval(Duration::from_secs(1));
    task_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut stats_tick = interval(Duration::from_secs(1));
    let mut cleanup_tick = interval(Duration::from_secs(CLEANUP_INTERVAL_SECS));

    refresh_status(&mut app, &ctx.state).await;
    let snapshot = projection::build_snapshot(&ctx.state).await;
    app.absorb_snapshot(snapshot);

    info!("Dashboard TUI started");

    loop {
        // Drain the status channel: everything queued is taken, at most
        // DRAIN_CAP_PER_FRAME lines are shown and the rest are dropped and counted, so a
        // flood can neither starve rendering nor grow the queue past one frame's worth.
        let batch = crate::logging::status_drain::drain_queued(
            &mut ctx.status_rx,
            None,
            DRAIN_CAP_PER_FRAME,
        );
        let mut needs_repoll = batch.update_ui_dropped;
        for line in &batch.lines {
            if line == crate::logging::status_drain::UPDATE_UI {
                needs_repoll = true;
            } else {
                route_line(&mut app, line);
            }
        }
        if let Some(notice) = batch.dropped_notice() {
            route_line(&mut app, &notice);
        }
        if needs_repoll {
            let snapshot = projection::build_snapshot(&ctx.state).await;
            app.absorb_snapshot(snapshot);
        }

        tokio::select! {
            maybe_event = events.next() => {
                match maybe_event {
                    Some(Ok(Event::Key(key))) if key.kind == KeyEventKind::Press => {
                        let outcome = keymap::handle_key(
                            &mut app, key, &ctx.state, &ctx.event_handler, &ctx.status_tx,
                        ).await;
                        if matches!(outcome, Outcome::Quit) || app.should_quit {
                            break;
                        }
                        // A UI-initiated mutation should show immediately.
                        let snapshot = projection::build_snapshot(&ctx.state).await;
                        app.absorb_snapshot(snapshot);
                    }
                    Some(Ok(Event::Mouse(mouse))) => {
                        let outcome = keymap::handle_mouse(&mut app, mouse, &ctx.state).await;
                        if matches!(outcome, Outcome::Quit) {
                            break;
                        }
                        let snapshot = projection::build_snapshot(&ctx.state).await;
                        app.absorb_snapshot(snapshot);
                    }
                    Some(Ok(Event::Resize(_, _))) => {
                        app.dirty = true;
                    }
                    Some(Ok(_)) => {}
                    Some(Err(e)) => {
                        debug!("Dashboard input error: {e}");
                    }
                    None => break,
                }
            }
            Some(msg) = ctx.ui_rx.recv() => {
                keymap::handle_ui_msg(&mut app, msg);
                let snapshot = projection::build_snapshot(&ctx.state).await;
                app.absorb_snapshot(snapshot);
            }
            Some(request) = ctx.web_approval_rx.recv() => {
                app.modals.push(Modal::WebApproval {
                    url: request.url,
                    response_tx: request.response_tx,
                });
                app.dirty = true;
            }
            _ = ui_tick.tick() => {
                app.tick_llm_activity(ctx.state.llm_activity.snapshot());
            }
            _ = task_tick.tick() => {
                // Load-bearing: without this scheduled tasks never fire.
                crate::cli::execute_due_tasks_public(
                    &ctx.state, &ctx.llm_client, &ctx.status_tx,
                ).await;
                crate::llm::feedback::execute_due_feedback(
                    &ctx.state, &ctx.llm_client, &ctx.status_tx,
                ).await;
            }
            _ = stats_tick.tick() => {
                refresh_status(&mut app, &ctx.state).await;
                let snapshot = projection::build_snapshot(&ctx.state).await;
                app.absorb_snapshot(snapshot);
                // Once a second, so a sample is bytes per second.
                app.sample_metrics();
            }
            _ = cleanup_tick.tick() => {
                ctx.state.cleanup_old_servers(SERVER_CLEANUP_TIMEOUT_SECS).await;
                ctx.state.cleanup_closed_connections(CONNECTION_CLEANUP_TIMEOUT_SECS).await;
                ctx.state.cleanup_old_connections(CONNECTIONLESS_CLEANUP_TIMEOUT_SECS).await;
                ctx.state.cleanup_old_conversations().await;
                app.dirty = true;
            }
        }

        if app.dirty {
            terminal.draw(|frame| render::draw(frame, &mut app))?;
            app.dirty = false;
        }
    }

    let _ = app.core.save_history();
    // Persist any settings the toggles changed.
    let _ = ctx.settings.lock().await;
    Ok(())
}

/// Put one status-channel line into the stream: `[LEVEL]` lines as log
/// entries (filtered by level), the model's reasoning and replies and
/// command output as conversation (never filtered).
fn route_line(app: &mut DashboardApp, line: &str) {
    use crate::tui::chat::{route_status_line, Routed};
    match route_status_line(line) {
        Routed::Control => {}
        Routed::Activity(level, text) => {
            app.activity.push_log(level, text);
            app.dirty = true;
        }
        Routed::Chat(kind, text) => {
            app.push_chat(kind, text);
        }
    }
}

async fn refresh_status(app: &mut DashboardApp, state: &AppState) {
    app.status.model = state.get_ollama_model().await.unwrap_or_default();
    app.status.web_search = format!("{:?}", state.get_web_search_mode().await).to_uppercase();
    app.status.handler_mode = format!("{:?}", state.get_event_handler_mode().await).to_uppercase();
    app.status.scripting = state
        .get_selected_scripting_mode()
        .await
        .as_str()
        .to_string();
    let (input, output, calls) = state.get_llm_stats().await;
    app.status.input_tokens = input;
    app.status.output_tokens = output;
    app.status.llm_calls = calls;
    app.status.active_conversations = state.llm_activity.snapshot().len();
}
