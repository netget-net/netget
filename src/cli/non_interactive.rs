//! Non-interactive mode execution
//!
//! This module handles execution when NetGet runs without the TUI,
//! processing a single prompt and outputting results to stdout/stderr.

use anyhow::Result;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::sync::Mutex;
use tracing::{debug, info};

use crate::events::EventHandler;
use crate::llm::OllamaClient;
use crate::settings::Settings;
use crate::state::app_state::{AppState, Mode};

/// True for a protocol that writes the model's payload to the process's own real
/// stdout — currently only the `stdio` pipe-filter. While such a server runs,
/// NetGet's own status/log lines must be kept OFF stdout (routed to stderr) so a
/// downstream pipe (`prog | netget | prog`) receives only the payload bytes. The
/// match is case-insensitive because the protocol name reaches state as both
/// `stdio` (base_stack) and `STDIO` (registry canonical name).
pub(crate) fn protocol_owns_stdout(protocol: &str) -> bool {
    protocol.eq_ignore_ascii_case("stdio")
}

/// Whether any currently-registered server owns the process's stdout (see
/// [`protocol_owns_stdout`]). Checked per status message so routing flips to
/// stderr the instant a stdio server is registered, leaving stdout pristine.
pub(crate) async fn server_owns_stdout(state: &AppState) -> bool {
    state
        .get_all_servers()
        .await
        .iter()
        .any(|s| protocol_owns_stdout(&s.protocol_name))
}

/// Whether an actions-JSON batch opens a server that owns the process's stdout
/// (a stdio pipe-filter). Determined up front from the raw action JSON so the
/// actions path can keep stdout pristine from the very first status line,
/// without waiting for the server to register. Matches both `protocol` and its
/// `base_stack` alias.
pub(crate) fn actions_launch_stdout_owner(actions: &[serde_json::Value]) -> bool {
    actions.iter().any(|a| {
        if a.get("type").and_then(|v| v.as_str()) != Some("open_server") {
            return false;
        }
        a.get("protocol")
            .or_else(|| a.get("base_stack"))
            .and_then(|v| v.as_str())
            .map(protocol_owns_stdout)
            .unwrap_or(false)
    })
}

/// Write one status line to the correct stream — stderr when a stdio server owns stdout,
/// otherwise stdout (the default the test harness parses) — and **never die trying**.
///
/// `println!` and `eprintln!` panic when the underlying write fails. On a status line that
/// makes a closed downstream pipe fatal: `netget "serve …" | head -1` exits `head` after the
/// first line, the next `[STATUS]` write gets `EPIPE`, and a running server with live
/// connections dies inside its own diagnostics. Nothing about the *service* has failed — only
/// the thing that was reading about it — so the write is made fallibly and the error dropped.
///
/// This used to be a load-bearing accident. A netget whose stdout reader had gone away died
/// within a second, which is the only reason orphaned test binaries did not accumulate faster
/// than they did; a *quiet* one, which is the kind that sits on a port doing nothing, never
/// learned and never exited. That backstop now belongs to `tests/helpers/child_guard.rs`,
/// which ties a child's life to its parent's at the OS level and covers the quiet case too.
/// Exiting on a closed pipe is a defensible policy; doing it by panicking from a status line —
/// and only when the process happens to be chatty — is not.
pub(crate) fn emit_status_line(line: &str, to_stderr: bool) {
    use std::io::Write;
    // This is a real terminal more often than not, and the line may quote a peer.
    let line = crate::utils::sanitize::multiline(line);
    if to_stderr {
        let mut sink = std::io::stderr().lock();
        let _ = writeln!(sink, "{line}");
        let _ = sink.flush();
    } else {
        let mut sink = std::io::stdout().lock();
        let _ = writeln!(sink, "{line}");
        let _ = sink.flush();
    }
}

/// When a non-interactive run ends on its own, besides Ctrl+C and every instance stopping.
///
/// Built once at the start of a run from `--run-for` and `--exit-after-events`, so the clock
/// and the event count both cover startup as well as the wait loop. Checked by every
/// non-interactive wait loop — [`run_server`], [`run_clients`] and `--client`'s own loop — so
/// both flags mean the same thing in server and client mode.
///
/// Events are counted with [`AppState::access_log_total`]: every network event a server or
/// client handles is recorded in the access log exactly once, whichever of handler, model or
/// operator answered it, so that counter already is "events handled across all instances" and
/// no parallel one is kept.
#[derive(Debug, Clone)]
pub(crate) struct RunLimits {
    exit_after_events: Option<u64>,
    run_for: Option<Duration>,
    started: crate::utils::clock::Instant,
}

impl RunLimits {
    pub(crate) fn from_args(args: &super::Args) -> Self {
        Self {
            exit_after_events: args.exit_after_events,
            run_for: args.run_for.map(Duration::from_secs),
            started: crate::utils::clock::Instant::now(),
        }
    }

    /// `Some(reason)` once a limit has been reached.
    pub(crate) async fn reached(&self, state: &AppState) -> Option<String> {
        if let Some(run_for) = self.run_for {
            if self.started.elapsed() >= run_for {
                return Some(format!("--run-for {}s elapsed", run_for.as_secs()));
            }
        }
        if let Some(limit) = self.exit_after_events {
            let handled = state.access_log_total().await;
            if handled >= limit {
                return Some(format!(
                    "--exit-after-events {limit}: {handled} network event(s) handled"
                ));
            }
        }
        None
    }
}

/// Resolve on Ctrl+C. Spawned once per wait loop; the loop polls the flag.
fn ctrl_c_flag() -> Arc<Mutex<bool>> {
    let shutdown = Arc::new(Mutex::new(false));
    let shutdown_clone = shutdown.clone();
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        *shutdown_clone.lock().await = true;
    });
    shutdown
}

/// Run NetGet in non-interactive mode with the given prompt
pub async fn run_non_interactive(
    prompt: String,
    args: &super::Args,
    settings: Settings,
) -> Result<()> {
    info!("Starting NetGet in non-interactive mode");
    debug!("Prompt: {}", prompt);
    let limits = RunLimits::from_args(args);

    // Create application state
    let base_url = args
        .openai_url
        .clone()
        .or_else(|| args.ollama_url.clone())
        .unwrap_or_else(|| "http://localhost:11434".to_string());
    let state = AppState::new_with_options(args.include_disabled_protocols, base_url);
    state.set_min_stability(args.parse_min_stability()?).await;

    // Configure rate limiter from CLI args
    let rate_limiter_config = args.build_rate_limiter_config();
    state.configure_rate_limiter(rate_limiter_config).await?;

    // Determine configured model: args override settings
    let configured_model = args.model.clone().or(settings.model.clone());

    // Select or validate model
    let is_openai = args.openai_url.is_some();
    let selected_model = if is_openai {
        // OpenAI mode: --model is required (validated in create_llm_client)
        configured_model
            .ok_or_else(|| anyhow::anyhow!("--model is required when using --openai-url"))?
    } else {
        let ollama_url_for_model = args
            .ollama_url
            .as_deref()
            .unwrap_or("http://localhost:11434");
        crate::llm::select_or_validate_model(configured_model, false, ollama_url_for_model)
            .await?
            .ok_or_else(|| anyhow::anyhow!("No model available"))?
    };

    info!("✓  Using model: {}", selected_model);
    state.set_ollama_model(Some(selected_model)).await;

    // Determine scripting mode with priority: CLI arg > saved setting > auto-detected
    let mode_to_set = if let Some(mode) = args.parse_scripting_mode()? {
        Some(mode)
    } else {
        settings.parse_scripting_mode()
    };

    if let Some(mode) = mode_to_set {
        // Validate that the requested environment is available
        let scripting_env = state.get_scripting_env().await;
        let available = match mode {
            crate::state::app_state::ScriptingMode::On => true, // LLM chooses runtime
            crate::state::app_state::ScriptingMode::Off => true, // Always available
            crate::state::app_state::ScriptingMode::Python => scripting_env.python.is_some(),
            crate::state::app_state::ScriptingMode::JavaScript => {
                scripting_env.javascript.is_some()
            }
            crate::state::app_state::ScriptingMode::Go => scripting_env.go.is_some(),
            crate::state::app_state::ScriptingMode::Perl => scripting_env.perl.is_some(),
        };

        if !available {
            anyhow::bail!(
                "{} environment is not available on this system. Please install it or choose a different environment.",
                mode
            );
        }

        state.set_selected_scripting_mode(mode).await;
        debug!("Using scripting mode: {}", mode);
    }

    // Apply event handler mode from CLI if provided
    if let Some(handler_mode) = args.parse_event_handler_mode()? {
        state.set_event_handler_mode(handler_mode).await;
        debug!("Using event handler mode: {}", handler_mode);
    }

    // Load web search setting from settings file
    // In non-interactive mode, ASK mode is not supported (no way to prompt user)
    // so we convert ASK to OFF
    let mut web_search_mode = settings.get_web_search_mode();
    if web_search_mode == crate::state::app_state::WebSearchMode::Ask {
        debug!("Web search mode ASK is not supported in non-interactive mode, using OFF instead");
        web_search_mode = crate::state::app_state::WebSearchMode::Off;
    }
    state.set_web_search_mode(web_search_mode).await;
    debug!("Web search mode: {:?}", web_search_mode);

    // Create event handler and LLM client
    let llm = super::create_llm_client(args)?.with_mock_config_file(args.mock_config_file.clone());

    // Store the configured LLM client in state so spawned servers can use it
    state.set_llm_client(llm.clone()).await;

    let mut event_handler = EventHandler::new(state.clone(), llm.clone());

    // Create status channel for messages from spawned servers
    let (status_tx, mut status_rx) = mpsc::unbounded_channel::<String>();

    // Spawn a background task to forward status messages in real-time so the
    // test helper can see server startup messages as they happen. Each message
    // goes to stdout by default, but to STDERR while a stdio server is running:
    // that server writes the model's payload to the process's real stdout, and
    // status lines mixed in would corrupt a downstream pipe. The per-message
    // check flips to stderr the moment the stdio server registers.
    let status_state = state.clone();
    let _status_forwarder = tokio::spawn(async move {
        while let Some(msg) = status_rx.recv().await {
            // Skip internal control messages
            if !msg.starts_with("__") {
                let clean_msg = msg
                    .strip_prefix("[INFO] ")
                    .unwrap_or(&msg)
                    .strip_prefix("[ERROR] ")
                    .unwrap_or(&msg)
                    .strip_prefix("[WARN] ")
                    .unwrap_or(&msg)
                    .strip_prefix("[DEBUG] ")
                    .unwrap_or(&msg);
                emit_status_line(clean_msg, server_owns_stdout(&status_state).await);
            }
        }
    });

    // Yield to allow the forwarder task to start
    tokio::task::yield_now().await;

    // Call handler directly - no need for separate task!
    // The handler will spawn servers directly now
    event_handler
        .handle_interpret_with_actions(prompt, status_tx.clone(), None)
        .await?;

    // Give spawned servers a moment to finish sending their startup messages
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Flush stdout to ensure all messages are visible to test helper
    {
        use std::io::Write;
        std::io::stdout().flush().ok();
    }

    // Server mode whenever any server was started — including alongside clients, which then
    // run for as long as the servers do. `Mode` records only the *first* instance's kind, so a
    // client opened before a server would otherwise leave the servers unwaited-for.
    if state.get_mode().await == Mode::Server || !state.get_all_servers().await.is_empty() {
        // Create a new status channel for the server
        // (the original status_rx was consumed by the forwarder task above)
        let (_new_status_tx, new_status_rx) = mpsc::unbounded_channel::<String>();
        return run_server(&state, llm, new_status_rx, limits).await;
    }

    // Client mode: stay alive while a client is still connected.
    //
    // This used to return here, so the process exited 500ms after the instruction was
    // interpreted. That is fine for a client whose whole exchange happens during
    // interpretation, and wrong for any client that listens: an IGMP client asked to
    // "join a group and log all received data" bound its socket, joined the group, logged
    // that its receive loop was listening, and was killed before a single datagram could
    // arrive. The same applies to every client with a read loop.
    run_clients(&state, &llm, &limits, false).await;

    Ok(())
}

/// Block while clients, servers created by tasks, or scheduled work remain live.
/// No instances/tasks still exits immediately; completed tasks do not keep a run alive.
pub(crate) async fn run_clients(
    state: &AppState,
    llm: &OllamaClient,
    limits: &RunLimits,
    to_stderr: bool,
) {
    let shutdown = ctrl_c_flag();
    let mut ticker = tokio::time::interval(Duration::from_secs(1));
    let (status_tx, mut status_rx) = mpsc::unbounded_channel::<String>();
    let owner = tokio_util::sync::CancellationToken::new();
    let _cancel_on_exit = owner.clone().drop_guard();
    loop {
        while let Ok(message) = status_rx.try_recv() {
            if !message.starts_with("__") {
                emit_status_line(&message, to_stderr);
            }
        }
        if !has_live_background_work(state).await {
            return;
        }
        if *shutdown.lock().await {
            emit_status_line("\nShutting down background work...", to_stderr);
            return;
        }
        if let Some(reason) = limits.reached(state).await {
            emit_status_line(&format!("Stopping: {reason}."), to_stderr);
            return;
        }
        tokio::select! {
            _ = ticker.tick() => {
                crate::cli::execute_due_tasks_owned_public(state, llm, &status_tx, owner.clone()).await;
                crate::llm::feedback::execute_due_feedback(state, llm, &status_tx).await;
            }
            Some(message) = status_rx.recv() => {
                if !message.starts_with("__") {
                    emit_status_line(&message, to_stderr);
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(100)) => {}
        }
    }
}

async fn has_live_background_work(state: &AppState) -> bool {
    state.get_all_clients().await.iter().any(|client| {
        matches!(
            client.status,
            crate::state::ClientStatus::Connecting | crate::state::ClientStatus::Connected
        )
    }) || state.get_all_servers().await.iter().any(|server| {
        matches!(
            server.status,
            crate::state::server::ServerStatus::Starting
                | crate::state::server::ServerStatus::Running
        )
    }) || state.get_all_tasks().await.iter().any(|task| {
        matches!(
            task.status,
            crate::state::task::TaskStatus::Scheduled | crate::state::task::TaskStatus::Executing
        )
    })
}

/// Run every started server in non-interactive mode until they have all stopped, Ctrl+C, or a
/// [`RunLimits`] limit.
///
/// Clients started alongside keep running for as long as this does. A server already in
/// `Error` when the loop begins makes the run fail (non-zero exit) rather than serve the rest
/// as if the configuration had loaded.
pub(crate) async fn run_server(
    state: &AppState,
    llm: OllamaClient,
    mut status_rx: mpsc::UnboundedReceiver<String>,
    limits: RunLimits,
) -> Result<()> {
    // Create status channel for server messages
    let (status_tx, mut server_status_rx) = mpsc::unbounded_channel::<String>();

    // Keep NetGet's own status lines OFF stdout while a stdio server is running,
    // so a downstream pipe receives only the model's payload bytes. The server
    // is already spawned by this point, so a single check settles the sink.
    let to_stderr = server_owns_stdout(state).await;

    // Servers were started by the caller; report every one of them.
    let mut servers = state.get_all_servers().await;
    servers.sort_by_key(|s| s.id.as_u32());
    if servers.is_empty() {
        return Err(anyhow::anyhow!(
            "No server configured. Use a command like 'listen on port 8080 via http'"
        ));
    }
    let failed: Vec<String> = servers
        .iter()
        .filter_map(|s| match &s.status {
            crate::state::server::ServerStatus::Error(e) => Some(format!(
                "server #{} ({}): {}",
                s.id.as_u32(),
                s.protocol_name,
                e
            )),
            _ => None,
        })
        .collect();
    if !failed.is_empty() {
        return Err(anyhow::anyhow!(
            "{} server(s) failed to start: {}",
            failed.len(),
            failed.join("; ")
        ));
    }
    for server in &servers {
        let at = server
            .local_addr
            .map(|a| format!(" on {a}"))
            .unwrap_or_default();
        emit_status_line(
            &format!(
                "Server #{} ({}) is running{at}.",
                server.id.as_u32(),
                server.protocol_name
            ),
            to_stderr,
        );
    }
    emit_status_line("Press Ctrl+C to stop.", to_stderr);
    emit_status_line("Waiting for connections...\n", to_stderr);

    let shutdown = ctrl_c_flag();

    // Set up task execution ticker (execute tasks every 1 second, same as TUI mode)
    use tokio::time::interval;
    let mut task_execution_interval = interval(Duration::from_secs(1));
    let owner = tokio_util::sync::CancellationToken::new();
    let _cancel_on_exit = owner.clone().drop_guard();

    // Main event loop
    loop {
        tokio::select! {
            // Check for shutdown
            _ = tokio::time::sleep(Duration::from_millis(100)) => {
                if *shutdown.lock().await {
                    emit_status_line("\nShutting down server...", to_stderr);
                    break;
                }
                if let Some(reason) = limits.reached(state).await {
                    emit_status_line(&format!("Stopping: {reason}."), to_stderr);
                    break;
                }
                // Every server stopped (closed by the model, errored, or removed): nothing is
                // left to wait for.
                let live = state
                    .get_all_servers()
                    .await
                    .iter()
                    .filter(|s| {
                        matches!(
                            s.status,
                            crate::state::server::ServerStatus::Starting
                                | crate::state::server::ServerStatus::Running
                        )
                    })
                    .count();
                if live == 0 && !has_live_background_work(state).await {
                    emit_status_line("All servers have stopped.", to_stderr);
                    break;
                }

                // Process status messages from handler (drain remaining)
                while let Ok(msg) = status_rx.try_recv() {
                    if !msg.starts_with("__") {
                        emit_status_line(&format!("[STATUS] {msg}"), to_stderr);
                    }
                }

                // Process server status messages
                while let Ok(msg) = server_status_rx.try_recv() {
                    emit_status_line(&format!("[STATUS] {msg}"), to_stderr);
                }
            }

            // Execute due tasks every 1 second, and drain any feedback that has become due
            _ = task_execution_interval.tick() => {
                crate::cli::execute_due_tasks_owned_public(state, &llm, &status_tx, owner.clone()).await;
                crate::llm::feedback::execute_due_feedback(state, &llm, &status_tx).await;
            }
        }
    }

    emit_status_line("Server stopped.", to_stderr);
    Ok(())
}

/// Run NetGet in non-interactive mode with actions JSON (--load or piped JSON)
pub async fn run_with_actions(
    actions: Vec<serde_json::Value>,
    args: &super::Args,
    settings: Settings,
) -> Result<()> {
    info!("Starting NetGet in non-interactive mode (actions JSON)");
    debug!("Loading {} actions", actions.len());
    let limits = RunLimits::from_args(args);

    // Create application state
    let base_url = args
        .openai_url
        .clone()
        .or_else(|| args.ollama_url.clone())
        .unwrap_or_else(|| "http://localhost:11434".to_string());
    let state = AppState::new_with_options(args.include_disabled_protocols, base_url);
    state.set_min_stability(args.parse_min_stability()?).await;

    // Configure rate limiter from CLI args
    let rate_limiter_config = args.build_rate_limiter_config();
    state.configure_rate_limiter(rate_limiter_config).await?;

    // Determine scripting mode
    let mode_to_set = if let Some(mode) = args.parse_scripting_mode()? {
        Some(mode)
    } else {
        settings.parse_scripting_mode()
    };

    if let Some(mode) = mode_to_set {
        state.set_selected_scripting_mode(mode).await;
    }

    // Apply event handler mode from CLI if provided
    if let Some(handler_mode) = args.parse_event_handler_mode()? {
        state.set_event_handler_mode(handler_mode).await;
    }

    // Setup web search mode
    let mut web_search_mode = settings.get_web_search_mode();
    if web_search_mode == crate::state::app_state::WebSearchMode::Ask {
        web_search_mode = crate::state::app_state::WebSearchMode::Off;
    }
    state.set_web_search_mode(web_search_mode).await;

    // Create LLM client
    let llm = super::create_llm_client(args)?.with_mock_config_file(args.mock_config_file.clone());

    // Store the configured LLM client in state so spawned servers can use it
    state.set_llm_client(llm.clone()).await;

    // A stdio pipe-filter server writes the model's payload to the process's
    // real stdout, so this batch's own status/log lines must go to stderr to
    // keep that stream pristine for a downstream pipe. Decided up front from the
    // action JSON so even the first "Loading ..." line lands on the right stream.
    let to_stderr = actions_launch_stdout_owner(&actions);

    // Create status channel
    let (status_tx, mut status_rx) = mpsc::unbounded_channel::<String>();

    // Spawn background task to print status messages in real-time
    let status_printer = tokio::spawn(async move {
        while let Some(msg) = status_rx.recv().await {
            if !msg.starts_with("__") {
                // Print status messages immediately for real-time output
                emit_status_line(&msg, to_stderr);
            }
        }
    });

    emit_status_line(
        &format!("Loading {} action(s)...\n", actions.len()),
        to_stderr,
    );

    // What failed to start: reported at the end, and the reason the run exits non-zero.
    let mut failures: Vec<String> = Vec::new();

    // Execute each action
    for (i, action) in actions.iter().enumerate() {
        if action.get("type").and_then(serde_json::Value::as_str) == Some("restore_session") {
            if let Err(error) =
                crate::utils::save_load::restore_session(&state, &llm, &action["session"]).await
            {
                failures.push(format!("action {} (session): {error:#}", i + 1));
            }
            continue;
        }

        // Try to parse as common action
        if let Ok(common_action) = crate::llm::actions::common::CommonAction::from_json(action) {
            use crate::cli::{client_startup, server_startup};
            use crate::llm::actions::common::CommonAction;

            match common_action {
                CommonAction::OpenServer {
                    mac_address,
                    interface,
                    host,
                    port,
                    protocol,
                    send_first,
                    initial_memory,
                    instruction,
                    startup_params,
                    event_handlers,
                    scheduled_tasks,
                    feedback_instructions,
                } => {
                    // Execute open_server action
                    match server_startup::start_server_from_action(
                        &state,
                        mac_address,
                        interface.clone(),
                        host,
                        port,
                        &protocol,
                        send_first,
                        initial_memory,
                        instruction.clone(),
                        startup_params,
                        event_handlers,
                        scheduled_tasks,
                        feedback_instructions,
                        Default::default(),
                        status_tx.clone(),
                    )
                    .await
                    {
                        Ok(server_id) => {
                            let binding_desc = if let Some(iface) = &interface {
                                format!("interface {} ({})", iface, protocol)
                            } else if let Some(p) = port {
                                format!("port {} ({})", p, protocol)
                            } else {
                                format!("({})", protocol)
                            };
                            emit_status_line(
                                &format!(
                                    "[{}] Opened server #{} on {}",
                                    i + 1,
                                    server_id.as_u32(),
                                    binding_desc
                                ),
                                to_stderr,
                            );
                        }
                        Err(e) => {
                            eprintln!("[{}] Failed to open server: {}", i + 1, e);
                            failures.push(format!("action {} ({} server): {}", i + 1, protocol, e));
                        }
                    }
                }
                CommonAction::OpenClient {
                    protocol,
                    remote_addr,
                    instruction,
                    startup_params,
                    initial_memory,
                    event_handlers,
                    scheduled_tasks,
                    feedback_instructions,
                } => {
                    // Execute open_client action
                    match client_startup::start_client_from_action(
                        &state,
                        &protocol,
                        &remote_addr,
                        instruction.clone(),
                        startup_params,
                        initial_memory,
                        event_handlers,
                        scheduled_tasks,
                        feedback_instructions,
                        Default::default(),
                        llm.clone(),
                        None, // status_tx: headless, drain to tracing
                    )
                    .await
                    {
                        Ok(client_id) => {
                            emit_status_line(
                                &format!(
                                    "[{}] Opened client #{} to {} ({})",
                                    i + 1,
                                    client_id.as_u32(),
                                    remote_addr,
                                    protocol
                                ),
                                to_stderr,
                            );
                        }
                        Err(e) => {
                            eprintln!("[{}] Failed to open client: {}", i + 1, e);
                            failures.push(format!("action {} ({} client): {}", i + 1, protocol, e));
                        }
                    }
                }
                CommonAction::ShowMessage { message } => {
                    emit_status_line(&format!("[{}] {}", i + 1, message), to_stderr);
                }
                _ => {
                    emit_status_line(
                        &format!("[{}] Skipping unsupported action type", i + 1),
                        to_stderr,
                    );
                }
            }
        } else {
            eprintln!("[{}] Skipping invalid action", i + 1);
        }
    }

    // The printer is NOT awaited. Every server started above holds a clone of `status_tx`
    // for its whole life, so the channel only closes when the last server stops; awaiting it
    // here parked this function forever as soon as one server was loaded — `run_server`, its
    // task ticker and every exit condition below were never reached. The printer keeps
    // forwarding the servers' status lines for the rest of the run, which is what it is for.
    drop(status_tx);
    // Let it print what the loading itself queued before the summary line.
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
    drop(status_printer);

    if !failures.is_empty() {
        // A configuration that only half loaded is a failed run: exit non-zero rather than
        // serve what did start as though everything had.
        return Err(anyhow::anyhow!(
            "{} of {} action(s) failed to start: {}",
            failures.len(),
            actions.len(),
            failures.join("; ")
        ));
    }

    emit_status_line("\nConfiguration loaded successfully.", to_stderr);

    // Any server → serve until they all stop (clients alongside run as long as that does).
    if !state.get_all_servers().await.is_empty() {
        // Create a new status channel for run_server
        let (_status_tx, status_rx) = mpsc::unbounded_channel::<String>();
        return run_server(&state, llm, status_rx, limits).await;
    }

    // Clients and restored global tasks remain live until work finishes or a run limit.
    run_clients(&state, &llm, &limits, to_stderr).await;

    Ok(())
}
