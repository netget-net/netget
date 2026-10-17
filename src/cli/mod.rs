//! CLI module - handles command-line interface and application startup

mod args;
#[cfg(not(target_arch = "wasm32"))]
pub(crate) mod banner;
pub mod client_startup;
pub mod crash_restore;
pub mod easy_startup;
pub mod input_state;
pub mod management;
pub mod model_select;
#[cfg(not(target_arch = "wasm32"))]
mod non_interactive;
pub mod server_startup;
#[cfg(not(target_arch = "wasm32"))]
mod setup;
mod startup_guard;
mod tasks;
#[cfg(not(target_arch = "wasm32"))]
mod terminal_cleanup;
pub mod theme;

// Re-exported so MCP mode (`src/mcp_stdio`) can drive the scheduled-task ticker on the
// same code path the TUI and non-interactive runner use, without exposing the whole
// private `tasks` module.
pub use tasks::{execute_due_tasks_owned_public, execute_due_tasks_public};

use anyhow::Result;
pub use args::{Args, MCP_TOKEN_ENV};
use clap::Parser;
use tracing::debug;

use crate::events::EventHandler;
use crate::llm::OllamaClient;
use crate::settings::Settings;
use crate::state::app_state::AppState;
use crate::ui::App;

/// Create the LLM client from CLI args, branching on --openai-url vs --ollama-url
#[cfg(not(target_arch = "wasm32"))]
pub fn create_llm_client(args: &Args) -> Result<OllamaClient> {
    let mut client = create_llm_client_inner(args)?;
    if let Some(secs) = args.llm_request_timeout {
        client = client.with_request_timeout(std::time::Duration::from_secs(secs));
    }
    if let Some(max_tokens) = args.llm_max_tokens {
        client = client.with_max_tokens(max_tokens);
    }
    client = client.with_sampling(crate::llm::SamplingOptions {
        seed: args.llm_seed,
        temperature: args.llm_temperature,
    });
    Ok(client)
}

#[cfg(not(target_arch = "wasm32"))]
fn create_llm_client_inner(args: &Args) -> Result<OllamaClient> {
    if let Some(ref openai_url) = args.openai_url {
        let api_key = args.resolve_api_key().ok_or_else(|| {
            anyhow::anyhow!(
                "API key required for OpenAI-compatible endpoint.\n   Set NETGET_API_KEY (or OPENAI_API_KEY); --api-key also works but exposes the key in the process table."
            )
        })?;
        if args.model.is_none() {
            anyhow::bail!(
                "--model is required when using --openai-url.\n   Example: --openai-url {} --model gpt-4o",
                openai_url
            );
        }
        Ok(OllamaClient::new_openai(openai_url, api_key))
    } else {
        let ollama_url = args
            .ollama_url
            .as_deref()
            .unwrap_or("http://localhost:11434");
        Ok(OllamaClient::new(ollama_url))
    }
}

/// Main CLI entry point
#[cfg(not(target_arch = "wasm32"))]
pub async fn run() -> Result<()> {
    let args = Args::parse();

    // Handle --simple-list flag (list available simple protocols and exit)
    if args.simple_list {
        use crate::protocol::EASY_REGISTRY;
        println!("Available simple protocols:");
        println!();
        let protocols = EASY_REGISTRY.get_all_names();
        if protocols.is_empty() {
            println!("  No simple protocols available (check compiled features)");
        } else {
            for name in protocols {
                println!("  - {}", name);
            }
        }
        println!();
        println!("Usage: netget --simple <protocol>");
        println!("Example: netget --simple http");
        return Ok(());
    }

    // Handle --simple <protocol> flag (start simple protocol in non-interactive mode)
    if let Some(ref protocol) = args.simple_protocol {
        return run_simple_protocol(protocol, &args).await;
    }

    // Handle --client-list flag (list protocols available as clients and exit)
    if args.client_list {
        println!("Available client protocols:");
        println!();
        let mut protocols = crate::protocol::CLIENT_REGISTRY.list_protocols();
        protocols.sort();
        if protocols.is_empty() {
            println!("  No client protocols available (check compiled features)");
        } else {
            for name in protocols {
                println!("  - {}", name);
            }
        }
        println!();
        println!("Usage: netget --client <protocol> --connect <address> [instruction]");
        println!("Example: netget --client redis --connect 127.0.0.1:6379");
        return Ok(());
    }

    // Handle --docs flag (print all protocol documentation and exit)
    if args.docs {
        print!("{}", crate::protocol::render_all_protocol_docs());
        return Ok(());
    }

    // Handle --client <protocol> flag (connect a client in non-interactive mode)
    if let Some(ref protocol) = args.client_protocol {
        return run_client(protocol, &args).await;
    }

    // Handle --server <protocol> flag (start a server directly, skipping the
    // initial LLM call that would interpret the prompt into an open_server).
    if let Some(ref protocol) = args.server_protocol {
        return run_server_direct(protocol, &args).await;
    }

    // --history and --batching describe the instance --server or --client starts. Anywhere
    // else nothing reads them, and a flag that silently does nothing is worse than a refusal.
    if args.history.is_some() || args.batching.is_some() {
        anyhow::bail!(
            "--history and --batching apply to the instance --server or --client starts; \
             with neither, ask for them in the prompt or pass them to start_server / \
             start_client over MCP"
        );
    }

    // Handle --mcp-stdio flag (run as MCP STDIO server)
    #[cfg(feature = "mcp-stdio")]
    if args.mcp_stdio {
        // Both MCP branches return before the init_logging() call further down,
        // so without this no tracing subscriber is ever installed and every
        // debug!/info!/error! in the process is silently discarded — half of the
        // dual logging this codebase is built around, gone in the mode most
        // often run. `false` selects the stderr writer, which is what MCP needs:
        // stdout carries JSON-RPC and must not be written to.
        setup::init_logging(&args, false)?;
        let settings = Settings::load();
        return crate::mcp_stdio::run_mcp_stdio(&args, settings).await;
    }
    #[cfg(not(feature = "mcp-stdio"))]
    if args.mcp_stdio {
        anyhow::bail!(
            "MCP STDIO mode requires the 'mcp-stdio' feature.\n\
             Build with: cargo build --features mcp-stdio"
        );
    }

    // Handle --mcp-http flag (run as MCP HTTP/SSE server)
    #[cfg(feature = "mcp-http")]
    if let Some(port) = args.mcp_http {
        // See the mcp-stdio branch above: this path also returns before the
        // init_logging() call further down.
        setup::init_logging(&args, false)?;
        let settings = Settings::load();
        return crate::mcp_stdio::run_mcp_http(&args, settings, port).await;
    }
    #[cfg(not(feature = "mcp-http"))]
    if args.mcp_http.is_some() {
        anyhow::bail!(
            "MCP HTTP mode requires the 'mcp-http' feature.\n\
             Build with: cargo build --features mcp-http"
        );
    }

    // Check for actions JSON first (--load flag or JSON input)
    let actions_json = args.get_actions_json()?;

    // Try to get prompt (this reads stdin if needed)
    let prompt = args.get_prompt()?;

    // Determine if we're in interactive mode
    let is_interactive = prompt.is_none() && actions_json.is_none() && args.is_interactive();

    // Setup logging based on mode
    setup::init_logging(&args, is_interactive)?;

    // Load settings
    let settings = Settings::load();

    // Decide on mode based on input type
    if let Some(actions) = actions_json {
        // Non-interactive mode - we have actions JSON to execute
        non_interactive::run_with_actions(actions, &args, settings).await
    } else if let Some(prompt) = prompt {
        // Non-interactive mode - we have a prompt
        non_interactive::run_non_interactive(prompt, &args, settings).await
    } else if args.is_interactive() {
        // Interactive TUI mode - no prompt and terminal is available
        debug!("Entering interactive TUI mode");
        debug!("Creating AppState...");
        let base_url = args
            .openai_url
            .clone()
            .or_else(|| args.ollama_url.clone())
            .unwrap_or_else(|| "http://localhost:11434".to_string());
        let state = AppState::new_with_options(args.include_disabled_protocols, base_url);
        state.set_min_stability(args.parse_min_stability()?).await;
        debug!("AppState created");

        // Configure rate limiter from CLI args
        debug!("Configuring rate limiter...");
        let rate_limiter_config = args.build_rate_limiter_config();
        state.configure_rate_limiter(rate_limiter_config).await?;
        debug!("Rate limiter configured");

        // Determine scripting mode with priority: CLI arg > saved setting > auto-detected
        debug!("Parsing scripting mode...");
        let mode_to_set = if let Some(mode) = args.parse_scripting_mode()? {
            Some(mode)
        } else {
            settings.parse_scripting_mode()
        };
        debug!("Scripting mode to set: {:?}", mode_to_set);

        if let Some(mode) = mode_to_set {
            // Validate that the requested environment is available
            debug!("Getting scripting environment for validation...");
            let scripting_env = state.get_scripting_env().await;
            debug!("Scripting environment retrieved");
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
        }

        // Determine theme: CLI arg > auto-detect > neutral fallback
        debug!("Parsing theme argument: {}", args.theme);
        let theme_option = theme::parse_theme(&args.theme)?;
        debug!("Theme option parsed: {:?}", theme_option);
        let theme = if let Some(t) = theme_option {
            debug!("Using explicit theme: {:?}", t);
            t
        } else {
            // Auto-detect
            debug!("Auto-detecting theme...");
            let detected = theme::detect_theme().unwrap_or(theme::Theme::Neutral);
            debug!("Theme detected: {:?}", detected);
            detected
        };
        debug!("Creating color palette from theme: {:?}", theme);
        let color_palette = theme::ColorPalette::from_theme(theme);
        debug!("Color palette created");

        // Get system capabilities for UI display
        debug!("Getting system capabilities...");
        let system_capabilities = state.get_system_capabilities().await;
        debug!("Creating App...");
        let app = App::new(system_capabilities);

        // Initialize LLM backend (OpenAI, Hybrid, or Ollama-only)
        #[cfg(feature = "embedded-llm")]
        let llm = {
            if args.openai_url.is_some() {
                debug!("Creating OpenAI-compatible client...");
                create_llm_client(&args)?
                    .with_mock_config_file(args.mock_config_file.clone())
                    .with_app_state(state.clone())
            } else {
                // Check if user wants embedded LLM
                let use_hybrid = args.use_embedded || args.embedded_model.is_some();

                if use_hybrid {
                    debug!("Creating HybridLLMManager...");
                    let embedded_path = args
                        .embedded_model
                        .as_ref()
                        .map(|p| p.display().to_string());
                    let hybrid =
                        crate::llm::HybridLLMManager::new(args.use_embedded, embedded_path).await?;

                    if let Some(client) = hybrid.ollama_client().await {
                        debug!("Using Ollama backend from HybridLLMManager");
                        client
                            .with_mock_config_file(args.mock_config_file.clone())
                            .with_app_state(state.clone())
                    } else {
                        debug!("Using embedded backend - creating fallback OllamaClient");
                        let ollama_url = args
                            .ollama_url
                            .as_deref()
                            .unwrap_or("http://localhost:11434");
                        OllamaClient::new(ollama_url)
                            .with_mock_config_file(args.mock_config_file.clone())
                            .with_app_state(state.clone())
                    }
                } else {
                    debug!("Creating OllamaClient...");
                    create_llm_client(&args)?
                        .with_mock_config_file(args.mock_config_file.clone())
                        .with_app_state(state.clone())
                }
            }
        };

        #[cfg(not(feature = "embedded-llm"))]
        let llm = {
            debug!("Creating LLM client...");
            create_llm_client(&args)?
                .with_mock_config_file(args.mock_config_file.clone())
                .with_app_state(state.clone())
        };

        // Store the configured LLM client in state so spawned servers can use it
        state.set_llm_client(llm.clone()).await;

        debug!("Creating EventHandler...");
        let event_handler = EventHandler::new(state.clone(), llm.clone());

        // The dashboard manages the terminal itself (no init_terminal needed).
        debug!("Entering dashboard TUI...");
        crate::tui::run_dashboard(
            state,
            app,
            event_handler,
            llm,
            settings,
            &args,
            color_palette,
        )
        .await
    } else {
        // No prompt and no terminal available
        anyhow::bail!(
            "Cannot start in interactive mode without a terminal.\n\
             Please provide a prompt via arguments or stdin."
        )
    }
}

/// Connect a client in non-interactive mode (`--client <PROTOCOL> --connect <ADDR>`)
///
/// The deterministic counterpart to the `open_client` LLM action: starting a
/// client from a shell or a test used to require a model round-trip just to
/// decide to do the thing the caller already asked for. This routes straight to
/// `client_startup::start_client_from_action`, the same function the MCP
/// `start_client` tool and the actions-JSON loader use.
///
/// Model selection deliberately mirrors `run_with_actions` rather than
/// `run_simple_protocol`: no `select_or_validate_model()` call, so a client
/// whose behaviour is fully described by `--client-handlers` connects and runs
/// without an LLM backend being reachable at all. A model is still configured
/// when one was requested, for clients that fall back to the `instruction`.
#[cfg(not(target_arch = "wasm32"))]
async fn run_client(protocol: &str, args: &Args) -> Result<()> {
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::Mutex;

    // Setup logging (non-interactive mode)
    setup::init_logging(args, false)?;
    let limits = non_interactive::RunLimits::from_args(args);

    let remote_addr = args.client_addr.clone().ok_or_else(|| {
        anyhow::anyhow!(
            "--client requires --connect <ADDRESS>\n   Example: netget --client {} --connect 127.0.0.1:6379",
            protocol
        )
    })?;

    // Resolve the protocol before doing any setup work, so an unknown name
    // fails immediately with the registry's own diagnostic.
    let canonical = client_startup::resolve_client_protocol(protocol).ok_or_else(|| {
        let mut available = crate::protocol::CLIENT_REGISTRY.list_protocols();
        available.sort();
        anyhow::anyhow!(
            "Unknown client protocol: {}\n   Available in this build: {}\n   (see --client-list)",
            protocol,
            if available.is_empty() {
                "none".to_string()
            } else {
                available.join(", ")
            }
        )
    })?;

    let startup_params = args.parse_client_params()?;
    let event_handlers = args.parse_client_handlers()?;
    let instruction = args.client_instruction(&canonical, &remote_addr);

    let settings = Settings::load();

    // Create application state
    let base_url = args
        .openai_url
        .clone()
        .or_else(|| args.ollama_url.clone())
        .unwrap_or_else(|| "http://localhost:11434".to_string());
    let state = AppState::new_with_options(args.include_disabled_protocols, base_url);
    state.set_min_stability(args.parse_min_stability()?).await;

    state
        .configure_rate_limiter(args.build_rate_limiter_config())
        .await?;

    if let Some(model) = args.model.clone().or_else(|| settings.model.clone()) {
        state.set_ollama_model(Some(model)).await;
    }

    if let Some(mode) = args
        .parse_scripting_mode()?
        .or_else(|| settings.parse_scripting_mode())
    {
        state.set_selected_scripting_mode(mode).await;
    }

    if let Some(handler_mode) = args.parse_event_handler_mode()? {
        state.set_event_handler_mode(handler_mode).await;
    }

    // ASK web-search mode has no way to prompt without a TUI
    let mut web_search_mode = settings.get_web_search_mode();
    if web_search_mode == crate::state::app_state::WebSearchMode::Ask {
        web_search_mode = crate::state::app_state::WebSearchMode::Off;
    }
    state.set_web_search_mode(web_search_mode).await;

    let llm = create_llm_client(args)?
        .with_mock_config_file(args.mock_config_file.clone())
        .with_app_state(state.clone());
    state.set_llm_client(llm.clone()).await;

    println!(
        "[CLIENT] Connecting {} client to {}",
        canonical, remote_addr
    );

    let client_id = client_startup::start_client_from_action(
        &state,
        &canonical,
        &remote_addr,
        instruction,
        startup_params,
        None, // initial_memory
        event_handlers,
        None, // scheduled_tasks
        None, // feedback_instructions
        crate::protocol::metadata::ConversationOverrides {
            history: args.history,
            batching: args.batching,
        },
        llm,
        None, // status_tx: direct --client mode, drain to tracing
    )
    .await?;

    println!(
        "[CLIENT] Client #{} ({}) connected to {}. Press Ctrl+C to stop.",
        client_id.as_u32(),
        canonical,
        remote_addr
    );

    // Set up Ctrl+C handler
    let shutdown = Arc::new(Mutex::new(false));
    let shutdown_clone = shutdown.clone();
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        let mut shutdown = shutdown_clone.lock().await;
        *shutdown = true;
    });

    // Run until interrupted or the client goes away
    loop {
        tokio::time::sleep(Duration::from_millis(100)).await;
        if *shutdown.lock().await {
            println!("\n[CLIENT] Shutting down...");
            break;
        }
        if let Some(reason) = limits.reached(&state).await {
            println!("[CLIENT] Stopping: {reason}.");
            break;
        }
        match state.get_client(client_id).await {
            Some(client) => {
                if matches!(
                    client.status,
                    crate::state::client::ClientStatus::Disconnected
                        | crate::state::client::ClientStatus::Error(_)
                ) {
                    println!(
                        "[CLIENT] Client #{} is {:?}",
                        client_id.as_u32(),
                        client.status
                    );
                    break;
                }
            }
            None => break,
        }
    }

    println!("[CLIENT] Client stopped.");
    Ok(())
}

/// Start a server of `protocol` directly (`--server <PROTOCOL>`), skipping the
/// initial model call that would otherwise interpret the prompt into an
/// `open_server` action.
///
/// The deterministic counterpart to `open_server`: the operator already told us
/// the protocol and port, so there is nothing for the model to decide up front.
/// The trailing prompt becomes the server's per-request instruction, used by the
/// per-request LLM (the same instruction `open_server` would have carried). This
/// routes straight to `server_startup::start_server_from_action`, the same
/// function the MCP `start_server` tool and the actions-JSON loader use, then
/// hands off to the shared non-interactive server loop.
#[cfg(not(target_arch = "wasm32"))]
async fn run_server_direct(protocol: &str, args: &Args) -> Result<()> {
    use tokio::sync::mpsc;

    setup::init_logging(args, false)?;
    let limits = non_interactive::RunLimits::from_args(args);

    // Resolve the protocol up front so an unknown/compiled-out name fails
    // immediately with the registry's own diagnostic (before any setup work).
    let canonical = crate::protocol::server_registry::registry()
        .resolve(protocol)
        .map(|p| p.protocol_name().to_string())
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    // The stdio pipe-filter owns the process's real stdout for the model's
    // payload, so ALL of this function's own diagnostics (including the model
    // line below) must go to stderr to keep that stream clean for a downstream
    // pipe. Known from `canonical` alone, before any output is produced.
    let to_stderr = non_interactive::protocol_owns_stdout(&canonical);

    let startup_params = args.parse_server_params()?;
    let instruction = args.server_instruction(&canonical);
    let settings = Settings::load();

    let base_url = args
        .openai_url
        .clone()
        .or_else(|| args.ollama_url.clone())
        .unwrap_or_else(|| "http://localhost:11434".to_string());
    let state = AppState::new_with_options(args.include_disabled_protocols, base_url);
    state.set_min_stability(args.parse_min_stability()?).await;
    state
        .configure_rate_limiter(args.build_rate_limiter_config())
        .await?;

    // Select/validate the model exactly as run_non_interactive does. A --server
    // needs the LLM to answer every request, so — unlike a scripted --client — an
    // unavailable model must fail HERE with a clear message. With no --model we
    // pick an available one from Ollama rather than sending an unvalidated name
    // (a stale settings default like a model that was never pulled) that fails on
    // the first request with an unhelpful "LLM failed to generate valid response".
    let configured_model = args.model.clone().or_else(|| settings.model.clone());
    let selected_model = if args.openai_url.is_some() {
        configured_model
            .ok_or_else(|| anyhow::anyhow!("--model is required when using --openai-url"))?
    } else {
        let ollama_url = args
            .ollama_url
            .as_deref()
            .unwrap_or("http://localhost:11434");
        crate::llm::select_or_validate_model(configured_model, false, ollama_url)
            .await?
            .ok_or_else(|| {
                anyhow::anyhow!("No model available — pull one in Ollama or pass --model")
            })?
    };
    non_interactive::emit_status_line(
        &format!("[SERVER] Using model: {}", selected_model),
        to_stderr,
    );
    state.set_ollama_model(Some(selected_model)).await;

    if let Some(mode) = args
        .parse_scripting_mode()?
        .or_else(|| settings.parse_scripting_mode())
    {
        state.set_selected_scripting_mode(mode).await;
    }
    if let Some(handler_mode) = args.parse_event_handler_mode()? {
        state.set_event_handler_mode(handler_mode).await;
    }
    let mut web_search_mode = settings.get_web_search_mode();
    if web_search_mode == crate::state::app_state::WebSearchMode::Ask {
        web_search_mode = crate::state::app_state::WebSearchMode::Off;
    }
    state.set_web_search_mode(web_search_mode).await;

    let llm = create_llm_client(args)?
        .with_mock_config_file(args.mock_config_file.clone())
        .with_app_state(state.clone());
    state.set_llm_client(llm.clone()).await;

    // Status channel + a forwarder that prints server startup/lifecycle lines.
    // `to_stderr` (computed above) routes them off stdout for the stdio filter,
    // so a downstream pipe receives only the model's payload bytes.
    let (status_tx, mut status_rx) = mpsc::unbounded_channel::<String>();
    let _forwarder = tokio::spawn(async move {
        while let Some(msg) = status_rx.recv().await {
            if !msg.starts_with("__") {
                let clean = msg
                    .strip_prefix("[INFO] ")
                    .or_else(|| msg.strip_prefix("[ERROR] "))
                    .or_else(|| msg.strip_prefix("[WARN] "))
                    .or_else(|| msg.strip_prefix("[DEBUG] "))
                    .unwrap_or(&msg);
                // Through the shared writer, which does not panic when the reader on the far
                // end of the pipe has gone away. See `non_interactive::emit_status_line`.
                non_interactive::emit_status_line(clean, to_stderr);
            }
        }
    });
    tokio::task::yield_now().await;

    let server_id = crate::cli::server_startup::start_server_from_action(
        &state,
        None, // mac_address
        None, // interface
        None, // host (defaults to 127.0.0.1)
        args.server_port,
        &canonical,
        false, // send_first
        None,  // initial_memory
        instruction,
        startup_params,
        None, // event_handlers
        None, // scheduled_tasks
        None, // feedback_instructions
        crate::protocol::metadata::ConversationOverrides {
            history: args.history,
            batching: args.batching,
        },
        status_tx,
    )
    .await?;

    let started_line = format!(
        "Server #{} ({}) started, skipping the initial model call. Press Ctrl+C to stop.",
        server_id.as_u32(),
        canonical
    );
    non_interactive::emit_status_line(&started_line, to_stderr);
    non_interactive::emit_status_line("Waiting for connections...\n", to_stderr);

    // Hand off to the shared non-interactive server loop (Ctrl+C + task ticker).
    let (_srv_tx, srv_rx) = mpsc::unbounded_channel::<String>();
    non_interactive::run_server(&state, llm, srv_rx, limits).await
}

/// Run a simple protocol in non-interactive mode
#[cfg(not(target_arch = "wasm32"))]
async fn run_simple_protocol(protocol: &str, args: &Args) -> Result<()> {
    use crate::protocol::EASY_REGISTRY;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::Mutex;

    // Setup logging (non-interactive mode)
    setup::init_logging(args, false)?;

    // Check if protocol exists
    if EASY_REGISTRY.get_by_name(protocol).is_none() {
        eprintln!("Error: Unknown simple protocol: {}", protocol);
        eprintln!("Use --simple-list to see available protocols");
        std::process::exit(1);
    }

    println!("[SIMPLE] Starting simple protocol: {}", protocol);

    // Load settings
    let settings = Settings::load();

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
    let selected_model = if args.openai_url.is_some() {
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

    println!("[SIMPLE] Using model: {}", selected_model);
    state.set_ollama_model(Some(selected_model)).await;

    // Create LLM client
    let llm = create_llm_client(args)?
        .with_mock_config_file(args.mock_config_file.clone())
        .with_app_state(state.clone());

    // Store the configured LLM client in state so spawned servers can use it
    state.set_llm_client(llm.clone()).await;

    // Start the easy protocol
    let easy_id = easy_startup::start_easy_protocol(
        protocol,
        None, // user_instruction - could be extended via CLI later
        None, // port - could be extended via CLI later
        Arc::new(state.clone()),
        Arc::new(llm.clone()),
    )
    .await?;

    println!(
        "[SIMPLE] Started {} (easy instance #{})",
        protocol,
        easy_id.as_u32()
    );

    // Get underlying server info
    if let Some(server_id) = state.get_first_server_id().await {
        if let Some(server) = state.get_server(server_id).await {
            println!("[SIMPLE] Listening on port {}", server.port);
        }
        println!(
            "[SIMPLE] Server #{} is running. Press Ctrl+C to stop.",
            server_id.as_u32()
        );
    }

    // Set up Ctrl+C handler
    let shutdown = Arc::new(Mutex::new(false));
    let shutdown_clone = shutdown.clone();
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        let mut shutdown = shutdown_clone.lock().await;
        *shutdown = true;
    });

    // Main event loop - just wait for shutdown
    loop {
        tokio::time::sleep(Duration::from_millis(100)).await;
        if *shutdown.lock().await {
            println!("\n[SIMPLE] Shutting down...");
            break;
        }
    }

    println!("[SIMPLE] Server stopped.");
    Ok(())
}
