//! Command-line argument parsing

use anyhow::Result;
use clap::Parser;
use std::io::{self, IsTerminal, Read};
use tracing::Level;

/// Get default log level based on build type
/// Development builds (debug_assertions) default to "debug"
/// Release builds default to "info"
///
/// Dev builds used to default to `trace`. TRACE is the level at which NetGet
/// writes whole network payloads and whole LLM prompts/responses to
/// `netget.log` - which is both a 481 MB-per-day disk problem and a disclosure
/// one, since those payloads can carry credentials from the wire. DEBUG keeps
/// the per-event summaries that make development logs useful and stops short of
/// the payloads; `--log-level trace` still turns them back on for the sessions
/// that genuinely need byte-level detail.
fn default_log_level() -> String {
    if cfg!(debug_assertions) {
        "debug".to_string()
    } else {
        "info".to_string()
    }
}

/// Piped stdin, read at most once per process.
///
/// `cli::run()` asks for the actions JSON and then for the prompt. Both used to
/// call `io::stdin().read_to_string()`, so the *first* call drained stdin and
/// the second saw EOF: a prompt piped in (`echo "listen on port 80" | netget`)
/// was consumed by the actions-JSON check, discarded because it was not JSON,
/// and the process then failed with "Cannot start in interactive mode without a
/// terminal" - only trailing-argument prompts worked non-interactively, despite
/// `cat prompt.txt | netget` being advertised in --help.
///
/// Reading is lazy as well as once: `--mcp`, `--mcp-http`, `--simple`,
/// `--client` and `--server` all return before either accessor is called, so
/// stdin is never touched in the modes that need it for their own protocol. An
/// interactive terminal is left alone entirely.
///
/// It is also only consulted when stdin is genuinely a prompt/actions *source*:
/// the two accessors below skip it whenever a trailing-argument prompt (or
/// `--load`) is present, because then the prompt does not come from stdin and
/// draining it is pure downside. That guard is what lets the stdio pipe-filter
/// (`prog | netget "be a filter" | prog`) start: its stdin is an open,
/// never-EOF pipe, and the blocking `read_to_string` below would otherwise hang
/// the whole process before any server could start. `cat prompt.txt | netget`
/// still works — there is no trailing prompt there, so stdin is the source and
/// is read.
fn piped_stdin() -> &'static str {
    static PIPED: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    PIPED
        .get_or_init(|| {
            if io::stdin().is_terminal() {
                return String::new();
            }
            let mut buffer = String::new();
            if let Err(e) = io::stdin().read_to_string(&mut buffer) {
                tracing::warn!("Failed to read stdin: {}", e);
                return String::new();
            }
            buffer.trim().to_string()
        })
        .as_str()
}

/// Read the `{"actions": [...]}` file named by `--load`.
///
/// Deliberately synchronous. `get_actions_json()` is called from inside the
/// `#[tokio::main]` runtime, and the previous implementation built a *second*
/// runtime there and `block_on`-ed `save_load::load_actions()` — which panics
/// ("Cannot start a runtime from within a runtime") on a thread that is already
/// driving one. `--load` therefore never worked; reading the file with
/// `std::fs` in the one place that needs it does.
///
/// The path is used as given, with `.netget` appended only as a fallback when
/// the literal path does not exist, so `--load configs/http` and
/// `--load configs/http.netget` both work and a path with a different
/// extension is still honoured.
fn load_actions_file(path: &str) -> Result<Vec<serde_json::Value>> {
    use anyhow::Context;

    let trimmed = path.trim();
    let candidate = std::path::Path::new(trimmed);
    let resolved: std::path::PathBuf = if candidate.exists() {
        candidate.to_path_buf()
    } else {
        let with_ext = std::path::PathBuf::from(format!(
            "{}{}",
            trimmed,
            crate::utils::save_load::NETGET_EXTENSION
        ));
        if with_ext.exists() {
            with_ext
        } else {
            candidate.to_path_buf() // report the error against what the user typed
        }
    };

    let content =
        crate::utils::file_io::read_text(&resolved, crate::utils::save_load::MAX_SESSION_BYTES)
            .with_context(|| format!("Failed to read --load file: {}", resolved.display()))?;

    let parsed: serde_json::Value = serde_json::from_str(&content)
        .with_context(|| format!("Failed to parse JSON from {}", resolved.display()))?;

    let actions = parsed
        .get("actions")
        .and_then(|v| v.as_array())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "{} must contain {{\"actions\": [...]}} (as written by the /save command)",
                resolved.display()
            )
        })?
        .clone();

    Ok(actions)
}

/// NetGet - LLM-Controlled Network Application
#[derive(Parser, Debug)]
#[clap(
    author,
    version,
    about,
    long_about = "NetGet - LLM-Controlled Network Application\n\n\
                  NetGet is an AI-powered network tool where an LLM controls network protocols.\n\
                  It can operate in interactive mode (with TUI) or non-interactive mode.",
    after_help = "EXAMPLES:\n\
                  \n\
                  Interactive mode (TUI):\n\
                      netget\n\
                  \n\
                  Non-interactive with prompt (no quotes needed):\n\
                      netget listen on port 80 via http\n\
                      netget \"listen on port 80 via http\"     # quoted version\n\
                      cat prompt.txt | netget\n\
                  \n\
                  Specify model with prompt after --:\n\
                      netget -m llama3.2:latest -- listen on port 80\n\
                      netget --model deepseek-coder:latest show version\n\
                  \n\
                  Specify scripting environment:\n\
                      netget -e python listen on port 80\n\
                      netget --env javascript -- start http server\n\
                      netget --env llm show version\n\
                  \n\
                  MCP over HTTP (loopback by default; any other bind address needs a token):\n\
                      netget --mcp-http 8080\n\
                      NETGET_MCP_TOKEN=$(openssl rand -hex 32) netget --mcp-http 8080 --listen-addr 0.0.0.0\n\
                  \n\
                  Connect a client without a model round-trip:\n\
                      netget --client redis --connect 127.0.0.1:6379\n\
                      netget --client tcp --connect 10.0.0.5:9000 log every banner you receive\n\
                      netget --client-list",
    trailing_var_arg = true,
    allow_hyphen_values = true
)]
pub struct Args {
    /// LLM model to use (e.g., "llama3.2:latest", "deepseek-coder:latest")
    #[clap(short = 'm', long = "model", value_name = "MODEL")]
    pub model: Option<String>,

    /// Log level (off, error, warn, info, debug, trace)
    /// Development builds default to 'debug', release builds default to 'info'
    /// ('trace' additionally writes full network payloads and LLM prompts to netget.log)
    #[clap(
        short = 'l',
        long = "log-level",
        value_name = "LEVEL",
        default_value_t = default_log_level()
    )]
    pub log_level: String,

    /// Scripting environment to use (on, off, python, javascript, go, perl)
    #[clap(
        short = 'e',
        long = "env",
        value_name = "ENVIRONMENT",
        help = "Scripting environment: on (LLM chooses runtime), off (LLM only mode), python (Python scripting), javascript (JavaScript scripting), go (Go scripting), perl (Perl scripting)"
    )]
    pub scripting_env: Option<String>,

    /// Event handler mode to use (any, script, static, llm)
    #[clap(
        long = "handler",
        value_name = "MODE",
        help = "Event handler mode: any (LLM chooses handler types), script (force script handlers), static (force static responses), llm (force LLM handlers)"
    )]
    pub event_handler_mode: Option<String>,

    /// Bind address for the MCP HTTP control endpoint (default: 127.0.0.1)
    ///
    /// Read only by `--mcp-http`. Protocol servers take their bind address from
    /// each `start_server` / `open_server` call's `host`, not from this flag.
    #[clap(
        long = "listen-addr",
        value_name = "ADDRESS",
        help = "IP address the --mcp-http control endpoint binds (default 127.0.0.1). Protocol servers are NOT affected; they bind per start_server 'host'. A non-loopback address requires --mcp-token or NETGET_MCP_TOKEN."
    )]
    pub listen_addr: Option<String>,

    /// Include disabled protocols (for testing honeypot-only protocols like IPSec, OpenVPN)
    #[clap(
        long = "include-disabled-protocols",
        help = "Includes experimental protocols for testing purposes"
    )]
    pub include_disabled_protocols: bool,

    /// Refuse to start any protocol below this maturity level
    #[clap(
        long = "min-stability",
        value_name = "LEVEL",
        help = "Refuse to start any protocol whose declared development state is below LEVEL (incomplete, experimental, beta, stable; case-insensitive). Also filters lower-maturity protocols out of the LLM's base-stack menu so the model is not offered a protocol the operator forbade. Default: no minimum (only Incomplete protocols are hidden from the model)."
    )]
    pub min_stability: Option<String>,

    // Developer note, deliberately a `//` comment and not a doc comment: clap derive turns
    // doc comments into `--help` output, and none of this belongs in front of an operator.
    //
    // **This field is now write-only, and that is the whole point.** Nothing reads
    // `args.ollama_lock`. The plumbing it used to feed is gone: the `ollama_lock_enabled` field
    // on `AppStateInner`, `AppState::get_ollama_lock_enabled()`, the second parameter of
    // `AppState::new_with_options`, the `lock_enabled` argument threaded through
    // `create_llm_client`, and `OllamaClient::new_with_options`, whose body was `Self::new(url)`
    // under a comment claiming locking was "handled at a different layer". Nothing in `src/` was
    // that layer and no `ollama.lock` was ever created, so every one of those hops carried a
    // boolean that could not change any behaviour — while making the flag look implemented to
    // anyone who followed it.
    //
    // The flag itself stays **accepted and inert** rather than deleted. Removing it turns
    // `--ollama-lock` into a hard clap error, and it appears in scripts and in this repo's own
    // history; breaking those buys nothing, since an ignored flag and an absent one differ only
    // in whether the caller gets an error for asking. `tests/ollama_lock_is_a_noop_test.rs`
    // pins that it is still parsed, still does nothing, and that no `ollama.lock` appears.
    //
    // Implementing it was considered and rejected: a real cross-process lock would serialise
    // every e2e test, and `--llm-max-concurrent` (with `--llm-queue-timeout` and
    // `--llm-max-queued`) already bounds LLM concurrency and is actually enforced.
    /// DEPRECATED AND IGNORED. Accepted for compatibility only; it locks nothing.
    #[clap(
        long = "ollama-lock",
        help = "DEPRECATED AND IGNORED. Accepted for compatibility only: nothing is locked, nothing is written to disk, and NetGet instances are not serialized against each other. It has never done any of those things. To bound LLM concurrency use --llm-max-concurrent (with --llm-queue-timeout and --llm-max-queued), which are enforced."
    )]
    pub ollama_lock: bool,

    /// Ollama API base URL (default: http://localhost:11434)
    #[clap(
        long = "ollama-url",
        value_name = "URL",
        help = "Base URL for Ollama API (default: http://localhost:11434). Use this to point to a custom Ollama instance or mock server for testing.",
        conflicts_with = "openai_url",
        hide = true  // Hidden from help output - primarily for testing
    )]
    pub ollama_url: Option<String>,

    /// OpenAI-compatible API base URL (e.g., "https://api.openai.com", "http://localhost:1234")
    #[clap(
        long = "openai-url",
        value_name = "URL",
        help = "Base URL for an OpenAI-compatible API endpoint (e.g., https://api.openai.com, http://localhost:1234 for vLLM/LM Studio). Requires --model and an API key in NETGET_API_KEY or OPENAI_API_KEY (or, less safely, --api-key).",
        conflicts_with = "ollama_url"
    )]
    pub openai_url: Option<String>,

    /// API key for OpenAI-compatible endpoint (prefer the environment variable)
    #[clap(
        long = "api-key",
        value_name = "KEY",
        help = "API key for the OpenAI-compatible endpoint. PREFER the NETGET_API_KEY (or OPENAI_API_KEY) environment variable: an argument is visible to every local user in the process table (`ps`), an environment variable is not. Passing this flag prints a warning."
    )]
    pub api_key: Option<String>,

    /// Route all LLM calls to the calling MCP agent instead of a model (MCP mode only)
    #[clap(
        long = "llm-agent",
        help = "Do not call any model. Queue every LLM request for the calling MCP agent (e.g. Claude Code) to answer via the get_next_llm_request / answer_llm_request tools. Only meaningful with --mcp / --mcp-http; mutually exclusive with --ollama-url / --openai-url.",
        conflicts_with_all = ["ollama_url", "openai_url"]
    )]
    pub llm_agent: bool,

    /// FIFO path for agent-queue push notifications
    #[clap(
        long = "llm-agent-pipe",
        value_name = "PATH",
        help = "Named pipe (FIFO) that receives the id of each newly queued LLM request, so the agent can block-read it to get woken instead of polling. Created if absent. Requires --llm-agent; the long-poll tool works without it.",
        requires = "llm_agent"
    )]
    pub llm_agent_pipe: Option<std::path::PathBuf>,

    /// Seconds a queued LLM request waits for the agent's answer before erroring
    #[clap(
        long = "llm-agent-timeout",
        value_name = "SECONDS",
        default_value = "300",
        help = "How long (seconds) a queued LLM request waits for the agent to answer before the call errors and the connection resets to Idle. Requires --llm-agent.",
        requires = "llm_agent"
    )]
    pub llm_agent_timeout: u64,

    /// Wall-clock bound (seconds) on a single LLM backend call
    #[clap(
        long = "llm-request-timeout",
        value_name = "SECONDS",
        help = "Wall-clock bound (seconds) on a single LLM backend call before it is treated as a transport failure and retried. Default: 300. A locally served 31B reasoning model answering a full prompt with the default tool list was measured at ~79s idle, so the old 120s default failed whenever anything else shared the GPU. Lower it only if you would rather fail fast than wait."
    )]
    pub llm_request_timeout: Option<u64>,

    /// Completion-token budget for a single LLM call
    #[clap(
        long = "llm-max-tokens",
        value_name = "TOKENS",
        help = "Completion tokens a single LLM call may produce before it is cut off. This is a runaway guard, not a working budget: the default (32768) sits far above any legitimate answer so it never truncates one, and --llm-request-timeout is the primary backstop. Lower it only to bound a model you expect to ramble."
    )]
    pub llm_max_tokens: Option<u32>,

    /// Sampler seed sent to the LLM backend
    #[clap(
        long = "llm-seed",
        value_name = "SEED",
        help = "Sampler seed sent with every LLM request (Ollama `options.seed`, OpenAI `seed`). With a fixed seed an identical prompt draws the same tokens, which is what makes a real-model run repeatable; a prompt that differs (a new port, a new query id) still diverges. Unset, nothing is sent and the model's own default applies."
    )]
    pub llm_seed: Option<u64>,

    /// Sampling temperature sent to the LLM backend
    #[clap(
        long = "llm-temperature",
        value_name = "TEMP",
        value_parser = parse_temperature,
        help = "Sampling temperature sent with every LLM request (Ollama `options.temperature`, OpenAI `temperature`). 0 is greedy decoding. Unset, nothing is sent and the model's own default applies (0.8 for most Ollama Modelfiles)."
    )]
    pub llm_temperature: Option<f32>,

    /// Path to embedded GGUF model file (enables embedded LLM inference)
    #[cfg(feature = "embedded-llm")]
    #[clap(
        long = "embedded-model",
        value_name = "PATH",
        help = "Path to GGUF model file for embedded inference (e.g., mistral-7b.Q4_K_M.gguf). When specified, NetGet will use embedded llama.cpp instead of or alongside Ollama."
    )]
    pub embedded_model: Option<std::path::PathBuf>,

    /// Force use of embedded LLM backend (skip Ollama)
    #[cfg(feature = "embedded-llm")]
    #[clap(
        long = "use-embedded",
        help = "Use embedded LLM backend exclusively, skipping Ollama health check. Requires --embedded-model to be set or configured in ~/.netget/config.toml"
    )]
    pub use_embedded: bool,

    /// Terminal color theme (auto, light, dark, neutral)
    #[clap(
        long = "theme",
        value_name = "THEME",
        default_value = "auto",
        help = "Color theme for TUI: auto (detect background), light (dark colors on light background), dark (bright colors on dark background), neutral (medium contrast for both)"
    )]
    pub theme: String,

    /// Show the generated ASCII art banner on startup (off by default)
    ///
    /// `--suppress-art` is kept as a hidden no-op so existing scripts and the
    /// test harness keep working now that suppressing is the default.
    #[clap(
        long = "show-art",
        help = "Show the Ollama-generated ASCII art banner on startup (costs one model round trip)"
    )]
    pub show_art: bool,

    #[clap(long = "suppress-art", hide = true)]
    pub suppress_art: bool,

    /// Maximum concurrent LLM requests (default: 1)
    #[clap(
        long = "llm-max-concurrent",
        value_name = "NUM",
        help = "Maximum number of LLM requests in flight at once. Default: 1, i.e. sequential processing - additional requests QUEUE and are served in turn (bounded by --llm-queue-timeout and --llm-max-queued), they are not dropped. Increase for higher throughput with local Ollama."
    )]
    pub llm_max_concurrent: Option<usize>,

    /// How long a network request waits for a concurrency permit
    #[clap(
        long = "llm-queue-timeout",
        value_name = "SECONDS",
        help = "How long a network-triggered LLM request waits for a free slot under --llm-max-concurrent before the protocol answers the peer with an overload error instead. Default: 120 (one backend request timeout). 0 waits forever."
    )]
    pub llm_queue_timeout: Option<u64>,

    /// How many network requests may wait for a concurrency permit at once
    #[clap(
        long = "llm-max-queued",
        value_name = "NUM",
        help = "How many network-triggered LLM requests may wait for a free slot at once. Beyond this the protocol answers the peer with an overload error immediately rather than growing the queue. Default: 128. 0 is unbounded."
    )]
    pub llm_max_queued: Option<usize>,

    /// Token limit per time window (optional, for cloud API usage control)
    #[clap(
        long = "llm-token-limit",
        value_name = "TOKENS",
        help = "Maximum tokens (input + output) per time window. Use for cloud API rate limiting. No limit by default (suitable for local Ollama)."
    )]
    pub llm_token_limit: Option<u64>,

    /// Token limit time window in seconds (default: 60)
    #[clap(
        long = "llm-token-window",
        value_name = "SECONDS",
        default_value = "60",
        help = "Time window in seconds for token limit enforcement."
    )]
    pub llm_token_window: u64,

    /// Disable scripting (LLM will only use actions, no script generation)
    #[clap(
        long = "no-scripts",
        help = "Disable script generation for tests that need action-only responses",
        hide = true  // Hidden from help output - primarily for testing
    )]
    pub no_scripts: bool,

    /// Load server/client configuration from a .netget file
    #[clap(
        long = "load",
        value_name = "FILE",
        help = "Load and execute server/client configurations from a .netget file"
    )]
    pub load_file: Option<String>,

    /// Non-interactive only: exit (status 0) once this many network events have been handled
    /// across every server and client.
    #[clap(
        long = "exit-after-events",
        value_name = "N",
        value_parser = clap::value_parser!(u64).range(1..),
        help = "Non-interactive mode: exit with status 0 once N network events have been handled across all servers and clients (each entry in the access log counts once, whatever answered it - handler, model or operator)"
    )]
    pub exit_after_events: Option<u64>,

    /// Non-interactive only: exit (status 0) after this many seconds.
    #[clap(
        long = "run-for",
        value_name = "SECS",
        value_parser = clap::value_parser!(u64).range(1..),
        help = "Non-interactive mode: run for SECS seconds, then stop everything and exit with status 0"
    )]
    pub run_for: Option<u64>,

    /// Path to mock LLM configuration file (for testing)
    #[clap(
        long = "mock-config-file",
        value_name = "FILE",
        help = "Path to JSON file containing mock LLM responses (used by tests)",
        hide = true  // Hidden from help output - internal testing flag
    )]
    pub mock_config_file: Option<std::path::PathBuf>,

    /// Start a simple protocol (simplified LLM interface for "dumb" models)
    #[clap(
        long = "simple",
        value_name = "PROTOCOL",
        help = "Start a simple protocol server (e.g., http). Use --simple-list to see available protocols."
    )]
    pub simple_protocol: Option<String>,

    /// List available simple protocols
    #[clap(
        long = "simple-list",
        help = "List available simple protocols that can be started with --simple"
    )]
    pub simple_list: bool,

    /// Connect a protocol client to a remote server (non-interactive)
    #[clap(
        long = "client",
        value_name = "PROTOCOL",
        help = "Connect a client of PROTOCOL to the address given by --connect, without asking the model to do it. Any trailing text is used as the client's instruction. Use --client-list to see available protocols."
    )]
    pub client_protocol: Option<String>,

    /// Remote address for --client
    #[clap(
        long = "connect",
        value_name = "ADDRESS",
        requires = "client_protocol",
        help = "Remote address the --client connects to, e.g. 127.0.0.1:6379"
    )]
    pub client_addr: Option<String>,

    /// Startup parameters for --client
    #[clap(
        long = "client-params",
        value_name = "JSON",
        requires = "client_protocol",
        help = "JSON object of startup parameters for --client (same keys as the MCP start_client tool's startup_params)"
    )]
    pub client_params: Option<String>,

    /// Event handlers for --client
    #[clap(
        long = "client-handlers",
        value_name = "JSON",
        requires = "client_protocol",
        help = "JSON array of event handlers for --client (script or static handlers run in-process with NO LLM call, which is what makes a scripted client deterministic)"
    )]
    pub client_handlers: Option<String>,

    /// List available client protocols
    #[clap(
        long = "client-list",
        help = "List protocols that can be connected as clients with --client"
    )]
    pub client_list: bool,

    /// Start a server of PROTOCOL directly, skipping the initial model call
    #[clap(
        long = "server",
        value_name = "PROTOCOL",
        conflicts_with = "client_protocol",
        help = "Start a server of PROTOCOL directly, WITHOUT asking the model which protocol to run — the initial LLM call is skipped. Any trailing text becomes the server's per-request instruction (the general prompt used for every request). Use a base-stack name (e.g. http, dns, redis); run with --docs to see them. Combine with --port and --server-params."
    )]
    pub server_protocol: Option<String>,

    /// Listen port for --server
    #[clap(
        long = "port",
        value_name = "PORT",
        requires = "server_protocol",
        help = "Port the --server listens on (default is the protocol's own default)."
    )]
    pub server_port: Option<u16>,

    /// Startup parameters for --server
    #[clap(
        long = "server-params",
        value_name = "JSON",
        requires = "server_protocol",
        help = "JSON object of startup parameters for --server (same keys as the MCP start_server tool's startup_params, e.g. request_filter/default_response for http). Not every parameter has a dedicated flag — use this for the rest."
    )]
    pub server_params: Option<String>,

    /// History length for --server / --client
    #[clap(
        long = "history",
        value_name = "ENTRIES",
        help = "For --server or --client: how many earlier exchanges on the same connection the model is shown with each event; 0 turns it off. Omit for the protocol's default (40 for conversational protocols, 0 for independent requests such as DNS and HTTP; --docs names each)."
    )]
    pub history: Option<u16>,

    /// Event batching for --server / --client
    #[clap(
        long = "batching",
        value_name = "true|false",
        action = clap::ArgAction::Set,
        help = "For --server or --client: hold events that arrive while the model is still answering and give them to it together afterwards. Omit for the protocol's default; refused where the protocol cannot batch."
    )]
    pub batching: Option<bool>,

    /// Print documentation for every protocol and exit
    #[clap(
        long = "docs",
        help = "Print documentation for every compiled-in server and client protocol (base stacks, keywords, startup parameters, events, actions, examples) to stdout, then exit."
    )]
    pub docs: bool,

    /// Connect an agent to a running --mcp-http --llm-agent process. Emits compact
    /// requests as JSON lines on stdout and reads answers as JSON lines on stdin.
    #[clap(long = "agent-connect", value_name = "MCP_URL", conflicts_with_all = ["mcp_stdio", "mcp_http", "server_protocol", "client_protocol", "simple_protocol", "load_file", "llm_agent"])]
    pub agent_connect: Option<String>,

    /// Run as MCP STDIO server (for Claude Desktop/Code integration)
    #[clap(
        long = "mcp",
        alias = "mcp-stdio",
        help = "Run as an MCP server over stdin/stdout for integration with MCP clients like Claude Desktop"
    )]
    pub mcp_stdio: bool,

    /// Run as an MCP server over HTTP/SSE on the given port (for remote/web MCP clients)
    #[clap(
        long = "mcp-http",
        value_name = "PORT",
        conflicts_with = "mcp_stdio",
        help = "Run as an MCP server over HTTP/SSE on the given port (e.g. --mcp-http 8080). Bind address comes from --listen-addr (default 127.0.0.1)"
    )]
    pub mcp_http: Option<u16>,

    /// Bearer token every --mcp-http request must carry
    #[clap(
        long = "mcp-token",
        value_name = "TOKEN",
        help = "Require 'Authorization: Bearer <TOKEN>' on every --mcp-http request. PREFER the NETGET_MCP_TOKEN environment variable: an argument is visible to every local user in the process table. Required to bind --listen-addr to anything but a loopback address; without it the endpoint admits loopback Host/Origin only."
    )]
    pub mcp_token: Option<String>,

    /// Prompt/command to execute (can be specified after --, or as trailing args, or via stdin)
    #[clap(value_name = "PROMPT", num_args = 0..)]
    pub prompt: Vec<String>,
}

/// Warn - once per process - that an API key was passed as a command-line
/// argument.
///
/// A process's argv is world-readable on every platform NetGet runs on: any
/// local user can read the key out of `ps` / `/proc/<pid>/cmdline` for as long
/// as the process lives, and it lands in shell history and process accounting
/// on the way in. The environment-variable path has none of those properties,
/// so it is the documented way in; the flag keeps working for callers that
/// already use it, but it says so.
fn warn_api_key_on_command_line() {
    static WARNED: std::sync::Once = std::sync::Once::new();
    WARNED.call_once(|| {
        const MSG: &str = "--api-key puts the key in this process's command line, where any local user can read it (ps / /proc). Prefer the NETGET_API_KEY or OPENAI_API_KEY environment variable.";
        tracing::warn!("{}", MSG);
        // stderr, not stdout: MCP stdio mode carries JSON-RPC on stdout.
        eprintln!("⚠  {}", MSG);
    });
}

/// Environment variable read when `--mcp-token` is not passed. Lives here rather than in
/// `mcp_stdio::http_guard` because that module is compiled only with `mcp-stdio` /
/// `mcp-http`, and `Args` is parsed at every feature set.
pub const MCP_TOKEN_ENV: &str = "NETGET_MCP_TOKEN";

/// Same warning as `warn_api_key_on_command_line`, for `--mcp-token`.
fn warn_mcp_token_on_command_line() {
    static WARNED: std::sync::Once = std::sync::Once::new();
    WARNED.call_once(|| {
        const MSG: &str = "--mcp-token puts the token in this process's command line, where any local user can read it (ps / /proc). Prefer the NETGET_MCP_TOKEN environment variable.";
        tracing::warn!("{}", MSG);
        eprintln!("⚠  {}", MSG);
    });
}

impl Args {
    /// Resolve the API key from NETGET_API_KEY / OPENAI_API_KEY, or the
    /// `--api-key` flag.
    ///
    /// The flag still wins when both are set - changing that would break
    /// callers - but using it warns, because it exposes the secret in the
    /// process table.
    pub fn resolve_api_key(&self) -> Option<String> {
        if let Some(key) = &self.api_key {
            warn_api_key_on_command_line();
            return Some(key.clone());
        }
        std::env::var("NETGET_API_KEY")
            .ok()
            .or_else(|| std::env::var("OPENAI_API_KEY").ok())
    }

    /// Resolve the MCP HTTP bearer token from `--mcp-token` or `NETGET_MCP_TOKEN`.
    ///
    /// Same shape as `resolve_api_key`: the flag wins and warns, the variable is
    /// the documented way in. An empty value counts as unset.
    pub fn resolve_mcp_token(&self) -> Option<String> {
        if let Some(token) = &self.mcp_token {
            warn_mcp_token_on_command_line();
            return Some(token.clone()).filter(|t| !t.is_empty());
        }
        std::env::var(MCP_TOKEN_ENV).ok().filter(|t| !t.is_empty())
    }

    /// Get the effective log level from --log-level flag
    pub fn effective_log_level(&self) -> Level {
        match self.log_level.to_lowercase().as_str() {
            "off" | "none" => Level::ERROR, // We'll filter this out separately
            "error" => Level::ERROR,
            "warn" | "warning" => Level::WARN,
            "info" => Level::INFO,
            "debug" => Level::DEBUG,
            "trace" => Level::TRACE,
            _ => Level::ERROR,
        }
    }

    /// Check if logging should be disabled entirely
    pub fn logging_disabled(&self) -> bool {
        self.log_level == "off" || self.log_level == "none"
    }

    /// Determine if we should run in interactive mode
    pub fn is_interactive(&self) -> bool {
        // Non-interactive if we have a prompt from args
        if !self.prompt.is_empty() {
            return false;
        }

        // Non-interactive if stdin is not a terminal (piped input)
        if !io::stdin().is_terminal() {
            return false;
        }

        // Non-interactive if stdout is not a terminal (piped output)
        // This ensures we don't try to show TUI when output is redirected
        if !io::stdout().is_terminal() {
            return false;
        }

        // Otherwise, run in interactive mode
        true
    }

    /// Get the prompt to execute, from various sources
    /// Returns None if the input should be treated as actions JSON instead
    pub fn get_prompt(&self) -> Result<Option<String>> {
        // First priority: --load flag (will be handled separately)
        if self.load_file.is_some() {
            return Ok(None);
        }

        // Second priority: trailing arguments after command
        if !self.prompt.is_empty() {
            let joined = self.prompt.join(" ");
            // Check if it's actions JSON instead of a prompt
            if crate::utils::save_load::is_actions_json(&joined) {
                // This will be handled by get_actions_json() instead
                return Ok(None);
            }
            return Ok(Some(joined));
        }

        // Third priority: stdin if not a terminal (piped/redirected input)
        let piped = piped_stdin();
        if !piped.is_empty() {
            // Check if it's actions JSON instead of a prompt
            if crate::utils::save_load::is_actions_json(piped) {
                // This will be handled by get_actions_json() instead
                return Ok(None);
            }
            return Ok(Some(piped.to_string()));
        }

        // No prompt available
        Ok(None)
    }

    /// Get actions JSON to execute, from various sources
    /// Returns None if the input is a regular prompt or no input
    pub fn get_actions_json(&self) -> Result<Option<Vec<serde_json::Value>>> {
        use crate::utils::save_load;

        // First priority: --load flag
        if let Some(ref filename) = self.load_file {
            // This will fail if file doesn't exist, which is appropriate
            return Ok(Some(load_actions_file(filename)?));
        }

        // Second priority: trailing arguments after command
        if !self.prompt.is_empty() {
            let joined = self.prompt.join(" ");
            if save_load::is_actions_json(&joined) {
                // Parse {"actions": [...]} format and extract the array
                let parsed: serde_json::Value = serde_json::from_str(&joined)?;
                let actions = parsed["actions"]
                    .as_array()
                    .ok_or_else(|| anyhow::anyhow!("Invalid actions format"))?
                    .clone();
                return Ok(Some(actions));
            }
        }

        // Third priority: stdin, but ONLY when no trailing prompt was given.
        //
        // When trailing args are present the prompt/actions come from there, and
        // stdin is not a source — it may instead be a live pipe feeding a stdio
        // server (`prog | netget "be a filter"`). Consulting `piped_stdin()`
        // there would block forever on that never-EOF pipe before any server
        // starts. With no trailing args stdin IS the source, so
        // `echo '{"actions":...}' | netget` and `cat prompt.txt | netget` still
        // read it (those pipes reach EOF).
        if self.prompt.is_empty() {
            let piped = piped_stdin();
            if !piped.is_empty() && save_load::is_actions_json(piped) {
                // Parse {"actions": [...]} format and extract the array
                let parsed: serde_json::Value = serde_json::from_str(piped)?;
                let actions = parsed["actions"]
                    .as_array()
                    .ok_or_else(|| anyhow::anyhow!("Invalid actions format"))?
                    .clone();
                return Ok(Some(actions));
            }
        }

        // No actions JSON available
        Ok(None)
    }

    /// Check if the environment is suitable for the requested mode
    pub fn validate_mode(&self) -> Result<()> {
        if self.is_interactive() {
            // Interactive mode requires a terminal
            if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
                anyhow::bail!(
                    "Cannot start in interactive mode without a terminal.\n\
                     Please provide a prompt via arguments, stdin, or use --non-interactive."
                );
            }
        } else {
            // Non-interactive mode requires a prompt
            if self.get_prompt()?.is_none() {
                anyhow::bail!(
                    "Non-interactive mode requires a prompt.\n\
                     Provide a prompt via arguments, stdin, or use interactive mode."
                );
            }
        }
        Ok(())
    }

    /// Parse the scripting environment argument into a ScriptingMode
    pub fn parse_scripting_mode(&self) -> Result<Option<crate::state::app_state::ScriptingMode>> {
        // --no-scripts flag takes precedence
        if self.no_scripts {
            return Ok(Some(crate::state::app_state::ScriptingMode::Off));
        }

        match &self.scripting_env {
            None => Ok(None),
            // The same parser the settings file is read with: `ScriptingMode::parse`.
            Some(env) => crate::state::app_state::ScriptingMode::parse(env)
                .map(Some)
                .map_err(|e| anyhow::anyhow!(e)),
        }
    }

    /// Parse the event handler mode argument into an EventHandlerMode
    pub fn parse_event_handler_mode(
        &self,
    ) -> Result<Option<crate::state::app_state::EventHandlerMode>> {
        match &self.event_handler_mode {
            None => Ok(None),
            Some(mode) => {
                let parsed_mode = match mode.to_lowercase().as_str() {
                    "any" => crate::state::app_state::EventHandlerMode::Any,
                    "script" => crate::state::app_state::EventHandlerMode::Script,
                    "static" => crate::state::app_state::EventHandlerMode::Static,
                    "llm" => crate::state::app_state::EventHandlerMode::Llm,
                    _ => {
                        anyhow::bail!(
                            "Invalid event handler mode: '{}'\n\
                             Valid options: any, script, static, llm",
                            mode
                        );
                    }
                };
                Ok(Some(parsed_mode))
            }
        }
    }

    /// Instruction for a `--client`: the trailing text if any was given,
    /// otherwise the same default the MCP `start_client` tool uses.
    pub fn client_instruction(&self, protocol: &str, remote_addr: &str) -> String {
        let trailing = self.prompt.join(" ").trim().to_string();
        if trailing.is_empty() {
            format!(
                "You are a {} client connected to {}. Handle responses appropriately.",
                protocol, remote_addr
            )
        } else {
            trailing
        }
    }

    /// The per-request instruction for `--server`: the trailing prompt, or a
    /// minimal default naming the protocol when none was given.
    pub fn server_instruction(&self, protocol: &str) -> String {
        let trailing = self.prompt.join(" ").trim().to_string();
        if trailing.is_empty() {
            format!(
                "You are a {} server. Respond to each request appropriately.",
                protocol
            )
        } else {
            trailing
        }
    }

    /// Parse `--server-params` into a JSON object.
    pub fn parse_server_params(&self) -> Result<Option<serde_json::Value>> {
        match &self.server_params {
            None => Ok(None),
            Some(raw) => {
                let value: serde_json::Value = serde_json::from_str(raw)
                    .map_err(|e| anyhow::anyhow!("--server-params is not valid JSON: {}", e))?;
                if !value.is_object() {
                    anyhow::bail!(
                        "--server-params must be a JSON object, e.g. '{{\"request_filter\": [...]}}'"
                    );
                }
                Ok(Some(value))
            }
        }
    }

    /// Parse `--client-params` into a JSON object
    pub fn parse_client_params(&self) -> Result<Option<serde_json::Value>> {
        match &self.client_params {
            None => Ok(None),
            Some(raw) => {
                let value: serde_json::Value = serde_json::from_str(raw)
                    .map_err(|e| anyhow::anyhow!("--client-params is not valid JSON: {}", e))?;
                if !value.is_object() {
                    anyhow::bail!("--client-params must be a JSON object, e.g. '{{\"db\": 0}}'");
                }
                Ok(Some(value))
            }
        }
    }

    /// Parse `--client-handlers` into a list of event handler definitions
    pub fn parse_client_handlers(&self) -> Result<Option<Vec<serde_json::Value>>> {
        match &self.client_handlers {
            None => Ok(None),
            Some(raw) => {
                let value: serde_json::Value = serde_json::from_str(raw)
                    .map_err(|e| anyhow::anyhow!("--client-handlers is not valid JSON: {}", e))?;
                match value {
                    serde_json::Value::Array(handlers) => Ok(Some(handlers)),
                    _ => anyhow::bail!(
                        "--client-handlers must be a JSON array of handler objects, e.g. '[{{\"event\": \"redis_response_received\", \"handler_type\": \"static\", \"response\": []}}]'"
                    ),
                }
            }
        }
    }

    /// Parse `--min-stability` into a [`DevelopmentState`].
    ///
    /// Returns `Ok(None)` when the flag is absent (no gate — current behaviour).
    /// An unrecognised value is a hard error naming the allowed set, mirroring
    /// `parse_scripting_mode`/`parse_event_handler_mode`.
    pub fn parse_min_stability(
        &self,
    ) -> Result<Option<crate::protocol::metadata::DevelopmentState>> {
        match &self.min_stability {
            None => Ok(None),
            Some(raw) => match crate::protocol::metadata::DevelopmentState::parse_ci(raw) {
                Some(state) => Ok(Some(state)),
                None => anyhow::bail!(
                    "Invalid --min-stability value: '{}'\n\
                     Valid options (case-insensitive): incomplete, experimental, beta, stable",
                    raw
                ),
            },
        }
    }

    /// Build a RateLimiterConfig from CLI arguments
    pub fn build_rate_limiter_config(&self) -> crate::llm::RateLimiterConfig {
        crate::llm::RateLimiterConfig {
            max_concurrent: self.llm_max_concurrent.unwrap_or(1),
            token_limit: self.llm_token_limit,
            token_window_secs: self.llm_token_window,
            queue_timeout_secs: self
                .llm_queue_timeout
                .unwrap_or(crate::llm::DEFAULT_QUEUE_TIMEOUT_SECS),
            max_queued: self
                .llm_max_queued
                .unwrap_or(crate::llm::DEFAULT_MAX_QUEUED),
        }
    }
}

/// A temperature is a finite, non-negative number. Rejected here rather than sent, because
/// backends disagree on what they do with a negative or NaN value and none of them says so.
fn parse_temperature(value: &str) -> Result<f32, String> {
    let t: f32 = value
        .parse()
        .map_err(|_| format!("'{}' is not a number", value))?;
    if !t.is_finite() || t < 0.0 {
        return Err(format!(
            "temperature must be a finite number >= 0, got {}",
            value
        ));
    }
    Ok(t)
}
