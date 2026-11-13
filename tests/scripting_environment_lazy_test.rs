//! The scripting runtimes are probed on first use, not at startup.
//!
//! Every `AppState` used to probe python3, node, go and perl as it was built — once per
//! process after caching, but still ahead of `netget --mcp`'s `initialize` answer and the
//! dashboard's first frame, where `node --version` alone costs 130–280 ms. Now nothing at
//! startup asks, and the first caller that needs the answer (a prompt listing the runtimes, a
//! script handler, an `--env <runtime>` check) probes once.
//!
//! One test in its own target: the probe result is a process-wide static, so this must be the
//! only code in the process that could have triggered it.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features mcp-stdio,sqlite \
//!       --test scripting_environment_lazy_test

use netget::scripting::environment::ScriptingEnvironment;
use netget::state::app_state::AppState;

#[tokio::test]
async fn startup_does_not_probe_and_the_first_use_does() {
    let state = AppState::new();
    #[cfg(feature = "mcp-stdio")]
    let service = {
        use clap::Parser;
        // `--env on` is what most saved settings say: it needs no runtime, so checking it
        // must not probe either.
        let args = netget::cli::Args::parse_from([
            "netget",
            "--ollama-url",
            "http://127.0.0.1:1",
            "--env",
            "on",
        ]);
        netget::mcp_stdio::tools::NetGetMcpService::new(
            &args,
            netget::settings::Settings::default(),
        )
        .await
        .expect("MCP service")
    };
    assert!(
        !ScriptingEnvironment::is_detected(),
        "building AppState (and the MCP service) must not spawn the runtime probes"
    );

    // An injected environment is answered without probing either.
    let injected = AppState::new();
    injected
        .set_scripting_env(ScriptingEnvironment {
            python: Some("Python 3.0".into()),
            ..Default::default()
        })
        .await;
    assert_eq!(
        injected.get_scripting_env().await.python.as_deref(),
        Some("Python 3.0")
    );
    assert!(!ScriptingEnvironment::is_detected());

    // The first use probes, once, and gives the machine's answer.
    let env = state.get_scripting_env().await;
    assert!(ScriptingEnvironment::is_detected());
    let again = ScriptingEnvironment::detect();
    assert_eq!(
        (&env.python, &env.javascript, &env.go, &env.perl),
        (&again.python, &again.javascript, &again.go, &again.perl),
        "the lazily probed environment is the machine's"
    );
    #[cfg(feature = "mcp-stdio")]
    {
        let mcp_env = service.app_state().get_scripting_env().await;
        assert_eq!(mcp_env.python, env.python);
    }
}
