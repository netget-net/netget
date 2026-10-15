//! NetGet's Vault against the real `vault` CLI.
//!
//! HashiCorp's CLI is a Go client NetGet did not write. Before any `kv` command it asks
//! `sys/internal/ui/mounts/<path>` which KV version the mount runs, then rewrites the path to
//! KV v2's `<mount>/data/…` or `<mount>/metadata/…`, and decodes the response envelope into its
//! own `api.Secret` — so a `vault kv get -field=password` that prints the right word proves the
//! preflight, the path rewrite, the envelope and the v2 `data`/`metadata` split at once.
//!
//! The child runs with a **cleared environment**: only `PATH`, a temp `HOME` (so no
//! `~/.vault-token` and no token helper from the user's config), `VAULT_ADDR` pointing at NetGet
//! and the test's own `VAULT_TOKEN`. No real Vault is ever contacted.
//!
//! Handlers are Python scripts (no model): one per event, answering from fixed data and
//! refusing a mismatched token with 403. `e2e_test.rs` drives the CLI against a mocked model.
//!
//! **These tests FAIL, they do not skip, when vault is absent.** Install with
//! `brew install hashicorp/tap/vault` (macOS) or HashiCorp's apt repository / release zip
//! (Linux).


use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use serde_json::{json, Value};
use std::time::Duration;
use tokio::sync::mpsc;

type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

pub const FIXTURE_TOKEN: &str = "hvs.netget-fixture-token";

pub fn require_tool(name: &str) -> String {
    if let Some(candidate) = crate::helpers::real_server::find_binary(name) {
        return candidate.to_string_lossy().into_owned();
    }
    panic!(
        "`{name}` was not found on PATH or in the usual install directories. These \
         tests drive HashiCorp's own vault CLI against NetGet's Vault server, and that is the \
         only independent check that its KV v2 preflight, paths and envelopes are what a real \
         client expects. Skipping would leave the Vault server's maturity rating resting on \
         nothing, so this is a failure and not a skip. Install with `brew install \
         hashicorp/tap/vault` (macOS) or HashiCorp's apt repository / release zip (Linux)."
    );
}

pub struct VaultOutput {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

/// Run the CLI against NetGet with a cleared environment.
pub async fn vault(
    bin: &str,
    home: &std::path::Path,
    port: u16,
    token: &str,
    args: &[&str],
) -> VaultOutput {
    let out = tokio::time::timeout(
        Duration::from_secs(60),
        tokio::process::Command::new(bin)
            .args(args)
            .env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("HOME", home)
            .env("VAULT_ADDR", format!("http://127.0.0.1:{port}"))
            .env("VAULT_TOKEN", token)
            .kill_on_drop(true)
            .output(),
    )
    .await
    .expect("vault did not finish within 60s")
    .expect("run vault");
    let result = VaultOutput {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    };
    println!(
        "$ vault {}\n  exit {}\n{}{}",
        args.join(" "),
        result.code,
        result.stdout,
        result.stderr
    );
    result
}

pub async fn start_vault(event_handlers: Vec<Value>, startup_params: Value) -> (AppState, u16) {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".to_string());
    state
        .set_llm_client(netget::llm::OllamaClient::new(
            "http://127.0.0.1:1".to_string(),
        ))
        .await;
    let (tx, _rx) = mpsc::unbounded_channel();
    let id = ServerForm {
        protocol: "vault".to_string(),
        port: Some(0),
        instruction: Some(String::new()),
        startup_params: Some(startup_params),
        event_handlers: Some(event_handlers),
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .expect("create vault server");
    for _ in 0..300 {
        if let Some(addr) = state.get_server(id).await.and_then(|s| s.local_addr) {
            return (state, addr.port());
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("vault server never bound a port");
}

fn script(event: &str, code: &str) -> Value {
    json!({
        "event_pattern": event,
        "handler": {"type": "script", "language": "python", "code": code}
    })
}

/// Fixed data, a 403 for a mismatched token, a 404 for anything unknown.
fn fixture_handlers() -> Vec<Value> {
    let prelude = "import json, sys\nevent = json.load(sys.stdin)['event']\n\
                   def reply(act):\n    print(json.dumps({'actions': [act]}))\n\
                   if not event['token_matches_configured']:\n    \
                   reply({'type': 'send_vault_error', 'status': 403, 'errors': ['permission denied']})\n    \
                   sys.exit(0)\n";
    vec![
        script(
            "vault_read",
            &format!(
                "{prelude}if event['mount'] == 'secret' and event['path'] == 'app/db':\n    \
                 reply({{'type': 'send_vault_secret', 'data': {{'user': 'admin-fixture', \
                 'password': 'hunter2-fixture'}}, 'version': 7, \
                 'created_time': '2026-09-01T10:00:00Z', \
                 'custom_metadata': {{'owner': 'netget-fixture'}}}})\n\
                 else:\n    reply({{'type': 'send_vault_error', 'status': 404, 'errors': []}})\n"
            ),
        ),
        script(
            "vault_list",
            &format!(
                "{prelude}keys = {{'': ['app/'], 'app': ['db', 'stripe', 'certs/']}}\
                 .get(event['path'].strip('/'))\n\
                 reply({{'type': 'send_vault_list', 'keys': keys}} if keys else \
                 {{'type': 'send_vault_error', 'status': 404, 'errors': []}})\n"
            ),
        ),
        script(
            "vault_write",
            &format!(
                "{prelude}ok = event['data'] == {{'password': 'hunter2', 'user': 'admin'}}\n\
                 reply({{'type': 'send_vault_write_ok', 'version': 8, \
                 'created_time': '2026-09-02T11:00:00Z'}} if ok else \
                 {{'type': 'send_vault_error', 'status': 400, 'errors': ['unexpected data']}})\n"
            ),
        ),
    ]
}

#[tokio::test]
async fn the_vault_cli_reads_writes_and_lists_through_kv_v2() -> TestResult {
    let bin = require_tool("vault");
    let home = tempfile::TempDir::new()?;
    let (_state, port) = start_vault(
        fixture_handlers(),
        json!({"token": FIXTURE_TOKEN, "vault_version": "1.18.3-netget-fixture"}),
    )
    .await;
    let h = home.path();
    let run = |args: &'static [&'static str]| vault(&bin, h, port, FIXTURE_TOKEN, args);

    // status: seal status and leader, both static.
    let status = run(&["status"]).await;
    assert_eq!(status.code, 0, "{}", status.stderr);
    for (key, value) in [
        ("Initialized", "true"),
        ("Sealed", "false"),
        ("Version", "1.18.3-netget-fixture"),
        ("Storage Type", "inmem"),
        ("HA Enabled", "false"),
    ] {
        assert!(
            status
                .stdout
                .lines()
                .any(|l| l.starts_with(key) && l.split_whitespace().last() == Some(value)),
            "vault status lacks {key} = {value}:\n{}",
            status.stdout
        );
    }

    // put: the CLI sends {"data": {...}} to secret/data/app/db and prints our metadata.
    let put = run(&[
        "kv",
        "put",
        "-mount=secret",
        "app/db",
        "password=hunter2",
        "user=admin",
    ])
    .await;
    assert_eq!(put.code, 0, "{}", put.stderr);
    assert!(put.stdout.contains("secret/data/app/db"), "{}", put.stdout);
    assert!(
        put.stdout
            .lines()
            .any(|l| l.starts_with("version") && l.trim_end().ends_with(" 8")),
        "{}",
        put.stdout
    );
    assert!(put.stdout.contains("2026-09-02T11:00:00"), "{}", put.stdout);

    // get: the table, a single field, and the JSON envelope.
    let get = run(&["kv", "get", "-mount=secret", "app/db"]).await;
    assert_eq!(get.code, 0, "{}", get.stderr);
    assert!(
        get.stdout
            .lines()
            .any(|l| l.starts_with("password") && l.trim_end().ends_with("hunter2-fixture")),
        "{}",
        get.stdout
    );
    let field = run(&["kv", "get", "-field=password", "secret/app/db"]).await;
    assert_eq!(field.code, 0, "{}", field.stderr);
    assert_eq!(
        field.stdout, "hunter2-fixture",
        "exactly the field, nothing else"
    );
    let as_json = run(&["kv", "get", "-format=json", "secret/app/db"]).await;
    let doc: Value = serde_json::from_str(&as_json.stdout)?;
    assert_eq!(doc["data"]["data"]["user"], "admin-fixture");
    assert_eq!(doc["data"]["metadata"]["version"], 7);
    assert_eq!(
        doc["data"]["metadata"]["custom_metadata"]["owner"],
        "netget-fixture"
    );

    // list: LIST (or GET ?list=true) on secret/metadata/app.
    let list = run(&["kv", "list", "secret/app"]).await;
    assert_eq!(list.code, 0, "{}", list.stderr);
    let keys: Vec<&str> = list.stdout.lines().skip(2).map(str::trim).collect();
    assert_eq!(keys, vec!["certs/", "db", "stripe"], "{}", list.stdout);

    // metadata get: built from the same answer as a read.
    let meta = run(&["kv", "metadata", "get", "secret/app/db"]).await;
    assert_eq!(meta.code, 0, "{}", meta.stderr);
    assert!(
        meta.stdout
            .lines()
            .any(|l| l.starts_with("current_version") && l.trim_end().ends_with(" 7")),
        "{}",
        meta.stdout
    );

    // Not found is the CLI's own message, and exit code 2.
    let missing = run(&["kv", "get", "secret/app/nothing"]).await;
    assert_eq!(missing.code, 2, "{}{}", missing.stdout, missing.stderr);
    assert!(
        format!("{}{}", missing.stdout, missing.stderr)
            .contains("No value found at secret/data/app/nothing"),
        "{}{}",
        missing.stdout,
        missing.stderr
    );

    // A wrong token: the handler refuses on the event's booleans; the token itself never
    // reached it.
    let denied = vault(&bin, h, port, "hvs.wrong", &["kv", "get", "secret/app/db"]).await;
    assert_ne!(denied.code, 0);
    assert!(
        denied.stderr.contains("Code: 403") && denied.stderr.contains("permission denied"),
        "{}",
        denied.stderr
    );

    // Deleting is not implemented: Vault's error shape, statically.
    let delete = run(&["kv", "delete", "secret/app/db"]).await;
    assert_ne!(delete.code, 0);
    assert!(delete.stderr.contains("Code: 405"), "{}", delete.stderr);
    Ok(())
}

/// The shipped script-mode example, as written.
#[tokio::test]
async fn the_documented_script_example_serves_the_cli() -> TestResult {
    use netget::llm::actions::protocol_trait::Protocol;
    let bin = require_tool("vault");
    let home = tempfile::TempDir::new()?;
    let handlers = netget::server::VaultProtocol::new()
        .get_startup_examples()
        .script_mode["event_handlers"]
        .as_array()
        .expect("script example has handlers")
        .clone();
    let (_state, port) = start_vault(handlers, json!({})).await;

    let field = vault(
        &bin,
        home.path(),
        port,
        "any-token",
        &["kv", "get", "-field=password", "secret/app/db"],
    )
    .await;
    assert_eq!(field.code, 0, "{}", field.stderr);
    assert_eq!(field.stdout, "s3cr3t");
    let list = vault(
        &bin,
        home.path(),
        port,
        "any-token",
        &["kv", "list", "secret/app"],
    )
    .await;
    assert!(list.stdout.contains("db"), "{}", list.stdout);
    let put = vault(
        &bin,
        home.path(),
        port,
        "any-token",
        &["kv", "put", "secret/app/new", "k=v"],
    )
    .await;
    assert_eq!(put.code, 0, "{}", put.stderr);
    Ok(())
}
