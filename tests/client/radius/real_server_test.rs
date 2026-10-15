//! The RADIUS client against **FreeRADIUS** — the evidence its maturity rating rests on.
//!
//! NetGet builds RADIUS packets with its own server's codec plus `src/client/radius/wire.rs`.
//! The server is FreeRADIUS 3 (`radiusd -X`), run unprivileged per test from a minimal raddb
//! in a temp dir: one client (127.0.0.1, secret `testing123`), a `users` file with a PAP/CHAP
//! user who gets a Reply-Message and a user who is always rejected, `pap`, `chap`, `files` and
//! `detail` modules, and authentication and accounting listeners on probed ports. FreeRADIUS
//! checks every authenticator NetGet computes (User-Password hiding, CHAP, the
//! Message-Authenticator, the Accounting-Request authenticator) and signs every reply NetGet
//! then verifies. Nothing on the wire was written by this repository except NetGet.
//!
//! Condition 4 of the client bar is asserted from the server's side: FreeRADIUS's `detail`
//! file must hold the accounting attributes the mocked model chose, including a session id the
//! model built from the Reply-Message it was shown.
//!
//! **No test here skips.** A missing `radiusd` fails with the install command. Ubuntu installs
//! the binary as `freeradius`; CI links it to `radiusd`, as it does libmemcached's tools, rather
//! than this test guessing between spellings.
//!
//! LLM calls: 8 in the first test. None in the second, whose model endpoint is unreachable on
//! purpose.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features radius --test client -- radius::real_server_test --test-threads=100

use crate::helpers::real_server::{InstallHint, RealServer};
use crate::helpers::*;
use serde_json::json;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

const FREERADIUS: InstallHint = InstallHint {
    brew: "freeradius-server",
    apt: "freeradius (and link /usr/sbin/freeradius to radiusd, as CI does)",
};

/// The shared secret. It must never appear in anything the model is shown.
const SECRET: &str = "testing123";

/// Where FreeRADIUS keeps its dictionaries and modules: Homebrew or a distribution layout.
fn freeradius_layout() -> E2EResult<(String, String)> {
    let prefix = ["/opt/homebrew", "/usr/local", "/usr"]
        .into_iter()
        .find(|p| Path::new(p).join("share/freeradius/dictionary").is_file())
        .ok_or(
            "no FreeRADIUS dictionary under /opt/homebrew, /usr/local or /usr share/freeradius",
        )?;
    let libdir = [
        "/opt/homebrew/lib",
        "/usr/local/lib",
        "/usr/lib/freeradius",
        "/usr/lib/x86_64-linux-gnu/freeradius",
        "/usr/lib/aarch64-linux-gnu/freeradius",
    ]
    .into_iter()
    .find(|d| {
        ["rlm_pap.so", "rlm_pap.dylib"]
            .iter()
            .any(|m| Path::new(d).join(m).is_file())
    })
    .ok_or("no FreeRADIUS module directory holding rlm_pap")?;
    Ok((prefix.to_string(), libdir.to_string()))
}

/// A minimal raddb. `{dir}`, `{port}` and `{port1}` are the RealServer placeholders;
/// `@PREFIX@` and `@LIBDIR@` are filled in from [`freeradius_layout`].
const RADIUSD_CONF: &str = r#"
prefix = @PREFIX@
exec_prefix = ${prefix}
sysconfdir = {dir}
localstatedir = {dir}
sbindir = ${exec_prefix}/sbin
logdir = {dir}
raddbdir = {dir}
radacctdir = {dir}/radacct
name = radiusd
confdir = ${raddbdir}
modconfdir = ${confdir}/mods-config
certdir = ${confdir}/certs
cadir = ${confdir}/certs
run_dir = {dir}
db_dir = ${raddbdir}
libdir = @LIBDIR@
pidfile = ${run_dir}/radiusd.pid
max_request_time = 30
cleanup_delay = 5
max_requests = 1024
hostname_lookups = no
log {
  destination = stdout
  colourise = no
  file = ${logdir}/radius.log
  stripped_names = no
  auth = yes
}
security {
  allow_core_dumps = no
  max_attributes = 200
  reject_delay = 0
  status_server = yes
}
thread pool {
  start_servers = 1
  max_servers = 4
  min_spare_servers = 1
  max_spare_servers = 4
  max_requests_per_server = 0
}
client localhost {
  ipaddr = 127.0.0.1
  secret = testing123
  require_message_authenticator = yes
}
modules {
  pap {
  }
  chap {
  }
  files {
    filename = ${confdir}/users
  }
  detail {
    filename = ${radacctdir}/detail
    permissions = 0600
    header = "%t"
  }
}
server default {
  listen {
    type = auth
    ipaddr = 127.0.0.1
    port = {port}
  }
  listen {
    type = acct
    ipaddr = 127.0.0.1
    port = {port1}
  }
  authorize {
    chap
    files
    pap
  }
  authenticate {
    Auth-Type PAP {
      pap
    }
    Auth-Type CHAP {
      chap
    }
  }
  preacct {
  }
  accounting {
    detail
  }
  post-auth {
  }
}
"#;

const USERS: &str = r#"alice	Cleartext-Password := "wonderland"
	Reply-Message = "Welcome, alice"

mallory	Auth-Type := Reject
	Reply-Message = "Go away"
"#;

async fn start_radiusd() -> E2EResult<RealServer> {
    let (prefix, libdir) = freeradius_layout()?;
    let conf = RADIUSD_CONF
        .replace("@PREFIX@", &prefix)
        .replace("@LIBDIR@", &libdir);
    RealServer::builder("radiusd", FREERADIUS)
        .config_file("radiusd.conf", &conf)
        .config_file("users", USERS)
        .config_file("dictionary", "")
        .config_file("radacct/.keep", "")
        .extra_ports(1)
        .args(["-X", "-d", "{dir}"])
        .ready_when_log_matches("Ready to process requests")
        .without_tcp_readiness()
        .start()
        .await
}

static SECRET_SEEN: AtomicBool = AtomicBool::new(false);

/// Record whether an event the model is shown carries the secret, then answer.
fn guarded(event: &serde_json::Value, answer: serde_json::Value) -> serde_json::Value {
    if event.to_string().contains(SECRET) {
        SECRET_SEEN.store(true, Ordering::SeqCst);
    }
    answer
}

/// PAP and CHAP accepted with the users file's Reply-Message, a wrong password and a Reject
/// user refused, accounting written to the detail file, and Status-Server answered — every
/// reply's Response Authenticator and Message-Authenticator verified by NetGet.
///
/// 1. connected → PAP alice/wonderland.
/// 2. `radius_access_accept {method: pap, reply_message: "Welcome, alice"}` → CHAP, same user.
/// 3. `radius_access_accept {method: chap}` → PAP alice with a wrong password.
/// 4. `radius_access_reject {user_name: alice}` → mallory.
/// 5. `radius_access_reject {user_name: mallory, reply_message: "Go away"}` → Accounting Start
///    with a session id built from the first Reply-Message, NAS-Port 7, Called-Station-Id.
/// 6. `radius_accounting_response` → Status-Server.
/// 7. `radius_status_response {code: Access-Accept}` → nothing.
///
/// Then FreeRADIUS's detail file must hold the model's accounting attributes.
#[tokio::test]
async fn radius_client_authenticates_and_accounts_against_freeradius() -> E2EResult<()> {
    let server = start_radiusd().await?;
    let result = authenticates_and_accounts(&server).await;
    server.with_log(result)
}

async fn authenticates_and_accounts(server: &RealServer) -> E2EResult<()> {
    let auth = server.addr();
    let acct_port = server.extra_ports[0];
    let config = NetGetConfig::new(format!(
        "Be a NAS for the RADIUS server at {auth}. RADIUS-REAL-SERVER-STARTUP."
    ))
    .with_mock(move |mock| {
        mock.on_instruction_containing("RADIUS-REAL-SERVER-STARTUP")
            .respond_with_actions(json!([{
                "type": "open_client",
                "protocol": "RADIUS",
                "remote_addr": auth,
                "instruction": "Log alice in both ways, check the refusals, start her \
                                accounting session and check the server is up.",
                "startup_params": {"secret": SECRET, "accounting_port": acct_port}
            }]))
            .expect_calls(1)
            .and()
            .on_event("radius_connected")
            .respond_with_actions_from_event(|e| {
                guarded(e, json!([{
                    "type": "radius_access_request", "user_name": "alice", "password": "wonderland"
                }]))
            })
            .expect_calls(1)
            .and()
            .on_event("radius_access_accept")
            .and_event_data_contains("method", "pap")
            .and_event_data_contains("reply_message", "Welcome, alice")
            .respond_with_actions_from_event(|e| {
                guarded(e, json!([{
                    "type": "radius_access_request", "user_name": "alice",
                    "password": "wonderland", "method": "chap"
                }]))
            })
            .expect_calls(1)
            .and()
            .on_event("radius_access_accept")
            .and_event_data_contains("method", "chap")
            .and_event_data_contains("user_name", "alice")
            .respond_with_actions_from_event(|e| {
                guarded(e, json!([{
                    "type": "radius_access_request", "user_name": "alice", "password": "looking-glass"
                }]))
            })
            .expect_calls(1)
            .and()
            .on_event("radius_access_reject")
            .and_event_data_contains("user_name", "alice")
            .respond_with_actions_from_event(|e| {
                guarded(e, json!([{
                    "type": "radius_access_request", "user_name": "mallory", "password": "anything"
                }]))
            })
            .expect_calls(1)
            .and()
            .on_event("radius_access_reject")
            .and_event_data_contains("user_name", "mallory")
            .and_event_data_contains("reply_message", "Go away")
            .respond_with_actions_from_event(|e| {
                guarded(e, json!([{
                    "type": "radius_accounting_request",
                    "status_type": "Start",
                    "session_id": "netget-after-go-away",
                    "user_name": "alice",
                    "attributes": {"NAS-Port": 7, "Called-Station-Id": "netget-e2e"}
                }]))
            })
            .expect_calls(1)
            .and()
            .on_event("radius_accounting_response")
            .and_event_data_contains("session_id", "netget-after-go-away")
            .respond_with_actions_from_event(|e| {
                guarded(e, json!([{"type": "radius_status_server"}]))
            })
            .expect_calls(1)
            .and()
            .on_event("radius_status_response")
            .and_event_data_contains("code", "Access-Accept")
            .respond_with_actions_from_event(|e| guarded(e, json!([])))
            .expect_calls(1)
            .and()
    });

    let client = start_netget_client(config).await?;
    client.wait_for_mocks(30).await;
    client.verify_mocks().await?;
    assert!(
        !SECRET_SEEN.load(Ordering::SeqCst),
        "the shared secret reached an event the model was shown"
    );
    // Nor anything NetGet printed: the open_client summary and the executor's action log both
    // redact credential-named startup parameters (src/utils/redact.rs).
    let leaked: Vec<String> = client
        .get_output()
        .await
        .into_iter()
        .filter(|line| line.contains(SECRET))
        .collect();
    assert!(
        leaked.is_empty(),
        "the shared secret appears in NetGet's output:\n{}",
        leaked.join("\n")
    );

    let detail = std::fs::read_to_string(server.dir().join("radacct/detail"))?;
    for expected in [
        "Acct-Status-Type = Start",
        "Acct-Session-Id = \"netget-after-go-away\"",
        "User-Name = \"alice\"",
        "NAS-Port = 7",
        "Called-Station-Id = \"netget-e2e\"",
        "NAS-Identifier = \"netget\"",
    ] {
        assert!(
            detail.contains(expected),
            "FreeRADIUS's detail file must hold {expected:?}; it holds:\n{detail}"
        );
    }
    client.stop().await?;
    Ok(())
}

/// The dashboard's `[ send ]` / MCP `send_to_client` path: an injected Access-Request that
/// FreeRADIUS logs as a good login, an injected Accounting Stop in the detail file, a
/// request naming a reserved attribute refused before the wire, and `disconnect`.
#[tokio::test]
async fn injected_radius_requests_reach_freeradius() -> E2EResult<()> {
    let server = start_radiusd().await?;
    let result = injected_requests(&server).await;
    server.with_log(result)
}

async fn injected_requests(server: &RealServer) -> E2EResult<()> {
    use ::netget::cli::management::ClientForm;
    use ::netget::state::app_state::AppState;
    use ::netget::state::client_handles::ClientSendOutcome;
    use ::netget::state::ClientStatus;

    let state = AppState::new_with_options(false, "http://127.0.0.1:1".to_string());
    let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
    let client_id = ClientForm {
        protocol: "radius".to_string(),
        remote_addr: Some(server.addr()),
        instruction: Some("test client".to_string()),
        startup_params: Some(json!({"secret": SECRET, "accounting_port": server.extra_ports[0]})),
        ..Default::default()
    }
    .create(
        &state,
        ::netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
        tx,
    )
    .await
    .map_err(|e| format!("create radius client: {e}"))?;
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    while !state.has_client_handle(client_id).await {
        if std::time::Instant::now() > deadline {
            return Err("radius client never registered a command handle".into());
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }

    let send = |action: serde_json::Value| {
        let state = &state;
        async move {
            state
                .send_to_client(client_id, action, Duration::from_secs(10))
                .await
        }
    };
    let outcome = send(json!({
        "type": "radius_access_request", "user_name": "alice", "password": "wonderland"
    }))
    .await?;
    assert!(
        matches!(outcome, ClientSendOutcome::Sent { .. }),
        "{outcome:?}"
    );
    server
        .wait_for_log("Login OK: [alice", Duration::from_secs(10))
        .await?;

    let outcome = send(json!({
        "type": "radius_accounting_request", "status_type": "Stop",
        "session_id": "injected-stop", "user_name": "alice"
    }))
    .await?;
    assert!(
        matches!(outcome, ClientSendOutcome::Sent { .. }),
        "{outcome:?}"
    );
    let detail_path = server.dir().join("radacct/detail");
    let mut detail = String::new();
    for _ in 0..200 {
        detail = std::fs::read_to_string(&detail_path).unwrap_or_default();
        if detail.contains("injected-stop") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        detail.contains("Acct-Session-Id = \"injected-stop\"")
            && detail.contains("Acct-Status-Type = Stop"),
        "the injected Accounting Stop must reach the detail file:\n{detail}"
    );

    let outcome = send(json!({
        "type": "radius_access_request", "user_name": "alice",
        "attributes": {"Message-Authenticator": "00"}
    }))
    .await?;
    assert!(
        matches!(outcome, ClientSendOutcome::Rejected { .. }),
        "a reserved attribute must be refused, got {outcome:?}"
    );

    let outcome = send(json!({"type": "disconnect"})).await?;
    assert!(
        matches!(outcome, ClientSendOutcome::Disconnected),
        "{outcome:?}"
    );
    for _ in 0..300 {
        let status = state.get_client(client_id).await.map(|c| c.status);
        if matches!(status, Some(ClientStatus::Disconnected))
            && !state.has_client_handle(client_id).await
        {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    Err("client should be Disconnected with no command handle".into())
}
