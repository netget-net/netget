//! Every `get_startup_examples()` entry must parse as an `open_server` action and produce a
//! server that reaches `ServerStatus::Running`.
//!
//! `tests/startup_examples_validation_test.rs` checks the **shape** of these examples: the
//! `type` is `open_server`, a `base_stack` is present, script mode carries a script handler.
//! Shape is what a reader can see. What it cannot see is whether the thing starts.
//!
//! These three JSON blobs are the most-copied text a protocol publishes. They are what the
//! model is shown when it asks how to open the protocol, what a person pastes into `--mcp`,
//! and what the docs render. An example that does not start is a defect that reaches every
//! caller at once, and nothing else in the tree looks at it — `startup_params` keys that the
//! protocol never declared are rejected at startup, and a handler whose event pattern names
//! an event the protocol does not raise simply never matches.
//!
//! # What this does and does not prove
//!
//! It proves the example parses through the same `CommonAction::from_json` the model's answer
//! goes through, that its `startup_params` and `event_handlers` survive validation, and that
//! the protocol binds. It does **not** prove the handler answers correctly — the BLE examples
//! that motivated this item were inert because `actions = [{...}]` under `python3 -c` assigns
//! a local and prints nothing, so the handler was recorded as failed and the event fell
//! through to the LLM. That is a *runtime* defect of the handler body, and it needs traffic to
//! surface; it is Tier 4's real-model eval, not this. Say so rather than letting a green run
//! here read as "the examples work".
//!
//! # The port is overridden, deliberately
//!
//! Examples name the protocol's real default port — 79 for finger, 70 for gopher, 6379 for
//! redis. Binding those would test the machine rather than the example: below 1024 needs
//! privilege, and at `--test-threads=100` two examples on the same port collide. Every spawn
//! here is on port 0, so what is under test is the handler table and the startup parameters.
//! Whether the declared default port is bindable is a property of the operator's machine and
//! is not something an example can get wrong.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features all-protocols \
//!       --test startup_examples_actually_start_test -- --test-threads=100 --nocapture

mod helpers;

use std::time::Duration;

use helpers::mock_builder::MockLlmBuilder;
use helpers::mock_ollama::MockOllamaServer;
use netget::cli::management::ServerForm;
use netget::llm::actions::common::CommonAction;
use netget::protocol::metadata::PrivilegeRequirement;
use netget::protocol::server_registry::registry;
use netget::state::app_state::AppState;
use netget::state::server::ServerStatus;
use tokio::sync::mpsc;

/// Protocols skipped because starting one needs hardware or an OS object this process cannot
/// conjure, with the reason. Matched as a **prefix** of the lowercased protocol name.
///
/// Privilege is *not* on this list: it is derived from each protocol's own
/// `metadata().privilege_requirement`, so a protocol that stops needing root stops being
/// skipped without anyone editing this file. This list is only for the cases the metadata
/// cannot express — `CLAUDE.md` records that there is no `PrivilegeRequirement` variant for
/// device access, and that the seventeen device protocols therefore sit at `None` because
/// every other option would be a lie.
///
/// Note what is **not** here: the USB family. Every `usb-*` protocol is a USB/IP server, and
/// USB/IP is a TCP protocol — it binds a socket and waits for a client to attach a device, so
/// it starts on this machine with no hardware at all. An earlier draft skipped them on the
/// assumption that "USB" means libusb; all seven start, and the assumption would have cost the
/// sweep seven protocols for nothing.
const NEEDS_HARDWARE_OR_AN_OS_OBJECT: &[(&str, &str)] = &[
    (
        "bluetooth_ble",
        "needs a Bluetooth adapter; on macOS it also needs the app to hold the single \
         CoreBluetooth peripheral role, which a test process claiming it would take from the \
         rest of the suite",
    ),
    ("nfc", "needs a PC/SC reader"),
    (
        "pty",
        "allocates a pseudo-terminal rather than binding a socket, so there is no port and \
         nothing here can assert on it",
    ),
    (
        "stdio",
        "takes over this process's stdin/stdout, which under a test harness is the harness's",
    ),
    (
        "named_pipe",
        "creates a filesystem object at a fixed path; two examples racing on it is the test's \
         bug, not the protocol's",
    ),
    (
        "socket_file",
        "creates a unix socket at a fixed filesystem path, same race",
    ),
];

/// Protocols whose transport is an OS facility this host may not have at all, with the reason.
///
/// These are *not* example defects and the distinction matters: both refuse to start with an
/// error naming the missing facility and how to get one, which is exactly the behaviour
/// `CLAUDE.md` asks for — a server that lies about being up is worse than one that refuses to
/// start. Skipping them here is skipping the host, not the protocol, so the skip lifts on a
/// platform that has the facility.
const NEEDS_A_KERNEL_FACILITY: &[(&str, &str)] = &[
    (
        "can",
        "SocketCAN needs the Linux kernel's AF_CAN address family, which macOS and Windows do \
         not have, and the examples name a `vcan0` interface someone has to create",
    ),
    (
        "m3ua",
        "M3UA's transport is SCTP, and macOS ships neither kernel support nor headers for it",
    ),
    (
        "ngap",
        "NGAP's transport is SCTP, and macOS ships neither kernel support nor headers for it",
    ),
];

/// How long one example gets to reach `Running`.
///
/// Generous on purpose: at `--test-threads=100` a bind contends with ninety-nine others, and a
/// deadline that is merely typical is how this repository's load-flakes were born.
const START_DEADLINE: Duration = Duration::from_secs(20);

struct Failure {
    protocol: String,
    mode: &'static str,
    detail: String,
}

fn hardware_skip_reason(protocol: &str) -> Option<&'static str> {
    let lower = protocol.to_lowercase();
    let matches = |table: &'static [(&'static str, &'static str)]| {
        table
            .iter()
            .find(|(prefix, _)| lower == *prefix || lower.starts_with(&format!("{prefix}_")))
            .map(|(_, reason)| *reason)
    };
    matches(NEEDS_HARDWARE_OR_AN_OS_OBJECT).or_else(|| {
        // On Linux these have their facility (a `vcan0` interface, and the `sctp` module),
        // so the skip is the host's and lifts there rather than being a standing exemption.
        let reason = matches(NEEDS_A_KERNEL_FACILITY)?;
        let present = cfg!(target_os = "linux")
            && (lower != "can" || std::path::Path::new("/sys/class/net/vcan0").exists());
        (!present).then_some(reason)
    })
}

/// The tool or system library this host lacks that the protocol's own dependency probe says
/// a start needs — the same check `server_startup` refuses on, so the protocol's refusal is
/// the correct behaviour and the skip is the host's. CI installs `protoc` and `capnp`, so there
/// gRPC, gRPC-Web, ConnectRPC and Cap'n Proto RPC are started rather than skipped.
fn missing_dependency(
    protocol: &dyn netget::llm::actions::protocol_trait::Server,
) -> Option<String> {
    let caps = netget::privilege::SystemCapabilities::detect();
    netget::protocol::dependencies::startup_blocker(&protocol.get_dependencies(), &caps)
        .map(|dep| format!("needs {}, which this host lacks", dep.name()))
}

/// Does this requirement block a start *on port 0*?
///
/// `PrivilegedPort` does not, and that is the whole reason this test overrides the port.
/// `server_startup.rs` enforces it only when the requested port is in `1..1024` — "port 0
/// means OS-assigned, which will always be unprivileged" — so a protocol whose only claim is
/// its default port is fully testable here. Skipping those would have cost this sweep 47 of
/// the 136 protocols it can reach, for a requirement that never fires.
fn blocks_an_unprivileged_start(requirement: &PrivilegeRequirement) -> bool {
    !matches!(
        requirement,
        PrivilegeRequirement::None | PrivilegeRequirement::PrivilegedPort(_)
    )
}

/// Turn one example into the form the management layer takes, or say why it cannot.
///
/// The example goes through `CommonAction::from_json` rather than being read field by field,
/// because that is the function the model's own answer goes through: it renames `base_stack`
/// to `protocol`, flattens an `args`/`arguments` wrapper, and converts the old
/// `script_inline`/`script_handles` pair. An example that only parses when read some other way
/// is an example the model cannot use.
fn form_from_example(example: &serde_json::Value) -> Result<ServerForm, String> {
    let action = CommonAction::from_json(example)
        .map_err(|e| format!("does not parse as a CommonAction: {e}"))?;

    let CommonAction::OpenServer {
        mac_address: _,
        interface: _,
        host: _,
        port: _,
        protocol,
        send_first,
        initial_memory,
        instruction,
        startup_params,
        event_handlers,
        scheduled_tasks,
        feedback_instructions,
        history,
        batching,
    } = action
    else {
        return Err("parses as some action other than open_server".to_string());
    };

    Ok(ServerForm {
        protocol,
        // See the module docs: the example's own port is not what is under test.
        port: Some(0),
        // The host is dropped rather than overridden, which is not the same thing. Every
        // protocol's `default_binding()` names its own loopback, and it is the loopback of the
        // right *family*: forcing 127.0.0.1 on DHCPv6 — which is IPv6-only and defaults to
        // `::1` — made it refuse to start, and that refusal was this test's bug, not the
        // example's. An example naming a LAN address is illustrating a deployment, not
        // asserting that address is bindable on whatever machine runs the suite.
        host: None,
        // `interface` is dropped with the privileged protocols that declare one; nothing that
        // reaches here needs a named interface.
        interface: None,
        mac_address: None,
        send_first,
        // `CommonAction` defaults a missing instruction to the empty string, and
        // `ServerForm::create` substitutes a default one for `None` — so an example carrying
        // no instruction must arrive as `Some("")` or the form quietly adds one.
        instruction: Some(instruction),
        initial_memory,
        startup_params,
        event_handlers,
        scheduled_tasks,
        feedback_instructions,
        history,
        batching,
    })
}

async fn start_and_stop(state: &AppState, form: ServerForm) -> Result<(), String> {
    let (tx, mut rx) = mpsc::unbounded_channel::<String>();
    // Drain: the status channel is unbounded and nothing here asserts on its text.
    tokio::spawn(async move { while rx.recv().await.is_some() {} });

    let id = match tokio::time::timeout(START_DEADLINE, form.create(state, tx)).await {
        Err(_) => return Err(format!("create() did not return within {START_DEADLINE:?}")),
        Ok(Err(e)) => return Err(format!("create() failed: {e}")),
        Ok(Ok(id)) => id,
    };

    let deadline = std::time::Instant::now() + START_DEADLINE;
    let outcome = loop {
        match state.get_server(id).await.map(|s| s.status) {
            Some(ServerStatus::Running) => break Ok(()),
            Some(ServerStatus::Error(e)) => break Err(format!("status Error({e})")),
            Some(ServerStatus::Stopped) => {
                break Err("status Stopped: it started and gave up".to_string())
            }
            None => break Err("the instance vanished from state before it reached Running".into()),
            Some(ServerStatus::Starting) => {}
        }
        if std::time::Instant::now() >= deadline {
            break Err(format!("still Starting after {START_DEADLINE:?}"));
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    };

    // Release the socket either way, so a later example is not told the port is in use by a
    // server this test forgot.
    state.remove_server(id).await;
    outcome
}

/// A skip entry that matches no compiled protocol is a skip nobody needs.
///
/// This is the same discipline the rest of the tree applies to a shrink-only baseline: an
/// exemption that outlives what it exempted reads to the next person as still necessary, and
/// it is how a coverage guard quietly stops guarding. The `usb` entry this file used to carry
/// was exactly that — it matched nothing, and all seven USB/IP servers start.
///
/// Only meaningful where the build compiles everything the list names.
#[test]
#[ignore = "a narrower build cannot tell a stale skip entry from an uncompiled protocol"]
fn every_skip_entry_names_a_protocol_that_exists() {
    let names: Vec<String> = registry()
        .all_protocols()
        .into_iter()
        .map(|(n, _)| n.to_lowercase())
        .collect();

    let mut stale = Vec::new();
    for (prefix, _) in NEEDS_HARDWARE_OR_AN_OS_OBJECT
        .iter()
        .chain(NEEDS_A_KERNEL_FACILITY)
    {
        let matched = names
            .iter()
            .any(|n| n == prefix || n.starts_with(&format!("{prefix}_")));
        if !matched {
            stale.push(*prefix);
        }
    }

    assert!(
        stale.is_empty(),
        "skip entr(ies) matching no compiled protocol: {stale:?}. Delete them — a skip that \
         exempts nothing still narrows this sweep the day someone adds a protocol whose name \
         happens to start with one of these."
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_startup_example_reaches_running() {
    let mock = MockOllamaServer::start(
        MockLlmBuilder::new()
            // Nothing here sends traffic, so nothing should reach the model. `expect_at_least(0)`
            // rather than a strict rule because a protocol that *does* consult the model while
            // starting must get an answer rather than a 500 that would look like a start failure.
            .on_any()
            .respond_with_actions(serde_json::json!([]))
            .expect_at_least(0)
            .build(),
    )
    .await
    .expect("mock ollama must start");

    let state = AppState::new_with_options(false, mock.base_url());
    state
        .set_llm_client(netget::llm::OllamaClient::new(mock.base_url()))
        .await;

    let mut skipped: Vec<(String, String)> = Vec::new();
    let mut failures: Vec<Failure> = Vec::new();
    let mut tested_protocols = 0usize;
    let mut tested_examples = 0usize;

    let mut protocols = registry().all_protocols();
    protocols.sort_by(|a, b| a.0.cmp(&b.0));

    for (name, protocol) in protocols {
        if let Some(reason) = hardware_skip_reason(&name) {
            skipped.push((name, reason.to_string()));
            continue;
        }
        if let Some(reason) = missing_dependency(protocol.as_ref()) {
            skipped.push((name, reason));
            continue;
        }
        let privilege = protocol.metadata().privilege_requirement;
        if blocks_an_unprivileged_start(&privilege) {
            skipped.push((
                name,
                format!("declares privilege_requirement {privilege:?}"),
            ));
            continue;
        }

        tested_protocols += 1;
        let examples = protocol.get_startup_examples();
        for (mode, example) in [
            ("llm_mode", &examples.llm_mode),
            ("script_mode", &examples.script_mode),
            ("static_mode", &examples.static_mode),
        ] {
            tested_examples += 1;
            let result = match form_from_example(example) {
                Err(detail) => Err(detail),
                Ok(form) => start_and_stop(&state, form).await,
            };
            if let Err(detail) = result {
                failures.push(Failure {
                    protocol: name.clone(),
                    mode,
                    detail,
                });
            }
        }
    }

    println!("\n=== startup examples spawned ===");
    println!(
        "protocols compiled into this build: {}",
        tested_protocols + skipped.len()
    );
    println!("protocols tested: {tested_protocols} ({tested_examples} examples)");
    println!("protocols skipped: {}", skipped.len());
    for (name, reason) in &skipped {
        println!("  SKIP {name}: {reason}");
    }

    assert!(
        tested_protocols > 0,
        "every compiled protocol was skipped, so this test asserted nothing. That is the \
         coverage failure this repository has already had twice — check the skip rules before \
         believing a green run."
    );

    if !failures.is_empty() {
        println!("\n=== examples that do not start ({}) ===", failures.len());
        for f in &failures {
            println!("  {} {}: {}", f.protocol, f.mode, f.detail);
        }
    }

    assert!(
        failures.is_empty(),
        "{} startup example(s) do not start. Each is text the model is shown and a person \
         pastes; fix the example (or the protocol it lies about), not this test.\n{}",
        failures.len(),
        failures
            .iter()
            .map(|f| format!("  {} {}: {}", f.protocol, f.mode, f.detail))
            .collect::<Vec<_>>()
            .join("\n")
    );
}
