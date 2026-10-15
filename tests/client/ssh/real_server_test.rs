//! The SSH client against a real OpenSSH **`sshd`** — the evidence its maturity rating rests on.
//!
//! NetGet's SSH client is `russh` (Rust). The server here is OpenSSH's `sshd` (C), run
//! unprivileged per test from an `sshd_config` in the guard's temporary directory: loopback
//! only, a host key and an authorized user key generated there with `ssh-keygen`, public-key
//! authentication only, no PAM. An unprivileged `sshd` can only log in the user it runs as, so
//! the client authenticates as the current OS user with the generated key — through the
//! `private_key_path` startup parameter. Nothing on the wire was written by this repository
//! except NetGet.
//!
//! Condition 4 of the client bar — the client acts on the model's answer, asserted on the wire
//! — is asserted from the server's side: the commands the model chose ran on the server and
//! wrote a file in the temp dir, one line of it built from the output the model was shown, and
//! `sshd`'s own log records the public-key login and the model's disconnect.
//!
//! **No test here skips.** A missing `sshd` or `ssh-keygen` fails with the install command.
//!
//! LLM calls: 12 across the file (4 + 1 + 7). All mocked and in-process.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features ssh --test client -- ssh::real_server_test --test-threads=100

use crate::helpers::real_server::{InstallHint, RealServer};
use crate::helpers::*;
use serde_json::json;
use std::time::Duration;

const SSHD: InstallHint = InstallHint {
    brew: "openssh (macOS ships /usr/sbin/sshd)",
    apt: "openssh-server",
};
const SSH_KEYGEN: InstallHint = InstallHint {
    brew: "openssh (macOS ships /usr/bin/ssh-keygen)",
    apt: "openssh-client",
};

/// The user the test process runs as — the only account an unprivileged `sshd` can log in.
pub(super) fn current_user() -> String {
    // SAFETY: getpwuid returns a pointer into static storage or null; it is read immediately,
    // before anything else in this thread can call it again.
    unsafe {
        let pw = libc::getpwuid(libc::getuid());
        if !pw.is_null() {
            return std::ffi::CStr::from_ptr((*pw).pw_name)
                .to_string_lossy()
                .into_owned();
        }
    }
    std::env::var("USER").expect("neither getpwuid nor $USER names the current user")
}

/// A throwaway `sshd`: host key, user key and a stranger's key made with `ssh-keygen` in the
/// guard's temp dir, the user key authorised, `sshd -D -e` on 127.0.0.1 only. `StrictModes no`
/// because the temp dir's permissions are the test harness's, not a home directory's; `UsePAM
/// no` and no password or keyboard-interactive auth, because an unprivileged sshd can check
/// neither.
pub(super) async fn start_sshd() -> E2EResult<RealServer> {
    start_sshd_with_subsystem("internal-sftp", "").await
}
pub(super) async fn start_sshd_with_subsystem(
    subsystem: &str,
    script: &str,
) -> E2EResult<RealServer> {
    let keygen = |name: &str| {
        [
            "-q".to_string(),
            "-t".to_string(),
            "ed25519".to_string(),
            "-N".to_string(),
            String::new(),
            "-C".to_string(),
            format!("netget-{name}"),
            "-f".to_string(),
            format!("{{dir}}/{name}"),
        ]
    };
    RealServer::builder("sshd", SSHD)
        .config_file(
            "sshd_config",
            &format!(
                "ListenAddress 127.0.0.1\n\
             Port {{port}}\n\
             HostKey {{dir}}/host_key\n\
             PidFile {{dir}}/sshd.pid\n\
             AuthorizedKeysFile {{dir}}/authorized_keys\n\
             StrictModes no\n\
             UsePAM no\n\
             PasswordAuthentication no\n\
             KbdInteractiveAuthentication no\n\
             PubkeyAuthentication yes\n\
             LogLevel VERBOSE\n\
             Subsystem sftp {subsystem}\n"
            ),
        )
        .config_file("sftp_peer.py", script)
        .setup_command("ssh-keygen", SSH_KEYGEN, keygen("host_key"))
        .setup_command("ssh-keygen", SSH_KEYGEN, keygen("user_key"))
        .setup_command("ssh-keygen", SSH_KEYGEN, keygen("stranger_key"))
        .setup_command(
            "cp",
            SSH_KEYGEN,
            ["{dir}/user_key.pub", "{dir}/authorized_keys"],
        )
        // sshd re-executes itself and insists on an absolute path; the helper spawns the
        // resolved path, so argv[0] is absolute.
        .args(["-D", "-e", "-f", "{dir}/sshd_config"])
        .ready_when_log_matches(r"Server listening on 127\.0\.0\.1 port \d+")
        .start()
        .await
}

fn read(path: &std::path::Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| format!("<unreadable: {e}>"))
}

/// Public-key login, a command the model chose, a second command built from the first one's
/// stdout, stderr and exit status, and a disconnect.
///
/// 1. `ssh_connected` (matched on the username) → a command that writes `hello from the model`
///    to `out.txt` and to stdout, writes `a warning` to stderr, and exits 3.
/// 2. Its output (matched on `exit_code` 3, the stdout and the stderr) → a command appending
///    `the model saw: <stdout> (exit <code>, stderr: <stderr>)`, all three taken from the event.
/// 3. That command's output (`exit_code` 0) → `disconnect`.
///
/// Then `out.txt` must hold exactly the two lines, and sshd's log must show the public-key
/// login for this user and the client's disconnect.
///
/// LLM calls: 4 (startup, ssh_connected, two ssh_output_received).
#[tokio::test]
async fn ssh_client_runs_the_models_commands_against_openssh() -> E2EResult<()> {
    let server = start_sshd().await?;
    let result = runs_the_models_commands(&server).await;
    server.with_log(result)
}

async fn runs_the_models_commands(server: &RealServer) -> E2EResult<()> {
    let addr = server.addr();
    let user = current_user();
    let key = server.dir().join("user_key").display().to_string();
    let out = server.dir().join("out.txt");
    let out_s = out.display().to_string();
    let first =
        format!("echo 'hello from the model' | tee '{out_s}'; echo 'a warning' >&2; exit 3");
    let out_for_follow_up = out_s.clone();
    let user_for_rule = user.clone();
    let user_for_open = user.clone();

    let config = NetGetConfig::new(format!(
        "Connect to SSH at {addr}. SSH-REAL-SERVER-STARTUP-TURN."
    ))
    .with_mock(move |mock| {
        mock.on_instruction_containing("SSH-REAL-SERVER-STARTUP-TURN")
            .respond_with_actions(json!([{
                "type": "open_client",
                "protocol": "SSH",
                "remote_addr": addr,
                "startup_params": {"username": user_for_open, "private_key_path": key},
                "instruction": "Write a greeting to a file, record what the command reported, \
                                then disconnect."
            }]))
            .expect_calls(1)
            .and()
            .on_event("ssh_connected")
            .and_event_data_contains("username", &user_for_rule)
            .respond_with_actions(json!([{"type": "execute_command", "command": first}]))
            .expect_calls(1)
            .and()
            .on_event("ssh_output_received")
            .and_event_data_contains("exit_code", "3")
            .and_event_data_contains("output", "hello from the model")
            .and_event_data_contains("stderr", "a warning")
            .respond_with_actions_from_event(move |event| {
                json!([{
                    "type": "execute_command",
                    "command": format!(
                        "echo 'the model saw: {} (exit {}, stderr: {})' >> '{}'",
                        event["output"].as_str().unwrap_or("").trim(),
                        event["exit_code"],
                        event["stderr"].as_str().unwrap_or("").trim(),
                        out_for_follow_up
                    )
                }])
            })
            .expect_calls(1)
            .and()
            .on_event("ssh_output_received")
            .and_event_data_contains("command", "the model saw")
            .and_event_data_contains("exit_code", "0")
            .respond_with_actions(json!([{"type": "disconnect"}]))
            .expect_calls(1)
            .and()
    });

    let client = start_netget_client(config).await?;
    client.wait_for_mocks(30).await;
    client.verify_mocks().await?;

    assert_eq!(
        read(&out),
        "hello from the model\nthe model saw: hello from the model (exit 3, stderr: a warning)\n",
        "sshd must have run both of the model's commands, the second built from the first's \
         stdout, exit status and stderr"
    );
    server
        .wait_for_log(
            &format!("Accepted publickey for {user}"),
            Duration::from_secs(10),
        )
        .await?;
    server
        .wait_for_log(
            "Received disconnect from 127.0.0.1",
            Duration::from_secs(10),
        )
        .await?;

    client.stop().await?;
    Ok(())
}

/// A key the server does not know is refused, the client says so, and the model is never asked
/// what to run.
///
/// LLM calls: 1 (startup). No `ssh_connected` rule exists, so a connect event would be an
/// unmatched request and fail the mock.
#[tokio::test]
async fn ssh_client_is_refused_with_an_unauthorised_key_by_openssh() -> E2EResult<()> {
    let server = start_sshd().await?;
    let result = is_refused_with_an_unauthorised_key(&server).await;
    server.with_log(result)
}

async fn is_refused_with_an_unauthorised_key(server: &RealServer) -> E2EResult<()> {
    let addr = server.addr();
    let user = current_user();
    let key = server.dir().join("stranger_key").display().to_string();
    let config = NetGetConfig::new(format!(
        "Connect to SSH at {addr}. SSH-STRANGER-STARTUP-TURN."
    ))
    .with_mock(move |mock| {
        mock.on_instruction_containing("SSH-STRANGER-STARTUP-TURN")
            .respond_with_actions(json!([{
                "type": "open_client",
                "protocol": "SSH",
                "remote_addr": addr,
                "startup_params": {"username": user, "private_key_path": key},
                "instruction": "Run whoami."
            }]))
            .expect_calls(1)
            .and()
    });

    let client = start_netget_client(config).await?;
    client
        .wait_for_any(&["SSH authentication failed"], 30)
        .await;
    assert!(
        client.output_contains("SSH authentication failed").await,
        "the client must report that sshd refused the key. Output: {:?}",
        client.get_output().await
    );
    client.wait_for_mocks(30).await;
    client.verify_mocks().await?;
    assert!(
        !server.log().contains("Accepted publickey"),
        "sshd must not have accepted a key it was never given"
    );

    client.stop().await?;
    Ok(())
}

/// The follow-up chain is bounded, counted on the server.
///
/// The model answers every command's output with another command appending `tick` to a file.
/// The connect event's command runs at depth 0 and each output's answer one level deeper; the
/// output at `MAX_FOLLOWUP_DEPTH` (4) is shown to the model and its answer dropped. So the model
/// sees five outputs and the file holds exactly five ticks — written by sshd's shell, not by
/// anything NetGet reports.
///
/// LLM calls: 7 (startup, ssh_connected, five ssh_output_received).
#[tokio::test]
async fn ssh_client_follow_up_chain_is_bounded_against_openssh() -> E2EResult<()> {
    let server = start_sshd().await?;
    let result = follow_up_chain_is_bounded(&server).await;
    server.with_log(result)
}

async fn follow_up_chain_is_bounded(server: &RealServer) -> E2EResult<()> {
    let addr = server.addr();
    let user = current_user();
    let key = server.dir().join("user_key").display().to_string();
    let ticks = server.dir().join("ticks.txt");
    let tick = json!([{
        "type": "execute_command",
        "command": format!("echo tick >> '{}'", ticks.display())
    }]);
    let tick_again = tick.clone();

    let config = NetGetConfig::new(format!("Connect to SSH at {addr}. SSH-BOUND-STARTUP-TURN."))
        .with_mock(move |mock| {
            mock.on_instruction_containing("SSH-BOUND-STARTUP-TURN")
                .respond_with_actions(json!([{
                    "type": "open_client",
                    "protocol": "SSH",
                    "remote_addr": addr,
                    "startup_params": {"username": user, "private_key_path": key},
                    "instruction": "Tick forever."
                }]))
                .expect_calls(1)
                .and()
                .on_event("ssh_connected")
                .respond_with_actions(tick)
                .expect_calls(1)
                .and()
                .on_event("ssh_output_received")
                .and_event_data_contains("exit_code", "0")
                .respond_with_actions(tick_again)
                .expect_calls(5)
                .and()
        });

    let client = start_netget_client(config).await?;
    client.wait_for_mocks(30).await;
    client.verify_mocks().await?;

    assert_eq!(
        read(&ticks),
        "tick\n".repeat(5),
        "sshd must have run exactly the connect event's command plus four bounded follow-ups"
    );

    client.stop().await?;
    Ok(())
}
