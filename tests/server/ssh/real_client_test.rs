//! The OpenSSH `ssh` binary — the **second** independent client for the SSH server.
//!
//! The rest of this directory drives `ssh2`, the Rust binding to the C **libssh2**. That is a
//! genuine third-party implementation — and it is the one whose absence, once, made this
//! protocol's rating wrong in both directions inside six weeks. But it is still **one**
//! implementation, and a rating resting on one client is a rating resting on that client's
//! leniency: `etcd` and `grpc` were each Beta on a single client while emitting no gRPC
//! trailers at all, and `mysql` was Beta on `mysql_async` while offering an auth plugin MySQL
//! 9.0 had deleted. In all three the *error* path was accidentally correct and the tests
//! asserted on the error path.
//!
//! OpenSSH is a third implementation again — neither russh (which this server is built on) nor
//! libssh2 — and it is the one an operator actually types.
//!
//! # What OpenSSH adds over libssh2
//!
//! - **It picks the algorithms.** OpenSSH 10 offers its own KEX and host-key preference list
//!   and will simply refuse a server whose offer it cannot meet. libssh2's list is different
//!   and older, so a russh configuration acceptable to libssh2 and unacceptable to OpenSSH
//!   would look fine here until this test existed.
//! - **`exec` without a PTY.** `ssh host <command>` opens an exec channel with no terminal
//!   attached, so the bytes the server writes reach stdout **unmodified** — no line discipline
//!   in between. That is how the CRLF finding below became visible at all.
//! - **It enforces the channel state machine.** A `SSH_MSG_CHANNEL_CLOSE` for a channel it has
//!   already freed is a fatal protocol error to OpenSSH and a no-op to libssh2. See part 1
//!   below.
//! - **The exit status is the answer.** `$(ssh host cmd)` captures stdout and a script branches
//!   on `$?`. OpenSSH surfaces the SSH `exit-status` request as its own exit code, so the
//!   status the server requested is asserted rather than inferred.
//! - **A refusal it renders itself.** A denied authentication comes back as OpenSSH's own
//!   `Permission denied (publickey).` and exit 255.
//!
//! # What this client found, part 1: a double `SSH_MSG_CHANNEL_CLOSE` — **fixed**
//!
//! `ssh host <command>` failed with exit **255** about one run in five, *after* the command's
//! output and `exit-status 0` had already arrived intact. OpenSSH at `LogLevel=DEBUG2` says
//! exactly what happened:
//!
//! ```text
//! debug2: channel 0: rcvd eof
//! debug2: channel 0: rcvd close
//! debug2: channel 0: send close for remote id 2
//! debug1: channel 0: free: client-session, nchannels 1
//! channel_by_id: 0: bad id: channel free
//! Disconnecting 127.0.0.1 port N: oclose packet referred to nonexistent channel 0
//! ```
//!
//! RFC 4254 §5.3 lets each party send `SSH_MSG_CHANNEL_CLOSE` once. NetGet sent two:
//! `exec_request` sends exit-status + EOF + CLOSE as soon as the answer is ready, and then the
//! client's *own* EOF arrives and `channel_eof` sent a second CLOSE. The race is whether the
//! client has garbage-collected the channel by then — if not, it is a
//! `channel 0: protocol error: close rcvd twice` on stderr and the session survives; if it
//! has, the CLOSE names a channel that no longer exists and OpenSSH disconnects.
//!
//! libssh2 ignores the second CLOSE, so nothing in the rest of this directory could see it.
//! `SshHandler::close_channel_once` is the fix, and the `stderr` assertion below is the guard.
//! Measured: **4 failures in 20 runs before, 0 in 25 after.**
//!
//! # What this client found, part 2: CRLF on the exec path — **not fixed**
//!
//! **NetGet translates `\n` to `\r\n` on the exec path, and a real `sshd` does not.**
//! `SshServerHandler::normalize_line_endings` is applied to every shell response
//! (`src/server/ssh/mod.rs`), including the one-shot `exec_request` path, where no PTY exists.
//! Real `sshd` never translates: the CRLF an interactive session shows comes from the *pty's*
//! `ONLCR`, not from the server. So
//!
//! ```text
//! ssh netget@host 'cat /etc/hostname' | xxd
//! ```
//!
//! returns `…\r\n` here and `…\n` against OpenSSH sshd, and the common `OUT=$(ssh host cmd)`
//! leaves a stray `\r` at the end of `$OUT`. Nothing in `ssh2`'s tests could see this: they
//! compare the output against a string the same test wrote, so `\r\n` on both sides agrees
//! with itself.
//!
//! This is **asserted as it behaves**, not as it ought to: the assertion below names the CRLF
//! explicitly and says why, so that a fix changes a test that describes the defect rather than
//! silently satisfying one that never noticed. The server is not changed here — `pty_request`
//! is not handled at all in `mod.rs`, so the honest fix (translate only when a PTY was
//! requested on that channel) is a change to the channel bookkeeping, not a one-line edit, and
//! it belongs with whoever owns that.
//!
//! # Non-vacuity: what was broken, and what OpenSSH then printed
//!
//! Verified by breaking the server and re-running the same commands.
//!
//! 1. **The auth decision inverted** — `SshServerHandler::llm_auth_decision`'s `Ok(true)`
//!    branch made to return `Ok(false)`, so the model's `allowed: true` no longer admitted
//!    anyone. OpenSSH printed `netget@127.0.0.1: Permission denied (publickey).` and exited
//!    **255**, and the test failed on the session it expected to succeed.
//! 2. **The exec exit status** made `69` unconditionally in `exec_request`. The command output
//!    still arrived intact on stdout, so every byte-level assertion still passed; only the exit
//!    code changed, and OpenSSH reported **69**. A test that read stdout and ignored `$?` would
//!    have passed against it — which is the whole point of asserting on the status.
//!
//! Both were reverted. (The one change to `src/server/ssh/` that stands is
//! `close_channel_once`, which is the fix for part 1 above, not a break.)
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features ssh \
//!       --test server -- server::ssh::real_client --test-threads=8

use crate::helpers::{self, E2EResult, NetGetConfig};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;
use tokio::time::timeout;

/// What the model prints for the one command this test runs.
///
/// Two lines and no trailing blank, so that a server which dropped a line, doubled one, or
/// mangled the separator fails on the content rather than on a length.
const COMMAND_OUTPUT: &str = "netget-demo\nkernel 6.11.0-netget\n";

/// Fail — never skip — unless the OpenSSH client tools exist, and say which version.
///
/// A `println!("SKIP: ssh is not installed")` and `Ok(())` is a silent pass on every runner
/// without them, and a maturity rating resting on a test like that rests on nothing wherever
/// the suite actually runs (`tests/server/npm/e2e_test.rs` states the rule in its own words).
async fn require_openssh() -> E2EResult<String> {
    // `ssh -V` writes its banner to stderr and exits 0.
    let out = timeout(
        Duration::from_secs(30),
        Command::new("ssh").arg("-V").stdin(Stdio::null()).output(),
    )
    .await
    .map_err(|_| "`ssh -V` did not finish within 30s")?;

    let version = match out {
        Ok(out) if out.status.success() => format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout).trim(),
            String::from_utf8_lossy(&out.stderr).trim()
        ),
        Ok(out) => {
            return Err(format!(
                "`ssh -V` exited {}: this test's whole point is driving the real OpenSSH \
                 client against NetGet's SSH server",
                out.status
            )
            .into())
        }
        Err(e) => {
            return Err(format!(
                "the OpenSSH client is not available ({e}): this test drives the real `ssh` \
                 binary, which is the SECOND independent client this protocol's rating rests \
                 on, and skipping it would leave that rating resting on libssh2 alone. Install \
                 it with `brew install openssh` (macOS) or \
                 `apt-get install -y openssh-client` (Debian/Ubuntu)."
            )
            .into())
        }
    };

    // `ssh-keygen` ships with the same package, and this test needs it to make an identity.
    match timeout(
        Duration::from_secs(30),
        Command::new("ssh-keygen")
            .arg("-?")
            .stdin(Stdio::null())
            .output(),
    )
    .await
    {
        // `-?` is an unknown option: ssh-keygen prints its usage and exits non-zero. That it
        // ran at all is the thing being checked, so the status is deliberately ignored.
        Ok(Ok(_)) => Ok(version),
        Ok(Err(e)) => Err(format!(
            "`ssh-keygen` is not available ({e}), so this test cannot create the identity it \
             authenticates with. It ships with the OpenSSH client package."
        )
        .into()),
        Err(_) => Err("`ssh-keygen -?` did not finish within 30s".into()),
    }
}

/// Create an ed25519 identity for this test and return the private key's path.
///
/// A fresh key in a temporary directory rather than anything of the operator's: the server
/// accepts any public key the model approves (it decides on the username alone), so the key's
/// only job is to let OpenSSH complete `publickey` without a terminal.
async fn make_identity(dir: &Path) -> E2EResult<PathBuf> {
    let key = dir.join("id_ed25519");
    let out = timeout(
        Duration::from_secs(60),
        Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-C", "netget-e2e"])
            .arg("-f")
            .arg(&key)
            .stdin(Stdio::null())
            .output(),
    )
    .await
    .map_err(|_| "ssh-keygen did not finish within 60s")??;
    if !out.status.success() {
        return Err(format!(
            "ssh-keygen failed ({}):\n{}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        )
        .into());
    }
    Ok(key)
}

/// Run `ssh <user>@127.0.0.1 <command>` and return (stdout, stderr, exit code).
///
/// Every option here exists to make the run reproducible and non-interactive:
///
/// - `-F /dev/null` ignores the operator's `~/.ssh/config`, the way `psql -X` ignores
///   `~/.psqlrc`. Without it a local `Host *` block can change what is asserted.
/// - `StrictHostKeyChecking=no` + `UserKnownHostsFile=/dev/null` +
///   `GlobalKnownHostsFile=/dev/null`: the server generates a fresh ed25519 host key on every
///   start, so it is unknown by construction and would otherwise prompt.
/// - `IdentitiesOnly=yes` + `IdentityAgent=none` + `PreferredAuthentications=publickey`: only
///   the key made above is offered. Without this, a running `ssh-agent`'s keys are tried first
///   and each one is a separate `ssh_auth` event.
/// - `BatchMode=yes` turns every prompt into a failure. OpenSSH will not read a password
///   without a TTY, which is why this test authenticates with a key rather than a password.
///
/// `tokio::process::Command`, not `std::process`: `#[tokio::test]` runs a current-thread
/// runtime, so a blocking `output()` parks the only worker — which is also the task draining
/// the netget child's pipes. They fill, netget blocks inside a log call while it is serving
/// this very session, and ssh times out against a server that is behaving perfectly.
async fn ssh_exec(
    key: &Path,
    port: u16,
    user: &str,
    command: &str,
) -> E2EResult<(Vec<u8>, String, i32)> {
    let out = timeout(
        Duration::from_secs(90),
        Command::new("ssh")
            .args(["-F", "/dev/null"])
            .arg("-i")
            .arg(key)
            .args(["-o", "IdentitiesOnly=yes"])
            .args(["-o", "IdentityAgent=none"])
            .args(["-o", "PreferredAuthentications=publickey"])
            .args(["-o", "StrictHostKeyChecking=no"])
            .args(["-o", "UserKnownHostsFile=/dev/null"])
            .args(["-o", "GlobalKnownHostsFile=/dev/null"])
            .args(["-o", "BatchMode=yes"])
            .args(["-o", "ConnectTimeout=20"])
            // Keeps "Warning: Permanently added ..." out of stderr so a refusal is the only
            // thing there.
            .args(["-o", "LogLevel=ERROR"])
            .args(["-p", &port.to_string()])
            .arg(format!("{user}@127.0.0.1"))
            .arg(command)
            .stdin(Stdio::null())
            .output(),
    )
    .await
    .map_err(|_| format!("ssh {user}@127.0.0.1 {command:?} did not finish within 90s"))??;

    Ok((
        out.stdout,
        String::from_utf8_lossy(&out.stderr).to_string(),
        out.status.code().unwrap_or(-1),
    ))
}

/// One netget server; two OpenSSH sessions against it — one admitted, one refused.
///
/// LLM calls: 1 startup + 2 auth decisions (one per session; OpenSSH offers exactly one key
/// because of `IdentitiesOnly`) + 1 exec command = **4**.
#[tokio::test]
async fn openssh_completes_a_session_against_the_ssh_server() -> E2EResult<()> {
    let version = require_openssh().await?;
    println!("\n=== E2E: the real OpenSSH client ({version}) ===");

    let keydir = tempfile::tempdir()?;
    let key = make_identity(keydir.path()).await?;

    let prompt = "Start an SSH server on port {AVAILABLE_PORT}. Let the user netget in and \
         refuse everyone else. Answer shell commands.";

    let config = NetGetConfig::new_no_scripts(prompt).with_mock(|mock| {
        mock.on_instruction_containing("SSH server")
            .respond_with_actions(serde_json::json!([{
                "type": "open_server",
                "port": 0,
                "base_stack": "SSH",
                "instruction": "Admit the user netget; refuse every other username"
            }]))
            .expect_calls(1)
            .and()
            // ONE rule branching on the username. Two rules on `ssh_auth` would be
            // first-match-wins: the first would answer both logins and the second would report
            // zero calls.
            .on_event("ssh_auth")
            .respond_with_actions_from_event(|event| {
                let user = event
                    .get("username")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default();
                serde_json::json!([{
                    "type": "ssh_auth_decision",
                    "allowed": user == "netget"
                }])
            })
            .expect_calls(2)
            .and()
            .on_event("ssh_shell_command")
            .respond_with_actions(serde_json::json!([{
                "type": "ssh_shell_response",
                "response": COMMAND_OUTPUT
            }]))
            .expect_calls(1)
            .and()
    });

    let server = timeout(
        Duration::from_secs(120),
        helpers::start_netget_server(config),
    )
    .await
    .map_err(|_| "netget startup timed out")??;
    helpers::wait_for_server_listening(&server, Duration::from_secs(30)).await?;
    let port = server.port;
    println!("  SSH server on port {port}");

    // ---- Session 1: admitted, one command, its output and its exit status ----
    let (stdout, stderr, code) = ssh_exec(&key, port, "netget", "cat /etc/hostname").await?;
    println!(
        "  ssh netget@ -> exit={code}\n  stdout={:?}\n  stderr={stderr}",
        String::from_utf8_lossy(&stdout)
    );

    assert_eq!(
        code, 0,
        "OpenSSH exited {code} rather than completing the session and reporting the server's \
         exit-status of 0.\nstderr:\n{stderr}"
    );
    assert!(
        !stderr.contains("Permission denied"),
        "OpenSSH was refused on the session the model admitted.\nstderr:\n{stderr}"
    );
    // The regression guard for the double `SSH_MSG_CHANNEL_CLOSE` (see this file's module
    // docs, part 1). At `LogLevel=ERROR` a clean session prints nothing at all here, so any
    // channel-level complaint is the server's doing. The surviving-but-noisy form of that bug
    // is `channel 0: protocol error: close rcvd twice`; the fatal form disconnects and is
    // caught by the exit-status assertion above, but only about one run in five — so this is
    // the assertion that fails every time rather than sometimes.
    assert!(
        !stderr.contains("protocol error") && !stderr.contains("nonexistent channel"),
        "OpenSSH reported a channel protocol error. RFC 4254 §5.3 allows one \
         SSH_MSG_CHANNEL_CLOSE per party; a second one is fatal once the client has freed the \
         channel.\nstderr:\n{stderr}"
    );

    // The bytes, exactly as they came off the exec channel. No PTY is attached to
    // `ssh host <command>`, so nothing between the server and this buffer can have changed
    // them — which is what makes the CRLF below the server's doing.
    let text = String::from_utf8(stdout.clone())
        .map_err(|e| format!("OpenSSH received non-UTF-8 output: {e}"))?;

    // What NetGet actually sends today. `normalize_line_endings` runs on the exec path too,
    // where a real sshd would not translate at all (the CRLF an interactive session shows is
    // the pty's ONLCR, not the server's). Asserted as-is, and named, so that fixing it changes
    // a test that describes the behaviour rather than quietly satisfying one that never
    // looked. See this file's module docs.
    assert_eq!(
        text,
        COMMAND_OUTPUT.replace('\n', "\r\n"),
        "the bytes OpenSSH received are not the model's output with NetGet's CRLF translation \
         applied. NOTE: the CRLF itself is a deviation from OpenSSH sshd, which does not \
         translate on an exec channel; it is asserted here because it is what the server does."
    );
    // Stated separately so a future reader cannot miss it, and so a fix fails loudly here
    // rather than inside the equality above.
    assert!(
        text.contains("\r\n"),
        "no CRLF in the exec output — if NetGet stopped translating line endings on the exec \
         path, that is a FIX (it now matches OpenSSH sshd) and this test should be updated to \
         expect COMMAND_OUTPUT verbatim, along with the note in the module docs."
    );
    assert!(
        text.contains("netget-demo") && text.contains("kernel 6.11.0-netget"),
        "OpenSSH did not receive both lines the model wrote: {text:?}"
    );

    // ---- Session 2: the refusal, as OpenSSH renders it ----
    let (deny_stdout, deny_stderr, deny_code) =
        ssh_exec(&key, port, "intruder", "cat /etc/hostname").await?;
    println!("  ssh intruder@ -> exit={deny_code}\n  stderr={deny_stderr}");

    assert_eq!(
        deny_code, 255,
        "OpenSSH exited {deny_code} for a login the model refused; 255 is its own code for a \
         connection that never got as far as running anything.\nstderr:\n{deny_stderr}"
    );
    assert!(
        deny_stderr.contains("Permission denied"),
        "OpenSSH did not render the refusal.\nstderr:\n{deny_stderr}"
    );
    assert!(
        deny_stdout.is_empty(),
        "OpenSSH received command output for a login the model refused: {:?}",
        String::from_utf8_lossy(&deny_stdout)
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    println!("  [TEST] ✓ OpenSSH completed a real session\n");
    Ok(())
}
