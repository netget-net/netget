//! Mercurial against the real `hg` client (7.2.4).
//!
//! # What this proves
//!
//! `tests/server/mercurial/e2e_test.rs` drives the metadata commands with `reqwest`, which the
//! root `AGENTS.md` rules out as evidence on its own: a generic HTTP client proves an HTTP
//! server answered, not that the protocol layered on top is right. These tests replace the
//! client with the real thing:
//!
//! * **The handshake.** `hg debugcapabilities <url>` runs `httppeer.performhandshake`, which
//!   requires `Content-Type: application/mercurial-*` before it treats us as a repository, and
//!   parses the capability list through hg's own parser.
//! * **Discovery arrives batched.** hg 7.x sends `heads` and `known` as one `batch` request
//!   whenever it has both to send, advertised or not, so the clone below also proves the batch
//!   framing (`;`-joined, `:`-escaped answers).
//! * **A clone of a described history.** A static handler answers every event with one
//!   `hg_repository` action — five commits with authors, dates, a multi-line message, a named
//!   branch, a merge, a removal, an executable file, an empty file and a file whose content
//!   begins with filelog's metadata marker. `hg clone` runs discovery (`heads`, `known`) and
//!   `getbundle`, applies our changegroup, and then **`hg verify`** re-reads every revlog and
//!   checks every node against `sha1(p1, p2, text)` — the check that our changelog, manifest
//!   and filelog texts are byte-for-byte what Mercurial would have written. `hg cat`, `hg log`
//!   and `hg manifest -v` then assert the exact bytes and history the action described.
//! * **An incremental pull.** `hg clone -r 1` resolves a revision through `lookup` and receives a
//!   partial changegroup; `hg pull` then asks `known` about the client's own head and receives
//!   only what is missing, with deltas whose base is a revision the client already holds.
//! * **A refused history** reaches the client as Mercurial's own error (`application/hg-error`,
//!   printed as `abort: remote error:`), and the reason stays in the server log.
//!
//! # Not circular
//!
//! `src/server/mercurial/` is hand-written over hyper and links no Mercurial library. `hg` is a
//! Python program that shares no code with it.

use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
use std::path::Path;
use std::time::Duration;

/// Fail — never skip — when hg is missing.
fn require_hg() -> E2EResult<()> {
    match std::process::Command::new("hg").arg("--version").output() {
        Ok(out) if out.status.success() => {
            println!(
                "{}",
                String::from_utf8_lossy(&out.stdout)
                    .lines()
                    .next()
                    .unwrap_or("hg present")
            );
            Ok(())
        }
        Ok(out) => Err(format!(
            "`hg --version` exited {}: this test's whole point is driving the real Mercurial \
             client",
            out.status
        )
        .into()),
        Err(e) => Err(format!(
            "hg not available ({e}): this test's whole point is driving the real Mercurial \
             client against NetGet's server, and skipping it would leave Mercurial's evidence \
             resting on reqwest, which cannot tell a Mercurial repository from a web page. \
             Install it with `brew install mercurial` (or your distribution's mercurial \
             package)."
        )
        .into()),
    }
}

/// Output of one `hg` run.
struct HgRun {
    success: bool,
    stdout: String,
    combined: String,
}

/// Run `hg` with the invoking user's configuration kept out: an extension or a UI setting in
/// `~/.hgrc` could change what these tests parse.
async fn hg(args: &[&str], cwd: Option<&Path>) -> E2EResult<HgRun> {
    let mut cmd = tokio::process::Command::new("hg");
    cmd.args(args)
        .env("HGRCPATH", "")
        .env("HGPLAIN", "1")
        .env("HGENCODING", "utf-8")
        .kill_on_drop(true);
    if let Some(dir) = cwd {
        cmd.current_dir(dir);
    }
    let output = tokio::time::timeout(Duration::from_secs(60), cmd.output())
        .await
        .map_err(|_| format!("`hg {}` did not finish within 60s", args.join(" ")))??;
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let combined = format!("{}{}", stdout, String::from_utf8_lossy(&output.stderr));
    println!(
        "--- hg {} (exit {}) ---\n{}",
        args.join(" "),
        output.status,
        combined
    );
    Ok(HgRun {
        success: output.status.success(),
        stdout,
        combined,
    })
}

/// `hg` that must succeed; returns stdout.
async fn hg_ok(args: &[&str], cwd: Option<&Path>) -> E2EResult<String> {
    let run = hg(args, cwd).await?;
    if !run.success {
        return Err(format!("`hg {}` failed:\n{}", args.join(" "), run.combined).into());
    }
    Ok(run.stdout)
}

/// The history every clone test serves.
fn lab_history() -> serde_json::Value {
    serde_json::json!({
        "type": "hg_repository",
        "commits": [
            {
                "id": "init",
                "author": "Ada Lovelace <ada@example.com>",
                "date": "2026-10-01T09:00:00+02:00",
                "message": "Initial commit",
                "files": [
                    {"path": "README", "content": "Hello from NetGet\n"},
                    {"path": "src/main.py", "content": "print('hello')\n", "executable": true},
                    // Begins with filelog's metadata marker, so the server must wrap it in an
                    // empty metadata block or hg would read the first line as metadata.
                    {"path": "notes/meta.txt", "content": "\u{1}\nlooks like metadata\n"}
                ]
            },
            {
                "id": "docs",
                "author": "Grace Hopper <grace@example.com>",
                "date": 1790000000,
                // Trailing whitespace and blank lines: stored as changelog.stripdesc stores it.
                "message": "Expand the README\n\nThe body explains why.  \n\n",
                "files": [
                    {"path": "README", "content": "Hello from NetGet\nServed over hg.\n"}
                ]
            },
            {
                "id": "stable-fix",
                "parents": ["init"],
                "branch": "stable",
                "message": "Fix on stable",
                "files": [{"path": "fix.txt", "content": "fixed\n"}],
                "removed": ["notes/meta.txt"]
            },
            {
                "id": "merge",
                "parents": ["docs", "stable-fix"],
                "author": "Ada Lovelace <ada@example.com>",
                "date": "2026-10-03T12:00:00-05:00",
                "message": "Merge stable into default"
            },
            {
                "id": "empty",
                "message": "Add an empty file",
                "files": [{"path": "EMPTY", "content": ""}]
            }
        ]
    })
}

/// A NetGet Mercurial server whose every event is answered by one static `hg_repository`
/// action: one LLM call (startup), none per request.
fn static_history_config(history: serde_json::Value) -> NetGetConfig {
    NetGetConfig::new("listen on port {AVAILABLE_PORT} via mercurial. Serve the lab repository")
        .with_mock(move |mock| {
            mock.on_instruction_containing("via mercurial")
                .respond_with_actions(serde_json::json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "Mercurial",
                    "instruction": "Serve the lab repository",
                    "event_handlers": [{
                        "event_pattern": "*",
                        "handler": {"type": "static", "actions": [history.clone()]}
                    }]
                }]))
                .expect_calls(1)
                .and()
        })
}

#[tokio::test]
async fn test_mercurial_handshake_against_real_hg_client() -> E2EResult<()> {
    println!("\n=== E2E Test: real `hg` performs the wire-protocol handshake ===");
    require_hg()?;

    let prompt = "listen on port {AVAILABLE_PORT} via mercurial. Serve the lab repository";

    let config = NetGetConfig::new_no_scripts(prompt).with_mock(|mock| {
        mock
            // The model is deliberately asked for a GENEROUS list including capabilities the
            // server cannot honour. `sanitize_capabilities` must strip them back to the ones
            // that are actually implemented, and the real client below must then see exactly
            // those — which is the assertion that matters, because advertising `unbundle` or
            // `pushkey` would invite a push, and `bundle2` a format this server never speaks.
            .on_event("hg_capabilities")
            .respond_with_actions(serde_json::json!([{
                "type": "hg_capabilities",
                "capabilities": [
                    "branchmap", "getbundle", "listkeys",
                    "lookup", "known", "batch", "unbundle", "pushkey", "bundle2=HG20"
                ]
            }]))
            .expect_calls(1)
            .and()
            .on_instruction_containing("via mercurial")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "Mercurial",
                    "instruction": "Serve the lab repository"
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let server = start_netget_server(config).await?;
    println!("Mercurial server on 127.0.0.1:{}", server.port);

    let url = format!("http://127.0.0.1:{}/lab", server.port);
    let run = hg(&["debugcapabilities", &url], None).await?;
    let out = run.combined;

    assert!(
        run.success,
        "the real hg client could not complete the Mercurial handshake against NetGet:\n{out}"
    );

    // hg only prints a capabilities block after `parsev1commandresponse` has accepted the
    // reply — which requires `Content-Type: application/mercurial-*`. A plain `text/plain`
    // body with identical bytes is rejected there, so this line is really an assertion about
    // the content type as much as about the list.
    assert!(
        out.contains("capabilities:"),
        "hg did not parse a capability list out of our response, so it did not accept us as a \
         Mercurial repository:\n{out}"
    );
    for advertised in [
        "batch",
        "branchmap",
        "getbundle",
        "known",
        "listkeys",
        "lookup",
    ] {
        assert!(
            out.contains(advertised),
            "hg did not see the `{advertised}` capability:\n{out}"
        );
    }
    // The sanitiser's whole job, checked through a real client's parser rather than through a
    // string comparison on our own output. Advertising any of these would make hg attempt a
    // push this server refuses, or negotiate a bundle format it never speaks.
    for forbidden in ["unbundle", "pushkey", "bundle2"] {
        assert!(
            !out.contains(forbidden),
            "hg saw the `{forbidden}` capability, which this server cannot honour — \
             sanitize_capabilities did not strip what the model asked for:\n{out}"
        );
    }

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

#[tokio::test]
async fn test_hg_clone_verify_cat_and_log_a_described_history() -> E2EResult<()> {
    println!("\n=== E2E Test: real `hg` clones, verifies and reads a described history ===");
    require_hg()?;

    let server = start_netget_server(static_history_config(lab_history())).await?;
    server
        .wait_for_log("Mercurial server listening on", 30)
        .await?;
    let url = format!("http://127.0.0.1:{}/lab", server.port);

    let work = tempfile::tempdir()?;
    let dest = work.path().join("lab");
    let dest_str = dest.to_str().ok_or("temp path is not UTF-8")?;

    let clone = hg_ok(&["clone", &url, dest_str], None).await?;
    assert!(
        clone.contains("added 5 changesets"),
        "hg clone did not receive the five described changesets:\n{clone}"
    );

    // hg verify re-reads every revlog and recomputes every node from (p1, p2, text): this is
    // the assertion that the changelog, manifest and filelog texts and their nodes are exactly
    // what Mercurial itself would have written.
    let verify = hg_ok(&["verify", "-R", dest_str], None).await?;
    assert!(
        verify.contains("checked 5 changesets with"),
        "hg verify did not check the five changesets:\n{verify}"
    );

    let log = hg_ok(
        &[
            "log",
            "-R",
            dest_str,
            "-r",
            "0:tip",
            "--template",
            "{rev}|{p1.rev}|{p2.rev}|{branch}|{author}|{date|hgdate}|{desc|firstline}|{files}\\n",
        ],
        None,
    )
    .await?;
    let expected_log = "\
0|-1|-1|default|Ada Lovelace <ada@example.com>|1790838000 -7200|Initial commit|README notes/meta.txt src/main.py
1|0|-1|default|Grace Hopper <grace@example.com>|1790000000 0|Expand the README|README
2|0|-1|stable|NetGet <netget@localhost>|1700000000 0|Fix on stable|fix.txt notes/meta.txt
3|1|2|default|Ada Lovelace <ada@example.com>|1791046800 18000|Merge stable into default|fix.txt
4|3|-1|default|NetGet <netget@localhost>|1700000000 0|Add an empty file|EMPTY
";
    assert_eq!(
        log, expected_log,
        "hg log does not show the described history"
    );

    let desc = hg_ok(
        &["log", "-R", dest_str, "-r", "1", "--template", "{desc}"],
        None,
    )
    .await?;
    assert_eq!(desc, "Expand the README\n\nThe body explains why.");

    // `hg cat` resolves file names against the working directory rather than `-R`, so it runs
    // inside the clone.
    let readme = hg_ok(&["cat", "-r", "tip", "README"], Some(&dest)).await?;
    assert_eq!(readme, "Hello from NetGet\nServed over hg.\n");
    let first_readme = hg_ok(&["cat", "-r", "0", "README"], Some(&dest)).await?;
    assert_eq!(first_readme, "Hello from NetGet\n");
    let meta = hg_ok(&["cat", "-r", "0", "notes/meta.txt"], Some(&dest)).await?;
    assert_eq!(meta, "\u{1}\nlooks like metadata\n");
    let empty = hg_ok(&["cat", "-r", "tip", "EMPTY"], Some(&dest)).await?;
    assert_eq!(empty, "");
    let fix = hg_ok(&["cat", "-r", "stable", "fix.txt"], Some(&dest)).await?;
    assert_eq!(fix, "fixed\n");

    let manifest = hg_ok(&["manifest", "-v", "-R", dest_str, "-r", "tip"], None).await?;
    for line in [
        "644   EMPTY",
        "644   README",
        "644   fix.txt",
        "644   notes/meta.txt",
        "755 * src/main.py",
    ] {
        assert!(
            manifest.lines().any(|l| l == line),
            "tip's manifest lacks {line:?}:\n{manifest}"
        );
    }

    // The clone checked out the default branch's tip, and the working copy has the bytes.
    assert_eq!(
        std::fs::read_to_string(dest.join("README"))?,
        "Hello from NetGet\nServed over hg.\n"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(dest.join("src/main.py"))?
            .permissions()
            .mode();
        assert!(
            mode & 0o111 != 0,
            "src/main.py was not checked out executable"
        );
    }

    // `hg id <url>` resolves `tip` through the lookup command.
    let tip = hg_ok(
        &[
            "log",
            "-R",
            dest_str,
            "-r",
            "tip",
            "--template",
            "{node|short}",
        ],
        None,
    )
    .await?;
    let id = hg_ok(&["id", &url], None).await?;
    assert_eq!(
        id.trim(),
        tip,
        "hg id <url> did not resolve tip to the cloned tip"
    );

    // An incremental exchange: clone revision 1 only (resolved through `lookup`), then pull the
    // rest — discovery asks `known` about the client's own head, and getbundle sends only the
    // missing changesets, with first deltas against revisions the client already holds.
    let partial = work.path().join("partial");
    let partial_str = partial.to_str().ok_or("temp path is not UTF-8")?;
    let clone_r = hg_ok(&["clone", "-r", "1", &url, partial_str], None).await?;
    assert!(
        clone_r.contains("added 2 changesets"),
        "hg clone -r 1 should receive revisions 0 and 1 only:\n{clone_r}"
    );
    let pull = hg_ok(&["pull", "-R", partial_str], None).await?;
    assert!(
        pull.contains("added 3 changesets"),
        "hg pull should receive exactly the three missing changesets:\n{pull}"
    );
    let verify_partial = hg_ok(&["verify", "-R", partial_str], None).await?;
    assert!(
        verify_partial.contains("checked 5 changesets with"),
        "hg verify after the incremental pull:\n{verify_partial}"
    );
    let nodes_full = hg_ok(
        &[
            "log",
            "-R",
            dest_str,
            "-r",
            "0:tip",
            "--template",
            "{node}\\n",
        ],
        None,
    )
    .await?;
    let nodes_partial = hg_ok(
        &[
            "log",
            "-R",
            partial_str,
            "-r",
            "0:tip",
            "--template",
            "{node}\\n",
        ],
        None,
    )
    .await?;
    assert_eq!(
        nodes_full, nodes_partial,
        "a clone and a clone-then-pull of the same description must hold the same changesets"
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

#[tokio::test]
async fn test_hg_clone_of_a_refused_history_is_an_hg_error() -> E2EResult<()> {
    println!("\n=== E2E Test: a history the server cannot build reaches hg as a remote error ===");
    require_hg()?;

    // The second commit names a parent that does not exist. The model path, not a static rule.
    // The history is validated whichever command it answers, so the clone stops at its very
    // first request, the handshake.
    let broken = serde_json::json!([{
        "type": "hg_repository",
        "commits": [
            {"id": "a", "message": "first", "files": [{"path": "README", "content": "x\n"}]},
            {"id": "b", "parents": ["no-such-commit"], "message": "second"}
        ]
    }]);

    let config = NetGetConfig::new_no_scripts(
        "listen on port {AVAILABLE_PORT} via mercurial. Serve the broken repository",
    )
    .with_mock(move |mock| {
        mock.on_event("hg_capabilities")
            .respond_with_actions(broken.clone())
            .expect_calls(1)
            .and()
            .on_instruction_containing("via mercurial")
            .respond_with_actions(serde_json::json!([{
                "type": "open_server",
                "port": 0,
                "base_stack": "Mercurial",
                "instruction": "Serve the broken repository"
            }]))
            .expect_calls(1)
            .and()
    });

    let server = start_netget_server(config).await?;
    let url = format!("http://127.0.0.1:{}/broken", server.port);
    let work = tempfile::tempdir()?;
    let dest = work.path().join("broken");
    let run = hg(&["clone", &url, dest.to_str().ok_or("temp path")?], None).await?;

    assert!(!run.success, "a clone of a refused history must fail");
    assert!(
        run.combined
            .contains("remote error:\nthe server could not build this repository's history"),
        "hg must report Mercurial's own remote error, not an HTTP failure:\n{}",
        run.combined
    );
    // The reason names the description's own parent id; it is for the operator's log only.
    assert!(
        !run.combined.contains("no-such-commit"),
        "the refusal's reason leaked onto the wire:\n{}",
        run.combined
    );
    server
        .wait_for_log("decision=fail_closed_invalid_repository", 30)
        .await?;

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}
