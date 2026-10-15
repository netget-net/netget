//! DICT against a real, independent client: `dict(1)` from the dictd project.
//!
//! `dict` 1.13 (GPL, Rickard Faith; `brew install dict`, Debian/Ubuntu package `dict`) is a C
//! implementation NetGet neither links nor wrote. It is run as a subprocess and what it
//! *printed* is asserted — which means it parsed our banner, our status lines, our quoting and
//! our dot-terminated text blocks, and un-stuffed them. Every other test in this directory is
//! NetGet reading bytes NetGet wrote.
//!
//! **These tests FAIL, they do not skip, when `dict` is absent.** A skip-when-missing gate
//! returns `Ok(())` on a runner without the binary, so the suite reports a silent pass and any
//! rating resting on it rests on nothing. `tests/server/memcached/real_client_test.rs` is the
//! precedent.
//!
//! The dictionary itself is a Python script handler (`common::DICTIONARY_SCRIPT`), so the
//! script-driven cases are deterministic and consult no model. The last test puts a mocked
//! model behind the same client, because the model path is the one the protocol exists for.
//!
//! No pcap oracle: this Wireshark build has no DICT dissector (`tshark -G protocols` lists
//! none, and `-d tcp.port==2628,dict` is rejected).
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features dict --test server -- dict::real_client --test-threads=100

use super::common::{self, dictionary_handler};
use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
use std::time::Duration;

/// Locate a binary, or fail saying why a skip would be worse. Named `require_tool("…")` so
/// `scripts/beta_evidence_table.py` can see which third-party client this file drives.
fn require_tool(name: &str) -> String {
    for prefix in ["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin"] {
        let candidate = std::path::Path::new(prefix).join(name);
        if candidate.exists() {
            return candidate.to_string_lossy().into_owned();
        }
    }
    if let Ok(path) = std::env::var("PATH") {
        if let Some(found) = path
            .split(':')
            .map(|dir| std::path::Path::new(dir).join(name))
            .find(|candidate| candidate.exists())
        {
            return found.to_string_lossy().into_owned();
        }
    }
    panic!(
        "`{name}` not found (searched /opt/homebrew/bin, /usr/local/bin, /usr/bin and $PATH). \
         These tests drive the dictd project's own dict(1) client against NetGet's DICT \
         server, and that is the only independent check that our banner, status lines, \
         quoting and dot-stuffed text blocks are acceptable to something we did not write. \
         Skipping would leave the DICT evidence resting on nothing, so this is a failure and \
         not a skip. Install with `brew install dict` (macOS) or `apt-get install -y dict` \
         (Debian/Ubuntu)."
    );
}

/// Run `dict -h 127.0.0.1 -p <port> <args>`; returns (exit code, stdout, stderr).
async fn run_dict(port: u16, args: &[&str]) -> (i32, String, String) {
    let dict = require_tool("dict");
    let mut command = tokio::process::Command::new(&dict);
    command
        .arg("-h")
        .arg("127.0.0.1")
        .arg("-p")
        .arg(port.to_string())
        .args(args)
        .kill_on_drop(true);
    let output = tokio::time::timeout(Duration::from_secs(60), command.output())
        .await
        .unwrap_or_else(|_| panic!("dict {args:?} did not exit within 60s"))
        .expect("run dict");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    println!(
        "--- dict -h 127.0.0.1 -p {port} {} (exit {:?}) ---\n{stdout}{stderr}",
        args.join(" "),
        output.status.code()
    );
    (output.status.code().unwrap_or(-1), stdout, stderr)
}

#[tokio::test]
async fn dict_looks_up_a_word_and_prints_both_definitions_unstuffed() {
    let state = common::new_state().await;
    let (_id, port, _rx) = common::start(&state, vec![dictionary_handler()], None).await;

    let (code, out, err) = run_dict(port, &["glimmer"]).await;
    assert_eq!(code, 0, "dict exited {code}. stdout: {out}\nstderr: {err}");
    assert!(
        out.contains("2 definitions found"),
        "dict parsed the 150 count: {out}"
    );
    assert!(
        out.contains("From Fantasy Lexicon [fantasy]:"),
        "dict parsed the 151 line's database and description: {out}"
    );
    assert!(out.contains("From Technical Terms [tech]:"), "{out}");
    assert!(
        out.contains("n. a small dragon that hoards moonlight"),
        "{out}"
    );
    // Dot-stuffing round trip: the model's line began with one dot, NetGet sent two, and dict
    // printed one. Had NetGet not stuffed it, dict would have printed it with its dot removed.
    assert!(
        out.contains(".a line that begins with a dot"),
        "dict un-stuffed the leading dot back to one: {out}"
    );
    assert!(
        !out.contains("..a line"),
        "the stuffing dot reached the reader: {out}"
    );
    // The model's lone "." line did not end the block early: the line after it arrived, and
    // so did the second definition.
    assert!(
        out.contains("last line"),
        "the block ended at the model's '.': {out}"
    );
}

#[tokio::test]
async fn dict_match_with_the_prefix_strategy_lists_the_matches() {
    let state = common::new_state().await;
    let (_id, port, _rx) = common::start(&state, vec![dictionary_handler()], None).await;

    let (code, out, err) = run_dict(port, &["-m", "-s", "prefix", "glimmer"]).await;
    assert_eq!(code, 0, "dict exited {code}. stdout: {out}\nstderr: {err}");
    let line = out
        .lines()
        .find(|l| l.starts_with("fantasy:"))
        .unwrap_or_else(|| panic!("dict printed no 'fantasy:' match line: {out}"));
    assert!(
        line.contains("glimmerwyrm") && line.contains("glimmerfox"),
        "dict parsed both 152 lines: {out}"
    );
}

#[tokio::test]
async fn dict_lists_databases_and_strategies_and_shows_info() {
    let state = common::new_state().await;
    let (_id, port, _rx) = common::start(&state, vec![dictionary_handler()], None).await;

    let (code, out, err) = run_dict(port, &["-D"]).await;
    assert_eq!(code, 0, "dict -D exited {code}. {out}{err}");
    assert!(out.contains("Databases available:"), "{out}");
    assert!(
        out.lines()
            .any(|l| l.trim_start().starts_with("fantasy") && l.contains("Fantasy Lexicon")),
        "dict parsed the 110 listing: {out}"
    );
    assert!(
        out.lines()
            .any(|l| l.trim_start().starts_with("tech") && l.contains("Technical Terms")),
        "{out}"
    );

    let (code, out, err) = run_dict(port, &["-S"]).await;
    assert_eq!(code, 0, "dict -S exited {code}. {out}{err}");
    assert!(out.contains("Strategies available:"), "{out}");
    assert!(
        out.lines()
            .any(|l| l.trim_start().starts_with("prefix") && l.contains("Match prefixes")),
        "dict parsed the 111 listing: {out}"
    );

    let (code, out, err) = run_dict(port, &["-i", "fantasy"]).await;
    assert_eq!(code, 0, "dict -i exited {code}. {out}{err}");
    assert!(
        out.contains("The Fantasy Lexicon") && out.contains("Invented words, invented meanings."),
        "dict printed the 112 text: {out}"
    );

    let (code, out, err) = run_dict(port, &["-I"]).await;
    assert_eq!(code, 0, "dict -I exited {code}. {out}{err}");
    assert!(
        out.contains("NetGet test dictionary"),
        "dict printed the 114 text: {out}"
    );
}

#[tokio::test]
async fn dict_in_mime_mode_receives_a_mime_header_ahead_of_each_definition() {
    let state = common::new_state().await;
    let (_id, port, _rx) = common::start(&state, vec![dictionary_handler()], None).await;

    // `-M` makes dict send OPTION MIME (it does not check our `<mime>` capability first, per
    // its man page). dict 1.13 does not interpret the header — it prints each text block as
    // received — so what this proves is placement: OPTION MIME was acknowledged, and each
    // 151 block opens with the header and one blank line, ahead of the definition's own first
    // line, while the 150 count and the 151 parsing are unaffected.
    let (code, out, err) = run_dict(port, &["-M", "glimmer"]).await;
    assert_eq!(code, 0, "dict -M exited {code}. {out}{err}");
    assert!(out.contains("2 definitions found"), "{out}");
    let lines: Vec<&str> = out.lines().map(str::trim).collect();
    let mut blocks = 0;
    for (i, line) in lines.iter().enumerate() {
        if line.starts_with("From ") {
            blocks += 1;
            let body: Vec<&str> = lines[i + 1..]
                .iter()
                .copied()
                .skip_while(|l| l.is_empty())
                .take(4)
                .collect();
            assert_eq!(
                body,
                [
                    "Content-type: text/plain; charset=utf-8",
                    "Content-transfer-encoding: 8bit",
                    "",
                    "glimmer"
                ],
                "each definition must open with the MIME header, one blank line, then the \
                 definition text: {out}"
            );
        }
    }
    assert_eq!(blocks, 2, "dict parsed both 151 blocks: {out}");
}

#[tokio::test]
async fn dict_reports_no_definitions_for_an_unknown_word() {
    let state = common::new_state().await;
    let (_id, port, _rx) = common::start(&state, vec![dictionary_handler()], None).await;

    let (code, out, err) = run_dict(port, &["nosuchword"]).await;
    let all = format!("{out}{err}");
    assert_ne!(code, 0, "dict must report failure for 552: {all}");
    assert!(
        all.contains("No definitions found for \"nosuchword\""),
        "dict read our 552 as 'no match': {all}"
    );
}

/// The model path, behind the same real client: a mocked model answers `dict_define` with the
/// word echoed back from the event, and dict prints it.
#[tokio::test]
async fn dict_prints_a_definition_the_model_wrote() -> E2EResult<()> {
    let _ = require_tool("dict");
    let config = NetGetConfig::new("listen on port {AVAILABLE_PORT} via dict. Define any word.")
        .with_log_level("debug")
        .with_mock(|mock| {
            mock.on_instruction_containing("via dict")
                .respond_with_actions(serde_json::json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "dict",
                    "instruction": "Define any word"
                }]))
                .expect_calls(1)
                .and()
                .on_event("dict_define")
                .respond_with_actions_from_event(|event| {
                    let word = event["word"].as_str().unwrap_or("").to_string();
                    serde_json::json!([{
                        "type": "send_dict_definitions",
                        "word": word,
                        "definitions": [{
                            "database": "model",
                            "database_description": "The Model's Own Dictionary",
                            "text": format!("{word}\n  n. a word the model was asked about")
                        }]
                    }])
                })
                .expect_calls(1)
                .and()
        });

    let server = start_netget_server(config).await?;
    let (code, out, err) = run_dict(server.port, &["quokka"]).await;
    assert_eq!(code, 0, "dict exited {code}. {out}{err}");
    assert!(out.contains("1 definition found"), "{out}");
    assert!(
        out.contains("From The Model's Own Dictionary [model]:"),
        "{out}"
    );
    assert!(out.contains("n. a word the model was asked about"), "{out}");

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}
