//! `netget --help` that a first-time reader can find things in: its fifty-odd flags under
//! headings, the ones that start something ahead of the model's tuning knobs, examples that
//! keep their indentation, and a queue-timeout default that is the constant's, not a copy of
//! it that drifted (it said 120 while the code used 300).
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features mcp-stdio,sqlite \
//!       --test cli_help_test

use clap::CommandFactory;
use netget::cli::Args;

#[test]
fn help_is_grouped_indented_and_states_the_real_defaults() {
    let help = Args::command().render_long_help().to_string();
    for heading in [
        "Start a server or client directly",
        "Non-interactive run:",
        "MCP and agents:",
        "Model:",
        "Model concurrency and budgets:",
    ] {
        assert!(
            help.contains(heading),
            "heading {heading:?} missing:\n{help}"
        );
    }
    // The flags a first-time user reaches for come before the model's tuning knobs.
    let server = help.find("--server <PROTOCOL>").expect("--server listed");
    let temperature = help
        .find("--llm-temperature")
        .expect("--llm-temperature listed");
    assert!(server < temperature, "--server is listed first:\n{help}");
    assert!(help.contains("--server-handlers <JSON>"), "{help}");
    // Examples keep their indentation.
    assert!(help.contains("\n    netget --mcp\n"), "{help}");
    // The queue-timeout default is the constant's, not a copy that drifted from it.
    let queue = &help[help.find("--llm-queue-timeout <SECONDS>").unwrap()..];
    let queue = &queue[..queue.find("--llm-max-queued <NUM>").unwrap()];
    assert!(
        queue.contains(&format!(
            "Default: {}",
            netget::llm::DEFAULT_QUEUE_TIMEOUT_SECS
        )),
        "{queue}"
    );
    // Developer notes in doc comments are not --help text.
    assert!(!help.contains("--suppress-art"), "{help}");
}

/// `-h` is the screenful: one line per flag under the same headings, pointing at `--help` for
/// the rest. It was 12 KB — every flag's whole paragraph and the examples — because every
/// flag set only `help`, which clap shows for both.
#[test]
fn short_help_fits_a_screen_or_two_and_long_help_keeps_the_detail() {
    let short = Args::command().render_help().to_string();
    let long = Args::command().render_long_help().to_string();
    assert!(
        short.len() <= 7 * 1024,
        "-h is {} bytes; keep it to a screen or two:\n{short}",
        short.len()
    );
    assert!(
        short.lines().count() <= 110,
        "-h is {} lines:\n{short}",
        short.lines().count()
    );
    assert!(
        long.len() > 2 * short.len(),
        "--help keeps the detail -h leaves out"
    );
    for heading in [
        "Start a server or client directly",
        "Non-interactive run:",
        "MCP and agents:",
        "Model:",
        "Model concurrency and budgets:",
    ] {
        assert!(
            short.contains(heading),
            "heading {heading:?} in -h:\n{short}"
        );
    }
    // Every flag is still listed.
    for flag in [
        "--server <PROTOCOL>",
        "--server-handlers <JSON>",
        "--mcp",
        "--llm-max-queued",
    ] {
        assert!(short.contains(flag), "{flag} in -h:\n{short}");
    }
    assert!(short.contains("--help"), "-h points at --help:\n{short}");
    // The paragraphs and the examples are --help's.
    for detail in ["EXAMPLES:", "Written atomically", "process table"] {
        assert!(!short.contains(detail), "{detail:?} is --help's:\n{short}");
        assert!(long.contains(detail), "{detail:?} in --help");
    }
}
