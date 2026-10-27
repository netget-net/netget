//! Publishing the score.
//!
//! Two artefacts, written side by side so they cannot disagree:
//!
//! - `eval-results/latest.json` — every run, every verdict, and the model's
//!   actual output for each. Machine-readable; this is what a trend line or a
//!   regression check would read.
//! - `eval-results/EVAL_RESULTS.md` — the same data as a table a human reads, plus the
//!   ranked failure modes, which are the actionable part.
//!
//! Both are regenerated wholesale from one run. Nothing is merged from a
//! previous run, because a half-merged score is a score nobody can trust.

#![allow(dead_code)]

use super::runner::CaseResult;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(serde::Serialize)]
pub struct EvalReport {
    pub schema: &'static str,
    pub generated_at: String,
    pub model: String,
    pub runs_per_case: usize,
    /// `--llm-seed` every run passed; `null` for an unpinned run.
    pub seed: Option<u64>,
    /// `--llm-temperature` every run passed; `null` leaves the model's default.
    pub temperature: Option<f32>,
    /// One sentence on what the seed does and does not pin, for a reader of the
    /// JSON alone.
    pub determinism: String,
    pub totals: Totals,
    pub protocols: Vec<ProtocolSummary>,
    pub failure_modes: Vec<FailureModeCount>,
    pub cases: Vec<CaseResult>,
}

#[derive(serde::Serialize)]
pub struct Totals {
    pub cases_total: usize,
    pub cases_attempted: usize,
    pub cases_skipped: usize,
    pub runs_total: usize,
    pub runs_passed: usize,
    pub pass_rate: f64,
    /// Failed runs in which the model had in fact produced executable actions,
    /// discarded only because text surrounded the JSON.
    pub runs_recoverable: usize,
    /// `(runs_passed + runs_recoverable) / runs_total` — the score this suite
    /// would report if `ActionResponse::from_str` took the first JSON value in
    /// the reply instead of requiring the whole reply to be one.
    pub pass_rate_with_lenient_parse: f64,
    /// Attempted cases with two or more runs — the population agreement is over.
    pub cases_with_repeats: usize,
    /// Of those, cases whose runs all reached the same verdict.
    pub cases_verdicts_agree: usize,
    /// Of those, cases whose runs executed byte-identical actions.
    pub cases_actions_agree: usize,
}

#[derive(serde::Serialize)]
pub struct ProtocolSummary {
    pub protocol: String,
    pub client: String,
    pub independence: String,
    pub instructions: usize,
    pub instructions_fully_passed: usize,
    pub runs: usize,
    pub runs_passed: usize,
    pub pass_rate: Option<f64>,
    pub dominant_failures: Vec<String>,
    pub skipped_reason: Option<String>,
    pub runs_recoverable: usize,
}

#[derive(serde::Serialize)]
pub struct FailureModeCount {
    pub mode: String,
    pub runs: usize,
    pub cases: Vec<String>,
    pub explanation: String,
}

fn now_iso() -> String {
    // No chrono in the test deps' default surface; seconds since epoch plus a
    // human hint is enough for a nightly artefact.
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("{}", secs)
}

pub fn build(model: &str, runs_per_case: usize, cases: Vec<CaseResult>) -> EvalReport {
    let seed = super::runner::eval_seed();
    let temperature = super::runner::eval_temperature();
    let repeated: Vec<&CaseResult> = cases
        .iter()
        .filter(|c| c.verdicts_agree.is_some())
        .collect();
    let cases_with_repeats = repeated.len();
    let cases_verdicts_agree = repeated
        .iter()
        .filter(|c| c.verdicts_agree == Some(true))
        .count();
    let cases_actions_agree = repeated
        .iter()
        .filter(|c| c.actions_agree == Some(true))
        .count();
    let runs_total: usize = cases.iter().map(|c| c.attempts).sum();
    let runs_passed: usize = cases.iter().map(|c| c.passes).sum();
    let runs_recoverable: usize = cases.iter().map(|c| c.recoverable_runs).sum();
    let attempted = cases.iter().filter(|c| c.status == "attempted").count();

    let mut by_protocol: BTreeMap<String, Vec<&CaseResult>> = BTreeMap::new();
    for case in &cases {
        by_protocol
            .entry(case.protocol.clone())
            .or_default()
            .push(case);
    }

    let protocols = by_protocol
        .into_iter()
        .map(|(protocol, group)| {
            let runs: usize = group.iter().map(|c| c.attempts).sum();
            let passed: usize = group.iter().map(|c| c.passes).sum();
            let attempted_here: Vec<&&CaseResult> =
                group.iter().filter(|c| c.status == "attempted").collect();
            let mut dominant: Vec<String> = group
                .iter()
                .filter_map(|c| c.dominant_failure.clone())
                .collect();
            dominant.sort();
            dominant.dedup();
            ProtocolSummary {
                protocol,
                client: group
                    .iter()
                    .find(|c| c.status == "attempted")
                    .map(|c| first_word(&c.client))
                    .unwrap_or_else(|| "-".to_string()),
                independence: group
                    .iter()
                    .find(|c| c.status == "attempted")
                    .map(|c| c.independence.clone())
                    .unwrap_or_else(|| "none".to_string()),
                instructions: group.len(),
                instructions_fully_passed: group
                    .iter()
                    .filter(|c| c.attempts > 0 && c.passes == c.attempts)
                    .count(),
                runs,
                runs_passed: passed,
                pass_rate: if runs > 0 {
                    Some(passed as f64 / runs as f64)
                } else {
                    None
                },
                dominant_failures: dominant,
                runs_recoverable: group.iter().map(|c| c.recoverable_runs).sum(),
                skipped_reason: if attempted_here.is_empty() {
                    group.iter().find_map(|c| c.status_reason.clone())
                } else {
                    None
                },
            }
        })
        .collect();

    let mut mode_runs: BTreeMap<String, (usize, Vec<String>)> = BTreeMap::new();
    for case in &cases {
        for run in &case.runs {
            if let Some(mode) = &run.failure_mode {
                let entry = mode_runs.entry(mode.clone()).or_default();
                entry.0 += 1;
                if !entry.1.contains(&case.id) {
                    entry.1.push(case.id.clone());
                }
            }
        }
    }
    let glossary: BTreeMap<&str, &str> = super::classify::MODE_GLOSSARY.iter().copied().collect();
    let mut failure_modes: Vec<FailureModeCount> = mode_runs
        .into_iter()
        .map(|(mode, (runs, case_ids))| FailureModeCount {
            explanation: glossary
                .get(mode.as_str())
                .copied()
                .unwrap_or("Harness-level, not a model or description defect.")
                .to_string(),
            mode,
            runs,
            cases: case_ids,
        })
        .collect();
    failure_modes.sort_by(|a, b| b.runs.cmp(&a.runs).then(a.mode.cmp(&b.mode)));

    EvalReport {
        schema: "netget.eval.v1",
        generated_at: now_iso(),
        model: model.to_string(),
        runs_per_case,
        seed,
        temperature,
        determinism: match seed {
            Some(_) => "pass-rate over N independent runs with a pinned sampler seed; the \
                        seed makes an identical prompt answer identically, but each run's \
                        prompt carries its own ports and ids, so agreement is measured \
                        (totals.cases_*_agree) rather than assumed"
                .to_string(),
            None => "pass-rate over N independent runs with no seed: the sampler is \
                     unpinned and runs are expected to differ"
                .to_string(),
        },
        totals: Totals {
            cases_total: cases.len(),
            cases_attempted: attempted,
            cases_skipped: cases.len() - attempted,
            runs_total,
            runs_passed,
            pass_rate: if runs_total > 0 {
                runs_passed as f64 / runs_total as f64
            } else {
                0.0
            },
            runs_recoverable,
            pass_rate_with_lenient_parse: if runs_total > 0 {
                (runs_passed + runs_recoverable) as f64 / runs_total as f64
            } else {
                0.0
            },
            cases_with_repeats,
            cases_verdicts_agree,
            cases_actions_agree,
        },
        protocols,
        failure_modes,
        cases,
    }
}

fn first_word(command: &str) -> String {
    command
        .split_whitespace()
        .next()
        .unwrap_or("-")
        .rsplit('/')
        .next()
        .unwrap_or("-")
        .to_string()
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Where the two artefacts go: the committed locations, or — when
/// `NETGET_EVAL_OUT_DIR` is set — `latest.json` and `EVAL_RESULTS.md` inside
/// that directory. A one-protocol rerun uses the second so it does not
/// overwrite the committed whole-suite baseline with a one-row table.
fn output_paths() -> (PathBuf, PathBuf) {
    match std::env::var("NETGET_EVAL_OUT_DIR") {
        Ok(dir) if !dir.trim().is_empty() => {
            let dir = PathBuf::from(dir);
            (dir.join("latest.json"), dir.join("EVAL_RESULTS.md"))
        }
        _ => {
            let root = repo_root();
            (
                root.join("eval-results").join("latest.json"),
                root.join("eval-results").join("EVAL_RESULTS.md"),
            )
        }
    }
}

/// Write both artefacts. Returns the paths written.
pub fn write(report: &EvalReport) -> Result<Vec<PathBuf>, Box<dyn std::error::Error>> {
    let (json_path, md_path) = output_paths();
    for path in [&json_path, &md_path] {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
    }
    std::fs::write(&json_path, serde_json::to_string_pretty(report)? + "\n")?;
    std::fs::write(&md_path, markdown(report))?;
    Ok(vec![json_path, md_path])
}

fn pct(rate: Option<f64>) -> String {
    match rate {
        Some(r) => format!("{:.0}%", r * 100.0),
        None => "—".to_string(),
    }
}

fn markdown(report: &EvalReport) -> String {
    let mut out = String::new();
    out.push_str("# Real-model eval results\n\n");
    out.push_str(
        "**Generated by the harness — do not hand-edit.** `./run-eval.sh` regenerates this \
         file and `eval-results/latest.json` together.\n\n",
    );
    out.push_str(
        "Every other test in this repository drives a **mock** model whose answers the test \
         author wrote. That proves the plumbing carries a correct answer; it proves nothing \
         about whether a real model, reading a protocol's own action descriptions and \
         parameter docs, can *produce* one. This file is that measurement.\n\n",
    );

    out.push_str("## How to read it\n\n");
    out.push_str(&format!(
        "- **Model**: `{}` · **runs per instruction**: {} · **seed**: {} · **temperature**: {}\n",
        report.model,
        report.runs_per_case,
        report
            .seed
            .map(|s| format!("`{}`", s))
            .unwrap_or_else(|| "none (unpinned)".to_string()),
        report
            .temperature
            .map(|t| format!("`{}`", t))
            .unwrap_or_else(|| "the model's default".to_string()),
    ));
    out.push_str(
        "- **The score is a rate, and whether the runs agreed is measured, not assumed.** \
         Every run passes `--llm-seed` (and `--llm-temperature` when one is set), so the \
         sampler draws the same tokens for the same prompt. But each run's prompt carries \
         its own client port, connection id and — for DNS/LDAP-style protocols — a random \
         query or message id, and one differing token changes every token drawn after it. \
         Each instruction therefore still runs N times against a **fresh netget process and \
         a fresh server**, the published number is passes/runs, and the `Runs agree` column \
         says whether those runs reached the same verdict and executed the same actions.\n",
    );
    out.push_str(
        "- **Every case is driven by a real third-party client binary** — `dig`, `curl`, \
         `redis-cli`, `psql`, `ldapsearch`, `ipptool`, `whois`, `ftp`, `mysql`. The \
         `evidence` column says whether the client understands the protocol \
         (`protocol-client`) or is only a byte pipe (`generic-transport`); a pass carried by \
         `nc` is weaker evidence and is labelled so.\n",
    );
    out.push_str(
        "- **A low score is a finding, not a test failure.** When the model cannot drive a \
         protocol the defect is usually in the action descriptions. The ranked failure modes \
         below carry the model's actual output.\n\n",
    );

    out.push_str(&format!(
        "## Score\n\n**{} of {} runs passed ({}) across {} instructions on {} protocol(s).**\n\n",
        report.totals.runs_passed,
        report.totals.runs_total,
        pct(Some(report.totals.pass_rate)),
        report.totals.cases_attempted,
        report.protocols.iter().filter(|p| p.runs > 0).count()
    ));

    out.push_str(
        "| Protocol | Client | Evidence | Instructions | Runs | Passed | Rate | \
         Would pass with a lenient parse | Dominant failure |\n",
    );
    out.push_str("|---|---|---|---:|---:|---:|---:|---:|---|\n");
    for p in &report.protocols {
        if p.runs == 0 {
            out.push_str(&format!(
                "| `{}` | — | — | {} | — | — | — | — | not attempted: {} |\n",
                p.protocol,
                p.instructions,
                p.skipped_reason.as_deref().unwrap_or("unknown")
            ));
            continue;
        }
        out.push_str(&format!(
            "| `{}` | `{}` | {} | {} | {} | {} | {} | {} | {} |\n",
            p.protocol,
            p.client,
            p.independence,
            p.instructions,
            p.runs,
            p.runs_passed,
            pct(p.pass_rate),
            pct(Some(
                (p.runs_passed + p.runs_recoverable) as f64 / p.runs as f64
            )),
            if p.dominant_failures.is_empty() {
                "—".to_string()
            } else {
                p.dominant_failures
                    .iter()
                    .map(|m| format!("`{}`", m))
                    .collect::<Vec<_>>()
                    .join(", ")
            }
        ));
    }
    out.push('\n');

    if report.totals.runs_recoverable > 0 {
        out.push_str(&format!(
            "**Read the last two columns together.** In {} of the {} failed runs the model \
             named the right action with the right parameters and netget threw the reply \
             away, because `ActionResponse::from_str` (`src/llm/actions/mod.rs`) strips a \
             *leading* ``` fence and nothing trailing, then requires `serde_json::from_str` \
             to consume the whole string. Small models routinely append an explanation after \
             the JSON. Taking the first value — `Deserializer::from_str(..).into_iter().next()` \
             — would move this suite from {} to {} without touching a single action \
             description.\n\n",
            report.totals.runs_recoverable,
            report.totals.runs_total - report.totals.runs_passed,
            pct(Some(report.totals.pass_rate)),
            pct(Some(report.totals.pass_rate_with_lenient_parse)),
        ));
    }

    if report.totals.cases_with_repeats > 0 {
        out.push_str(&format!(
            "## Reproducibility\n\n**{} of {} repeated instructions reached the same verdict \
             on every run; {} of {} executed byte-identical actions on every run.** The second \
             number is the strict one: an answer that must echo a random query id cannot be \
             byte-identical across runs even when the model's choice was, so it undercounts \
             agreement for DNS-, LDAP- and FTP-style protocols by design.\n\n",
            report.totals.cases_verdicts_agree,
            report.totals.cases_with_repeats,
            report.totals.cases_actions_agree,
            report.totals.cases_with_repeats,
        ));
    }

    out.push_str("## Per-instruction detail\n\n");
    out.push_str(
        "| Case | Instruction | Passed | Runs agree | Failure mode |\n|---|---|---:|---|---|\n",
    );
    for case in &report.cases {
        let score = if case.attempts == 0 {
            format!("— ({})", case.status)
        } else {
            format!("{}/{}", case.passes, case.attempts)
        };
        let agree = match (case.verdicts_agree, case.actions_agree) {
            (None, _) => "—",
            (Some(true), Some(true)) => "verdict + actions",
            (Some(true), _) => "verdict",
            (Some(false), _) => "no",
        };
        out.push_str(&format!(
            "| `{}` | {} | {} | {} | {} |\n",
            case.id,
            escape_pipes(&case.instruction),
            score,
            agree,
            case.dominant_failure
                .as_ref()
                .map(|m| format!("`{}`", m))
                .unwrap_or_else(|| "—".to_string())
        ));
    }
    out.push('\n');

    out.push_str("## Failure modes, ranked\n\n");
    if report.failure_modes.is_empty() {
        out.push_str("None — every attempted run passed.\n\n");
    } else {
        for mode in &report.failure_modes {
            out.push_str(&format!(
                "### `{}` — {} failed run(s)\n\n{}\n\nSeen in: {}\n\n",
                mode.mode,
                mode.runs,
                mode.explanation,
                mode.cases
                    .iter()
                    .map(|c| format!("`{}`", c))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
    }

    out.push_str("## The model's actual output, per failing case\n\n");
    out.push_str(
        "Each block is the verbatim netget log line carrying the action the model built. \
         This is the diagnostic input for a prompt-quality fix.\n\n",
    );
    let mut any = false;
    for case in &report.cases {
        let failing: Vec<&super::runner::RunRecord> = case
            .runs
            .iter()
            .filter(|r| r.verdict != "pass" && !r.model_output.is_empty())
            .collect();
        if failing.is_empty() {
            continue;
        }
        any = true;
        out.push_str(&format!(
            "<details><summary><code>{}</code> — {}/{} passed</summary>\n\n",
            case.id, case.passes, case.attempts
        ));
        out.push_str(&format!("**Instruction:** {}\n\n", case.instruction));
        out.push_str(&format!("**Client:** `{}`\n\n", case.client));
        for run in failing {
            out.push_str(&format!(
                "Run {} — `{}`: {}\n\n```\n{}\n```\n\n",
                run.run,
                run.failure_mode.as_deref().unwrap_or("?"),
                run.detail.as_deref().unwrap_or(""),
                run.model_output.join("\n")
            ));
        }
        out.push_str("</details>\n\n");
    }
    if !any {
        out.push_str("None.\n\n");
    }

    out.push_str(
        "## Known limits of this measurement\n\n\
         - **A pinned seed is not a pinned run.** The seed fixes the sampler, not the \
           prompt; see the Reproducibility section for how often the runs agreed.\n\
         - **A pass means the client observed the right thing**, not that the frame is \
           spec-clean. The pcap oracle (Tier 1) is the check for that, and the two are \
           complementary.\n\
         - **`generic-transport` rows are weak evidence.** The check is a substring in a \
           byte stream; only the protocol clients validate framing.\n\
         - **One model.** A different model scores differently. The model is recorded in \
           every artefact for that reason; comparing two protocols is only valid within one \
           run.\n",
    );

    out
}

fn escape_pipes(text: &str) -> String {
    text.replace('|', "\\|")
}

/// Print the table to stdout too, so a nightly log is readable without opening
/// the artefact.
pub fn print_summary(report: &EvalReport) {
    println!(
        "\n══ real-model eval ══ model={} runs={} seed={:?} temperature={:?}",
        report.model, report.runs_per_case, report.seed, report.temperature
    );
    for p in &report.protocols {
        println!(
            "  {:<14} {:>7}  {:<18} {}",
            p.protocol,
            if p.runs == 0 {
                "skipped".to_string()
            } else {
                format!("{}/{}", p.runs_passed, p.runs)
            },
            p.independence,
            p.dominant_failures.join(", ")
        );
    }
    println!(
        "  TOTAL {}/{} ({})",
        report.totals.runs_passed,
        report.totals.runs_total,
        pct(Some(report.totals.pass_rate))
    );
    println!(
        "  AGREEMENT {}/{} cases same verdict every run, {}/{} same actions",
        report.totals.cases_verdicts_agree,
        report.totals.cases_with_repeats,
        report.totals.cases_actions_agree,
        report.totals.cases_with_repeats
    );
}

/// Where the artefacts land, for the runner script's message.
pub fn artefact_paths() -> (PathBuf, PathBuf) {
    output_paths()
}

pub fn exists(path: &Path) -> bool {
    path.exists()
}
