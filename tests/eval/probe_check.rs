//! The eval's own probes and expectations, run against a **mocked** model.
//!
//! The eval scores a real model, so a defect in the harness scores as a defect
//! in the model — and two of them did, for whole protocols, before anything
//! here existed:
//!
//! - **beanstalkd**, 0/15 `event_never_reached_model`. The greenstalk probe was
//!   a Rust string built with `\` continuations, which drop the next line's
//!   leading whitespace; Python raised `IndentationError` before connecting.
//! - **gemini** and **bolt**, 0/15 each `client_left_before_model_answered`.
//!   Both clients write a warning to stderr before the exchange (Python's
//!   `CryptographyDeprecationWarning`, the JVM's `ThreadPriorityPolicy`), so
//!   the probe's two-second idle settle killed them during the model call.
//!
//! Each test here takes one published case by id — its instruction, its probe
//! and its `Expect`, unchanged — and puts a mocked model behind it that answers
//! the case's event **correctly** and only after [`MODEL_LATENCY`], which is
//! longer than the probe's settle. It then requires three things, each of which
//! one of the defects above broke:
//!
//! 1. the model was asked for the event the instruction depends on
//!    (`expect_calls` on the event rule — the beanstalkd defect fails here);
//! 2. the probe was still there when the slow answer arrived;
//! 3. the case's own expectation accepts that correct answer (the gemini and
//!    bolt defects fail here and in 2).
//!
//! So a case that passes here and scores 0 in the eval is a finding about the
//! model or the descriptions, not about the harness.
//!
//! These tests drive the same real clients the eval does and **fail** when one
//! is missing, as the eval itself reports `client-missing` rather than
//! skipping.
//!
//! Run with, e.g.:
//!   ./cargo-isolated.sh test --no-default-features --features beanstalkd --test eval -- probe_check --test-threads=100

#![allow(dead_code)]

use super::case::ProbeKind;
use super::probe;
use super::suites::all_cases;
use crate::helpers::common::E2EResult;
use crate::helpers::mock_builder::MockLlmBuilder;
use crate::helpers::{start_netget_server, NetGetConfig};
use std::time::Duration;

/// How long the mocked model takes to answer each event: longer than the
/// probe's idle settle (two seconds after the first byte), shorter than any
/// client's own timeout.
pub const MODEL_LATENCY: Duration = Duration::from_secs(5);

/// Run published case `id` against a mocked model. `answer` adds the rules for
/// the case's events; each must use `.after_delay(MODEL_LATENCY)` and pin its
/// call count, which is what proves the event reached the model.
pub async fn check_case<F>(id: &'static str, answer: F) -> E2EResult<()>
where
    F: FnOnce(MockLlmBuilder) -> MockLlmBuilder,
{
    let case = all_cases()
        .into_iter()
        .find(|c| c.id == id)
        .unwrap_or_else(|| panic!("no eval case {id:?} in this build"));
    let ProbeKind::Command(probe_spec) = case.probe.clone() else {
        panic!("eval case {id} has no probe to check");
    };
    let protocol = case.protocol;
    let instruction = case.instruction;

    let config = NetGetConfig::new(format!(
        "listen on port {{AVAILABLE_PORT}} via {protocol}. Eval probe check."
    ))
    .with_log_level("debug")
    // `run-eval.sh` runs this binary with NETGET_USE_OLLAMA=1; these checks are about the
    // mock's answers, never a real model's.
    .with_forced_mock()
    .with_mock(move |mock| {
        let mock = mock
            .on_instruction_containing(format!("via {protocol}"))
            .respond_with_actions(serde_json::json!([{
                "type": "open_server",
                "port": 0,
                "base_stack": protocol,
                "instruction": instruction
            }]))
            .expect_calls(1)
            .and();
        answer(mock)
    });

    let server = start_netget_server(config).await?;
    let outcome = probe::run(&probe_spec, server.port, Duration::from_secs(120))
        .await
        .map_err(|e| format!("{id}: {e}"))?;
    let output = outcome.combined();
    println!(
        "--- {id}: {} (exit {:?}, {:.1}s) ---\n{output}",
        outcome.command,
        outcome.exit_code,
        outcome.elapsed.as_secs_f64()
    );

    server.wait_for_mocks(30).await;
    // First: was the model asked at all? A probe that never reaches the server
    // fails here, naming the rule that went unanswered.
    server.verify_mocks().await?;
    assert!(
        !outcome.output_truncated,
        "probe output exceeded capture budget"
    );
    assert!(
        !outcome.timed_out,
        "{id}: the probe was still running after 120s"
    );
    // Then: did the probe wait for the slow answer, and does the case's own
    // expectation accept a correct one?
    if let Err(why) = case
        .expect
        .check(&output, "", outcome.exit_code, outcome.timed_out)
    {
        panic!(
            "{id}: a mocked model answered correctly after {MODEL_LATENCY:?} and the case still \
             fails — {why}. That is a harness defect, and the eval would score it against the \
             model. Client output:\n{output}"
        );
    }
    server.stop().await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// beanstalkd — greenstalk
// ---------------------------------------------------------------------------

#[tokio::test]
async fn beanstalkd_accept_a_job_reaches_the_model() -> E2EResult<()> {
    check_case("beanstalkd/accept-a-job", |mock| {
        mock.on_event("beanstalkd_put")
            .respond_with_actions(
                serde_json::json!([{"type": "insert_beanstalkd_job", "job_id": 100}]),
            )
            .after_delay(MODEL_LATENCY)
            .expect_calls(1)
            .and()
    })
    .await
}

#[tokio::test]
async fn beanstalkd_hand_out_a_job_reaches_the_model() -> E2EResult<()> {
    check_case("beanstalkd/hand-out-a-job", |mock| {
        mock.on_event("beanstalkd_reserve")
            .respond_with_actions(serde_json::json!([{
                "type": "reserve_beanstalkd_job",
                "job_id": 7,
                "body": "resize photo.jpg to 640 wide"
            }]))
            .after_delay(MODEL_LATENCY)
            .expect_calls(1)
            .and()
    })
    .await
}

#[tokio::test]
async fn beanstalkd_queue_statistics_reaches_the_model() -> E2EResult<()> {
    check_case("beanstalkd/queue-statistics", |mock| {
        mock.on_event("beanstalkd_stats")
            .respond_with_actions(serde_json::json!([{
                "type": "send_beanstalkd_stats",
                "stats": {"current-jobs-ready": 5, "current-jobs-buried": 2, "version": "1.13"}
            }]))
            .after_delay(MODEL_LATENCY)
            .expect_calls(1)
            .and()
    })
    .await
}

// ---------------------------------------------------------------------------
// gemini — ignition
// ---------------------------------------------------------------------------

#[tokio::test]
async fn gemini_home_page_waits_for_the_model() -> E2EResult<()> {
    check_case("gemini/home-page", |mock| {
        mock.on_event("gemini_request")
            .respond_with_actions(serde_json::json!([{
                "type": "send_gemtext",
                "lines": [
                    {"type": "heading1", "text": "Welcome to the NetGet capsule"},
                    {"type": "link", "url": "/about", "text": "About"}
                ]
            }]))
            .after_delay(MODEL_LATENCY)
            .expect_calls(1)
            .and()
    })
    .await
}

#[tokio::test]
async fn gemini_ask_for_input_waits_for_the_model() -> E2EResult<()> {
    check_case("gemini/ask-for-input", |mock| {
        mock.on_event("gemini_request")
            .respond_with_actions(serde_json::json!([{
                "type": "send_gemini_response",
                "status": 10,
                "meta": "What is your name?"
            }]))
            .after_delay(MODEL_LATENCY)
            .expect_calls(1)
            .and()
    })
    .await
}

#[tokio::test]
async fn gemini_not_found_waits_for_the_model() -> E2EResult<()> {
    check_case("gemini/not-found", |mock| {
        mock.on_event("gemini_request")
            .respond_with_actions(serde_json::json!([{
                "type": "send_gemini_response",
                "status": 51,
                "meta": "Not found"
            }]))
            .after_delay(MODEL_LATENCY)
            .expect_calls(1)
            .and()
    })
    .await
}

// ---------------------------------------------------------------------------
// zabbix — zabbix_sender
// ---------------------------------------------------------------------------

#[tokio::test]
async fn zabbix_accept_known_host_waits_for_the_model() -> E2EResult<()> {
    check_case("zabbix/accept-known-host", |mock| {
        mock.on_event("zabbix_sender_data")
            .respond_with_actions(serde_json::json!([{
                "type": "send_zabbix_result", "processed": 1, "failed": 0
            }]))
            .after_delay(MODEL_LATENCY)
            .expect_calls(1)
            .and()
    })
    .await
}

#[tokio::test]
async fn zabbix_reject_unknown_host_waits_for_the_model() -> E2EResult<()> {
    check_case("zabbix/reject-unknown-host", |mock| {
        mock.on_event("zabbix_sender_data")
            .respond_with_actions(serde_json::json!([{
                "type": "send_zabbix_result", "processed": 0, "failed": 1
            }]))
            .after_delay(MODEL_LATENCY)
            .expect_calls(1)
            .and()
    })
    .await
}

// ---------------------------------------------------------------------------
// docker — the docker CLI
// ---------------------------------------------------------------------------

#[tokio::test]
async fn docker_ps_running_container_waits_for_the_model() -> E2EResult<()> {
    check_case("docker/ps-running-container", |mock| {
        mock.on_event("docker_api_request")
            .and_event_data_contains("resource", "containers")
            .respond_with_actions(serde_json::json!([{
                "type": "send_docker_containers",
                "containers": [{
                    "names": ["eval-web"], "image": "nginx:1.27", "state": "running",
                    "ports": [{"private_port": 80, "public_port": 8080, "type": "tcp"}]
                }]
            }]))
            .after_delay(MODEL_LATENCY)
            .expect_calls(1)
            .and()
    })
    .await
}

#[tokio::test]
async fn docker_ps_all_includes_stopped_waits_for_the_model() -> E2EResult<()> {
    check_case("docker/ps-all-includes-stopped", |mock| {
        mock.on_event("docker_api_request")
            .and_event_data_contains("resource", "containers")
            .respond_with_actions(serde_json::json!([{
                "type": "send_docker_containers",
                "containers": [
                    {"names": ["eval-api"], "image": "api:2", "state": "running"},
                    {"names": ["eval-migrate"], "image": "api:2", "state": "exited",
                     "exit_code": 0}
                ]
            }]))
            .after_delay(MODEL_LATENCY)
            .expect_calls(1)
            .and()
    })
    .await
}

#[tokio::test]
async fn docker_inspect_missing_waits_for_the_model() -> E2EResult<()> {
    check_case("docker/inspect-missing", |mock| {
        mock.on_event("docker_api_request")
            .and_event_data_contains("resource", "container")
            .respond_with_actions(serde_json::json!([{
                "type": "send_docker_error",
                "status": 404,
                "message": "No such container: eval-ghost"
            }]))
            .after_delay(MODEL_LATENCY)
            .expect_calls(1)
            .and()
            // Before giving up on a name, the CLI reads /info to decide whether to try the
            // swarm object types.
            .on_event("docker_api_request")
            .and_event_data_contains("resource", "info")
            .respond_with_actions(serde_json::json!([{"type": "send_docker_info"}]))
            .after_delay(MODEL_LATENCY)
            .expect_at_most(1)
            .and()
    })
    .await
}

// ---------------------------------------------------------------------------
// bolt — cypher-shell
// ---------------------------------------------------------------------------

/// The login every bolt case needs first. One or two: the Java driver's pool
/// sometimes opens a second connection, and each logs in.
fn accept_bolt_login(mock: MockLlmBuilder) -> MockLlmBuilder {
    mock.on_event("bolt_authenticate")
        .respond_with_actions(serde_json::json!([{"type": "accept_bolt_login"}]))
        .after_delay(MODEL_LATENCY)
        .expect_at_least(1)
        .expect_at_most(2)
        .and()
}

#[tokio::test]
async fn bolt_people_by_name_waits_for_the_model() -> E2EResult<()> {
    check_case("bolt/people-by-name", |mock| {
        accept_bolt_login(mock)
            .on_event("bolt_query")
            .respond_with_actions(serde_json::json!([{
                "type": "send_bolt_records",
                "fields": ["name"],
                "records": [["Ada"], ["Grace"], ["Linus"]]
            }]))
            .after_delay(MODEL_LATENCY)
            .expect_calls(1)
            .and()
    })
    .await
}

#[tokio::test]
async fn bolt_count_waits_for_the_model() -> E2EResult<()> {
    check_case("bolt/count", |mock| {
        accept_bolt_login(mock)
            .on_event("bolt_query")
            .respond_with_actions(serde_json::json!([{
                "type": "send_bolt_records",
                "fields": ["movies"],
                "records": [[42]]
            }]))
            .after_delay(MODEL_LATENCY)
            .expect_calls(1)
            .and()
    })
    .await
}

#[tokio::test]
async fn bolt_syntax_error_waits_for_the_model() -> E2EResult<()> {
    check_case("bolt/syntax-error", |mock| {
        accept_bolt_login(mock)
            .on_event("bolt_query")
            .respond_with_actions(serde_json::json!([{
                "type": "send_bolt_failure",
                "code": "Neo.ClientError.Statement.SyntaxError",
                "message": "Invalid input 'SELECT': expected 'MATCH' (line 1, column 1 (offset: 0))"
            }]))
            .after_delay(MODEL_LATENCY)
            .expect_calls(1)
            .and()
    })
    .await
}

// ---------------------------------------------------------------------------
// smtp — smtplib
// ---------------------------------------------------------------------------

/// A mail server that greets as NetGet Eval Mail, takes every sender, and takes a
/// recipient only at example.com: one rule on `smtp_command`, branching on the
/// command, because the greeting and every command are the same event. EHLO is
/// answered by NetGet and never reaches the model.
fn answer_smtp(mock: MockLlmBuilder, calls: usize) -> MockLlmBuilder {
    mock.on_event("smtp_command")
        .respond_with_actions_from_event(|event| {
            let command = event["command"].as_str().unwrap_or_default().to_string();
            let upper = command.to_ascii_uppercase();
            if upper == "CONNECTION_ESTABLISHED" {
                serde_json::json!([{
                    "type": "send_smtp_greeting",
                    "hostname": "mail.example.com",
                    "message": "NetGet Eval Mail"
                }])
            } else if upper.starts_with("MAIL") {
                serde_json::json!([{"type": "send_smtp_ok", "message": "Sender OK"}])
            } else if upper.starts_with("RCPT") && command.contains("@example.com") {
                serde_json::json!([{"type": "send_smtp_ok", "message": "Recipient OK"}])
            } else {
                serde_json::json!([{
                    "type": "send_smtp_error", "code": 550, "message": "Relaying denied"
                }])
            }
        })
        .after_delay(MODEL_LATENCY)
        .expect_calls(calls)
        .and()
}

#[tokio::test]
async fn smtp_named_banner_waits_for_the_model() -> E2EResult<()> {
    check_case("smtp/named-banner", |mock| answer_smtp(mock, 1)).await
}

#[tokio::test]
async fn smtp_accept_local_domain_waits_for_the_model() -> E2EResult<()> {
    // Greeting, MAIL, RCPT - EHLO is NetGet's own.
    check_case("smtp/accept-local-domain", |mock| answer_smtp(mock, 3)).await
}

#[tokio::test]
async fn smtp_refuse_other_domain_waits_for_the_model() -> E2EResult<()> {
    check_case("smtp/refuse-other-domain", |mock| answer_smtp(mock, 3)).await
}

// ---------------------------------------------------------------------------
// pop3 — poplib
// ---------------------------------------------------------------------------

fn answer_pop3(mock: MockLlmBuilder) -> MockLlmBuilder {
    // Greeting, USER, PASS, then STAT or RETR.
    mock.on_event("pop3_command")
        .respond_with_actions_from_event(|event| {
            let command = event["command"]
                .as_str()
                .unwrap_or_default()
                .to_ascii_uppercase();
            if command == "CONNECTION_ESTABLISHED" {
                serde_json::json!([{"type": "send_pop3_greeting", "message": "POP3 ready"}])
            } else if command.starts_with("STAT") {
                serde_json::json!([{"type": "send_pop3_stat", "message_count": 7, "total_size": 7000}])
            } else if command.starts_with("RETR") {
                serde_json::json!([{
                    "type": "send_pop3_retr",
                    "content": "From: alice@example.com\nTo: eval@example.com\n\
                                Subject: Quarterly figures are in\n\nSee attached."
                }])
            } else {
                serde_json::json!([{"type": "send_pop3_ok", "message": "OK"}])
            }
        })
        .after_delay(MODEL_LATENCY)
        .expect_calls(4)
        .and()
}

#[tokio::test]
async fn pop3_message_count_waits_for_the_model() -> E2EResult<()> {
    check_case("pop3/message-count", answer_pop3).await
}

#[tokio::test]
async fn pop3_message_subject_waits_for_the_model() -> E2EResult<()> {
    check_case("pop3/message-subject", answer_pop3).await
}

// ---------------------------------------------------------------------------
// imap — imaplib
// ---------------------------------------------------------------------------

/// Greeting, LOGIN, and one rule for `imap_command` branching on the command.
/// imaplib issues CAPABILITY on its own before LOGIN; NetGet answers it from the
/// greeting's list, so the model sees only the command under test.
fn answer_imap(mock: MockLlmBuilder) -> MockLlmBuilder {
    mock.on_event("imap_connection")
        .respond_with_actions(serde_json::json!([{
            "type": "send_imap_greeting",
            "hostname": "mail.example.com",
            "capabilities": ["IMAP4rev1"]
        }]))
        .after_delay(MODEL_LATENCY)
        .expect_calls(1)
        .and()
        .on_event("imap_auth")
        .respond_with_actions_from_event(|event| {
            let tag = event["tag"].as_str().unwrap_or("A001").to_string();
            serde_json::json!([{
                "type": "send_imap_response", "tag": tag, "status": "OK",
                "message": "LOGIN completed"
            }])
        })
        .after_delay(MODEL_LATENCY)
        .expect_calls(1)
        .and()
        .on_event("imap_command")
        .respond_with_actions_from_event(|event| {
            let tag = event["tag"].as_str().unwrap_or("A001").to_string();
            let command = event["command"]
                .as_str()
                .unwrap_or_default()
                .to_ascii_uppercase();
            match command.as_str() {
                "LIST" => serde_json::json!([
                    {"type": "send_imap_list", "mailboxes": [
                        {"name": "INBOX", "delimiter": "/", "flags": []},
                        {"name": "Archive", "delimiter": "/", "flags": []},
                        {"name": "Receipts", "delimiter": "/", "flags": []}
                    ]},
                    {"type": "send_imap_response", "tag": tag, "status": "OK",
                     "message": "LIST completed"}
                ]),
                "SELECT" => serde_json::json!([
                    {"type": "send_imap_select", "exists": 12, "recent": 0,
                     "uidvalidity": 1, "uidnext": 13, "flags": ["\\Seen"]},
                    {"type": "send_imap_response", "tag": tag, "status": "OK",
                     "code": "READ-WRITE", "message": "SELECT completed"}
                ]),
                _ => serde_json::json!([
                    {"type": "send_imap_response", "tag": tag, "status": "BAD",
                     "message": format!("unexpected command {command}")}
                ]),
            }
        })
        .after_delay(MODEL_LATENCY)
        .expect_calls(1)
        .and()
}

#[tokio::test]
async fn imap_list_folders_waits_for_the_model() -> E2EResult<()> {
    check_case("imap/list-folders", answer_imap).await
}

#[tokio::test]
async fn imap_inbox_count_waits_for_the_model() -> E2EResult<()> {
    check_case("imap/inbox-count", answer_imap).await
}

// ---------------------------------------------------------------------------
// nntp — nntplib
// ---------------------------------------------------------------------------

/// Greeting, then the command under test. nntplib sends CAPABILITIES on connect;
/// NetGet answers it, so it never reaches the model.
fn answer_nntp(mock: MockLlmBuilder) -> MockLlmBuilder {
    mock.on_event("nntp_command_received")
        .respond_with_actions_from_event(|event| {
            let command = event["command"]
                .as_str()
                .unwrap_or_default()
                .to_ascii_uppercase();
            if command == "GREETING" {
                serde_json::json!([{
                    "type": "send_nntp_response", "code": 201, "text": "NetGet news ready"
                }])
            } else if command == "GROUP COMP.LANG.EVAL" {
                serde_json::json!([{
                    "type": "send_nntp_group",
                    "name": "comp.lang.eval", "count": 42, "low": 1, "high": 42
                }])
            } else if command.starts_with("GROUP") {
                serde_json::json!([{
                    "type": "send_nntp_response", "code": 411, "text": "No such newsgroup"
                }])
            } else if command.starts_with("LIST") {
                serde_json::json!([{
                    "type": "send_nntp_list",
                    "groups": [
                        {"name": "comp.lang.eval", "high": 42, "low": 1, "status": "y"},
                        {"name": "alt.netget.test", "high": 7, "low": 1, "status": "y"}
                    ]
                }])
            } else {
                serde_json::json!([{
                    "type": "send_nntp_response", "code": 500, "text": "Command not recognized"
                }])
            }
        })
        .after_delay(MODEL_LATENCY)
        .expect_calls(2)
        .and()
}

#[tokio::test]
async fn nntp_group_article_count_waits_for_the_model() -> E2EResult<()> {
    check_case("nntp/group-article-count", answer_nntp).await
}

#[tokio::test]
async fn nntp_list_groups_waits_for_the_model() -> E2EResult<()> {
    check_case("nntp/list-groups", answer_nntp).await
}

#[tokio::test]
async fn nntp_unknown_group_waits_for_the_model() -> E2EResult<()> {
    check_case("nntp/unknown-group", answer_nntp).await
}

// ---------------------------------------------------------------------------
// memcached — pymemcache
// ---------------------------------------------------------------------------

fn answer_memcached_get(mock: MockLlmBuilder) -> MockLlmBuilder {
    mock.on_event("memcached_get")
        .respond_with_actions_from_event(|event| {
            let key = event["keys"][0].as_str().unwrap_or_default().to_string();
            if key == "motd" {
                serde_json::json!([{
                    "type": "send_memcached_values",
                    "values": [{"key": key, "value": "netget-eval-cache-hit", "flags": 0}]
                }])
            } else {
                serde_json::json!([{"type": "send_memcached_values", "values": []}])
            }
        })
        .after_delay(MODEL_LATENCY)
        .expect_calls(1)
        .and()
}

#[tokio::test]
async fn memcached_get_value_waits_for_the_model() -> E2EResult<()> {
    check_case("memcached/get-value", answer_memcached_get).await
}

#[tokio::test]
async fn memcached_missing_key_waits_for_the_model() -> E2EResult<()> {
    check_case("memcached/missing-key", answer_memcached_get).await
}

#[tokio::test]
async fn memcached_stats_version_waits_for_the_model() -> E2EResult<()> {
    check_case("memcached/stats-version", |mock| {
        mock.on_event("memcached_stats")
            .respond_with_actions(serde_json::json!([{
                "type": "send_memcached_stats",
                "stats": {"pid": "4242", "uptime": "600", "version": "1.6.21", "curr_items": "12"}
            }]))
            .after_delay(MODEL_LATENCY)
            .expect_calls(1)
            .and()
    })
    .await
}

// ---------------------------------------------------------------------------
// mqtt — mosquitto_sub
// ---------------------------------------------------------------------------

#[tokio::test]
async fn mqtt_retained_message_waits_for_the_model() -> E2EResult<()> {
    check_case("mqtt/retained-message", |mock| {
        mock.on_event("mqtt_connect")
            .respond_with_actions(serde_json::json!([{"type": "mqtt_connack", "return_code": 0}]))
            .after_delay(MODEL_LATENCY)
            .expect_calls(1)
            .and()
            // The SUBACK, then the retained message on the same connection.
            .on_event("mqtt_subscribe")
            .respond_with_actions_from_event(|event| {
                serde_json::json!([
                    {"type": "mqtt_suback",
                     "packet_id": event["packet_id"].as_u64().unwrap_or(0),
                     "granted_qos": [0]},
                    {"type": "mqtt_publish", "topic": "sensors/greenhouse/temp",
                     "payload": "19.5", "qos": 0, "retain": true}
                ])
            })
            .after_delay(MODEL_LATENCY)
            .expect_calls(1)
            .and()
    })
    .await
}

#[tokio::test]
async fn mqtt_refuse_client_id_waits_for_the_model() -> E2EResult<()> {
    check_case("mqtt/refuse-client-id", |mock| {
        mock.on_event("mqtt_connect")
            .and_event_data_contains("client_id", "guest")
            .respond_with_actions(serde_json::json!([{"type": "mqtt_connack", "return_code": 2}]))
            .after_delay(MODEL_LATENCY)
            .expect_calls(1)
            .and()
    })
    .await
}

// ---------------------------------------------------------------------------
// coap — coap-client
// ---------------------------------------------------------------------------

fn answer_coap(mock: MockLlmBuilder) -> MockLlmBuilder {
    mock.on_event("coap_request")
        .respond_with_actions_from_event(|event| {
            if event["path"].as_str() == Some("/temperature") {
                serde_json::json!([{
                    "type": "send_coap_response", "code": "2.05",
                    "payload": "19.5 C", "content_format": "text/plain"
                }])
            } else {
                serde_json::json!([{"type": "send_coap_response", "code": "4.04"}])
            }
        })
        .after_delay(MODEL_LATENCY)
        .expect_calls(1)
        .and()
}

#[tokio::test]
async fn coap_text_resource_waits_for_the_model() -> E2EResult<()> {
    check_case("coap/text-resource", answer_coap).await
}

#[tokio::test]
async fn coap_not_found_waits_for_the_model() -> E2EResult<()> {
    check_case("coap/not-found", answer_coap).await
}

// ---------------------------------------------------------------------------
// modbus — pymodbus
// ---------------------------------------------------------------------------

fn answer_modbus(mock: MockLlmBuilder) -> MockLlmBuilder {
    mock.on_event("modbus_read_registers")
        .respond_with_actions_from_event(|event| {
            // Each device's registers, keyed by address, as the read answer asks for them. The
            // illegal-address device's map, 0-9, has no 500, which NetGet answers exception 2.
            if event["start_address"].as_u64() == Some(0) {
                serde_json::json!([{"type": "send_modbus_registers",
                                    "registers": {"0": 1200, "1": 350, "2": 42}}])
            } else {
                let registers: serde_json::Map<String, serde_json::Value> = (0..10)
                    .map(|a| (a.to_string(), serde_json::json!(0)))
                    .collect();
                serde_json::json!([{"type": "send_modbus_registers", "registers": registers}])
            }
        })
        .after_delay(MODEL_LATENCY)
        .expect_calls(1)
        .and()
}

#[tokio::test]
async fn modbus_holding_registers_waits_for_the_model() -> E2EResult<()> {
    check_case("modbus/holding-registers", answer_modbus).await
}

#[tokio::test]
async fn modbus_illegal_address_waits_for_the_model() -> E2EResult<()> {
    check_case("modbus/illegal-address", answer_modbus).await
}

// ---------------------------------------------------------------------------
// snmp — snmpget
// ---------------------------------------------------------------------------

fn answer_snmp(mock: MockLlmBuilder) -> MockLlmBuilder {
    mock.on_event("snmp_request")
        .respond_with_actions_from_event(|event| {
            let variables: Vec<serde_json::Value> = event["oids"]
                .as_array()
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .map(|oid| {
                    let oid = oid.as_str().unwrap_or_default().to_string();
                    let value = if oid.ends_with("1.1.5.0") {
                        "eval-core-01"
                    } else {
                        "NetGet Eval Switch 1.0"
                    };
                    serde_json::json!({"oid": oid, "type": "string", "value": value})
                })
                .collect();
            serde_json::json!([{"type": "send_snmp_response", "variables": variables}])
        })
        .after_delay(MODEL_LATENCY)
        .expect_calls(1)
        .and()
}

#[tokio::test]
async fn snmp_sysdescr_waits_for_the_model() -> E2EResult<()> {
    check_case("snmp/sysdescr", answer_snmp).await
}

#[tokio::test]
async fn snmp_sysdescr_and_sysname_waits_for_the_model() -> E2EResult<()> {
    check_case("snmp/sysdescr-and-sysname", answer_snmp).await
}

// ---------------------------------------------------------------------------
// sip — sipsak
// ---------------------------------------------------------------------------

/// sipsak's first resend comes at T1 = 10s, after the mocked 5s answer, so the
/// model is asked once; the second allowance covers a resend under load.
fn answer_sip(mock: MockLlmBuilder, status: u16, reason: &str) -> MockLlmBuilder {
    mock.on_event("sip_options")
        .respond_with_actions(serde_json::json!([{
            "type": "sip_options",
            "status_code": status,
            "reason_phrase": reason,
            "allow_methods": ["INVITE", "ACK", "BYE", "CANCEL", "OPTIONS"]
        }]))
        .after_delay(MODEL_LATENCY)
        .expect_at_least(1)
        .expect_at_most(2)
        .and()
}

#[tokio::test]
async fn sip_available_waits_for_the_model() -> E2EResult<()> {
    check_case("sip/available", |mock| answer_sip(mock, 200, "OK")).await
}

#[tokio::test]
async fn sip_busy_waits_for_the_model() -> E2EResult<()> {
    check_case("sip/busy", |mock| answer_sip(mock, 486, "Busy Here")).await
}

// ---------------------------------------------------------------------------
// websocket — websocat
// ---------------------------------------------------------------------------

fn accept_websocket(mock: MockLlmBuilder) -> MockLlmBuilder {
    mock.on_event("websocket_handshake")
        .respond_with_actions(serde_json::json!([{"type": "accept_websocket"}]))
        .after_delay(MODEL_LATENCY)
        .expect_calls(1)
        .and()
}

#[tokio::test]
async fn websocket_echo_waits_for_the_model() -> E2EResult<()> {
    check_case("websocket/echo", |mock| {
        accept_websocket(mock)
            .on_event("websocket_connection_opened")
            .respond_with_actions(serde_json::json!([]))
            .after_delay(MODEL_LATENCY)
            .expect_calls(1)
            .and()
            .on_event("websocket_text_message")
            .respond_with_actions_from_event(|event| {
                serde_json::json!([{
                    "type": "send_websocket_text",
                    "text": event["text"].as_str().unwrap_or_default()
                }])
            })
            .after_delay(MODEL_LATENCY)
            .expect_calls(1)
            .and()
    })
    .await
}

#[tokio::test]
async fn websocket_greeting_waits_for_the_model() -> E2EResult<()> {
    check_case("websocket/greeting", |mock| {
        accept_websocket(mock)
            .on_event("websocket_connection_opened")
            .respond_with_actions(serde_json::json!([{
                "type": "send_websocket_text", "text": "Welcome to NetGet Eval"
            }]))
            .after_delay(MODEL_LATENCY)
            .expect_calls(1)
            .and()
    })
    .await
}

// ---------------------------------------------------------------------------
// nsq — nsq_tail and to_nsq
// ---------------------------------------------------------------------------

#[tokio::test]
async fn nsq_deliver_waiting_messages_waits_for_the_model() -> E2EResult<()> {
    check_case("nsq/deliver-waiting-messages", |mock| {
        mock.on_event("nsq_subscribe")
            .respond_with_actions(serde_json::json!([{"type": "send_nsq_ok"}]))
            .after_delay(MODEL_LATENCY)
            .expect_calls(1)
            .and()
            .on_event("nsq_ready")
            .respond_with_actions(serde_json::json!([{
                "type": "deliver_nsq_messages",
                "messages": [{"body": "order 1 shipped"}, {"body": "order 2 packed"}]
            }]))
            .after_delay(MODEL_LATENCY)
            .expect_calls(1)
            .and()
            // nsq_tail exits from inside its handler for the last message, so whether its
            // FINs reach the server is a race; answered with nothing either way.
            .on_event("nsq_finish")
            .respond_with_actions(serde_json::json!([]))
            .expect_at_most(2)
            .and()
    })
    .await
}

#[tokio::test]
async fn nsq_accept_publish_waits_for_the_model() -> E2EResult<()> {
    check_case("nsq/accept-publish", |mock| {
        mock.on_event("nsq_publish")
            .respond_with_actions(serde_json::json!([{"type": "send_nsq_ok"}]))
            .after_delay(MODEL_LATENCY)
            .expect_calls(1)
            .and()
    })
    .await
}

#[tokio::test]
async fn nsq_refuse_closed_topic_waits_for_the_model() -> E2EResult<()> {
    check_case("nsq/refuse-closed-topic", |mock| {
        mock.on_event("nsq_publish")
            .respond_with_actions(serde_json::json!([{
                "type": "send_nsq_error", "code": "E_PUB_FAILED", "message": "topic is closed"
            }]))
            .after_delay(MODEL_LATENCY)
            .expect_calls(1)
            .and()
    })
    .await
}

// ---------------------------------------------------------------------------
// otlp — otel-cli
// ---------------------------------------------------------------------------

fn answer_otlp(mock: MockLlmBuilder) -> MockLlmBuilder {
    mock.on_event("otlp_export")
        .respond_with_actions_from_event(|event| {
            if event["service_name"] == "checkout" && event["span_names"][0] != "debug-probe" {
                serde_json::json!([{"type": "accept_otlp"}])
            } else {
                serde_json::json!([{"type": "reject_otlp", "code": 403, "message": "refused"}])
            }
        })
        .after_delay(MODEL_LATENCY)
        .expect_calls(1)
        .and()
}

#[tokio::test]
async fn otlp_accept_known_service_waits_for_the_model() -> E2EResult<()> {
    check_case("otlp/accept-known-service", answer_otlp).await
}

#[tokio::test]
async fn otlp_refuse_unknown_service_waits_for_the_model() -> E2EResult<()> {
    check_case("otlp/refuse-unknown-service", answer_otlp).await
}

#[tokio::test]
async fn otlp_refuse_debug_spans_waits_for_the_model() -> E2EResult<()> {
    check_case("otlp/refuse-debug-spans", answer_otlp).await
}

// ---------------------------------------------------------------------------
// nostr — nak
// ---------------------------------------------------------------------------

#[tokio::test]
async fn nostr_serve_notes_waits_for_the_model() -> E2EResult<()> {
    check_case("nostr/serve-notes", |mock| {
        mock.on_event("nostr_req")
            .respond_with_actions(serde_json::json!([{
                "type": "send_nostr_events",
                "events": [
                    {"kind": 1, "content": "Stalker is a masterpiece"},
                    {"kind": 1, "content": "Solaris is slower but worth it"}
                ]
            }]))
            .after_delay(MODEL_LATENCY)
            .expect_calls(1)
            .and()
    })
    .await
}

#[tokio::test]
async fn nostr_refuse_adverts_waits_for_the_model() -> E2EResult<()> {
    check_case("nostr/refuse-adverts", |mock| {
        mock.on_event("nostr_event")
            .respond_with_actions(serde_json::json!([{
                "type": "reject_nostr_event",
                "reason": "blocked: adverts are not allowed"
            }]))
            .after_delay(MODEL_LATENCY)
            .expect_calls(1)
            .and()
    })
    .await
}

#[tokio::test]
async fn nostr_accept_film_note_waits_for_the_model() -> E2EResult<()> {
    check_case("nostr/accept-film-note", |mock| {
        mock.on_event("nostr_event")
            .respond_with_actions(serde_json::json!([{"type": "accept_nostr_event"}]))
            .after_delay(MODEL_LATENCY)
            .expect_calls(1)
            .and()
    })
    .await
}
