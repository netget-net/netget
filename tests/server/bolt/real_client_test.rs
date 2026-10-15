//! Bolt against a real, independent client: Neo4j's own `cypher-shell`.
//!
//! `cypher-shell` 2026.09 (`brew install cypher-shell`; Neo4j's Debian/Ubuntu repository or the
//! release zip on Linux) is Java, built on neo4j-java-driver 6.2, which NetGet neither links nor
//! wrote — and NetGet uses no Bolt library at all. It is run as a subprocess and what it
//! *printed* is asserted, which means it negotiated our version, accepted our HELLO agent,
//! decoded our PackStream, reassembled our chunks, followed our state machine through RUN,
//! PULL, RESET, BEGIN/COMMIT and ROUTE, and classified our FAILUREs. Every other test in this
//! directory is NetGet's codec reading bytes NetGet's codec wrote.
//!
//! **These tests FAIL, they do not skip, when `cypher-shell` (or the Java runtime it needs) is
//! absent.** A skip-when-missing gate returns `Ok(())` on a runner without the binary, so the
//! suite reports a silent pass and any rating resting on it rests on nothing.
//! `tests/server/memcached/real_client_test.rs` is the precedent.
//!
//! The graph is a Python script handler (`common::GRAPH_SCRIPT`), so these cases are
//! deterministic and consult no model; the last test puts a mocked model behind the same
//! client, because the model path is the one the protocol exists for.
//!
//! No pcap oracle: this Wireshark build (4.6.8) has no Bolt dissector.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features bolt --test server -- bolt::real_client --test-threads=100


use super::common;
use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
use std::time::Duration;

const INSTALL: &str = "Install with `brew install cypher-shell` (macOS; pulls in openjdk@21) or, \
                       on Debian/Ubuntu, `apt-get install -y openjdk-21-jre-headless` and the \
                       cypher-shell release zip from \
                       https://dist.neo4j.org/cypher-shell/cypher-shell-2026.09.0.zip";

/// Locate a binary, or fail saying why a skip would be worse. Named `require_tool("…")` so
/// `scripts/beta_evidence_table.py` can see which third-party client this file drives.
pub fn require_tool(name: &str) -> String {
    if let Some(found) = crate::helpers::real_server::find_binary(name) {
        return found.to_string_lossy().into_owned();
    }
    panic!(
        "`{name}` not found (searched /opt/homebrew/bin, /usr/local/bin, /usr/bin and $PATH). \
         These tests drive Neo4j's own cypher-shell against NetGet's Bolt server, and that is \
         the only independent check that our handshake, PackStream, chunking and state machine \
         are acceptable to something we did not write. Skipping would leave the Bolt evidence \
         resting on nothing, so this is a failure and not a skip. {INSTALL}"
    );
}

/// What one cypher-shell run printed.
pub struct Shell {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

impl Shell {
    /// stdout's lines, trimmed of trailing whitespace, empties dropped.
    pub fn lines(&self) -> Vec<String> {
        self.stdout
            .lines()
            .map(|l| l.trim_end().to_string())
            .filter(|l| !l.is_empty())
            .collect()
    }
}

/// Run the CLI with an owned HOME and explicit credential environment; no credential CLI args.
pub async fn cypher_shell(uri: &str, password: &str, args: &[&str]) -> Shell {
    shell(uri, password, args, false).await
}
async fn cypher_shell_diagnostics(uri: &str, password: &str, args: &[&str]) -> Shell {
    shell(uri, password, args, true).await
}
// Both5.26 and2026 support native --log, which retains independent driver exception classes.
async fn shell(uri: &str, password: &str, args: &[&str], diagnostics: bool) -> Shell {
    let bin = require_tool("cypher-shell");
    let home = tempfile::TempDir::new().expect("temp HOME");
    let mut command = tokio::process::Command::new(&bin);
    command
        .arg("-a")
        .arg(uri)
        .arg("--non-interactive")
        .args(args)
        .env("HOME", home.path())
        .env_remove("NEO4J_ADDRESS")
        .env_remove("NEO4J_URI")
        .env("NEO4J_USERNAME", "neo4j")
        .env("NEO4J_PASSWORD", password)
        .env_remove("NEO4J_DATABASE")
        .kill_on_drop(true);
    let diagnostic_file = home.path().join("driver.log");
    if diagnostics {
        command.arg("--log").arg(&diagnostic_file);
    }
    let output = tokio::time::timeout(Duration::from_secs(180), command.output())
        .await
        .unwrap_or_else(|_| panic!("cypher-shell {args:?} did not exit within 180s"))
        .expect("run cypher-shell");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    // The JVM's own ThreadPriorityPolicy notice is not cypher-shell talking.
    let mut stderr: String = String::from_utf8_lossy(&output.stderr)
        .lines()
        .filter(|l| !l.contains("ThreadPriorityPolicy"))
        .collect::<Vec<_>>()
        .join("\n");
    if diagnostics {
        let log = std::fs::read_to_string(diagnostic_file).expect("native cypher-shell driver log");
        assert!(
            log.len() <= 1024 * 1024,
            "owned driver diagnostic log bound"
        );
        stderr.push_str(&log);
    }
    stderr = stderr.replace(password, "<redacted>");
    println!(
        "--- cypher-shell -a {uri} {} (exit {:?}) ---\n{stdout}{stderr}",
        args.join(" "),
        output.status.code()
    );
    if stderr.contains("Unable to locate a Java Runtime")
        || stderr.contains("JAVA_HOME is not defined correctly")
        || stderr.contains("java: not found")
        || stderr.contains("java: command not found")
    {
        panic!("cypher-shell is installed but cannot find a Java runtime. {INSTALL}\n{stderr}");
    }
    Shell {
        code: output.status.code().unwrap_or(-1),
        stdout,
        stderr,
    }
}

async fn graph_server(
    params: Option<serde_json::Value>,
) -> (netget::state::app_state::AppState, u16) {
    let state = common::new_state().await;
    let (_id, port, _rx) = common::start(
        &state,
        vec![common::accept_logins(), common::graph_handler()],
        params,
    )
    .await;
    (state, port)
}

#[tokio::test]
async fn cypher_shell_prints_exactly_the_rows_the_graph_returned() {
    let (_state, port) = graph_server(None).await;
    let out = cypher_shell(
        &format!("bolt://127.0.0.1:{port}"),
        "pw",
        &[
            "--format",
            "plain",
            "MATCH (n:Person) RETURN n.name AS name",
        ],
    )
    .await;
    assert_eq!(out.code, 0, "{}{}", out.stdout, out.stderr);
    assert_eq!(out.lines(), ["name", "\"Alice\"", "\"Bob\""]);
}

#[tokio::test]
async fn cypher_shell_renders_nodes_relationships_and_paths_as_graph_values() {
    let (_state, port) = graph_server(None).await;
    let uri = format!("bolt://127.0.0.1:{port}");

    let out = cypher_shell(
        &uri,
        "pw",
        &["--format", "plain", "MATCH (n:Person) RETURN n"],
    )
    .await;
    assert_eq!(out.code, 0, "{}{}", out.stdout, out.stderr);
    assert_eq!(
        out.lines(),
        ["n", "(:Person {name: \"Alice\", born: 1990})"]
    );

    let out = cypher_shell(
        &uri,
        "pw",
        &["--format", "plain", "MATCH ()-[r]->() RETURN r"],
    )
    .await;
    assert_eq!(out.code, 0, "{}{}", out.stdout, out.stderr);
    assert_eq!(out.lines(), ["r", "[:ACTED_IN {role: \"Neo\"}]"]);

    let out = cypher_shell(
        &uri,
        "pw",
        &["--format", "plain", "MATCH p=()-->() RETURN p"],
    )
    .await;
    assert_eq!(out.code, 0, "{}{}", out.stdout, out.stderr);
    assert_eq!(
        out.lines(),
        [
            "p",
            "(:Person {name: \"Alice\", born: 1990})-[:ACTED_IN {role: \"Neo\"}]->(:Movie {title: \"The Matrix\"})"
        ]
    );

    // The same relationship walked from its end: the driver read our negative index.
    let out = cypher_shell(
        &uri,
        "pw",
        &["--format", "plain", "MATCH back=()<--() RETURN back"],
    )
    .await;
    assert_eq!(out.code, 0, "{}{}", out.stdout, out.stderr);
    assert_eq!(
        out.lines(),
        [
            "back",
            "(:Movie {title: \"The Matrix\"})<-[:ACTED_IN {role: \"Neo\"}]-(:Person {name: \"Alice\", born: 1990})"
        ]
    );
}

#[tokio::test]
async fn cypher_shell_prints_the_write_statistics() {
    let (_state, port) = graph_server(None).await;
    let out = cypher_shell(
        &format!("bolt://127.0.0.1:{port}"),
        "pw",
        &[
            "--format",
            "verbose",
            "CREATE (n:Person {name: 'Zed', born: 2000})",
        ],
    )
    .await;
    assert_eq!(out.code, 0, "{}{}", out.stdout, out.stderr);
    assert!(
        out.stdout
            .contains("Created 1 node, set 2 properties, added 1 label")
            || out
                .stdout
                .contains("Added 1 nodes, Set 2 properties, Added 1 labels"),
        "{}",
        out.stdout
    );
}

#[tokio::test]
async fn a_failure_code_is_raised_by_the_driver_as_that_error() {
    let (_state, port) = graph_server(None).await;
    let uri = format!("bolt://127.0.0.1:{port}");
    let out = cypher_shell(&uri, "pw", &["--format", "plain", "RETRUN 1"]).await;
    assert_eq!(out.code, 1, "{}{}", out.stdout, out.stderr);
    assert!(
        out.stderr.contains("This graph only knows Person nodes"),
        "{}",
        out.stderr
    );
    // The driver maps the Neo4j status code to an exception class; a stack trace names it.
    let out = cypher_shell_diagnostics(&uri, "pw", &["RETRUN 1"]).await;
    assert!(
        out.stderr.contains(
            "org.neo4j.driver.exceptions.ClientException: This graph only knows Person nodes"
        ),
        "{}",
        out.stderr
    );
}

#[tokio::test]
async fn a_wrong_password_is_cypher_shells_authentication_error() {
    let (_state, port) = graph_server(Some(serde_json::json!({"password": "right"}))).await;
    let uri = format!("bolt://127.0.0.1:{port}");

    let out = cypher_shell(&uri, "wrong", &["RETURN 1"]).await;
    assert_eq!(out.code, 1, "{}{}", out.stdout, out.stderr);
    assert!(
        out.stderr
            .contains("The client is unauthorized due to authentication failure."),
        "{}",
        out.stderr
    );
    let out = cypher_shell_diagnostics(&uri, "wrong", &["RETURN 1"]).await;
    assert!(
        out.stderr
            .contains("org.neo4j.driver.exceptions.AuthenticationException"),
        "{}",
        out.stderr
    );

    let out = cypher_shell(
        &uri,
        "right",
        &[
            "--format",
            "plain",
            "MATCH (n:Person) RETURN n.name AS name",
        ],
    )
    .await;
    assert_eq!(out.code, 0, "{}{}", out.stdout, out.stderr);
    assert_eq!(out.lines(), ["name", "\"Alice\"", "\"Bob\""]);
}

#[tokio::test]
async fn an_explicit_transaction_with_parameters_and_a_database_runs_to_commit() {
    let (_state, port) = graph_server(None).await;
    let dir = tempfile::TempDir::new().unwrap();
    let file = dir.path().join("tx.cypher");
    std::fs::write(
        &file,
        ":begin\nCREATE (n:Person {name: $x});\nMATCH (p:Person) RETURN $x AS x;\n:commit\n",
    )
    .unwrap();
    let out = cypher_shell(
        &format!("bolt://127.0.0.1:{port}"),
        "pw",
        &[
            "-d",
            "movies",
            "-P",
            "{x: 'param-value'}",
            "--format",
            "plain",
            "-f",
            file.to_str().unwrap(),
        ],
    )
    .await;
    assert_eq!(out.code, 0, "{}{}", out.stdout, out.stderr);
    // The handler echoes $x: the parameter crossed the wire and came back as a record.
    assert_eq!(out.lines(), ["x", "\"param-value\""], "{}", out.stderr);
}

#[tokio::test]
async fn neo4j_scheme_routing_comes_back_to_this_server() {
    let (_state, port) = graph_server(None).await;
    let out = cypher_shell(
        &format!("neo4j://127.0.0.1:{port}"),
        "pw",
        &[
            "--format",
            "plain",
            "MATCH (n:Person) RETURN n.name AS name",
        ],
    )
    .await;
    assert_eq!(out.code, 0, "{}{}", out.stdout, out.stderr);
    assert_eq!(out.lines(), ["name", "\"Alice\"", "\"Bob\""]);
}

/// The model path, behind the same real client: a mocked model accepts the login and answers
/// the query with rows built from the event, and cypher-shell prints them. Connecting costs
/// nothing more: cypher-shell's own `db.ping()` and `dbms.licenseAgreementDetails()` are
/// answered by NetGet, which `expect_calls(1)` on the query rule proves.
#[tokio::test]
async fn cypher_shell_prints_the_rows_a_model_wrote() -> E2EResult<()> {
    let _ = require_tool("cypher-shell");
    let config =
        NetGetConfig::new("listen on port {AVAILABLE_PORT} via bolt. A graph of film people.")
            .with_log_level("debug")
            .with_mock(|mock| {
                mock.on_instruction_containing("via bolt")
                    .respond_with_actions(serde_json::json!([{
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "bolt",
                        "instruction": "A graph of film people"
                    }]))
                    .expect_calls(1)
                    .and()
                    .on_event("bolt_authenticate")
                    .and_event_data_contains("principal", "neo4j")
                    .respond_with_actions(serde_json::json!([{"type": "accept_bolt_login"}]))
                    // One or two: the Java driver's pool sometimes opens a second connection
                    // while the first is still running cypher-shell's connect queries, and each
                    // connection logs in (observed in 2 of 3 runs at --test-threads=100).
                    .expect_at_least(1)
                    .expect_at_most(2)
                    .and()
                    .on_event("bolt_query")
                    .respond_with_actions_from_event(|event| {
                        let query = event["query"].as_str().unwrap_or("").to_string();
                        serde_json::json!([{
                            "type": "send_bolt_records",
                            "fields": ["title", "released"],
                            "records": [["The Matrix", 1999], [format!("asked: {query}"), 2026]]
                        }])
                    })
                    .expect_calls(1)
                    .and()
            });

    let server = start_netget_server(config).await?;
    let out = cypher_shell(
        &format!("bolt://127.0.0.1:{}", server.port),
        "pw",
        &[
            "--format",
            "plain",
            "MATCH (m:Movie) RETURN m.title AS title, m.released AS released",
        ],
    )
    .await;
    assert_eq!(out.code, 0, "{}{}", out.stdout, out.stderr);
    assert_eq!(
        out.lines(),
        [
            "title, released",
            "\"The Matrix\", 1999",
            "\"asked: MATCH (m:Movie) RETURN m.title AS title, m.released AS released\", 2026"
        ]
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}
