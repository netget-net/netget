//! NetGet's Db2 server against an independent DRDA client: **Apache Derby 10.17.1.0's JDBC
//! client driver** (`derbyclient.jar`, `org.apache.derby.client.net`), driven through Derby's
//! `ij` tool. Derby's driver shares no code with NetGet; it negotiates manager levels, chains
//! its requests (EXCSAT with ACCSEC, SECCHK with ACCRDB, EXCSQLIMM with its SQLSTT and the
//! autocommit RDBCMM) and reads every reply with its own FD:OCA parser.
//!
//! What it shows, from the client's side:
//! - the model's login decision: `app` is accepted and `intruder` refused;
//! - the SQL text the model is shown is the statement the driver sent, decoded from SQLSTT;
//! - the model's row count reaches the driver (`1 row inserted/updated/deleted`, SQLERRD3);
//! - the model's SQLCODE/SQLSTATE reach the driver (`ERROR 42704`);
//! - autocommit's RDBCMM is answered.
//!
//! After the error the driver asks for message text with PRPSQLSTT (`CALL
//! SYSIBM.SQLCAMESSAGE`); that is answered with one CMDNSPRM, its command data unanswered and
//! never shown to the model, and the driver prints the SQLCODE and SQLSTATE without text.
//!
//! A recording proxy hands the conversation to tshark's DRDA dissector.
//!
//! **Fails rather than skips** without java or the Derby jars (`NETGET_DERBY_LIB`, from
//! `tests/client/db2/install_derby.py`) or tshark. LLM calls: 6.

use super::super::super::helpers::pcap_oracle::PcapOracle;
use super::super::super::helpers::real_server::{run_tool, InstallHint};
use super::super::super::helpers::{self, E2EResult, NetGetConfig};
use std::path::PathBuf;
use std::process::Command;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const DERBY_VERSION: &str = "10.17.1.0";
const JAVA: InstallHint = InstallHint {
    brew: "openjdk@21 (Derby 10.17 needs Java 21 or newer)",
    apt: "openjdk-21-jre-headless",
};

fn client_classpath() -> E2EResult<String> {
    let dir = std::env::var_os("NETGET_DERBY_LIB")
        .map(PathBuf::from)
        .ok_or(
            "NETGET_DERBY_LIB is not set. This test drives NetGet's Db2 server with Apache \
             Derby's JDBC client and FAILS rather than skipping without it: run \
             `python3 tests/client/db2/install_derby.py /some/dir` and export the \
             NETGET_DERBY_LIB it prints (Java 21+ is needed too).",
        )?;
    let mut parts = Vec::new();
    for jar in ["derbytools", "derbyclient", "derbyshared"] {
        let p = dir.join(format!("{jar}-{DERBY_VERSION}.jar"));
        if !p.is_file() {
            return Err(format!(
                "{} is missing; run tests/client/db2/install_derby.py",
                p.display()
            )
            .into());
        }
        parts.push(p.display().to_string());
    }
    Ok(parts.join(":"))
}

async fn ij(port: u16, script: &str) -> E2EResult<String> {
    let cp = client_classpath()?;
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("script.sql");
    std::fs::write(&path, script.replace("{port}", &port.to_string()))?;
    let mut cmd = Command::new("java");
    cmd.arg("-Dij.driver=org.apache.derby.client.ClientAutoloadedDriver")
        .arg("-cp")
        .arg(cp)
        .arg("org.apache.derby.tools.ij")
        .arg(&path);
    run_tool(cmd, "java", JAVA).await
}

type Recording = Arc<Mutex<Vec<(bool, Vec<u8>)>>>;

/// A loopback relay to `target` recording both directions (`true` = client to server).
async fn recording_proxy(target: u16) -> E2EResult<(u16, Recording)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let recording: Recording = Arc::default();
    let rec = recording.clone();
    tokio::spawn(async move {
        while let Ok((client, _)) = listener.accept().await {
            let Ok(server) = TcpStream::connect(("127.0.0.1", target)).await else {
                continue;
            };
            let (cr, cw) = client.into_split();
            let (sr, sw) = server.into_split();
            tokio::spawn(relay(cr, sw, true, rec.clone()));
            tokio::spawn(relay(sr, cw, false, rec.clone()));
        }
    });
    Ok((port, recording))
}

async fn relay(
    mut from: tokio::net::tcp::OwnedReadHalf,
    mut to: tokio::net::tcp::OwnedWriteHalf,
    up: bool,
    rec: Recording,
) {
    let mut b = vec![0u8; 65536];
    while let Ok(n) = from.read(&mut b).await {
        if n == 0 {
            break;
        }
        rec.lock().unwrap().push((up, b[..n].to_vec()));
        if to.write_all(&b[..n]).await.is_err() {
            break;
        }
    }
    let _ = to.shutdown().await;
}

#[tokio::test]
async fn derby_jdbc_client_against_netget_db2_server() -> E2EResult<()> {
    let config = NetGetConfig::new(
        "Start an IBM Db2 server on port {AVAILABLE_PORT}. DB2-DERBY-CLIENT-STARTUP.",
    )
    .with_mock(|mock| {
        mock.on_instruction_containing("DB2-DERBY-CLIENT-STARTUP")
            .respond_with_actions(serde_json::json!([{
                "type": "open_server", "port": 0, "base_stack": "db2",
                "instruction": "A Db2 server: admit app, refuse anyone else."
            }]))
            .expect_calls(1)
            .and()
            .on_event("db2_connect")
            .and_event_data_contains("user_id", "app")
            .and_event_data_contains("rdb_name", "SAMPLE")
            .respond_with_actions(serde_json::json!([{ "type": "db2_accept_connection" }]))
            .expect_calls(1)
            .and()
            .on_event("db2_connect")
            .and_event_data_contains("user_id", "intruder")
            .respond_with_actions(serde_json::json!([{
                "type": "db2_reject_connection", "sec_check_code": "password_invalid"
            }]))
            .expect_calls(1)
            .and()
            .on_event("db2_query")
            .and_event_data_contains("sql_text", "create table notes (id int, body varchar(40))")
            .respond_with_actions(serde_json::json!([{ "type": "db2_query_ok", "sqlcode": 0 }]))
            .expect_calls(1)
            .and()
            .on_event("db2_query")
            .and_event_data_contains("sql_text", "insert into notes values (1, 'héllo')")
            .respond_with_actions(serde_json::json!([{
                "type": "db2_query_ok", "sqlcode": 0, "rows_affected": 1
            }]))
            .expect_calls(1)
            .and()
            .on_event("db2_query")
            .and_event_data_contains("sql_text", "drop table nosuch")
            .respond_with_actions(serde_json::json!([{
                "type": "db2_query_error", "sqlcode": -204, "sqlstate": "42704",
                "message": "NOSUCH is an undefined name"
            }]))
            .expect_calls(1)
            .and()
    });
    let server = helpers::start_netget_server(config).await?;
    let (proxy_port, recording) = recording_proxy(server.port).await?;

    let out = ij(
        proxy_port,
        "connect 'jdbc:derby://127.0.0.1:{port}/SAMPLE;user=app;password=secret';\n\
         create table notes (id int, body varchar(40));\n\
         insert into notes values (1, 'héllo');\n\
         drop table nosuch;\n\
         disconnect;\n\
         connect 'jdbc:derby://127.0.0.1:{port}/SAMPLE;user=intruder;password=wrong';\n\
         exit;\n",
    )
    .await?;
    println!("{out}");

    server.verify_mocks().await?;
    assert!(
        out.contains("0 rows inserted/updated/deleted"),
        "the CREATE must succeed for Derby's driver:\n{out}"
    );
    assert!(
        out.contains("1 row inserted/updated/deleted"),
        "the model's row count must reach the driver in SQLERRD3:\n{out}"
    );
    assert!(
        out.contains("ERROR 42704"),
        "the model's SQLSTATE must reach the driver:\n{out}"
    );
    let refusal = out
        .split("user=intruder")
        .nth(1)
        .unwrap_or_default()
        .to_string();
    assert!(
        refusal.contains("ERROR") && !refusal.contains("ij(CONNECTION1)>"),
        "the model's refusal must refuse the connection:\n{out}"
    );

    let recording = recording.lock().unwrap().clone();
    let mut oracle = PcapOracle::tcp("db2");
    for (to_server, bytes) in &recording {
        oracle = if *to_server {
            oracle.to_server(bytes)
        } else {
            oracle.from_server(bytes)
        };
    }
    oracle.assert_clean();

    server.stop().await?;
    Ok(())
}

/// The Python interpreter that has IBM's `ibm_db` driver installed.
fn ibm_db_python() -> E2EResult<PathBuf> {
    let python = std::env::var_os("NETGET_IBM_DB_PYTHON")
        .map(PathBuf::from)
        .ok_or(
            "NETGET_IBM_DB_PYTHON is not set. This test drives NetGet's Db2 server with IBM's \
             own DRDA client (ibm_db over IBM Data Server Driver for ODBC and CLI) and FAILS \
             rather than skipping without it: `python3 -m venv /some/venv && \
             /some/venv/bin/pip install ibm_db==3.3.0`, then export \
             NETGET_IBM_DB_PYTHON=/some/venv/bin/python.",
        )?;
    Ok(python)
}

/// One JSON line the peer printed for `step`.
fn step(out: &str, name: &str) -> E2EResult<serde_json::Value> {
    out.lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .find(|v| v["step"] == name)
        .ok_or_else(|| format!("the ibm_db peer printed no {name:?} step:\n{out}").into())
}

/// IBM's CLI driver (`ibm_db` 3.3.0) — a second independent client, and the vendor's own.
///
/// - By default it asks for an encrypted security mechanism (EUSRIDPWD, 9). The server offers
///   the ones it can read instead, and the driver reports reason 17, UNSUPPORTED FUNCTION:
///   no login is attempted with credentials the server cannot see.
/// - With `AUTHENTICATION=SERVER` (USRIDPWD) the model's acceptance opens the connection. The
///   driver sets its special registers (`EXCSQLSET`, acknowledged without the model), then the
///   model's row count and SQLSTATE come back as `num_rows` 1 and `SQLSTATE=42704`.
/// - The model's refusal of `intruder` is reason 24, USERNAME AND/OR PASSWORD INVALID.
///
/// LLM calls: 5.
#[tokio::test]
async fn ibm_db_client_against_netget_db2_server() -> E2EResult<()> {
    let python = ibm_db_python()?;
    let config = NetGetConfig::new(
        "Start an IBM Db2 server on port {AVAILABLE_PORT}. DB2-IBM-CLIENT-STARTUP.",
    )
    .with_mock(|mock| {
        mock.on_instruction_containing("DB2-IBM-CLIENT-STARTUP")
            .respond_with_actions(serde_json::json!([{
                "type": "open_server", "port": 0, "base_stack": "db2",
                "instruction": "A Db2 server: admit app, refuse anyone else."
            }]))
            .expect_calls(1)
            .and()
            .on_event("db2_connect")
            .and_event_data_contains("user_id", "app")
            .and_event_data_contains("rdb_name", "SAMPLE")
            .respond_with_actions(serde_json::json!([{ "type": "db2_accept_connection" }]))
            .expect_calls(1)
            .and()
            .on_event("db2_connect")
            .and_event_data_contains("user_id", "intruder")
            .respond_with_actions(serde_json::json!([{
                "type": "db2_reject_connection", "sec_check_code": "password_invalid"
            }]))
            .expect_calls(1)
            .and()
            .on_event("db2_query")
            .and_event_data_contains("sql_text", "insert into notes values (2, 'from ibm_db')")
            .respond_with_actions(serde_json::json!([{
                "type": "db2_query_ok", "sqlcode": 0, "rows_affected": 1
            }]))
            .expect_calls(1)
            .and()
            .on_event("db2_query")
            .and_event_data_contains("sql_text", "drop table nosuch")
            .respond_with_actions(serde_json::json!([{
                "type": "db2_query_error", "sqlcode": -204, "sqlstate": "42704",
                "message": "NOSUCH is an undefined name"
            }]))
            .expect_calls(1)
            .and()
    });
    let server = helpers::start_netget_server(config).await?;
    let (proxy_port, recording) = recording_proxy(server.port).await?;
    let script = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/server/db2/ibm_db_peer.py");
    let mut cmd = Command::new(&python);
    cmd.arg("-I").arg(&script).arg(proxy_port.to_string());
    let hint = InstallHint {
        brew: "python, then `pip install ibm_db==3.3.0` in a venv",
        apt: "python3-venv, then `pip install ibm_db==3.3.0` in a venv",
    };
    let out = run_tool(cmd, "python (ibm_db)", hint).await?;
    println!("{out}");
    server.verify_mocks().await?;

    let encrypted = step(&out, "encrypted")?;
    assert_eq!(encrypted["ok"], false, "{out}");
    assert!(
        encrypted["message"]
            .as_str()
            .unwrap_or("")
            .contains("\"17\""),
        "an encrypted mechanism must be declined as unsupported (reason 17):\n{out}"
    );
    assert_eq!(step(&out, "connect")?["ok"], true, "{out}");
    let insert = step(&out, "insert into notes values (2, 'from ibm_db')")?;
    assert_eq!(
        (insert["ok"].clone(), insert["rows"].clone()),
        (serde_json::json!(true), serde_json::json!(1)),
        "{out}"
    );
    let drop = step(&out, "drop table nosuch")?;
    let message = drop["message"].as_str().unwrap_or("");
    assert!(
        drop["ok"] == false
            && message.contains("SQLSTATE=42704")
            && message.contains("SQLCODE=-204"),
        "the model's SQLCODE and SQLSTATE must reach IBM's driver:\n{out}"
    );
    let intruder = step(&out, "intruder")?;
    assert!(
        intruder["ok"] == false
            && intruder["message"]
                .as_str()
                .unwrap_or("")
                .contains("\"24\""),
        "the model's refusal must be reason 24 (user name or password invalid):\n{out}"
    );

    let recording = recording.lock().unwrap().clone();
    // Judge NetGet's direction only. IBM's Linux x86_64 CLI driver sends an EXCSAT whose
    // EXTNAM is EBCDIC text, then 32 NUL bytes, then more text ("python  ...000039D0000",
    // NULs, "-0001runner..."). tshark's drda dissector also shows every parameter as an ASCII
    // string, and Wireshark flags a string holding a NUL followed by more data as "[Warn]
    // Trailing stray characters" - IBM's bytes, in a field NetGet's server does not read.
    // tshark 4.6.8 flags those bytes and passed the macOS arm64 driver's, so the Mac build
    // lays EXTNAM out differently; it is the driver build, not the tshark version (CI has
    // 4.2.2). Derby's driver above is still judged in both directions.
    let mut oracle = PcapOracle::tcp("db2").peer_input_is_context();
    for (to_server, bytes) in &recording {
        oracle = if *to_server {
            oracle.to_server(bytes)
        } else {
            oracle.from_server(bytes)
        };
    }
    oracle.assert_clean();
    server.stop().await?;
    Ok(())
}
