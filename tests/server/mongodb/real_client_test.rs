//! MongoDB server driven by the real **`mongosh`** binary (the official Node.js
//! driver).
//!
//! The peer is not a Rust crate. `src/server/mongodb/mod.rs` parses OP_MSG by hand
//! and builds documents with the `bson` crate; `mongosh` is MongoDB's own shell,
//! JavaScript on the Node driver, sharing no code with anything NetGet links
//! against. The existing e2e suite drives the Rust `mongodb` driver, which is
//! independent too — but it is one vendor implementation, and the Node driver's
//! handshake and cursor handling differ enough that agreeing with both is a stronger
//! claim than agreeing with either.
//!
//! What is driven is a real session, not a connect:
//!
//! ```text
//!   hello (OP_MSG, apiVersion 1)  -> wire-version range accepted, topology settles
//!   find  on testdb.users         -> two documents decoded by the Node driver and
//!                                    printed, asserted field by field
//! ```
//!
//! `--apiVersion 1` is load-bearing: it makes the Node driver open with OP_MSG
//! instead of the legacy OP_QUERY handshake, which this server answers by closing the
//! connection. That limitation is stated in the protocol's `metadata()` rather than
//! papered over here.
//!
//! This test is **not** `#[ignore]`d and does **not** skip when mongosh is missing —
//! see `require_mongosh`.

use crate::helpers::*;
use serde_json::json;
use std::time::Duration;
use tokio::process::Command;

/// Fail — never skip — when `mongosh` is absent.
///
/// A skip that returns `Ok(())` is a silent pass on any machine without the shell,
/// which is how a maturity rating outlives its evidence.
async fn require_mongosh() -> E2EResult<()> {
    match Command::new("mongosh").arg("--version").output().await {
        Ok(out) if out.status.success() => {
            println!(
                "[real-client] mongosh {}",
                String::from_utf8_lossy(&out.stdout).trim()
            );
            Ok(())
        }
        Ok(out) => Err(format!(
            "`mongosh --version` exited {}: this test's whole point is driving MongoDB's own \
             shell against NetGet's server, and skipping it would leave MongoDB's maturity \
             rating resting on nothing. stderr: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        )
        .into()),
        Err(e) => Err(format!(
            "mongosh is not available ({e}). This test's whole point is driving MongoDB's own \
             shell against NetGet's server, and skipping it would leave MongoDB's maturity \
             rating resting on nothing."
        )
        .into()),
    }
}

#[tokio::test]
async fn test_mongodb_find_against_mongosh() -> E2EResult<()> {
    require_mongosh().await?;

    let config = NetGetConfig::new(
        "Listen on port {AVAILABLE_PORT} via MongoDB. \
         When queried for users, return Alice (age 30) and Bob (age 25).",
    )
    .with_log_level("debug")
    .with_mock(|mock| {
        mock.on_instruction_containing("MongoDB")
            .respond_with_actions(json!([{
                "type": "open_server",
                "port": 0,
                "base_stack": "MongoDB",
                "instruction": "MongoDB server for testing"
            }]))
            .expect_calls(1)
            .and()
            // The query under test. Declared first: first match wins, and the
            // catch-all below would otherwise swallow it.
            .on_event("mongodb_command")
            .and_event_data_contains("command", "find")
            .and_event_data_contains("collection", "users")
            .respond_with_actions(json!([{
                "type": "find_response",
                "documents": [
                    {"_id": {"$oid": "507f1f77bcf86cd799439011"}, "name": "Alice", "age": 30},
                    {"_id": {"$oid": "507f191e810c19729de860ea"}, "name": "Bob", "age": 25}
                ]
            }]))
            .expect_at_least(1)
            .and()
            // Everything else the shell says on its way in. `hello`/`isMaster` are
            // answered in Rust and never reach here, but a real shell also sends
            // buildInfo, getParameter, connectionStatus, atlasVersion, getLog, ping
            // and endSessions, and an unanswered command comes back `ok: 0`, which
            // the shell reports as an error. An empty cursor is the only shape in
            // this protocol's vocabulary that says `ok: 1` with no data.
            //
            // This rule is what a real deployment would put behind a wildcard, and
            // it is deliberately last so it can never mask the assertion above.
            .on_event("mongodb_command")
            .respond_with_actions(json!([{"type": "find_response", "documents": []}]))
            .expect_at_least(1)
            .and()
    });

    let server = start_netget_server(config).await?;
    let uri = format!(
        "mongodb://127.0.0.1:{}/testdb?directConnection=true",
        server.port
    );
    println!("[real-client] NetGet MongoDB server at {uri}");

    // The shell prints what the Node driver decoded out of NetGet's OP_MSG reply:
    // a BSON document per element of the cursor's firstBatch. Printing it at all
    // means the driver accepted the message length, the flag bits, section kind 0,
    // the `ok` field and the cursor shape.
    let script = "print(JSON.stringify(db.getSiblingDB('testdb')\
                  .users.find({}).toArray().map(d => ({name: d.name, age: d.age}))))";

    let out = tokio::time::timeout(
        Duration::from_secs(90),
        Command::new("mongosh")
            .args([&uri, "--apiVersion", "1", "--quiet", "--eval", script])
            .output(),
    )
    .await
    .map_err(|_| "mongosh did not finish within 90s")?
    .map_err(|e| format!("failed to run mongosh: {e}"))?;

    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    println!("[mongosh] status={}\nstdout:\n{stdout}", out.status);
    if !stderr.trim().is_empty() {
        println!("[mongosh] stderr:\n{stderr}");
    }

    assert!(
        out.status.success(),
        "mongosh exited {} against NetGet's MongoDB server.\nstdout:\n{stdout}\nstderr:\n{stderr}",
        out.status
    );

    // Assert on the *decoded* documents, not on "some bytes arrived". The Node
    // driver reconstructed these from BSON that NetGet encoded.
    let line = stdout
        .lines()
        .find(|l| l.trim_start().starts_with('['))
        .ok_or_else(|| {
            format!("mongosh printed no JSON array. stdout:\n{stdout}\nstderr:\n{stderr}")
        })?;
    let docs: serde_json::Value = serde_json::from_str(line.trim())
        .map_err(|e| format!("mongosh printed {line:?} which is not JSON: {e}"))?;
    let docs = docs
        .as_array()
        .ok_or_else(|| format!("mongosh printed {line:?}, which is not an array"))?;

    assert_eq!(
        docs.len(),
        2,
        "the Node driver decoded {} documents out of NetGet's cursor batch, not 2: {line}",
        docs.len()
    );
    assert_eq!(
        docs[0].get("name").and_then(|v| v.as_str()),
        Some("Alice"),
        "first document decoded by the Node driver is not Alice: {line}"
    );
    assert_eq!(
        docs[0].get("age").and_then(|v| v.as_i64()),
        Some(30),
        "Alice's age did not survive BSON encoding: {line}"
    );
    assert_eq!(
        docs[1].get("name").and_then(|v| v.as_str()),
        Some("Bob"),
        "second document decoded by the Node driver is not Bob: {line}"
    );
    assert_eq!(
        docs[1].get("age").and_then(|v| v.as_i64()),
        Some(25),
        "Bob's age did not survive BSON encoding: {line}"
    );
    println!("[real-client] the Node driver decoded both documents NetGet served");

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    Ok(())
}
