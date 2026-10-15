//! gRPC against a real, independent third-party client: **grpcurl 1.9.4**.
//!
//! # Why this test exists
//!
//! `tests/server/grpc/e2e_test.rs` drives the server with `reqwest` in
//! `.http2_prior_knowledge()` mode and reads the `grpc-status` header. That proves an HTTP/2
//! server answered; it does not prove a gRPC client can use the answer, because **reqwest does
//! not implement gRPC** — it never looks for trailers, never decodes the length-prefixed
//! message framing, and never turns protobuf bytes back into fields. The root `CLAUDE.md`
//! lists `grpc` among the protocols whose evidence is "codecs and parsers rather than clients"
//! for exactly this reason.
//!
//! grpcurl is the gRPC project's own command-line client, built on grpc-go. It applies grpc-go's
//! rules about where a status may appear, strips the 5-byte length prefix, and decodes the
//! protobuf payload against the schema — so what it prints is our wire bytes interpreted by a
//! real gRPC implementation.
//!
//! # Not circular
//!
//! NetGet's gRPC server frames with `hyper` + `prost`/`prost-reflect`; `tonic` is a dependency
//! of the feature but the serving path here is hyper's `http2::Builder` directly. grpcurl is a
//! Go binary that links none of it.
//!
//! # Reflection is NOT served, so the schema comes from the client side
//!
//! `tonic-reflection` is a declared dependency and is referenced nowhere in `src/`; a
//! reflection call is answered `12 UNIMPLEMENTED`. So `grpcurl` is given the same `.proto` the
//! server was started with, via `-import-path`/`-proto`, rather than `-use-reflection`.


use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
use std::time::Duration;
use tempfile::TempDir;

/// The schema both sides are given. Deliberately the same one the mocked suite uses.
const PROTO: &str = r#"syntax = "proto3";
package test;
message UserId { int32 id = 1; }
message User { int32 id = 1; string name = 2; string email = 3; }
service UserService { rpc GetUser(UserId) returns (User); }
"#;

/// Fail — never skip — when grpcurl is missing.
fn require_grpcurl() -> E2EResult<()> {
    match std::process::Command::new("grpcurl")
        .arg("--version")
        .output()
    {
        Ok(out) => {
            let mut banner = String::from_utf8_lossy(&out.stdout).into_owned();
            banner.push_str(&String::from_utf8_lossy(&out.stderr));
            println!(
                "grpcurl present: {}",
                banner.lines().next().unwrap_or("(no banner)")
            );
            Ok(())
        }
        Err(e) => Err(format!(
            "grpcurl not available ({e}): this test's whole point is driving a real gRPC \
             client against NetGet's server, and skipping it would leave gRPC's maturity \
             rating resting on reqwest, which does not implement gRPC at all. Install it with \
             `brew install grpcurl` (or download it from \
             https://github.com/fullstorydev/grpcurl/releases)."
        )
        .into()),
    }
}

/// Write the schema into `dir` and return its path, so both NetGet and grpcurl read one file.
fn write_proto(dir: &TempDir) -> E2EResult<std::path::PathBuf> {
    let path = dir.path().join("user.proto");
    std::fs::write(&path, PROTO)?;
    Ok(path)
}

/// Run one unary call with grpcurl and return (exit status, combined output).
async fn grpcurl_call(
    port: u16,
    dir: &TempDir,
    body: &str,
) -> E2EResult<(std::process::ExitStatus, String)> {
    let output = tokio::time::timeout(
        Duration::from_secs(60),
        tokio::process::Command::new("grpcurl")
            .arg("-plaintext")
            .arg("-import-path")
            .arg(dir.path())
            .arg("-proto")
            .arg("user.proto")
            .arg("-d")
            .arg(body)
            .arg(format!("127.0.0.1:{port}"))
            .arg("test.UserService/GetUser")
            .output(),
    )
    .await
    .map_err(|_| "grpcurl did not finish within 60s")??;

    let mut combined = String::from_utf8_lossy(&output.stdout).into_owned();
    combined.push_str(&String::from_utf8_lossy(&output.stderr));
    println!("--- grpcurl output ---\n{combined}\n--- end ---");
    Ok((output.status, combined))
}

/// **This test currently FAILS, and that is a real defect in NetGet — not in the test.**
///
/// Measured 16 September 2026 with grpcurl 1.9.4:
///
/// ```text
/// ERROR:
///   Code: Internal
///   Message: server closed the stream without sending trailers
/// ```
///
/// gRPC requires the status of a response **that carried a message** to arrive in an HTTP/2
/// TRAILERS frame. `src/server/grpc/mod.rs` used to write `grpc-status` into the *initial*
/// HEADERS and emit no trailers at all. For a successful call the body is non-empty, so
/// `http_body_util::Full::is_end_stream()` is false and hyper emitted HEADERS (no END_STREAM)
/// then DATA (END_STREAM) — a stream that ends with no trailers, which grpc-go rejects with the
/// message above.
///
/// **The error path next door did not hit this, and the asymmetry is the whole explanation.**
/// An error has an empty body, `is_end_stream()` is true, and hyper emits one HEADERS frame
/// with END_STREAM — a valid gRPC **Trailers-Only** response, which grpc-go accepts. So NetGet
/// could report a failure to a real gRPC client and could not report a success. That is why
/// every test in the tree passed: the failure paths were the ones being asserted on.
///
/// The server now builds the success reply as a two-frame body — the length-prefixed message,
/// then `Frame::trailers` carrying the status — and keeps the Trailers-Only shape for errors,
/// which was already correct. `src/server/etcd/mod.rs` had the identical defect and was fixed
/// the same way at the same time.
///
/// This test was written `#[ignore]`d, deliberately: asserting the broken behaviour would have
/// enshrined it and failed the day somebody fixed it. It is now the regression test.
#[tokio::test]
async fn test_grpc_unary_call_against_real_grpcurl() -> E2EResult<()> {
    println!("\n=== E2E Test: grpcurl unary call against NetGet's gRPC server ===");
    require_grpcurl()?;

    let dir = TempDir::new()?;
    let proto_path = write_proto(&dir)?;

    let prompt = "Start a gRPC server on port {AVAILABLE_PORT} answering GetUser";

    let config = NetGetConfig::new_no_scripts(prompt).with_mock(|mock| {
        mock.on_instruction_containing("gRPC server")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "gRPC",
                    "instruction": "Answer GetUser from the directory",
                    "startup_params": { "proto_schema": proto_path.to_string_lossy() }
                }
            ]))
            .expect_calls(1)
            .and()
            // Matching on the decoded request field is the server-side half: grpcurl sent
            // protobuf, and `id` reaching the event as 123 means our prost-reflect decode of a
            // real client's encoding was right.
            .on_event("grpc_unary_request")
            .and_event_data_contains("method", "GetUser")
            .respond_with_actions(serde_json::json!([{
                "type": "grpc_unary_response",
                "message": { "id": 123, "name": "Alice", "email": "alice@example.com" }
            }]))
            .expect_calls(1)
            .and()
    });

    let server = start_netget_server(config).await?;
    println!("gRPC server on 127.0.0.1:{}", server.port);

    let (status, out) = grpcurl_call(server.port, &dir, r#"{"id":123}"#).await?;

    assert!(
        status.success(),
        "grpcurl rejected NetGet's unary response (exit {status}):\n{out}\n\nA \"server \
         closed the stream without sending trailers\" here means grpc-status has moved back \
         into the initial HEADERS beside the DATA frame, which is not gRPC — see \
         grpc_body_with_trailers() in src/server/grpc/mod.rs."
    );
    // grpcurl prints these only after stripping the 5-byte gRPC length prefix and decoding the
    // protobuf body against the schema. Field names and values both have to survive.
    assert!(
        out.contains("\"name\"") && out.contains("Alice"),
        "grpcurl did not decode the `name` field out of our protobuf response:\n{out}"
    );
    assert!(
        out.contains("alice@example.com"),
        "grpcurl did not decode the `email` field:\n{out}"
    );
    assert!(
        out.contains("123"),
        "grpcurl did not decode the `id` field:\n{out}"
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

/// The error path, read back by the same real client.
///
/// This is a different wire shape, not merely a different value: an error carries an empty
/// body, so hyper emits a single HEADERS frame with END_STREAM — a gRPC **Trailers-Only**
/// response — where the success path above emits HEADERS + DATA. Both have to be acceptable to
/// grpc-go, and only a real gRPC client can say so.
#[tokio::test]
async fn test_grpc_error_status_is_read_back_by_real_grpcurl() -> E2EResult<()> {
    println!("\n=== E2E Test: grpcurl reads NetGet's gRPC error status ===");
    require_grpcurl()?;

    let dir = TempDir::new()?;
    let proto_path = write_proto(&dir)?;

    let prompt = "Start a gRPC server on port {AVAILABLE_PORT} that reports a missing user";

    let config = NetGetConfig::new_no_scripts(prompt).with_mock(|mock| {
        mock.on_instruction_containing("gRPC server")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "gRPC",
                    "instruction": "Report a missing user",
                    "startup_params": { "proto_schema": proto_path.to_string_lossy() }
                }
            ]))
            .expect_calls(1)
            .and()
            .on_event("grpc_unary_request")
            .respond_with_actions(serde_json::json!([{
                "type": "grpc_error",
                "code": "NOT_FOUND",
                "message": "User not found"
            }]))
            .expect_calls(1)
            .and()
    });

    let server = start_netget_server(config).await?;
    let (status, out) = grpcurl_call(server.port, &dir, r#"{"id":999}"#).await?;

    assert!(
        !status.success(),
        "grpcurl exited 0 for a NOT_FOUND status, so it did not read our status at all:\n{out}"
    );
    // grpc-go maps code 5 to `NotFound`. Seeing the name means the numeric code AND the
    // message reached it in the place gRPC says they belong.
    assert!(
        out.contains("NotFound"),
        "grpcurl did not report the NOT_FOUND code NetGet sent:\n{out}"
    );
    assert!(
        out.contains("User not found"),
        "grpcurl did not report our grpc-message:\n{out}"
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}
