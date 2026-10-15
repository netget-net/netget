//! The real `aws` CLI against NetGet's DynamoDB server.
//!
//! # Why
//!
//! `dynamo`'s Beta rating rested on `aws-sdk-dynamodb` alone — the Rust SDK, in-process, in the
//! same async runtime. The AWS CLI is botocore: Python, a different SDK generation, a different
//! serialiser, and the client that **renders** a reply rather than deserialising it into a
//! generated struct. A field name or JSON shape the Rust SDK tolerates shows up there as a
//! missing key.
//!
//! # This test must never be able to reach real AWS, and for this protocol that is not abstract
//!
//! The project CLAUDE.md records the exact incident under this protocol's name: the DynamoDB
//! **client** took its address as `_remote_addr` and dropped it, so with no explicit endpoint the
//! SDK resolved `https://dynamodb.<region>.amazonaws.com` and signed with whatever ambient
//! credentials the machine had. **A client pointed at localhost issued real reads and writes
//! against real AWS.**
//!
//! Three guards, all load-bearing: `--endpoint-url` on every invocation, the port asserted
//! non-zero before the CLI is spawned (an unset port is how a URL degrades into something
//! resolvable), and credentials, region, profile and the EC2 metadata service overridden in the
//! child's environment so nothing is inherited from the operator's machine.


use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
use serde_json::json;
use std::time::Duration;
use tokio::process::Command;

/// Fail — never skip — when the AWS CLI is absent.
async fn require_aws() -> E2EResult<String> {
    match Command::new("aws").arg("--version").output().await {
        Ok(out) if out.status.success() => {
            let text = if out.stdout.is_empty() {
                String::from_utf8_lossy(&out.stderr)
            } else {
                String::from_utf8_lossy(&out.stdout)
            };
            Ok(text.trim().to_string())
        }
        Ok(out) => Err(format!("`aws --version` exited {}", out.status).into()),
        Err(e) => Err(format!(
            "the AWS CLI is not available ({e}): this test's whole point is driving botocore, a \
             different SDK from the aws-sdk-dynamodb crate the other test uses. \
             `brew install awscli` provides it."
        )
        .into()),
    }
}

struct AwsOutput {
    success: bool,
    stdout: String,
    stderr: String,
}

/// Run one `aws dynamodb` command against the local server.
///
/// **`tokio::process`, not `std::process`.** `#[tokio::test]` runs a current-thread runtime, so
/// a blocking `output()` parks the only worker and stops the harness tasks draining the netget
/// child's pipes; the pipes fill, netget blocks inside a log call while serving, and the CLI
/// times out against a server that is perfectly correct.
async fn aws_ddb(port: u16, args: &[&str]) -> AwsOutput {
    assert!(
        port != 0,
        "refusing to run the AWS CLI with no port: an endpoint URL that degrades into something \
         resolvable is precisely how this protocol's client once signed requests against real AWS"
    );

    let out = Command::new("aws")
        .arg("dynamodb")
        .args(args)
        .arg("--endpoint-url")
        .arg(format!("http://127.0.0.1:{port}"))
        .arg("--region")
        .arg("us-east-1")
        .arg("--no-cli-pager")
        .env("AWS_ACCESS_KEY_ID", "netget-test")
        .env("AWS_SECRET_ACCESS_KEY", "netget-test-secret")
        .env("AWS_REGION", "us-east-1")
        .env("AWS_DEFAULT_REGION", "us-east-1")
        .env("AWS_CONFIG_FILE", "/dev/null")
        .env("AWS_SHARED_CREDENTIALS_FILE", "/dev/null")
        .env("AWS_EC2_METADATA_DISABLED", "true")
        .env("AWS_RETRY_MODE", "standard")
        // Retries would each be another `dynamo_request` event, so `expect_calls` would stop
        // meaning anything.
        .env("AWS_MAX_ATTEMPTS", "1")
        // **Removed, not blanked.** `AWS_PROFILE=""` is not "no profile": the CLI looks for a
        // profile named the empty string and exits `The config profile () could not be found`
        // before touching the network.
        .env_remove("AWS_PROFILE")
        .env_remove("AWS_DEFAULT_PROFILE")
        .env_remove("AWS_SESSION_TOKEN")
        .output()
        .await
        .expect("failed to spawn the aws CLI");

    AwsOutput {
        success: out.status.success(),
        stdout: String::from_utf8_lossy(&out.stdout).to_string(),
        stderr: String::from_utf8_lossy(&out.stderr).to_string(),
    }
}

fn dynamo_server() -> NetGetConfig {
    NetGetConfig::new("Listen on port {AVAILABLE_PORT} via DynamoDB. Answer table operations")
        .with_mock(|mock| {
            mock.on_instruction_containing("via DynamoDB")
                .respond_with_actions(json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "DYNAMO",
                    "instruction": "Answer table operations"
                }]))
                .expect_calls(1)
                .and()
                .on_event("dynamo_request")
                .and_event_data_contains("operation", "PutItem")
                .respond_with_actions(json!([{
                    "type": "send_dynamo_response",
                    "status_code": 200,
                    "body": "{}"
                }]))
                .expect_calls(1)
                .and()
                .on_event("dynamo_request")
                .and_event_data_contains("operation", "GetItem")
                .respond_with_actions(json!([{
                    "type": "send_dynamo_response",
                    "status_code": 200,
                    "body": "{\"Item\":{\"id\":{\"S\":\"alpha\"},\"count\":{\"N\":\"7\"},\"live\":{\"BOOL\":true}}}"
                }]))
                .expect_calls(1)
                .and()
                .on_event("dynamo_request")
                .and_event_data_contains("operation", "ListTables")
                .respond_with_actions(json!([{
                    "type": "send_dynamo_response",
                    "status_code": 200,
                    "body": "{\"TableNames\":[\"netget-alpha\",\"netget-beta\"]}"
                }]))
                .expect_calls(1)
                .and()
        })
}

#[tokio::test]
async fn the_aws_cli_reads_typed_attribute_values_back() -> E2EResult<()> {
    let version = require_aws().await?;
    println!("aws cli: {version}");

    let server = start_netget_server(dynamo_server()).await?;
    crate::helpers::wait_for_server_listening(&server, Duration::from_secs(30)).await?;
    let port = server.port;

    // --- ListTables: a plain array of strings -------------------------------
    let list = aws_ddb(port, &["list-tables"]).await;
    assert!(
        list.success,
        "the AWS CLI could not complete ListTables.\nstdout: {}\nstderr: {}\n\nThis is the first \
         client other than aws-sdk-dynamodb to read this server's replies, so a failure here is \
         about the wire, not about the test.",
        list.stdout, list.stderr
    );
    for name in ["netget-alpha", "netget-beta"] {
        assert!(
            list.stdout.contains(name),
            "botocore did not render `{name}` out of TableNames:\n{}",
            list.stdout
        );
    }

    // --- PutItem: typed attribute values on the way OUT ---------------------
    let put = aws_ddb(
        port,
        &[
            "put-item",
            "--table-name",
            "netget-alpha",
            "--item",
            r#"{"id":{"S":"alpha"},"count":{"N":"7"}}"#,
        ],
    )
    .await;
    assert!(
        put.success,
        "the AWS CLI could not complete PutItem.\nstdout: {}\nstderr: {}",
        put.stdout, put.stderr
    );

    // --- GetItem: typed attribute values on the way BACK --------------------
    //
    // This is the assertion worth having. DynamoDB's wire format wraps every value in a
    // one-letter type tag, and botocore refuses an item whose tags it does not recognise rather
    // than rendering it as text — so `"7"` arriving under `N` and `true` under `BOOL` is a real
    // check on the shape, not just on the bytes.
    let get = aws_ddb(
        port,
        &[
            "get-item",
            "--table-name",
            "netget-alpha",
            "--key",
            r#"{"id":{"S":"alpha"}}"#,
        ],
    )
    .await;
    assert!(
        get.success,
        "the AWS CLI could not complete GetItem.\nstdout: {}\nstderr: {}",
        get.stdout, get.stderr
    );
    let parsed: serde_json::Value = serde_json::from_str(&get.stdout)
        .unwrap_or_else(|e| panic!("the CLI printed unparseable JSON ({e}):\n{}", get.stdout));
    assert_eq!(
        parsed["Item"]["id"]["S"], "alpha",
        "the string attribute did not survive to botocore:\n{parsed}"
    );
    assert_eq!(
        parsed["Item"]["count"]["N"], "7",
        "the number attribute did not survive; DynamoDB numbers cross the wire as STRINGS under \
         an N tag, and a client that receives a JSON number instead rejects the item:\n{parsed}"
    );
    assert_eq!(
        parsed["Item"]["live"]["BOOL"], true,
        "the boolean attribute did not survive:\n{parsed}"
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}
