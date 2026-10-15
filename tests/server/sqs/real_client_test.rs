//! The real `aws` CLI against NetGet's SQS server.
//!
//! # Why this exists
//!
//! `sqs`'s Beta rating rested on `aws-sdk-sqs` alone — the Rust SDK, in-process, in the same
//! async runtime. One client can agree with one bug, and this session found three protocols
//! where it was doing exactly that: `etcd` and `grpc` could not complete a successful call for
//! any conformant gRPC client, and `mysql` could not be connected to by the CLI a user would
//! reach for. The AWS CLI is botocore — Python, a different SDK generation and a different
//! serialiser — driving the same JSON 1.0 protocol.
//!
//! # This test must never be able to reach real AWS
//!
//! That is not a hypothetical concern here. The project CLAUDE.md records that the DynamoDB
//! *client* took its address as `_remote_addr` and dropped it, so with no explicit endpoint the
//! SDK resolved `https://dynamodb.<region>.amazonaws.com` and signed with whatever ambient
//! credentials the machine had — **a client pointed at localhost issued real reads and writes
//! against real AWS.** Any vendor SDK inherits defaults that point at production.
//!
//! So three guards, and all three are load-bearing:
//!
//! 1. `--endpoint-url http://127.0.0.1:<port>` on every invocation.
//! 2. The port is asserted non-zero before the CLI is spawned, because an unset port is exactly
//!    how a URL degrades into something resolvable.
//! 3. Credentials, region and the metadata service are overridden in the child's environment, so
//!    the CLI cannot pick up the operator's profile, `~/.aws/config`, or an instance role.
//!
//! # What botocore checks that the Rust SDK does not
//!
//! It signs with SigV4 independently, sets its own `x-amz-target` and `content-type`, and — the
//! part that matters — **renders** the reply. A field name or JSON shape the Rust SDK tolerates
//! through its generated deserialiser shows up here as a missing column or a parse error.

use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
use serde_json::json;
use std::time::Duration;
use tokio::process::Command;

/// Fail — never skip — when the AWS CLI is absent.
async fn require_aws() -> E2EResult<String> {
    match Command::new("aws").arg("--version").output().await {
        Ok(out) if out.status.success() => {
            // `aws --version` writes to stdout on v2 and stderr on v1.
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
             different SDK from the aws-sdk-sqs crate the other test uses. `brew install \
             awscli` provides it."
        )
        .into()),
    }
}

struct AwsOutput {
    success: bool,
    stdout: String,
    stderr: String,
}

/// Run one `aws sqs` command against the local server.
///
/// **`tokio::process`, not `std::process`.** `#[tokio::test]` runs a current-thread runtime, so
/// a blocking `output()` parks the only worker and stops the harness tasks draining the netget
/// child's pipes; the pipes fill, netget blocks inside a log call while serving, and the CLI
/// times out against a server that is perfectly correct.
async fn aws_sqs(port: u16, args: &[&str]) -> AwsOutput {
    assert!(
        port != 0,
        "refusing to run the AWS CLI with no port: an endpoint URL that degrades into something \
         resolvable is how a test aimed at localhost ends up signing requests against real AWS"
    );

    let out = Command::new("aws")
        .arg("sqs")
        .args(args)
        .arg("--endpoint-url")
        .arg(format!("http://127.0.0.1:{port}"))
        .arg("--region")
        .arg("us-east-1")
        .arg("--no-cli-pager")
        // Nothing may be inherited from the operator's machine.
        .env("AWS_ACCESS_KEY_ID", "netget-test")
        .env("AWS_SECRET_ACCESS_KEY", "netget-test-secret")
        .env("AWS_REGION", "us-east-1")
        .env("AWS_DEFAULT_REGION", "us-east-1")
        .env("AWS_CONFIG_FILE", "/dev/null")
        .env("AWS_SHARED_CREDENTIALS_FILE", "/dev/null")
        .env("AWS_EC2_METADATA_DISABLED", "true")
        .env("AWS_RETRY_MODE", "standard")
        .env("AWS_MAX_ATTEMPTS", "1")
        // **Removed, not blanked.** `AWS_PROFILE=""` is not "no profile": the CLI looks for a
        // profile whose name is the empty string and exits `The config profile () could not be
        // found` before touching the network. Same for a blank session token, which reaches the
        // signer as a real value.
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

/// One rule per operation, each answering with the JSON the real service would.
///
/// `AWS_MAX_ATTEMPTS=1` above is what makes `expect_calls` mean something: botocore retries by
/// default, and each retry is another `sqs_request` event.
fn sqs_server() -> NetGetConfig {
    NetGetConfig::new("Listen on port {AVAILABLE_PORT} via SQS. Handle queue operations").with_mock(
        |mock| {
            mock.on_instruction_containing("via SQS")
                .respond_with_actions(json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "SQS",
                    "instruction": "Handle SQS queue operations"
                }]))
                .expect_calls(1)
                .and()
                .on_event("sqs_request")
                .and_event_data_contains("operation", "CreateQueue")
                .respond_with_actions(json!([{
                    "type": "send_sqs_response",
                    "status_code": 200,
                    "body": "{\"QueueUrl\":\"http://127.0.0.1/queue/netget-real\"}"
                }]))
                .expect_calls(1)
                .and()
                .on_event("sqs_request")
                .and_event_data_contains("operation", "SendMessage")
                .respond_with_actions(json!([{
                    "type": "send_sqs_response",
                    "status_code": 200,
                    "body": "{\"MessageId\":\"11111111-2222-3333-4444-555555555555\",\"MD5OfMessageBody\":\"5eb63bbbe01eeed093cb22bb8f5acdc3\"}"
                }]))
                .expect_calls(1)
                .and()
                .on_event("sqs_request")
                .and_event_data_contains("operation", "ReceiveMessage")
                .respond_with_actions(json!([{
                    "type": "send_sqs_response",
                    "status_code": 200,
                    "body": "{\"Messages\":[{\"MessageId\":\"11111111-2222-3333-4444-555555555555\",\"ReceiptHandle\":\"receipt-alpha\",\"Body\":\"hello world\",\"MD5OfBody\":\"5eb63bbbe01eeed093cb22bb8f5acdc3\"}]}"
                }]))
                .expect_calls(1)
                .and()
        },
    )
}

#[tokio::test]
async fn the_aws_cli_completes_a_queue_round_trip() -> E2EResult<()> {
    let version = require_aws().await?;
    println!("aws cli: {version}");

    let server = start_netget_server(sqs_server()).await?;
    crate::helpers::wait_for_server_listening(&server, Duration::from_secs(30)).await?;
    let port = server.port;

    // --- CreateQueue --------------------------------------------------------
    let create = aws_sqs(port, &["create-queue", "--queue-name", "netget-real"]).await;
    assert!(
        create.success,
        "the AWS CLI could not complete CreateQueue.\nstdout: {}\nstderr: {}\n\nThis is the \
         first client other than aws-sdk-sqs to read this server's replies, so a failure here \
         is about the wire, not about the test.",
        create.stdout, create.stderr
    );
    assert!(
        create.stdout.contains("http://127.0.0.1/queue/netget-real"),
        "botocore did not render the QueueUrl out of our reply:\n{}",
        create.stdout
    );

    // --- SendMessage --------------------------------------------------------
    //
    // The MD5 is the interesting field: the CLI prints what we sent, and a response shape it
    // could not deserialise loses the whole object rather than one key.
    let send = aws_sqs(
        port,
        &[
            "send-message",
            "--queue-url",
            "http://127.0.0.1/queue/netget-real",
            "--message-body",
            "hello world",
        ],
    )
    .await;
    assert!(
        send.success,
        "the AWS CLI could not complete SendMessage.\nstdout: {}\nstderr: {}",
        send.stdout, send.stderr
    );
    assert!(
        send.stdout.contains("11111111-2222-3333-4444-555555555555"),
        "botocore did not render the MessageId:\n{}",
        send.stdout
    );
    assert!(
        send.stdout.contains("5eb63bbbe01eeed093cb22bb8f5acdc3"),
        "botocore did not render MD5OfMessageBody:\n{}",
        send.stdout
    );

    // --- ReceiveMessage -----------------------------------------------------
    //
    // A list of objects rather than a flat one, which is where a hand-written JSON reply most
    // often goes wrong and where a generated deserialiser is most forgiving.
    let receive = aws_sqs(
        port,
        &[
            "receive-message",
            "--queue-url",
            "http://127.0.0.1/queue/netget-real",
        ],
    )
    .await;
    assert!(
        receive.success,
        "the AWS CLI could not complete ReceiveMessage.\nstdout: {}\nstderr: {}",
        receive.stdout, receive.stderr
    );
    for needle in ["hello world", "receipt-alpha"] {
        assert!(
            receive.stdout.contains(needle),
            "botocore did not render `{needle}` out of the Messages array:\n{}",
            receive.stdout
        );
    }

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}
