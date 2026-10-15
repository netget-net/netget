//! The real `aws s3api` CLI against NetGet's S3 server.
//!
//! # Why
//!
//! `s3`'s Beta rating rested on **rust-s3** alone. The AWS CLI is botocore: a different SDK, a
//! different XML parser, and — the part that matters for S3 specifically — a different signing
//! implementation. S3 is XML rather than JSON, so this is the one protocol in the AWS family
//! where the second client exercises a hand-written *document*, not a serde struct.
//!
//! This session found three protocols that were Beta on one lenient client and unusable by every
//! conformant one (`etcd`, `grpc`, `mysql`), which is why the item exists.
//!
//! # Path style, and why it is forced
//!
//! botocore defaults to virtual-hosted addressing — `http://bucket.127.0.0.1:port/key` — which
//! is not resolvable and is not what this server routes. `--endpoint-url` plus
//! `AWS_S3_ADDRESSING_STYLE=path` keeps the bucket in the path, which is also how the rust-s3
//! test drives it.
//!
//! # This test must never be able to reach real AWS
//!
//! The project CLAUDE.md records the sibling incident: the DynamoDB client dropped its target,
//! let the SDK resolve the production endpoint, and signed with ambient credentials. Same three
//! guards here — an explicit endpoint on every call, a non-zero port asserted before the CLI is
//! spawned, and credentials, region, profile and the EC2 metadata service overridden in the
//! child's environment.


use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
use serde_json::json;
use std::time::Duration;
use tokio::process::Command;

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
            "the AWS CLI is not available ({e}): this test's whole point is driving botocore's \
             XML parser and signer against a hand-written S3 document. `brew install awscli` \
             provides it."
        )
        .into()),
    }
}

struct AwsOutput {
    success: bool,
    stdout: String,
    stderr: String,
}

/// Run one `aws s3api` command. **`tokio::process`, not `std::process`** — a blocking `output()`
/// parks the current-thread runtime's only worker and deadlocks the harness draining netget's
/// pipes, which presents as the client timing out against a perfectly correct server.
async fn aws_s3api(port: u16, args: &[&str]) -> AwsOutput {
    assert!(
        port != 0,
        "refusing to run the AWS CLI with no port: an endpoint URL that degrades into something \
         resolvable is how a test aimed at localhost ends up signing requests against real AWS"
    );

    let out = Command::new("aws")
        .arg("s3api")
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
        .env("AWS_MAX_ATTEMPTS", "1")
        // Virtual-hosted addressing would put the bucket in the hostname.
        .env("AWS_S3_ADDRESSING_STYLE", "path")
        // Removed, not blanked: `AWS_PROFILE=""` makes the CLI look for a profile named the
        // empty string and exit before touching the network.
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

fn s3_server() -> NetGetConfig {
    NetGetConfig::new("Listen on port {AVAILABLE_PORT} via S3. Answer bucket operations").with_mock(
        |mock| {
            mock.on_instruction_containing("via S3")
                .respond_with_actions(json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "S3",
                    "instruction": "Answer bucket operations"
                }]))
                .expect_calls(1)
                .and()
                .on_event("s3_request")
                .and_event_data_contains("operation", "ListObjects")
                .respond_with_actions(json!([{
                    "type": "send_s3_object_list",
                    "objects": [
                        {"key": "alpha.txt", "size": 11},
                        {"key": "nested/beta.json", "size": 23}
                    ]
                }]))
                .expect_calls(1)
                .and()
                .on_event("s3_request")
                .and_event_data_contains("operation", "GetObject")
                .respond_with_actions(json!([{
                    "type": "send_s3_object",
                    "content": "hello botocore",
                    "content_type": "text/plain"
                }]))
                .expect_calls(1)
                .and()
        },
    )
}

#[tokio::test]
async fn the_aws_cli_parses_our_s3_xml() -> E2EResult<()> {
    let version = require_aws().await?;
    println!("aws cli: {version}");

    let server = start_netget_server(s3_server()).await?;
    crate::helpers::wait_for_server_listening(&server, Duration::from_secs(30)).await?;
    let port = server.port;

    // --- ListObjects: the hand-written XML document -------------------------
    //
    // botocore parses `ListBucketResult` itself and prints JSON. A key it could not find, or an
    // element name or namespace it does not expect, loses the whole `Contents` array rather than
    // one field — which is exactly what an in-house XML round-trip cannot notice.
    let list = aws_s3api(port, &["list-objects", "--bucket", "netget-bucket"]).await;
    assert!(
        list.success,
        "the AWS CLI could not complete ListObjects.\nstdout: {}\nstderr: {}\n\nThis is the \
         first client other than rust-s3 to parse this server's XML, so a failure here is about \
         the document, not about the test.",
        list.stdout, list.stderr
    );
    let parsed: serde_json::Value = serde_json::from_str(&list.stdout)
        .unwrap_or_else(|e| panic!("the CLI printed unparseable JSON ({e}):\n{}", list.stdout));
    let contents = parsed["Contents"]
        .as_array()
        .unwrap_or_else(|| panic!("botocore found no Contents array in our XML:\n{parsed}"));
    assert_eq!(
        contents.len(),
        2,
        "botocore read {} objects out of a listing of two:\n{parsed}",
        contents.len()
    );
    let keys: Vec<&str> = contents.iter().filter_map(|c| c["Key"].as_str()).collect();
    assert!(
        keys.contains(&"alpha.txt") && keys.contains(&"nested/beta.json"),
        "the keys did not survive the XML round trip; a key containing `/` is the one most \
         likely to be mangled by escaping: {keys:?}"
    );
    assert_eq!(
        contents
            .iter()
            .find(|c| c["Key"] == "alpha.txt")
            .map(|c| c["Size"].clone()),
        Some(json!(11)),
        "the Size element did not reach botocore as a number:\n{parsed}"
    );

    // --- GetObject: the body, written to a file the CLI chose ---------------
    let dir = tempfile::tempdir()?;
    let out_path = dir.path().join("alpha.txt");
    let get = aws_s3api(
        port,
        &[
            "get-object",
            "--bucket",
            "netget-bucket",
            "--key",
            "alpha.txt",
            out_path.to_str().expect("temp path is utf-8"),
        ],
    )
    .await;
    assert!(
        get.success,
        "the AWS CLI could not complete GetObject.\nstdout: {}\nstderr: {}",
        get.stdout, get.stderr
    );
    let body = std::fs::read_to_string(&out_path)?;
    assert_eq!(
        body, "hello botocore",
        "the object body the model authored did not reach the file botocore wrote"
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}
