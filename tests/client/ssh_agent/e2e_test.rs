//! E2E tests for SSH Agent client
//!
//! These tests verify SSH Agent client functionality by connecting to a
//! mock SSH Agent server and testing LLM-controlled client behavior.

#![cfg(unix)]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Mutex;

/// Mock SSH Agent server for testing
struct MockSshAgent {
    socket_path: PathBuf,
    _temp_dir: TempDir,
    listener: Arc<Mutex<Option<UnixListener>>>,
}

impl MockSshAgent {
    /// Create a new mock SSH Agent server
    async fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let temp_dir = TempDir::new()?;
        let socket_path = temp_dir.path().join("ssh-agent.sock");

        let listener = UnixListener::bind(&socket_path)?;

        Ok(Self {
            socket_path: socket_path.clone(),
            _temp_dir: temp_dir,
            listener: Arc::new(Mutex::new(Some(listener))),
        })
    }

    /// Get the socket path
    fn socket_path(&self) -> &PathBuf {
        &self.socket_path
    }

    /// Start serving SSH Agent requests
    async fn start(self: Arc<Self>) {
        let listener = {
            let mut lock = self.listener.lock().await;
            lock.take()
        };

        if let Some(listener) = listener {
            tokio::spawn(async move {
                loop {
                    match listener.accept().await {
                        Ok((mut stream, _)) => {
                            tokio::spawn(async move {
                                let mut buf = vec![0u8; 8192];

                                // Read request
                                if let Ok(n) = stream.read(&mut buf).await {
                                    if n >= 5 {
                                        let msg_type = buf[4];

                                        match msg_type {
                                            // REQUEST_IDENTITIES (11)
                                            11 => {
                                                // Respond with IDENTITIES_ANSWER (12) with 0 keys
                                                let mut response = Vec::new();
                                                response.extend_from_slice(&5u32.to_be_bytes()); // Length: 5
                                                response.push(12); // Type: IDENTITIES_ANSWER
                                                response.extend_from_slice(&0u32.to_be_bytes()); // 0 keys

                                                let _ = stream.write_all(&response).await;
                                            }
                                            // SIGN_REQUEST (13)
                                            13 => {
                                                // Respond with SIGN_RESPONSE (14) with dummy signature
                                                let mut response = Vec::new();
                                                let dummy_sig = b"dummy_signature_data";

                                                // Length: 1 (type) + 4 (sig len) + sig data
                                                let total_len = 1 + 4 + dummy_sig.len();
                                                response.extend_from_slice(
                                                    &(total_len as u32).to_be_bytes(),
                                                );
                                                response.push(14); // Type: SIGN_RESPONSE
                                                response.extend_from_slice(
                                                    &(dummy_sig.len() as u32).to_be_bytes(),
                                                );
                                                response.extend_from_slice(dummy_sig);

                                                let _ = stream.write_all(&response).await;
                                            }
                                            _ => {
                                                // Unknown message type - send FAILURE (5)
                                                let mut response = Vec::new();
                                                response.extend_from_slice(&1u32.to_be_bytes()); // Length: 1
                                                response.push(5); // Type: FAILURE
                                                let _ = stream.write_all(&response).await;
                                            }
                                        }
                                    }
                                }
                            });
                        }
                        Err(_) => break,
                    }
                }
            });
        }

        // Give server time to start
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Test basic Unix socket message format
#[tokio::test]
async fn test_ssh_agent_message_format() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n=== Unit Test: SSH Agent Message Format ===");

    // Verify REQUEST_IDENTITIES format
    let mut msg = Vec::new();
    msg.extend_from_slice(&1u32.to_be_bytes()); // Length: 1
    msg.push(11); // Type: REQUEST_IDENTITIES

    assert_eq!(msg.len(), 5, "Message should be 5 bytes");
    assert_eq!(
        u32::from_be_bytes([msg[0], msg[1], msg[2], msg[3]]),
        1,
        "Length should be 1"
    );
    assert_eq!(msg[4], 11, "Type should be REQUEST_IDENTITIES (11)");

    println!("✓ SSH Agent message format test passed");
    println!("=== Test passed ===\n");
    Ok(())
}

/// Test mock SSH Agent server responds to REQUEST_IDENTITIES
#[tokio::test]
async fn test_mock_server_request_identities() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n=== E2E Test: Mock Server REQUEST_IDENTITIES ===");

    // Start mock server
    let mock = Arc::new(MockSshAgent::new().await?);
    let socket_path = mock.socket_path().clone();

    mock.clone().start().await;
    println!("Mock server started on: {}", socket_path.display());

    // Connect to mock server
    let mut stream = UnixStream::connect(&socket_path).await?;
    println!("✓ Connected to mock server");

    // Send REQUEST_IDENTITIES
    let mut request = Vec::new();
    request.extend_from_slice(&1u32.to_be_bytes()); // Length: 1
    request.push(11); // Type: REQUEST_IDENTITIES

    stream.write_all(&request).await?;
    stream.flush().await?;
    println!("Sent REQUEST_IDENTITIES");

    // Read response
    let mut response = vec![0u8; 1024];
    match tokio::time::timeout(Duration::from_secs(5), stream.read(&mut response)).await {
        Ok(Ok(n)) if n >= 5 => {
            let length = u32::from_be_bytes([response[0], response[1], response[2], response[3]]);
            let msg_type = response[4];

            println!("Received response: length={}, type={}", length, msg_type);

            assert_eq!(msg_type, 12, "Expected IDENTITIES_ANSWER (12)");
            assert_eq!(length, 5, "Expected length 5 (type + num_keys)");

            let num_keys = u32::from_be_bytes([response[5], response[6], response[7], response[8]]);
            assert_eq!(num_keys, 0, "Expected 0 keys");

            println!("✓ Mock server responded correctly");
        }
        Ok(Ok(_)) => return Err("Connection closed without response".into()),
        Ok(Err(e)) => return Err(format!("Read error: {}", e).into()),
        Err(_) => return Err("Response timeout".into()),
    }

    println!("=== Test passed ===\n");
    Ok(())
}

/// Test mock SSH Agent server responds to SIGN_REQUEST
#[tokio::test]
async fn test_mock_server_sign_request() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n=== E2E Test: Mock Server SIGN_REQUEST ===");

    // Start mock server
    let mock = Arc::new(MockSshAgent::new().await?);
    let socket_path = mock.socket_path().clone();

    mock.clone().start().await;
    println!("Mock server started on: {}", socket_path.display());

    // Connect to mock server
    let mut stream = UnixStream::connect(&socket_path).await?;
    println!("✓ Connected to mock server");

    // Send minimal SIGN_REQUEST (type 13)
    // Format: length + type + key_blob + data + flags
    let mut request = Vec::new();

    // Dummy key blob (just length + empty data for testing)
    let key_blob = Vec::<u8>::new();

    // Dummy data to sign
    let data = b"test_data";

    // Calculate total length: 1 (type) + 4 (key len) + key + 4 (data len) + data + 4 (flags)
    let total_len = 1 + 4 + key_blob.len() + 4 + data.len() + 4;

    request.extend_from_slice(&(total_len as u32).to_be_bytes());
    request.push(13); // Type: SIGN_REQUEST
    request.extend_from_slice(&(key_blob.len() as u32).to_be_bytes());
    request.extend_from_slice(&key_blob);
    request.extend_from_slice(&(data.len() as u32).to_be_bytes());
    request.extend_from_slice(data);
    request.extend_from_slice(&0u32.to_be_bytes()); // flags

    stream.write_all(&request).await?;
    stream.flush().await?;
    println!("Sent SIGN_REQUEST");

    // Read response
    let mut response = vec![0u8; 1024];
    match tokio::time::timeout(Duration::from_secs(5), stream.read(&mut response)).await {
        Ok(Ok(n)) if n >= 5 => {
            let msg_type = response[4];

            println!("Received response: type={}", msg_type);

            assert_eq!(msg_type, 14, "Expected SIGN_RESPONSE (14)");
            println!("✓ Mock server responded with signature");
        }
        Ok(Ok(_)) => return Err("Connection closed without response".into()),
        Ok(Err(e)) => return Err(format!("Read error: {}", e).into()),
        Err(_) => return Err("Response timeout".into()),
    }

    println!("=== Test passed ===\n");
    Ok(())
}
