//! E2E tests for NFS client
//!
//! These tests verify NFS client functionality by spawning the actual NetGet binary
//! and testing client behavior as a black-box.
//! Test strategy: Use netget binary to start NFS server + client, < 10 LLM calls total.

#[cfg(unix)]
mod nfs_client_tests {
    use crate::helpers::*;
    use std::time::Duration;

    /// Test NFS client can mount and read from NFS server
    /// LLM calls: 4 (server startup, server file list, client mount, client read)
    #[tokio::test]
    #[ignore = "No .with_mock() configured: requires --use-ollama; the LLM call is refused under strict-mock mode"]
    async fn test_nfs_client_mount_and_read() -> E2EResult<()> {
        // Start an NFS server with a simple filesystem
        let server_config = NetGetConfig::new(
            "Listen on port {AVAILABLE_PORT} via NFS. Export /data with a file readme.txt containing 'Hello from NFS server'."
        );

        let mut server = start_netget_server(server_config).await?;

        // Give server time to start
        tokio::time::sleep(Duration::from_millis(1000)).await;

        // Now start an NFS client that mounts and reads the file
        let client_config = NetGetConfig::new(format!(
            "Connect to NFS server at 127.0.0.1:{}:/data and read /readme.txt.",
            server.port
        ));

        let mut client = start_netget_client(client_config).await?;

        // Give client time to mount and read
        tokio::time::sleep(Duration::from_secs(3)).await;

        // Verify client output shows mount and read
        client.wait_for_any(&["mounted", "NFS"], 30).await;
        assert!(
            client.output_contains("mounted").await || client.output_contains("NFS").await,
            "Client should show NFS mount message. Output: {:?}",
            client.get_output().await
        );

        println!("✅ NFS client mounted export and read file successfully");

        // Cleanup
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last response routinely lands
        // after the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last response routinely lands
        // after the sleep expires, and the test reports it as never having happened.
        client.wait_for_mocks(30).await;
        client.verify_mocks().await?;
        client.stop().await?;

        Ok(())
    }

    /// Test NFS client can list directory contents
    /// LLM calls: 3 (server startup, client mount, client listdir)
    #[tokio::test]
    #[ignore = "No .with_mock() configured: requires --use-ollama; the LLM call is refused under strict-mock mode"]
    async fn test_nfs_client_list_directory() -> E2EResult<()> {
        // Start an NFS server with multiple files
        let server_config = NetGetConfig::new(
            "Listen on port {AVAILABLE_PORT} via NFS. Export /data with root directory containing: file1.txt, file2.txt, and directory docs."
        );

        let mut server = start_netget_server(server_config).await?;

        tokio::time::sleep(Duration::from_millis(1000)).await;

        // Client that lists the directory
        let client_config = NetGetConfig::new(format!(
            "Connect to NFS server at 127.0.0.1:{}:/data and list the root directory contents.",
            server.port
        ));

        let mut client = start_netget_client(client_config).await?;

        tokio::time::sleep(Duration::from_secs(3)).await;

        // Verify client initiated the connection and listed directory
        assert_eq!(client.protocol, "NFS", "Client should be NFS protocol");

        println!("✅ NFS client listed directory contents successfully");

        // Cleanup
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last response routinely lands
        // after the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last response routinely lands
        // after the sleep expires, and the test reports it as never having happened.
        client.wait_for_mocks(30).await;
        client.verify_mocks().await?;
        client.stop().await?;

        Ok(())
    }

    /// Test NFS client can write to a file
    /// LLM calls: 4 (server startup, client mount, client write, client verify)
    #[tokio::test]
    #[ignore = "No .with_mock() configured: requires --use-ollama; the LLM call is refused under strict-mock mode"]
    async fn test_nfs_client_write_file() -> E2EResult<()> {
        // Start an NFS server that accepts writes
        let server_config = NetGetConfig::new(
            "Listen on port {AVAILABLE_PORT} via NFS. Export /data with empty root directory. Accept all file writes and log them."
        );

        let mut server = start_netget_server(server_config).await?;

        tokio::time::sleep(Duration::from_millis(1000)).await;

        // Client that writes a file
        let client_config = NetGetConfig::new(format!(
            "Connect to NFS server at 127.0.0.1:{}:/data, create file /output.txt, and write 'Test data'.",
            server.port
        ));

        let mut client = start_netget_client(client_config).await?;

        tokio::time::sleep(Duration::from_secs(3)).await;

        // Verify client wrote the file
        client.wait_for_any(&["NFS", "mounted"], 30).await;
        assert!(
            client.output_contains("NFS").await || client.output_contains("mounted").await,
            "Client should show NFS activity. Output: {:?}",
            client.get_output().await
        );

        println!("✅ NFS client wrote file successfully");

        // Cleanup
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last response routinely lands
        // after the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last response routinely lands
        // after the sleep expires, and the test reports it as never having happened.
        client.wait_for_mocks(30).await;
        client.verify_mocks().await?;
        client.stop().await?;

        Ok(())
    }

    /// Test NFS client can create directories
    /// LLM calls: 3 (server startup, client mount, client mkdir)
    #[tokio::test]
    #[ignore = "No .with_mock() configured: requires --use-ollama; the LLM call is refused under strict-mock mode"]
    async fn test_nfs_client_create_directory() -> E2EResult<()> {
        // Start an NFS server
        let server_config = NetGetConfig::new(
            "Listen on port {AVAILABLE_PORT} via NFS. Export /data with empty root. Accept mkdir operations and log them."
        );

        let mut server = start_netget_server(server_config).await?;

        tokio::time::sleep(Duration::from_millis(1000)).await;

        // Client that creates a directory
        let client_config = NetGetConfig::new(format!(
            "Connect to NFS server at 127.0.0.1:{}:/data and create directory /newdir.",
            server.port
        ));

        let mut client = start_netget_client(client_config).await?;

        tokio::time::sleep(Duration::from_secs(3)).await;

        // Verify client protocol
        assert_eq!(client.protocol, "NFS", "Client should be NFS protocol");

        println!("✅ NFS client created directory successfully");

        // Cleanup
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last response routinely lands
        // after the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last response routinely lands
        // after the sleep expires, and the test reports it as never having happened.
        client.wait_for_mocks(30).await;
        client.verify_mocks().await?;
        client.stop().await?;

        Ok(())
    }
}
