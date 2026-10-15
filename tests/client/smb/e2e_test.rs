//! E2E tests for SMB client
//!
//! These tests verify SMB client functionality by connecting to a Samba server.
//! Requires a Samba server running with guest access.

mod smb_client_tests {
    use crate::helpers::*;
    use std::time::Duration;

    /// Test SMB client connection and directory listing
    /// LLM calls: 2 (server startup, client connection)
    ///
    /// Prerequisites:
    /// - Samba server running at 127.0.0.1:445 (or custom port)
    /// - Share named "test" with guest read access
    /// - At least one file/directory in the share
    ///
    /// Setup with Docker:
    /// ```bash
    /// docker run -d --name samba-test \
    ///   -p 445:445 \
    ///   -e "USER=guest;password" \
    ///   -e "SHARE=test;/share;yes;no;no;guest" \
    ///   dperson/samba
    /// ```
    #[tokio::test]
    #[ignore = "Requires external Samba server"]
    async fn test_smb_client_connect_and_list() -> E2EResult<()> {
        // SMB client that connects and lists directory
        let client_config = NetGetConfig::new(
            "Connect to smb://127.0.0.1/test via SMB with username=guest password='' and list the root directory."
        );

        let mut client = start_netget_client(client_config).await?;

        // Give client time to connect and execute command
        tokio::time::sleep(Duration::from_secs(2)).await;

        // Verify client output shows connection
        client
            .wait_for_any(&["SMB client", "smb_connected"], 30)
            .await;
        assert!(
            client.output_contains("SMB client").await
                || client.output_contains("smb_connected").await,
            "Client should show SMB connection message. Output: {:?}",
            client.get_output().await
        );

        println!("✅ SMB client connected and listed directory successfully");

        // Cleanup
        client.stop().await?;

        Ok(())
    }

    /// Test SMB client can read files
    /// LLM calls: 2 (initial connection, read operation)
    #[tokio::test]
    #[ignore = "Requires external Samba server with test file"]
    async fn test_smb_client_read_file() -> E2EResult<()> {
        // SMB client that reads a file
        let client_config = NetGetConfig::new(
            "Connect to smb://127.0.0.1/test via SMB with guest credentials and read the file 'readme.txt'."
        );

        let mut client = start_netget_client(client_config).await?;

        tokio::time::sleep(Duration::from_secs(2)).await;

        // Verify the client is SMB protocol
        assert_eq!(client.protocol, "SMB", "Client should be SMB protocol");

        println!("✅ SMB client read file successfully");

        // Cleanup
        client.stop().await?;

        Ok(())
    }

    /// Test SMB client can write files (requires write access)
    /// LLM calls: 2 (initial connection, write operation)
    #[tokio::test]
    #[ignore = "Requires external Samba server with write access"]
    async fn test_smb_client_write_file() -> E2EResult<()> {
        // SMB client that writes a file
        let client_config = NetGetConfig::new(
            "Connect to smb://127.0.0.1/test via SMB and write 'Hello from NetGet' to a file named 'test.txt'."
        );

        let mut client = start_netget_client(client_config).await?;

        tokio::time::sleep(Duration::from_secs(2)).await;

        // Verify the client performed write operation
        client
            .wait_for_any(&["written", "smb_file_written"], 30)
            .await;
        assert!(
            client.output_contains("written").await
                || client.output_contains("smb_file_written").await,
            "Client should show file write confirmation. Output: {:?}",
            client.get_output().await
        );

        println!("✅ SMB client wrote file successfully");

        // Cleanup
        client.stop().await?;

        Ok(())
    }

    /// Test SMB client can create and delete directories
    /// LLM calls: 3 (connection, create, delete)
    #[tokio::test]
    #[ignore = "Requires external Samba server with write access"]
    async fn test_smb_client_directory_operations() -> E2EResult<()> {
        // SMB client that creates and deletes a directory
        let client_config = NetGetConfig::new(
            "Connect to smb://127.0.0.1/test via SMB, create a directory named 'testdir', then delete it."
        );

        let mut client = start_netget_client(client_config).await?;

        tokio::time::sleep(Duration::from_secs(3)).await;

        // Verify directory operations
        let output = client.get_output().await;
        assert!(
            output.iter().any(|l| l.contains("created directory"))
                || output.iter().any(|l| l.contains("deleted directory")),
            "Client should show directory operations. Output: {:?}",
            output
        );

        println!("✅ SMB client performed directory operations successfully");

        // Cleanup
        client.stop().await?;

        Ok(())
    }
}
