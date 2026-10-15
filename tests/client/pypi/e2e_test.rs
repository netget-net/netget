//! E2E tests for PyPI client
//!
//! These tests verify PyPI client functionality by spawning the actual NetGet binary
//! and testing client behavior as a black-box.

mod pypi_client_tests {
    use crate::helpers::*;
    use std::time::Duration;

    /// Test PyPI client fetching package information
    /// LLM calls: 1 (client connection and package query)
    #[tokio::test]
    #[ignore = "No .with_mock() configured: hits real pypi.org and requires --use-ollama; the LLM call is refused under strict-mock mode"]
    async fn test_pypi_get_package_info() -> E2EResult<()> {
        // Start PyPI client that queries package info
        let client_config = NetGetConfig::new(
            "Connect to PyPI and get information about the 'requests' package. Show the package description and latest version."
        );

        let mut client = start_netget_client(client_config).await?;

        // Give client time to make request and process response
        tokio::time::sleep(Duration::from_secs(3)).await;

        // Verify client output shows PyPI protocol or package info
        let output = client.get_output().await;
        assert!(
            output.iter().any(|l| l.contains("PyPI"))
                || output.iter().any(|l| l.contains("requests"))
                || output.iter().any(|l| l.contains("package")),
            "Client should show PyPI protocol or package information. Output: {:?}",
            output
        );

        println!("✅ PyPI client fetched package info successfully");

        // Cleanup
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last response routinely lands
        // after the sleep expires, and the test reports it as never having happened.
        client.wait_for_mocks(30).await;
        client.verify_mocks().await?;
        client.stop().await?;

        Ok(())
    }

    /// Test PyPI client listing package files
    /// LLM calls: 1 (client connection and file list query)
    #[tokio::test]
    #[ignore = "No .with_mock() configured: hits real pypi.org and requires --use-ollama. See test_pypi_get_package_info for details"]
    async fn test_pypi_list_package_files() -> E2EResult<()> {
        // Start PyPI client that lists available files
        let client_config = NetGetConfig::new(
            "Connect to PyPI and list all available distribution files (wheels and source distributions) for the 'flask' package."
        );

        let mut client = start_netget_client(client_config).await?;

        // Give client time to make request
        tokio::time::sleep(Duration::from_secs(3)).await;

        // Verify client is PyPI protocol
        assert_eq!(client.protocol, "PyPI", "Client should be PyPI protocol");

        // Verify output mentions files or wheels
        let output = client.get_output().await;
        assert!(
            output.iter().any(|l| l.contains("whl"))
                || output.iter().any(|l| l.contains("tar.gz"))
                || output.iter().any(|l| l.contains("file"))
                || output.iter().any(|l| l.contains("wheel")),
            "Client should show package files information. Output: {:?}",
            output
        );

        println!("✅ PyPI client listed package files successfully");

        // Cleanup
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last response routinely lands
        // after the sleep expires, and the test reports it as never having happened.
        client.wait_for_mocks(30).await;
        client.verify_mocks().await?;
        client.stop().await?;

        Ok(())
    }

    /// Test PyPI client handling non-existent package
    /// LLM calls: 1 (client connection and query)
    #[tokio::test]
    #[ignore = "No .with_mock() configured: hits real pypi.org and requires --use-ollama. See test_pypi_get_package_info for details"]
    async fn test_pypi_nonexistent_package() -> E2EResult<()> {
        // Start PyPI client that queries a non-existent package
        let client_config = NetGetConfig::new(
            "Connect to PyPI and try to get information about the package 'this-package-definitely-does-not-exist-12345678'."
        );

        let mut client = start_netget_client(client_config).await?;

        // Give client time to make request and handle error
        tokio::time::sleep(Duration::from_secs(3)).await;

        // Verify client handled error gracefully
        let output = client.get_output().await;
        assert!(
            output.iter().any(|l| l.contains("ERROR"))
                || output.iter().any(|l| l.contains("not found"))
                || output.iter().any(|l| l.contains("404"))
                || output.iter().any(|l| l.contains("failed")),
            "Client should show error for non-existent package. Output: {:?}",
            output
        );

        println!("✅ PyPI client handled non-existent package error");

        // Cleanup
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last response routinely lands
        // after the sleep expires, and the test reports it as never having happened.
        client.wait_for_mocks(30).await;
        client.verify_mocks().await?;
        client.stop().await?;

        Ok(())
    }

    /// Test PyPI client with LLM-controlled package exploration
    /// LLM calls: 1 (client connection and exploration)
    #[tokio::test]
    #[ignore = "No .with_mock() configured: hits real pypi.org and requires --use-ollama. See test_pypi_get_package_info for details"]
    async fn test_pypi_llm_controlled_exploration() -> E2EResult<()> {
        // Client that explores package ecosystem based on LLM instruction
        let client_config = NetGetConfig::new(
            "Connect to PyPI and explore the 'django' package. Look at its metadata and determine if it's a web framework."
        );

        let mut client = start_netget_client(client_config).await?;

        // Give client time to explore
        tokio::time::sleep(Duration::from_secs(3)).await;

        // Verify the client is PyPI protocol
        assert_eq!(client.protocol, "PyPI", "Client should be PyPI protocol");

        // Verify output shows exploration
        let output = client.get_output().await;
        assert!(
            output.iter().any(|l| l.contains("django"))
                || output.iter().any(|l| l.contains("package"))
                || output.iter().any(|l| l.contains("info")),
            "Client should show package exploration. Output: {:?}",
            output
        );

        println!("✅ PyPI client responded to LLM exploration instruction");

        // Cleanup
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last response routinely lands
        // after the sleep expires, and the test reports it as never having happened.
        client.wait_for_mocks(30).await;
        client.verify_mocks().await?;
        client.stop().await?;

        Ok(())
    }
}
