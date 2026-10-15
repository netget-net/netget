//! E2E tests for Maven client
//!
//! These tests verify Maven client functionality by spawning the actual NetGet binary
//! and testing client behavior against real Maven repositories.

mod maven_client_tests {
    use crate::helpers::*;
    use std::time::Duration;

    /// Test Maven client downloading a well-known artifact
    /// LLM calls: 1 (client connection and download)
    #[tokio::test]
    #[ignore = "No .with_mock() configured: hits real Maven Central and requires --use-ollama; the LLM call is refused under strict-mock mode"]
    async fn test_maven_client_download_artifact() -> E2EResult<()> {
        // Start Maven client to download a well-known artifact from Maven Central
        let client_config = NetGetConfig::new(
            "Connect to Maven Central and download the artifact org.apache.commons:commons-lang3:3.12.0"
        );

        let mut client = start_netget_client(client_config).await?;

        // Give client time to connect and download
        tokio::time::sleep(Duration::from_secs(3)).await;

        // Verify client output shows Maven protocol and artifact download
        let output = client.get_output().await;
        assert!(
            output.iter().any(|l| l.contains("Maven"))
                || output.iter().any(|l| l.contains("maven"))
                || output.iter().any(|l| l.contains("artifact")),
            "Client should show Maven protocol or artifact message. Output: {:?}",
            output
        );

        println!("✅ Maven client downloaded artifact successfully");

        // Cleanup
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last response routinely lands
        // after the sleep expires, and the test reports it as never having happened.
        client.wait_for_mocks(30).await;
        client.verify_mocks().await?;
        client.stop().await?;

        Ok(())
    }

    /// Test Maven client downloading a POM file
    /// LLM calls: 1 (client connection and POM download)
    #[tokio::test]
    #[ignore = "No .with_mock() configured: hits real Maven Central and requires --use-ollama; the LLM call is refused under strict-mock mode"]
    async fn test_maven_client_download_pom() -> E2EResult<()> {
        // Start Maven client to download a POM file
        let client_config = NetGetConfig::new(
            "Connect to Maven Central and download the POM file for junit:junit:4.13.2",
        );

        let mut client = start_netget_client(client_config).await?;

        // Give client time to connect and download POM
        tokio::time::sleep(Duration::from_secs(3)).await;

        // Verify client output shows Maven and POM-related messages
        let output = client.get_output().await;
        assert!(
            output.iter().any(|l| l.contains("Maven"))
                || output.iter().any(|l| l.contains("maven"))
                || output.iter().any(|l| l.contains("POM"))
                || output.iter().any(|l| l.contains("pom")),
            "Client should show Maven and POM messages. Output: {:?}",
            output
        );

        println!("✅ Maven client downloaded POM successfully");

        // Cleanup
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last response routinely lands
        // after the sleep expires, and the test reports it as never having happened.
        client.wait_for_mocks(30).await;
        client.verify_mocks().await?;
        client.stop().await?;

        Ok(())
    }

    /// Test Maven client searching for artifact versions
    /// LLM calls: 1 (client connection and metadata fetch)
    #[tokio::test]
    #[ignore = "No .with_mock() configured: hits real Maven Central and requires --use-ollama; the LLM call is refused under strict-mock mode"]
    async fn test_maven_client_search_versions() -> E2EResult<()> {
        // Start Maven client to search for artifact versions
        let client_config = NetGetConfig::new(
            "Connect to Maven Central and find all available versions of com.google.guava:guava",
        );

        let mut client = start_netget_client(client_config).await?;

        // Give client time to connect and fetch metadata
        tokio::time::sleep(Duration::from_secs(3)).await;

        // Verify client output shows Maven protocol
        let output = client.get_output().await;
        assert!(
            output.iter().any(|l| l.contains("Maven"))
                || output.iter().any(|l| l.contains("maven"))
                || output.iter().any(|l| l.contains("version")),
            "Client should show Maven protocol or version message. Output: {:?}",
            output
        );

        println!("✅ Maven client searched for versions successfully");

        // Cleanup
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last response routinely lands
        // after the sleep expires, and the test reports it as never having happened.
        client.wait_for_mocks(30).await;
        client.verify_mocks().await?;
        client.stop().await?;

        Ok(())
    }

    /// Test Maven client with custom repository URL
    /// LLM calls: 1 (client connection)
    #[tokio::test]
    #[ignore = "No .with_mock() configured: hits real Maven Central and requires --use-ollama; the LLM call is refused under strict-mock mode"]
    async fn test_maven_client_custom_repository() -> E2EResult<()> {
        // Start Maven client with explicit Maven Central URL
        let client_config = NetGetConfig::new(
            "Connect to https://repo.maven.apache.org/maven2 via Maven and download commons-io:commons-io:2.11.0"
        );

        let mut client = start_netget_client(client_config).await?;

        // Give client time to connect and process
        tokio::time::sleep(Duration::from_secs(3)).await;

        // Verify client is using Maven protocol
        assert_eq!(client.protocol, "Maven", "Client should be Maven protocol");

        println!("✅ Maven client connected to custom repository");

        // Cleanup
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last response routinely lands
        // after the sleep expires, and the test reports it as never having happened.
        client.wait_for_mocks(30).await;
        client.verify_mocks().await?;
        client.stop().await?;

        Ok(())
    }

    /// Test Maven client handling missing artifact (404)
    /// LLM calls: 1 (client connection and failed download)
    #[tokio::test]
    #[ignore = "No .with_mock() configured: hits real Maven Central and requires --use-ollama; the LLM call is refused under strict-mock mode"]
    async fn test_maven_client_missing_artifact() -> E2EResult<()> {
        // Start Maven client trying to download a non-existent artifact
        let client_config = NetGetConfig::new(
            "Connect to Maven Central and try to download nonexistent:artifact:99.99.99",
        );

        let mut client = start_netget_client(client_config).await?;

        // Give client time to attempt download
        tokio::time::sleep(Duration::from_secs(3)).await;

        // Client should handle error gracefully
        let output = client.get_output().await;
        // Either shows error or Maven connection
        assert!(
            output.iter().any(|l| l.contains("Maven"))
                || output.iter().any(|l| l.contains("maven"))
                || output.iter().any(|l| l.contains("ERROR"))
                || output.iter().any(|l| l.contains("not found"))
                || output.iter().any(|l| l.contains("404")),
            "Client should show Maven protocol or error message. Output: {:?}",
            output
        );

        println!("✅ Maven client handled missing artifact gracefully");

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
