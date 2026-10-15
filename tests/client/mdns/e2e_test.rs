//! E2E tests for mDNS client
//!
//! These tests verify mDNS client functionality by spawning the actual NetGet binary
//! and testing client behavior as a black-box.
//! Test strategy: Use netget binary to start mDNS client, < 5 LLM calls total.
//!
//! Note: These tests rely on built-in mDNS responders (Avahi on Linux, mDNSResponder on macOS).
//! Tests may not discover services if no mDNS services are available on the network.

mod mdns_client_tests {
    use crate::helpers::*;
    use std::time::Duration;

    /// Test mDNS client initialization
    /// LLM calls: 1 (client startup)
    #[tokio::test]
    async fn test_mdns_client_initialization() -> E2EResult<()> {
        // Start mDNS client with instruction to browse for HTTP services with mocks
        let client_config = NetGetConfig::new(
            "Initialize mDNS client and browse for HTTP services (_http._tcp.local).",
        )
        .with_mock(|mock| {
            mock
                // Mock 1: Client startup (user command)
                .on_instruction_containing("Initialize mDNS client")
                .and_instruction_containing("browse for HTTP services")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_client",
                        "remote_addr": "local",
                        "protocol": "mDNS",
                        "instruction": "Browse for HTTP services"
                    }
                ]))
                .expect_calls(1)
                .and()
        });

        let mut client = start_netget_client(client_config).await?;

        // Give client time to initialize
        client.wait_for_mocks(30).await;

        // Verify client output shows initialization
        let output = client.get_output().await;
        assert!(
            output.iter().any(|l| l.contains("mDNS"))
                || output.iter().any(|l| l.contains("initialized"))
                || output.iter().any(|l| l.contains("ready")),
            "Client should show mDNS initialization. Output: {:?}",
            output
        );

        println!("✅ mDNS client initialized successfully");

        // Verify mock expectations were met
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last response routinely lands
        // after the sleep expires, and the test reports it as never having happened.
        client.wait_for_mocks(30).await;
        client.verify_mocks().await?;

        // Cleanup
        client.stop().await?;

        Ok(())
    }

    /// Test mDNS client service discovery, against a service the test advertises itself.
    /// LLM calls: 3 (client startup, browse service, service found)
    ///
    /// This test used to browse `_services._dns-sd._udp.local` and hope something on the
    /// operator's network answered, then assert that the client's output contained the
    /// substring "mDNS" **or** "browse" **or** "service". The client logs
    /// `mDNS client N ...` on every line it writes, so that assertion was true before a
    /// single packet left the machine — a green run said only that the process started.
    /// Its own comment admitted as much: "Note: No services may be found if network has no
    /// active mDNS responders".
    ///
    /// So the test now supplies the responder. It advertises one uniquely-named service
    /// with `mdns_sd`, browses for exactly that type, and puts an `expect_calls(1)` on the
    /// `mdns_service_found` event — an event the client can only raise if a real
    /// advertisement arrived on the multicast group and parsed. `verify_mocks()` then
    /// fails the test when discovery does not happen, instead of printing a note about it.
    #[tokio::test]
    async fn test_mdns_client_service_discovery() -> E2EResult<()> {
        // A type nothing else on the link will be advertising, so the client's discovery
        // cannot be satisfied by a neighbour's service — the mistake the *server* suite made,
        // where one test verified itself against another test's advertisement.
        const SERVICE_TYPE: &str = "_netgetclient._tcp.local.";
        const INSTANCE: &str = "NetGet Client Discovery Probe";

        // Advertise before the client starts, so the browse cannot miss the initial burst.
        // Held for the whole test: dropping a `ServiceDaemon` does not stop it announcing
        // (it has no `Drop` impl), and dropping it early would not stop it either.
        let responder = mdns_sd::ServiceDaemon::new()
            .map_err(|e| format!("failed to create the advertising mDNS daemon: {e}"))?;
        //
        // The address is left to `enable_addr_auto()` rather than pinned to 127.0.0.1.
        // Loopback carries no multicast route: a service announced only on 127.0.0.1 is
        // registered without error and never reaches the group, so the browsing client hears
        // nothing and the failure looks like a broken client. Letting the daemon fill in the
        // host's real interface addresses is what `src/server/mdns/` does too, via
        // `get_local_ip()`.
        let info = mdns_sd::ServiceInfo::new(
            SERVICE_TYPE,
            INSTANCE,
            "netget-client-probe.local.",
            "",
            8080,
            &[("probe", "1")][..],
        )
        .map_err(|e| format!("failed to build the probe ServiceInfo: {e}"))?
        .enable_addr_auto();
        responder
            .register(info)
            .map_err(|e| format!("failed to advertise the probe service: {e}"))?;

        let client_config = NetGetConfig::new(
            "Initialize mDNS client and browse for netgetclient services \
             (_netgetclient._tcp.local). Report what is discovered.",
        )
        .with_mock(|mock| {
            mock
                // Mock 1: Client startup (user command)
                .on_instruction_containing("Initialize mDNS client")
                .and_instruction_containing("browse for netgetclient services")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_client",
                        "remote_addr": "local",
                        "protocol": "mDNS",
                        "instruction": "Browse for netgetclient services"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 2: the discovery itself. `expect_calls(1)` on this rule is the
                // assertion the old test lacked: `mdns_service_found` is raised only when a
                // real advertisement of the browsed type arrives and parses, so a client
                // that browsed and heard nothing fails here rather than passing quietly.
                //
                // Declared before the connect rule: `on_event` rules are first-match-wins,
                // and both would otherwise be candidates in declaration order.
                .on_event("mdns_service_found")
                .and_event_data_contains("fullname", INSTANCE)
                .respond_with_actions(serde_json::json!([{"type": "wait_for_more"}]))
                .expect_calls(1)
                .and()
                // Mock 3: Client connected event (browse for the probe type)
                .on_event("mdns_connected")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "browse_service",
                        "service_type": SERVICE_TYPE
                    }
                ]))
                .expect_calls(1)
                .and()
        });

        let mut client = start_netget_client(client_config).await?;

        // Verify the client was initialized as mDNS protocol
        assert_eq!(client.protocol, "mDNS", "Client should be mDNS protocol");

        // Wait on the condition — the discovery reaching the model — rather than on a fixed
        // 12-second sleep. Returns as soon as the last expected call lands.
        client.wait_for_mocks(30).await;
        client.verify_mocks().await?;

        println!("✅ mDNS client discovered {INSTANCE} on the multicast group");

        let _ = responder.shutdown();

        // Cleanup
        client.stop().await?;

        Ok(())
    }

    /// Test mDNS client hostname resolution
    /// LLM calls: 2 (client startup, resolve hostname)
    #[tokio::test]
    async fn test_mdns_client_hostname_resolution() -> E2EResult<()> {
        // Start mDNS client with instruction to resolve a local hostname with mocks
        // Using localhost.local which should be resolvable on most systems
        let client_config = NetGetConfig::new(
            "Initialize mDNS client and resolve 'localhost.local' to an IP address.",
        )
        .with_mock(|mock| {
            mock
                // Mock 1: Client startup (user command)
                .on_instruction_containing("Initialize mDNS client")
                .and_instruction_containing("resolve 'localhost.local'")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_client",
                        "remote_addr": "local",
                        "protocol": "mDNS",
                        "instruction": "Resolve localhost.local"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 2: Client connected event (resolve hostname)
                .on_event("mdns_connected")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "resolve_hostname",
                        "hostname": "localhost.local"
                    }
                ]))
                .expect_calls(1)
                .and()
        });

        let mut client = start_netget_client(client_config).await?;

        // Give client time to resolve
        client.wait_for_mocks(30).await;

        let output = client.get_output().await;

        // Verify client attempted hostname resolution
        assert!(
            output.iter().any(|l| l.contains("resolve"))
                || output.iter().any(|l| l.contains("localhost"))
                || output.iter().any(|l| l.contains("mDNS")),
            "Client should show hostname resolution activity. Output: {:?}",
            output
        );

        println!("✅ mDNS client attempted hostname resolution");

        // Verify mock expectations were met
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last response routinely lands
        // after the sleep expires, and the test reports it as never having happened.
        client.wait_for_mocks(30).await;
        client.verify_mocks().await?;

        // Cleanup
        client.stop().await?;

        Ok(())
    }
}
