//! End-to-end mDNS tests for NetGet
//!
//! These tests spawn the actual NetGet binary with mDNS prompts and validate the
//! advertisements with an `mdns-sd` browser.
//!
//! ## These tests used to assert nothing
//!
//! Every one of them computed a `found_service` flag and then **printed** it:
//!
//! ```ignore
//! if found_service { println!("✓ verified"); } else { println!("Note: not discovered"); }
//! ```
//!
//! so the suite was green whether or not a single byte was advertised, and mDNS's
//! `metadata().e2e_testing` claimed they were "asserting on ServiceResolved" when nothing
//! was asserted at all. `verify_mocks()` was the only real check, and it proves the startup
//! LLM call happened — not that anything reached the multicast group.
//!
//! Two further defects the rewrite fixed, both of which would have survived a naive
//! `assert!(found_service)`:
//!
//! - **They accepted a neighbour's advertisement.** Browsing `_http._tcp.local.` returns
//!   every such service on the link, and these four tests run concurrently and advertise
//!   into it. A run captured here had `test_mdns_service_advertisement` report
//!   `Instance: Web Service._http._tcp.local.` — the service belonging to
//!   `test_mdns_multiple_services` — and call itself verified. Every wait now matches on the
//!   instance name it registered.
//! - **The wait loop broke on the wrong event.** `ServiceFound` arrives before
//!   `ServiceResolved`, and the `_ => break` arm treated it as a reason to stop, so a
//!   service that was about to resolve was abandoned.
//!
//! ## What this evidence is worth
//!
//! `mdns-sd` is the crate the **server** uses, so this is one crate round-tripping through
//! itself — the same circularity that keeps `websocket` and `webrtc_signaling` out of Beta,
//! and that `rss` escaped only by parsing with `feed-rs` instead. It is real coverage of
//! NetGet's registration plumbing (startup params → `ServiceInfo` → the group) and it is not
//! evidence of interop. `mdns` is rated Experimental for that reason. An independent peer
//! would be the platform tool — `dns-sd -L` on macOS, `avahi-browse -r` on Linux — which is
//! what a promotion to Beta needs.


// Helper module imported from parent

use super::super::super::helpers::{self, E2EResult, NetGetConfig};
use std::time::Duration;

/// How long to wait for a service to be browsed and resolved.
///
/// Generous because discovery is multicast and the suite runs at `--test-threads=100`;
/// the wait is on the *condition*, so a fast machine returns as soon as it resolves.
const DISCOVERY_TIMEOUT: Duration = Duration::from_secs(20);

/// Browse `service_type` until an instance named `instance_name` resolves.
///
/// Matching on the instance name is what makes the result mean anything: the browse returns
/// every service of that type on the link, including the ones the sibling tests in this file
/// advertise, so accepting the first `ServiceResolved` asserts on whoever answered first.
///
/// Non-matching events (`ServiceFound`, another instance resolving, `SearchStarted`) are
/// skipped rather than treated as an end of stream.
async fn resolve_service(
    mdns: &mdns_sd::ServiceDaemon,
    service_type: &str,
    instance_name: &str,
) -> Option<mdns_sd::ResolvedService> {
    let receiver = match mdns.browse(service_type) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("failed to browse {service_type}: {e}");
            return None;
        }
    };

    let expected_prefix = format!("{instance_name}.");
    let deadline = std::time::Instant::now() + DISCOVERY_TIMEOUT;

    while std::time::Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        match tokio::time::timeout(remaining, receiver.recv_async()).await {
            Ok(Ok(mdns_sd::ServiceEvent::ServiceResolved(resolved))) => {
                if resolved.fullname.starts_with(&expected_prefix) {
                    return Some(*resolved);
                }
                println!(
                    "  (ignoring {} — waiting for {})",
                    resolved.fullname, instance_name
                );
            }
            // ServiceFound precedes ServiceResolved; SearchStarted and the rest are noise.
            Ok(Ok(_)) => continue,
            // The daemon dropped the channel: nothing more will arrive.
            Ok(Err(e)) => {
                eprintln!("mDNS browse channel closed: {e}");
                return None;
            }
            Err(_) => return None,
        }
    }
    None
}

#[tokio::test]
async fn test_mdns_service_advertisement() -> E2EResult<()> {
    println!("\n=== E2E Test: mDNS Service Advertisement ===");

    // PROMPT: Tell the LLM to advertise a service via mDNS
    let prompt = "listen on port {AVAILABLE_PORT} via mdns. Advertise service: \
        type '_http._tcp.local.', name 'NetGet Advertisement Test', port {AVAILABLE_PORT}, \
        with property 'version=1.0'";

    // Start the server
    let server_config = NetGetConfig::new(prompt).with_mock(|mock| {
        mock.on_instruction_containing("mdns")
            .and_instruction_containing("Advertise service")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "mdns",
                    "instruction": "mDNS service advertisement",
                    "startup_params": {
                        "service_type": "_http._tcp.local.",
                        "service_name": "NetGet Advertisement Test",
                        "properties": {"version": "1.0"}
                    }
                }
            ]))
            .expect_calls(1)
            .and()
    });
    let server = helpers::start_netget_server(server_config).await?;
    println!("Server started, mDNS should be advertising");

    let mdns = mdns_sd::ServiceDaemon::new()
        .map_err(|e| format!("Failed to create mDNS daemon: {}", e))?;

    let info = resolve_service(&mdns, "_http._tcp.local.", "NetGet Advertisement Test")
        .await
        .ok_or(
            "mDNS service 'NetGet Advertisement Test' was never resolved: the server \
                registered it at startup and nothing appeared on the multicast group",
        )?;

    println!("✓ resolved {}", info.fullname);

    // The TXT record is part of the advertisement, not decoration: DNS-SD clients read it
    // to learn how to use the service. Nothing checked it before, so a server that
    // advertised the name and dropped the properties looked identical to one that worked.
    assert_eq!(
        info.txt_properties.get_property_val_str("version"),
        Some("1.0"),
        "the TXT record must carry the property the server was started with; \
         got {:?}",
        info.txt_properties
    );

    let _ = mdns.shutdown();

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    println!("=== Test completed ===\n");
    Ok(())
}

#[tokio::test]
async fn test_mdns_multiple_services() -> E2EResult<()> {
    println!("\n=== E2E Test: mDNS Multiple Services ===");

    // PROMPT: Tell the LLM to advertise multiple services
    let prompt = "listen on port {AVAILABLE_PORT} via mdns. Register two services: \
        1) type '_http._tcp.local.', name 'NetGet Multi Web', port {AVAILABLE_PORT} \
        2) type '_ftp._tcp.local.', name 'NetGet Multi FTP', port {AVAILABLE_PORT}";

    // Start the server
    let server_config = NetGetConfig::new(prompt).with_mock(|mock| {
        mock.on_instruction_containing("mdns")
            .and_instruction_containing("two services")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "mdns",
                    "instruction": "mDNS multiple services",
                    "startup_params": {
                        "services": [
                            {"service_type": "_http._tcp.local.", "service_name": "NetGet Multi Web"},
                            {"service_type": "_ftp._tcp.local.", "service_name": "NetGet Multi FTP"}
                        ]
                    }
                }
            ]))
            .expect_calls(1)
            .and()
    });
    let server = helpers::start_netget_server(server_config).await?;
    println!("Server started, mDNS should be advertising multiple services");

    let mdns = mdns_sd::ServiceDaemon::new()
        .map_err(|e| format!("Failed to create mDNS daemon: {}", e))?;

    // Both must resolve. The old version counted whatever it found and printed the count,
    // so one service out of two — or zero — passed just as happily.
    let web = resolve_service(&mdns, "_http._tcp.local.", "NetGet Multi Web")
        .await
        .ok_or("the _http._tcp service from the `services` array never resolved")?;
    println!("✓ resolved {}", web.fullname);

    let ftp = resolve_service(&mdns, "_ftp._tcp.local.", "NetGet Multi FTP")
        .await
        .ok_or(
            "the _ftp._tcp service from the `services` array never resolved: a \
                `services` array that registers only its first entry would look like this",
        )?;
    println!("✓ resolved {}", ftp.fullname);

    let _ = mdns.shutdown();

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    println!("=== Test completed ===\n");
    Ok(())
}

#[tokio::test]
async fn test_mdns_service_with_properties() -> E2EResult<()> {
    println!("\n=== E2E Test: mDNS Service with TXT Properties ===");

    // PROMPT: Tell the LLM to advertise a service with properties
    let prompt = "listen on port {AVAILABLE_PORT} via mdns. Register service: \
        type '_http._tcp.local.', name 'NetGet Property Test', port {AVAILABLE_PORT}, \
        with properties: version='2.0', path='/api', secure='true'";

    // Start the server
    let server_config = NetGetConfig::new(prompt).with_mock(|mock| {
        mock.on_instruction_containing("mdns")
            .and_instruction_containing("properties")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "mdns",
                    "instruction": "mDNS service with properties",
                    "startup_params": {
                        "service_type": "_http._tcp.local.",
                        "service_name": "NetGet Property Test",
                        "properties": {"version": "2.0", "path": "/api", "secure": "true"}
                    }
                }
            ]))
            .expect_calls(1)
            .and()
    });
    let server = helpers::start_netget_server(server_config).await?;
    println!("Server started, mDNS advertising with properties");

    let mdns = mdns_sd::ServiceDaemon::new()
        .map_err(|e| format!("Failed to create mDNS daemon: {}", e))?;

    let info = resolve_service(&mdns, "_http._tcp.local.", "NetGet Property Test")
        .await
        .ok_or("mDNS service 'NetGet Property Test' was never resolved")?;

    // Every key, by value. The old test asserted `!props.is_empty()` at most, and in
    // practice not even that — it printed the count.
    for (key, expected) in [("version", "2.0"), ("path", "/api"), ("secure", "true")] {
        assert_eq!(
            info.txt_properties.get_property_val_str(key),
            Some(expected),
            "TXT property {key} must survive startup_params -> ServiceInfo -> the wire; \
             the whole record was {:?}",
            info.txt_properties
        );
    }
    println!("✓ all three TXT properties round-tripped");

    let _ = mdns.shutdown();

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    println!("=== Test completed ===\n");
    Ok(())
}

#[tokio::test]
async fn test_mdns_custom_service_type() -> E2EResult<()> {
    println!("\n=== E2E Test: mDNS Custom Service Type ===");

    // PROMPT: Tell the LLM to advertise a custom service type
    let prompt = "listen on port {AVAILABLE_PORT} via mdns. Register custom service: \
        type '_netget._tcp.local.', name 'Custom NetGet Service', port {AVAILABLE_PORT}";

    // Start the server
    let server_config = NetGetConfig::new(prompt).with_mock(|mock| {
        mock.on_instruction_containing("mdns")
            .and_instruction_containing("custom service")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "mdns",
                    "instruction": "mDNS custom service type",
                    "startup_params": {
                        "service_type": "_netget._tcp.local.",
                        "service_name": "Custom NetGet Service"
                    }
                }
            ]))
            .expect_calls(1)
            .and()
    });
    let server = helpers::start_netget_server(server_config).await?;
    println!("Server started with custom service type");

    let mdns = mdns_sd::ServiceDaemon::new()
        .map_err(|e| format!("Failed to create mDNS daemon: {}", e))?;

    let info = resolve_service(&mdns, "_netget._tcp.local.", "Custom NetGet Service")
        .await
        .ok_or("mDNS service of the non-standard type '_netget._tcp.local.' never resolved")?;

    assert_eq!(
        info.fullname, "Custom NetGet Service._netget._tcp.local.",
        "an unregistered service type must be advertised verbatim, not normalised"
    );
    println!("✓ resolved {}", info.fullname);

    let _ = mdns.shutdown();

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    println!("=== Test completed ===\n");
    Ok(())
}
