//! DataLink declaration tests: what the protocol promises the model, and what the startup path
//! accepts. No privileges, no Ollama - the wire behaviour lives in `e2e_test.rs`.
//!
//! What was here before: `test_arp_responder`, which shelled out to `arping` and printed a note
//! on *every* outcome - reply, no reply, `arping` missing - then returned `Ok(())`. Its failure
//! branch read *"No ARP reply received (this is expected if server isn't fully implemented)"*: a
//! test announcing its own meaninglessness. It also tested a premise that cannot hold. DataLink
//! has **no packet-injection action**, so a DataLink server can never answer an ARP request, and
//! no amount of privilege would have made it pass. Answering ARP is `src/server/arp/`'s job and
//! `tests/server/arp/e2e_test.rs` covers it. Replaced below by assertions that can fail.

#![cfg(all(unix, feature = "libpcap"))]

use super::super::super::helpers::E2EResult;
use netget::llm::actions::protocol_trait::Protocol;
use netget::privilege::SystemCapabilities;
use netget::protocol::metadata::PrivilegeRequirement;
use netget::server::DataLinkProtocol;

/// The loopback name this platform uses.
fn loopback() -> &'static str {
    if cfg!(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    )) {
        "lo0"
    } else {
        "lo"
    }
}

/// The default binding must name an interface that exists on *this* platform. Hardcoding `lo`
/// made the default unresolvable on macOS ("Device 'lo' not found"), i.e. a startup failure for
/// anyone who does not pass `interface` explicitly.
#[test]
fn datalink_default_binding_is_the_platform_loopback() {
    let binding = DataLinkProtocol::new()
        .default_binding()
        .expect("DataLink binds to an interface, so it must declare a default binding");

    assert_eq!(
        binding.interface.as_deref(),
        Some(loopback()),
        "default interface must be this platform's loopback name"
    );
    assert_eq!(
        binding.port, None,
        "DataLink is Layer 2 and has no port; declaring one would make the TUI and MCP ask for it"
    );
}

/// DataLink needs layer-2 capture, which is *not* the same capability as a raw IP socket - a
/// macOS user in the ChmodBPF group has one and not the other. `server_startup` gates on this
/// declaration, so it has to be exactly this variant, and it has to agree with the probe.
#[test]
fn datalink_declares_packet_capture_privilege() {
    let meta = DataLinkProtocol::new().metadata();

    assert_eq!(
        meta.privilege_requirement,
        PrivilegeRequirement::PacketCapture,
        "DataLink opens a pcap handle, not a SOCK_RAW socket"
    );

    let caps = SystemCapabilities::detect();
    assert_eq!(
        meta.privilege_requirement.is_met_by(&caps),
        caps.has_packet_capture_access,
        "PacketCapture must be satisfied by exactly the capture capability, or the pre-flight in \
         server_startup either never fires or fires for everyone"
    );
}

/// DataLink is observation-only, and says so in three places (`llm_control`, its CLAUDE.md and
/// this action set). If injection is ever added, all three change together.
#[test]
fn datalink_offers_only_observation_actions() {
    let protocol = DataLinkProtocol::new();
    let names: Vec<String> = protocol
        .get_sync_actions()
        .iter()
        .map(|a| a.name.clone())
        .collect();

    assert_eq!(
        names,
        vec!["show_message".to_string(), "ignore_packet".to_string()],
        "DataLink cannot inject frames; offering an action that implies it would make the model \
         try to answer packets it has no way to answer"
    );

    // Every event the model can see must carry actions, or `call_llm` offers an empty tool list
    // and the model cannot respond at all.
    for event in protocol.get_event_types() {
        assert!(
            !event.actions.is_empty(),
            "event '{}' declares no actions, so call_llm would offer the model nothing",
            event.id
        );
    }
}

/// The registry contract DataLink depends on, checkable with no privileges at all.
///
/// This replaces a placebo: the previous body of this test built a `format!` string, printed
/// it, and returned `Ok(())` without a single assertion, so it could not fail for any reason.
/// What it *claimed* to cover — that a prompt naming an interface reaches a DataLink server —
/// is really two registry facts, and both are assertable without root.
#[tokio::test]
async fn test_datalink_registration_and_startup_params() -> E2EResult<()> {
    use netget::protocol::server_registry::registry;

    let protocol = registry()
        .get("DataLink")
        .expect("DataLink must be registered under its protocol_name when the feature is on");

    // A prompt that names an interface is routed by keyword, so the keyword must exist.
    assert!(
        protocol.keywords().contains(&"datalink"),
        "DataLink must claim the 'datalink' keyword or no prompt can reach it; got {:?}",
        protocol.keywords()
    );

    // The interface itself is *not* a startup parameter (it arrives via the flexible binding
    // system). Passing it as one would be rejected by StartupParams::new, so the declared set
    // must not contain it, and must contain the BPF filter that callers do pass.
    let params: Vec<String> = protocol
        .get_startup_parameters()
        .into_iter()
        .map(|p| p.name)
        .collect();
    assert!(
        params.iter().any(|p| p == "filter"),
        "DataLink must declare the 'filter' BPF parameter; declared: {:?}",
        params
    );
    assert!(
        !params.iter().any(|p| p == "interface"),
        "'interface' must not be a startup parameter - it is bound separately; declared: {:?}",
        params
    );

    Ok(())
}
