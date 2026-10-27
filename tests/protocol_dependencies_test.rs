//! The protocol dependency mechanism must actually report something.
//!
//! `get_excluded_protocols()` is called from the event handler (`src/events/handler.rs`) and the
//! TUI sticky footer, and both render whatever it returns. It was fully plumbed and completely
//! inert: not one protocol overrode `Protocol::get_dependencies()`, whose default returned an
//! empty vector, so the exclusion map was always empty and the feature did nothing.
//!
//! The default now derives from `metadata().privilege_requirement` — one declaration, two
//! consumers, nothing to drift. These tests pin that it is live, and that the derivation maps
//! each privilege onto the dependency that is actually checked.
//!
//! Note the two consumers differ in force: `privilege_requirement` hard-gates startup in
//! `server_startup.rs`, while dependencies are informational. Nothing here should be read as
//! blocking a protocol.

use netget::privilege::SystemCapabilities;
use netget::protocol::dependencies::ProtocolDependency;
use netget::protocol::server_registry::registry;

/// Capabilities of an ordinary unprivileged process: no root, no privileged ports, no raw
/// sockets, no capture. Device flags are left on because nothing in this test depends on them
/// and `DeviceAccess` deliberately derives no dependency.
fn unprivileged() -> SystemCapabilities {
    SystemCapabilities {
        can_bind_privileged_ports: false,
        has_raw_socket_access: false,
        has_packet_capture_access: false,
        has_bluetooth_access: true,
        has_usb_access: true,
        has_nfc_access: true,
        is_root: false,
    }
}

#[test]
fn the_exclusion_map_is_not_empty_for_an_unprivileged_process() {
    use netget::protocol::metadata::PrivilegeRequirement;

    let excluded = registry().get_excluded_protocols(&unprivileged());

    // Only a privilege no port choice can satisfy should exclude. `PrivilegedPort` deliberately
    // derives no dependency — a port is a startup parameter, and DNS on 5353 or HTTP on 8080
    // runs unprivileged — so a build containing only those has an empty map *correctly*. That
    // is the CI feature set exactly (tcp, http, dns, udp, redis), where this used to fail.
    let excludable = registry()
        .all_protocols()
        .into_iter()
        .filter(|(_, protocol)| {
            matches!(
                protocol.metadata().privilege_requirement,
                PrivilegeRequirement::RawSockets | PrivilegeRequirement::Root
            )
        })
        .count();

    if excludable == 0 {
        eprintln!(
            "note: no compiled-in protocol requires raw sockets or root, so there is correctly \
             nothing to exclude; run at --all-features for this assertion to mean anything"
        );
        return;
    }

    assert!(
        !excluded.is_empty(),
        "{excludable} compiled-in protocol(s) require raw sockets or root, which no port choice \
         can provide, yet none reported a missing dependency for a process with no root, no \
         privileged ports, no raw sockets and no capture access. The derivation in \
         Protocol::get_dependencies() has regressed to an empty vector, making \
         get_excluded_protocols() inert — the defect this test exists to catch."
    );
}

/// The protocols that need a privilege must be the ones reported, with the right dependency.
///
/// "The map is non-empty" is too weak on its own — it would still pass if the derivation mapped
/// every privilege onto the wrong dependency. Each case below is feature-gated so this runs
/// wherever the protocol is compiled in and is skipped, not failed, where it is not.
#[test]
fn privileged_protocols_map_onto_the_dependency_they_actually_need() {
    let excluded = registry().get_excluded_protocols(&unprivileged());

    let check = |protocol: &str, want: ProtocolDependency| {
        let Some(missing) = excluded.get(protocol) else {
            panic!(
                "{protocol} declares a privilege requirement but was not excluded for an \
                 unprivileged process. Registered as: {:?}",
                excluded.keys().collect::<Vec<_>>()
            )
        };
        assert!(
            missing.contains(&want),
            "{protocol} was excluded, but for {missing:?} rather than the expected {want:?}"
        );
    };

    // Layer-2 capture, NOT raw IP sockets — the distinction PromiscuousMode exists for.
    #[cfg(all(unix, feature = "libpcap"))]
    check("ARP", ProtocolDependency::PromiscuousMode);
    #[cfg(all(unix, feature = "libpcap"))]
    check("DataLink", ProtocolDependency::PromiscuousMode);

    // Raw IP sockets, NOT capture.
    #[cfg(unix)]
    check("ICMP", ProtocolDependency::RawSocketAccess);
    #[cfg(unix)]
    check("IGMP", ProtocolDependency::RawSocketAccess);
}

/// gRPC must declare its runtime `protoc` dependency.
///
/// `proto_schema` is required, and both forms a caller is told to use — a `.proto` path and
/// inline text — are compiled by `protoc` (`compile_proto_file`, `compile_proto_text`). A
/// pre-compiled descriptor set is not, which `startup_dependencies` accounts for
/// (`tests/startup_dependency_gate_test.rs`). Without this declaration the non-privilege half of
/// the startup dependency gate has nothing to enforce and is decorative — the inert-mechanism
/// shape this file exists to catch.
#[test]
fn grpc_declares_its_runtime_protoc_dependency() {
    let protocol = registry()
        .get("gRPC")
        .expect("gRPC is compiled in under this feature set");

    assert!(
        protocol
            .get_dependencies()
            .contains(&ProtocolDependency::ToolInPath("protoc")),
        "gRPC invokes protoc at runtime on every startup path, so it must declare \
         ToolInPath(\"protoc\"). Declared: {:?}",
        protocol.get_dependencies()
    );
}

/// Everything reported missing must genuinely be unavailable under those capabilities.
///
/// This is the property that matters for a *false* exclusion: telling a user a protocol is
/// unusable when it is fine is worse than saying nothing, because it hides a working protocol.
#[test]
fn every_reported_exclusion_is_genuinely_unavailable() {
    let caps = unprivileged();
    for (protocol, missing) in registry().get_excluded_protocols(&caps) {
        for dep in missing {
            assert!(
                !dep.is_available(&caps),
                "{protocol} was excluded for {:?}, but that dependency reports as available",
                dep
            );
        }
    }
}

/// A fully-privileged process should have nothing excluded on privilege grounds.
#[test]
fn a_root_process_excludes_nothing_derived_from_privilege() {
    let caps = SystemCapabilities {
        can_bind_privileged_ports: true,
        has_raw_socket_access: true,
        has_packet_capture_access: true,
        has_bluetooth_access: true,
        has_usb_access: true,
        has_nfc_access: true,
        is_root: true,
    };

    // Only privilege-derived dependencies are asserted on: a protocol that overrides
    // get_dependencies() to add a SystemLibrary may still be excluded here, legitimately.
    for (protocol, missing) in registry().get_excluded_protocols(&caps) {
        for dep in &missing {
            assert!(
                matches!(
                    dep,
                    ProtocolDependency::SystemLibrary(_)
                        | ProtocolDependency::ToolInPath(_)
                        | ProtocolDependency::ProgramAt { .. }
                ),
                "{protocol} reports {:?} missing for a root process with every capability; \
                 privilege-derived dependencies should all be satisfied",
                dep
            );
        }
    }
}

/// Packet capture must check capture access, not raw-socket access.
///
/// These are separable — a macOS user in the ChmodBPF group owns `/dev/bpf*` without being root,
/// so capture succeeds while `SOCK_RAW` fails. `PromiscuousMode` checked the raw-socket flag,
/// which reported ARP/DataLink/IS-IS unavailable to exactly the users who can run them.
#[test]
fn promiscuous_mode_reads_capture_access_not_raw_sockets() {
    let capture_only = SystemCapabilities {
        can_bind_privileged_ports: false,
        has_raw_socket_access: false,
        has_packet_capture_access: true,
        has_bluetooth_access: false,
        has_usb_access: false,
        has_nfc_access: false,
        is_root: false,
    };

    assert!(
        ProtocolDependency::PromiscuousMode.is_available(&capture_only),
        "capture access alone must satisfy PromiscuousMode"
    );
    assert!(
        !ProtocolDependency::RawSocketAccess.is_available(&capture_only),
        "capture access must NOT satisfy RawSocketAccess"
    );
}

/// The gRPC **client** shells out to the same `protoc` and must declare it too.
///
/// The server has declared this since the mechanism was adopted and the client did not, which
/// is the shape worth remembering: a dependency was found, declared once, and the other half of
/// the pair running the identical `Command::new("protoc")` was never looked at. A host with no
/// protoc was warned about one direction and discovered the other from a failure part-way
/// through a call.
///
/// `src/client/grpc/mod.rs` runs `protoc --descriptor_set_out=/dev/stdout` to compile the
/// inline `.proto` text form of `proto_schema`.
#[test]
fn the_grpc_client_declares_protoc_as_well_as_the_server() {
    use netget::protocol::client_registry::CLIENT_REGISTRY;

    let client = CLIENT_REGISTRY
        .get_all()
        .into_iter()
        .find(|c| c.protocol_name().to_lowercase().contains("grpc"))
        .expect("the grpc client is compiled in under this feature set");

    assert!(
        client
            .get_dependencies()
            .contains(&ProtocolDependency::ToolInPath("protoc")),
        "the gRPC client runs protoc to compile an inline .proto schema, so it must declare \
         ToolInPath(\"protoc\") exactly as the server does. Declared: {:?}",
        client.get_dependencies()
    );
}

/// WireGuard needs an external `wireguard-go` on macOS, and that is a second missing piece.
///
/// NetGet implements none of the WireGuard protocol: it orchestrates `defguard_wireguard_rs`,
/// whose macOS backend is a *driver* for a userspace implementation rather than the
/// implementation — `wgapi_userspace.rs` runs `Command::new("wireguard-go")` and talks to it
/// over a unix socket. Linux, FreeBSD and Windows have it in the kernel, so there is nothing
/// external to want and nothing is declared there.
///
/// It sits behind the `Root` requirement the metadata already declares, and that is the point:
/// they are different missing pieces, and an operator who gains root still cannot start this
/// without the binary.
#[test]
#[cfg(all(unix, target_os = "macos"))]
fn wireguard_declares_the_external_binary_its_macos_backend_runs() {
    let server = registry()
        .get("WireGuard")
        .expect("wireguard is compiled in under this feature set");

    assert!(
        server
            .get_dependencies()
            .contains(&ProtocolDependency::ToolInPath("wireguard-go")),
        "on macOS defguard shells out to wireguard-go, so the server must declare it. \
         Declared: {:?}",
        server.get_dependencies()
    );

    // Root is still declared alongside it — adding the binary must not have replaced the
    // derived list, which `default_dependencies_from_privilege(self)` exists to prevent.
    assert!(
        server
            .get_dependencies()
            .contains(&ProtocolDependency::RootAccess),
        "the privilege-derived RootAccess was dropped when the tool dependency was added; \
         override get_dependencies() by extending default_dependencies_from_privilege(self), \
         never by replacing it. Declared: {:?}",
        server.get_dependencies()
    );
}

/// A dependency that cannot be probed honestly must stay undeclared.
///
/// The obvious move for the seventeen device protocols is to declare "needs a Bluetooth
/// adapter". There is no `ProtocolDependency` variant for it and no probe that answers
/// reliably, so such a declaration would exclude protocols that work on the operator's machine
/// — and an exclusion is informational, so the operator would simply be told a lie.
/// `Protocol::get_dependencies`'s own docs say this; asserting it means a future pass that adds
/// a device variant has to come past the reasoning rather than around it.
#[test]
#[cfg(all(unix, feature = "bluetooth"))]
fn a_device_protocol_declares_nothing_it_cannot_probe() {
    let ble = registry()
        .get("BLUETOOTH_BLE")
        .expect("bluetooth-ble is compiled in under this feature set");

    let deps = ble.get_dependencies();
    assert!(
        deps.is_empty(),
        "bluetooth_ble declares {deps:?}. It sits at PrivilegeRequirement::None because every \
         other option would be a lie, and DeviceAccess deliberately derives nothing. If a \
         device dependency is being added, it needs a probe that can answer first."
    );
}
