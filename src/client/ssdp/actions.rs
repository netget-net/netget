//! SSDP / UPnP discovery **client** — LLM vocabulary and action executor.
//!
//! This is the control-point half of SSDP: it sends `M-SEARCH` and reads what comes back.
//! The device half lives in `src/server/ssdp/`, and the two share one thing — the HTTPU
//! codec in [`crate::server::ssdp::message`]. Sharing it is deliberate: SSDP's grammar is a
//! start line plus `NAME: value` lines, and a second hand-rolled parser would drift from the
//! first the first time either was touched.
//!
//! Everything here is pure. No socket, no state, no LLM: `execute_action` turns a model's
//! JSON into a [`ClientActionResult`] and `mod.rs` decides what that means on the wire.

use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, Parameter, ParameterDefinition,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::EventType;
use crate::server::ssdp::message::{self, MAX_MX_SECONDS};
use crate::state::app_state::AppState;
use anyhow::{Context, Result};
use serde_json::json;
use std::sync::LazyLock;

/// Default `MX` when the model does not name one.
///
/// UDA 1.1 §1.3.2 requires `1 <= MX <= 5` and says a control point SHOULD keep it small.
/// Three is the value real control points use: long enough that a busy device's jitter fits
/// inside it, short enough that discovery feels immediate.
pub const DEFAULT_MX_SECONDS: u32 = 3;

/// The search target that asks every device for everything it has (UDA 1.1 §1.3.2).
pub const SEARCH_TARGET_ALL: &str = "ssdp:all";

// ---------------------------------------------------------------------------
// Actions
// ---------------------------------------------------------------------------

/// `send_msearch` — the only action that puts bytes on the wire.
fn send_msearch_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_msearch".to_string(),
        description: format!(
            "Send an SSDP M-SEARCH discovery request and collect every reply for the MX \
             window. This is a ONE-TO-MANY request: on a real network many devices answer, \
             each with its own ssdp_search_response event, and a single ssdp_search_complete \
             event follows saying how many did. Search targets: '{SEARCH_TARGET_ALL}' asks \
             every device for every service it has (the widest sweep, and the noisiest); \
             'upnp:rootdevice' asks only for top-level devices, one reply per physical box; \
             'uuid:<device-uuid>' asks one specific device; a URN such as \
             'urn:schemas-upnp-org:device:MediaServer:1' or \
             'urn:schemas-upnp-org:service:AVTransport:1' asks only for that device or \
             service type. Start wide, read what answers, then search again for the specific \
             types you saw — that is how a control point maps a network."
        ),
        parameters: vec![
            Parameter {
                name: "st".to_string(),
                type_hint: "string".to_string(),
                description: format!(
                    "Search target. '{SEARCH_TARGET_ALL}', 'upnp:rootdevice', \
                     'uuid:<device-uuid>', or a URN like \
                     'urn:schemas-upnp-org:device:MediaServer:1'. Required: a device only \
                     answers a search whose target it matches."
                ),
                required: true,
            },
            Parameter {
                name: "mx".to_string(),
                type_hint: "number".to_string(),
                description: format!(
                    "Seconds a device may wait before answering, and therefore how long \
                     replies are collected. UDA 1.1 caps it at {MAX_MX_SECONDS}; larger \
                     values are clamped. Default {DEFAULT_MX_SECONDS}. A larger MX finds \
                     more devices on a busy network and makes every search slower."
                ),
                required: false,
            },
            Parameter {
                name: "target".to_string(),
                type_hint: "string".to_string(),
                description: "Override the destination for this one search, as 'ip:port'. \
                              Normally omitted: the search goes to the address the client was \
                              opened with, which is the multicast group 239.255.255.250:1900 \
                              for a real network scan. A unicast address here searches exactly \
                              one device — UDA 1.1 §1.3.2 permits that, and it is also the only \
                              form that works over loopback, because loopback carries no \
                              multicast route."
                    .to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_msearch",
            "st": "ssdp:all",
            "mx": 3
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> M-SEARCH ST={st}")
                .with_debug("SSDP M-SEARCH st={st} mx={mx}"),
        ),
    }
}

fn wait_for_more_action() -> ActionDefinition {
    ActionDefinition {
        name: "wait_for_more".to_string(),
        description: "Do nothing and keep listening. The correct answer when a search is \
                      still collecting replies, when one device's answer is not enough to \
                      decide on, or when you simply want to record what you saw and see the \
                      rest."
            .to_string(),
        parameters: vec![],
        example: json!({"type": "wait_for_more"}),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> SSDP wait for more")
                .with_debug("SSDP client wait_for_more"),
        ),
    }
}

fn disconnect_action() -> ActionDefinition {
    ActionDefinition {
        name: "disconnect".to_string(),
        description: "Stop discovery and close the socket. Discovery is finished; nothing \
                      further will be received."
            .to_string(),
        parameters: vec![],
        example: json!({"type": "disconnect"}),
        log_template: None,
    }
}

/// Every action, in the order the model should see them.
///
/// One list, used by `get_async_actions`, by every event's `with_actions(...)`, and by
/// nothing else. `get_sync_actions()` is deliberately empty: a client has a single LLM entry
/// point (`call_llm_for_client` serves both the initial instruction and every network event),
/// so a client cannot express a narrowing and the async/sync split is vestigial there. The
/// ~40 clients that duplicate their whole list into both methods are working around a bug in
/// `call_llm_for_client` that no longer exists — see `client_llm_action_set`.
fn all_actions() -> Vec<ActionDefinition> {
    vec![
        send_msearch_action(),
        wait_for_more_action(),
        disconnect_action(),
    ]
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

/// Raised once, as soon as the search socket is bound.
///
/// This is where a discovery session starts: nothing is on the wire yet, and the model's
/// answer decides what the first search looks for.
pub static SSDP_CLIENT_CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "ssdp_connected",
        "SSDP discovery socket is bound and ready. Nothing has been searched for yet — \
         answer with send_msearch to start discovery.",
        json!({"type": "send_msearch", "st": SEARCH_TARGET_ALL, "mx": DEFAULT_MX_SECONDS}),
    )
    .with_parameters(vec![
        Parameter {
            name: "local_addr".to_string(),
            type_hint: "string".to_string(),
            description: "Local ip:port the search socket is bound to".to_string(),
            required: true,
        },
        Parameter {
            name: "default_target".to_string(),
            type_hint: "string".to_string(),
            description: "Where searches go unless an action overrides it. \
                          '239.255.255.250:1900' is the SSDP multicast group; anything else \
                          is a unicast search of one device."
                .to_string(),
            required: true,
        },
        Parameter {
            name: "multicast_joined".to_string(),
            type_hint: "boolean".to_string(),
            description: "Whether the 239.255.255.250 group was joined. False means \
                          unsolicited NOTIFY announcements will not be seen; unicast \
                          searches still work."
                .to_string(),
            required: true,
        },
    ])
    .with_actions(all_actions())
});

/// Raised once per device that answers a search, while the MX window is open.
pub static SSDP_SEARCH_RESPONSE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "ssdp_search_response",
        "A device answered the M-SEARCH. One of these is raised per responder while the \
         search window is open, so expect several on a real network.",
        json!({"type": "wait_for_more"}),
    )
    .with_parameters(vec![
        Parameter {
            name: "st".to_string(),
            type_hint: "string".to_string(),
            description: "The search target this device is answering for — the concrete \
                          device or service type it claims to be."
                .to_string(),
            required: true,
        },
        Parameter {
            name: "usn".to_string(),
            type_hint: "string".to_string(),
            description: "Unique Service Name: 'uuid:<device-uuid>' optionally followed by \
                          '::<service or device type>'. This is the identity to search for \
                          specifically next."
                .to_string(),
            required: true,
        },
        Parameter {
            name: "location".to_string(),
            type_hint: "string".to_string(),
            description: "URL of the device description XML. NetGet does NOT fetch it — \
                          that is plain HTTP, not SSDP. Open an HTTP client against this \
                          URL if the description is wanted."
                .to_string(),
            required: false,
        },
        Parameter {
            name: "server".to_string(),
            type_hint: "string".to_string(),
            description: "SERVER header: 'OS/version UPnP/version product/version'. Often \
                          the most informative field about what the device actually is."
                .to_string(),
            required: false,
        },
        Parameter {
            name: "cache_control".to_string(),
            type_hint: "string".to_string(),
            description: "CACHE-CONTROL header verbatim, e.g. 'max-age=1800'".to_string(),
            required: false,
        },
        Parameter {
            name: "cache_control_max_age".to_string(),
            type_hint: "number".to_string(),
            description: "The max-age directive parsed out as seconds, so freshness can be \
                          reasoned about without parsing a header"
                .to_string(),
            required: false,
        },
        Parameter {
            name: "source_address".to_string(),
            type_hint: "string".to_string(),
            description: "ip:port the reply came from — the device's own address".to_string(),
            required: true,
        },
        Parameter {
            name: "headers".to_string(),
            type_hint: "object".to_string(),
            description: "Every header of the reply as a name-to-value map, including \
                          vendor-specific ones the fields above do not cover"
                .to_string(),
            required: true,
        },
    ])
    .with_actions(all_actions())
});

/// Raised for an unsolicited `NOTIFY` announcement overheard on the multicast group.
pub static SSDP_NOTIFY_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "ssdp_notify_received",
        "A device announced itself unprompted: NTS 'ssdp:alive' means it appeared or \
         refreshed, 'ssdp:byebye' means it is going away, 'ssdp:update' means its \
         configuration changed. Nothing was searched for — this arrived on its own.",
        json!({"type": "wait_for_more"}),
    )
    .with_parameters(vec![
        Parameter {
            name: "nt".to_string(),
            type_hint: "string".to_string(),
            description: "Notification Type: the device or service type being announced"
                .to_string(),
            required: true,
        },
        Parameter {
            name: "nts".to_string(),
            type_hint: "string".to_string(),
            description: "Notification Sub Type: 'ssdp:alive', 'ssdp:byebye' or 'ssdp:update'"
                .to_string(),
            required: true,
        },
        Parameter {
            name: "usn".to_string(),
            type_hint: "string".to_string(),
            description: "Unique Service Name identifying the announcing device".to_string(),
            required: true,
        },
        Parameter {
            name: "location".to_string(),
            type_hint: "string".to_string(),
            description: "Description URL. Absent on an ssdp:byebye, which carries only \
                          HOST, NT, NTS and USN."
                .to_string(),
            required: false,
        },
        Parameter {
            name: "server".to_string(),
            type_hint: "string".to_string(),
            description: "SERVER header, when present".to_string(),
            required: false,
        },
        Parameter {
            name: "cache_control_max_age".to_string(),
            type_hint: "number".to_string(),
            description: "max-age in seconds: how long this announcement stays valid".to_string(),
            required: false,
        },
        Parameter {
            name: "source_address".to_string(),
            type_hint: "string".to_string(),
            description: "ip:port the announcement came from".to_string(),
            required: true,
        },
        Parameter {
            name: "headers".to_string(),
            type_hint: "object".to_string(),
            description: "Every header of the announcement as a name-to-value map".to_string(),
            required: true,
        },
    ])
    .with_actions(all_actions())
});

/// Raised when a search's collection window closes.
///
/// This is the event that makes iterative discovery possible: it is the first moment the
/// model knows *how many* devices answered and what they were, so it is where "now search
/// again, specifically" belongs.
pub static SSDP_SEARCH_COMPLETE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "ssdp_search_complete",
        "The search window closed. This is the summary of one M-SEARCH and the natural \
         place to decide what to search for next — a second, narrower search aimed at a type \
         or a uuid seen in the results usually learns more than repeating the first one.",
        json!({"type": "wait_for_more"}),
    )
    .with_parameters(vec![
        Parameter {
            name: "st".to_string(),
            type_hint: "string".to_string(),
            description: "The search target that was searched for".to_string(),
            required: true,
        },
        Parameter {
            name: "mx".to_string(),
            type_hint: "number".to_string(),
            description: "MX that was sent, i.e. how many seconds replies were collected for"
                .to_string(),
            required: true,
        },
        Parameter {
            name: "target".to_string(),
            type_hint: "string".to_string(),
            description: "Where the search was actually sent".to_string(),
            required: true,
        },
        Parameter {
            name: "responder_count".to_string(),
            type_hint: "number".to_string(),
            description: "How many distinct devices/services answered. Zero means nothing on \
                          this network matched the target — searching for something narrower \
                          will not help; searching wider might."
                .to_string(),
            required: true,
        },
        Parameter {
            name: "responders".to_string(),
            type_hint: "array".to_string(),
            description: "One entry per responder: {st, usn, location, server, \
                          source_address}. The same list already delivered one at a time as \
                          ssdp_search_response events, repeated here so a decision can be \
                          made against the whole set."
                .to_string(),
            required: true,
        },
        Parameter {
            name: "duplicate_count".to_string(),
            type_hint: "number".to_string(),
            description: "Replies suppressed as repeats of a responder already reported \
                          (same source address and USN). Usually a device retransmitting."
                .to_string(),
            required: true,
        },
        Parameter {
            name: "search_depth".to_string(),
            type_hint: "number".to_string(),
            description: "How many searches deep this chain is. Searches started in reply to \
                          an event are bounded; when this reaches the limit a further \
                          send_msearch is refused and logged."
                .to_string(),
            required: true,
        },
        Parameter {
            name: "send_error".to_string(),
            type_hint: "string".to_string(),
            // Present only on the failure path, and undeclared until now — the payload
            // carried it while the model's schema for this event did not mention it, so the
            // one field that explains a zero-responder search was invisible to the reader
            // most in need of it.
            description: "Only present when the search could not be SENT at all; then \
                          responder_count is 0 for that reason and not because nothing \
                          answered. The usual cause is sending to 239.255.255.250 from a \
                          loopback-bound socket, which has no multicast route — retry with \
                          'target' set to a specific device's address."
                .to_string(),
            required: false,
        },
    ])
    .with_actions(all_actions())
});

// ---------------------------------------------------------------------------
// Protocol
// ---------------------------------------------------------------------------

/// SSDP discovery client: the LLM's action vocabulary and executor.
pub struct SsdpClientProtocol;

impl SsdpClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

impl Default for SsdpClientProtocol {
    fn default() -> Self {
        Self::new()
    }
}

impl Protocol for SsdpClientProtocol {
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        all_actions()
    }

    /// Deliberately empty — see [`all_actions`].
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        Vec::new()
    }

    fn protocol_name(&self) -> &'static str {
        // Must match the client registry's ("SSDP", "ssdp") entry.
        "SSDP"
    }

    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            SSDP_CLIENT_CONNECTED_EVENT.clone(),
            SSDP_SEARCH_RESPONSE_EVENT.clone(),
            SSDP_NOTIFY_RECEIVED_EVENT.clone(),
            SSDP_SEARCH_COMPLETE_EVENT.clone(),
        ]
    }

    fn stack_name(&self) -> &'static str {
        "ETH>IP>UDP>SSDP"
    }

    fn keywords(&self) -> Vec<&'static str> {
        // Narrow on purpose: "discovery" alone would hijack keyword resolution from mdns,
        // llmnr and netbios-ns, which are discovery protocols too.
        vec![
            "ssdp",
            "upnp",
            "upnp discovery",
            "m-search",
            "ssdp:discover",
            "discover upnp devices",
        ]
    }

    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{
            DevelopmentState, PrivilegeRequirement, ProtocolMetadataV2,
        };

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            // Nothing here needs a privileged port: the search socket binds an ephemeral
            // port by default, and 1900 (needed only to overhear NOTIFY announcements) is
            // above 1023. Declaring PrivilegedPort(1900) would be the svn/3690 mistake —
            // a check that can never fire, read by the next maintainer as protection.
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation(
                "Sends M-SEARCH over a tokio UdpSocket and collects every unicast reply for \
                 the MX window rather than returning on the first datagram, because SSDP is \
                 one-to-many: each responder gets its own ssdp_search_response event and the \
                 window ends with one ssdp_search_complete. Parses replies with the server \
                 half's HTTPU codec (src/server/ssdp/message.rs) rather than a second \
                 hand-rolled parser. Also receives unsolicited NOTIFY announcements when \
                 bound to port 1900 with the multicast group joined. Does NOT fetch the \
                 LOCATION device-description XML: that is HTTP, not SSDP, and an automatic \
                 fetch would turn discovery into an outbound request the operator never \
                 asked for. No SOAP control, no SCPD, no GENA eventing.",
            )
            .llm_control(
                "The model chooses every search target and MX, reads each responder's ST, \
                 USN, LOCATION and SERVER, and decides what to search for next — a wide \
                 ssdp:all sweep followed by narrow searches for the types that answered. \
                 Searches started in reply to an event are bounded by a follow-up depth \
                 limit; hitting it is logged, never silent.",
            )
            .e2e_testing(
                "Mocked end-to-end through the real binary against NetGet's OWN SSDP server \
                 over unicast loopback. That is same-project evidence: it shows the two \
                 halves of NetGet agree, NOT that either matches a real UPnP device. Also \
                 driven by raw UDP sockets in-test that emulate two devices answering one \
                 search and one announcing itself, which is an independent reading of UDA \
                 1.1 rather than an independent implementation of it (the dhcp / usbip \
                 class). NOT validated against any real UPnP device or emulator.",
            )
            .notes(
                "EXPERIMENTAL, and the reason is the peer, not the code. Every test peer is \
                 either NetGet's own SSDP server (circular — same project, same codec) or a \
                 device hand-written inside the test from the spec. Beta requires a device \
                 NetGet did not write: a real router/TV/printer on a real LAN, or an \
                 installed UPnP device emulator. Neither exists in this environment. \
                 MULTICAST ON LOOPBACK: measured on macOS 27, joining 239.255.255.250 from \
                 a 127.0.0.1 bind succeeds but SENDING to the group fails with \
                 EADDRNOTAVAIL (49), because loopback carries no multicast route — bind \
                 0.0.0.0 for a real scan, and use send_msearch's 'target' for a unicast \
                 search over loopback. To overhear NOTIFY announcements the socket must bind \
                 port 1900 and join the group (startup params local_port and \
                 join_multicast); with an ephemeral port only unicast replies to our own \
                 searches arrive.",
            )
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }

    fn description(&self) -> &'static str {
        "SSDP / UPnP discovery client: M-SEARCH the network and enumerate the UPnP devices \
         that answer"
    }

    fn example_prompt(&self) -> &'static str {
        "discover the UPnP devices on my network over ssdp: search ssdp:all first, then \
         search again for each device type that answered, and tell me what you found"
    }

    fn group_name(&self) -> &'static str {
        "Application"
    }

    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "bind_address".to_string(),
                type_hint: "string".to_string(),
                description: "Local IP the search socket binds to. Default '0.0.0.0', which \
                              is what a real network scan needs: a socket bound to 127.0.0.1 \
                              cannot send to the multicast group at all (EADDRNOTAVAIL on \
                              macOS — loopback carries no multicast route), though it can \
                              still send and receive unicast searches."
                    .to_string(),
                required: false,
                example: json!("0.0.0.0"),
                default: None,
            },
            ParameterDefinition {
                name: "local_port".to_string(),
                type_hint: "number".to_string(),
                description: "Local UDP port to bind. Default 0 (ephemeral), which is right \
                              for searching: replies to our own M-SEARCH are unicast back to \
                              whatever port we sent from. Set 1900 to also overhear the \
                              NOTIFY announcements devices multicast to the group, which \
                              only arrive on the well-known port."
                    .to_string(),
                required: false,
                example: json!(0),
                default: None,
            },
            ParameterDefinition {
                name: "join_multicast".to_string(),
                type_hint: "boolean".to_string(),
                description: "Whether to join the 239.255.255.250 group so multicast NOTIFY \
                              announcements are received. Default true. Best effort: a \
                              failure is logged and the client keeps running, because \
                              searching does not depend on the join."
                    .to_string(),
                required: false,
                example: json!(true),
                default: None,
            },
            ParameterDefinition {
                name: "multicast_interface".to_string(),
                type_hint: "string".to_string(),
                description: "Local IPv4 address of the interface to join the group on, e.g. \
                              '192.168.1.10'. Default '0.0.0.0', letting the kernel choose. \
                              Only meaningful for an IPv4 bind."
                    .to_string(),
                required: false,
                example: json!("0.0.0.0"),
                default: None,
            },
            ParameterDefinition {
                name: "response_window_ms".to_string(),
                type_hint: "number".to_string(),
                description: "Override how long replies to a search are collected, in \
                              milliseconds. Default 0, meaning use the search's own MX (MX \
                              seconds), which is what the devices were told to expect. Set \
                              it longer to catch devices that answer late, or shorter to \
                              make a scripted sweep finish quickly."
                    .to_string(),
                required: false,
                example: json!(0),
                default: None,
            },
            ParameterDefinition {
                name: "user_agent".to_string(),
                type_hint: "string".to_string(),
                description: "USER-AGENT header sent with every M-SEARCH, in the UDA 1.1 \
                              form 'OS/version UPnP/1.1 product/version'. Default \
                              'NetGet/1.0 UPnP/1.1 NetGet-SSDP-Client/1.0'. Some devices \
                              vary what they advertise by control point."
                    .to_string(),
                required: false,
                example: json!("Linux/6.1 UPnP/1.1 NetGet-SSDP-Client/1.0"),
                default: None,
            },
        ]
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;

        StartupExamples::new(
            // LLM mode: the model runs the sweep and decides what to narrow to.
            json!({
                "type": "open_client",
                "remote_addr": "239.255.255.250:1900",
                "base_stack": "ssdp",
                "startup_params": {"bind_address": "0.0.0.0", "local_port": 1900},
                "instruction": "Discover the UPnP devices on this network. Start with an \
                                ssdp:all search, then for each distinct device type that \
                                answers run a narrower search for that exact type. Report \
                                each device's SERVER string, USN and LOCATION."
            }),
            // Script mode: deterministic, no model in the loop.
            json!({
                "type": "open_client",
                "remote_addr": "239.255.255.250:1900",
                "base_stack": "ssdp",
                "event_handlers": [{
                    "event_pattern": "ssdp_connected",
                    "handler": {
                        "type": "static",
                        "actions": [{"type": "send_msearch", "st": "upnp:rootdevice", "mx": 3}]
                    }
                }, {
                    "event_pattern": "ssdp_search_response",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "respond([{'type': 'wait_for_more'}])"
                    }
                }]
            }),
            // Static mode: one fixed search, everything after it ignored.
            json!({
                "type": "open_client",
                "remote_addr": "239.255.255.250:1900",
                "base_stack": "ssdp",
                "event_handlers": [{
                    "event_pattern": "ssdp_connected",
                    "handler": {
                        "type": "static",
                        "actions": [{"type": "send_msearch", "st": "ssdp:all", "mx": 3}]
                    }
                }, {
                    "event_pattern": "*",
                    "handler": {"type": "static", "actions": [{"type": "wait_for_more"}]}
                }]
            }),
        )
    }
}

impl Client for SsdpClientProtocol {
    fn connect(
        &self,
        ctx: crate::protocol::ConnectContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            crate::client::ssdp::SsdpClient::connect_with_llm_actions(
                ctx.remote_addr,
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.client_id,
                ctx.startup_params,
            )
            .await
        })
    }

    fn execute_action(&self, action: serde_json::Value) -> Result<ClientActionResult> {
        let action_type = action
            .get("type")
            .and_then(|v| v.as_str())
            .context("Missing 'type' field in action")?;

        match action_type {
            "send_msearch" => {
                let st = action
                    .get("st")
                    .and_then(|v| v.as_str())
                    .context(
                        "Missing 'st' field: an M-SEARCH must name a search target, e.g. \
                         'ssdp:all', 'upnp:rootdevice' or a \
                         'urn:schemas-upnp-org:device:...' URN",
                    )?
                    .trim();
                if st.is_empty() {
                    return Err(anyhow::anyhow!(
                        "'st' is empty: a device answers only a search whose target it \
                         matches, and an empty target matches nothing"
                    ));
                }
                // Refused, not sanitised: a CR or LF here would end the ST line early and
                // append attacker-chosen headers to our own request — the HTTP
                // response-splitting shape, applied to a search. The model is told what it
                // did rather than having it quietly rewritten.
                message::validate_header_piece("value", "ST", st)?;

                // Clamped rather than rejected: UDA 1.1 §1.3.2 requires a *device* to treat
                // an MX above 5 as 5, so sending a larger one is pointless rather than
                // wrong, and refusing would fail a search over a detail the device ignores.
                let mx = match action.get("mx") {
                    None | Some(serde_json::Value::Null) => DEFAULT_MX_SECONDS,
                    Some(v) => {
                        let n = v.as_u64().ok_or_else(|| {
                            anyhow::anyhow!(
                                "'mx' must be a number of seconds (1..={MAX_MX_SECONDS}), got {v}"
                            )
                        })?;
                        n.clamp(1, u64::from(MAX_MX_SECONDS)) as u32
                    }
                };

                let target = match action.get("target") {
                    None | Some(serde_json::Value::Null) => None,
                    Some(v) => {
                        let s = v.as_str().ok_or_else(|| {
                            anyhow::anyhow!("'target' must be a string 'ip:port', got {v}")
                        })?;
                        let s = s.trim();
                        if s.is_empty() {
                            None
                        } else {
                            // Parsed here rather than in mod.rs so a typo is reported to the
                            // model as a rejected action instead of a silent non-send.
                            let addr: std::net::SocketAddr = s.parse().map_err(|e| {
                                anyhow::anyhow!(
                                    "'target' must be 'ip:port' (e.g. '192.168.1.1:1900'): {e}"
                                )
                            })?;
                            Some(addr.to_string())
                        }
                    }
                };

                Ok(ClientActionResult::Custom {
                    name: "send_msearch".to_string(),
                    data: json!({"st": st, "mx": mx, "target": target}),
                })
            }
            "wait_for_more" => Ok(ClientActionResult::WaitForMore),
            "disconnect" => Ok(ClientActionResult::Disconnect),
            other => Err(anyhow::anyhow!(
                "Unknown SSDP client action: {other}. Valid actions: send_msearch, \
                 wait_for_more, disconnect"
            )),
        }
    }
}
