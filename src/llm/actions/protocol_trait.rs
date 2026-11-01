//! Protocol trait - common interface for all network protocols
//!
//! This module defines the core Protocol trait that both Server and Client traits extend.
//! It contains common functionality shared across all protocol implementations.

use super::{ActionDefinition, ParameterDefinition, StartupExamples};
use crate::protocol::dependencies::ProtocolDependency;
use crate::state::app_state::AppState;

/// Common trait for all protocol implementations (both servers and clients)
///
/// This trait defines the common interface that all protocol implementations
/// must provide, regardless of whether they're servers or clients.
pub trait Protocol: Send + Sync {
    /// Get default binding parameters for this protocol
    ///
    /// Protocols can return `Some(BindingDefaults)` to opt into the flexible
    /// binding system. Protocols that return `None` use the legacy listen_addr system.
    ///
    /// Examples:
    /// - TCP: `Some(BindingDefaults::port_based("127.0.0.1", 0))`
    /// - ICMP: `Some(BindingDefaults::interface_based("lo"))`
    /// - Unmigrated protocols: `None`
    ///
    /// Default implementation returns `None` (unmigrated, use legacy system).
    fn default_binding(&self) -> Option<crate::protocol::BindingDefaults> {
        None
    }

    /// Get startup parameters that can be provided when starting this protocol
    ///
    /// These parameters configure the protocol before it starts. Examples:
    /// - HTTP: request_headers, user_agent, follow_redirects (client)
    /// - HTTP: certificate_mode, request_filter_mode (server)
    /// - SSH: username, password, private_key_path (client)
    /// - SSH: host_key_path, banner_message (server)
    ///
    /// Default implementation returns empty vector (no startup parameters).
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        Vec::new()
    }

    /// Get async actions that can be executed anytime from user input
    ///
    /// These actions don't require network context. Examples:
    /// - HTTP client: send_request(method, path, headers, body)
    /// - HTTP server: close_connection(id), send_to_connection(id, data)
    /// - Redis client: execute_command(cmd, args)
    /// - Generic: disconnect(), reconnect()
    fn get_async_actions(&self, state: &AppState) -> Vec<ActionDefinition>;

    /// Get sync actions available during network events
    ///
    /// These actions only make sense in response to network events. Examples:
    /// - TCP: send_tcp_data(output), wait_for_more()
    /// - HTTP: send_http_response(status, headers, body)
    /// - SSH: handle_auth_challenge(), send_command_output()
    fn get_sync_actions(&self) -> Vec<ActionDefinition>;

    /// Get protocol name for debugging and identification
    ///
    /// This should be a short, uppercase identifier. Examples:
    /// - "TCP", "HTTP", "SSH", "DNS", "WireGuard"
    fn protocol_name(&self) -> &'static str;

    /// Get the event types that this protocol can emit
    ///
    /// Each event type includes:
    /// - A unique ID (e.g., "http_request", "ssh_auth")
    /// - A description of when it occurs
    /// - The actions that can be used to respond to this event
    ///
    /// # Returns
    /// A vector of EventType definitions for this protocol
    ///
    /// Default implementation returns empty vector (protocol hasn't migrated to event system yet)
    fn get_event_types(&self) -> Vec<crate::protocol::EventType> {
        Vec::new()
    }

    /// Get the stack name (e.g., "ETH>IP>TCP>HTTP")
    ///
    /// This represents the network stack layers used by this protocol.
    /// Used for display in UI and logging.
    fn stack_name(&self) -> &'static str;

    /// Get parsing keywords for protocol detection
    ///
    /// Returns a list of keywords that can be used to identify this protocol
    /// from user input. Examples:
    /// - HTTP: ["http", "http server", "via http", "hyper"]
    /// - SSH: ["ssh"]
    /// - mDNS: ["mdns", "bonjour", "dns-sd", "zeroconf"]
    ///
    /// Keywords are matched case-insensitively as substrings.
    fn keywords(&self) -> Vec<&'static str>;

    /// Get protocol metadata with implementation details
    ///
    /// Returns detailed metadata including:
    /// - Protocol state (Incomplete, Experimental, Beta, Stable)
    /// - Implementation approach description
    /// - LLM control scope description
    /// - E2E testing approach description
    /// - Privilege requirements
    /// - Optional notes
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2;

    /// Get a short description of this protocol
    ///
    /// This should be a concise, one-line description of what this protocol does.
    /// Examples:
    /// - HTTP: "Web server serving HTTP traffic"
    /// - SSH: "Secure shell server for remote access"
    /// - DNS: "Domain name resolution server"
    fn description(&self) -> &'static str;

    /// Get an example prompt that would trigger this protocol
    ///
    /// This should be a realistic, engaging example that demonstrates
    /// how a user would ask the LLM to start this protocol.
    /// Examples:
    /// - HTTP server: "Pretend to be a sassy HTTP server on port 8080 serving cooking recipes"
    /// - HTTP client: "Connect to http://example.com:8080 and fetch /api/status every 10 seconds"
    /// - SSH server: "Pretend to be a shell via SSH on port 2222"
    fn example_prompt(&self) -> &'static str;

    /// Get startup examples for this protocol with different handler modes
    ///
    /// Returns examples showing how to start this protocol with:
    /// - LLM mode: LLM handles all responses intelligently
    /// - Script mode: Code-based deterministic responses
    /// - Static mode: Fixed, unchanging responses
    ///
    /// These examples are used in:
    /// - Protocol documentation (shown when user requests docs)
    /// - Prompt templates to guide LLM in creating servers
    ///
    /// All examples must be valid `open_server` or `open_client` actions
    /// that can be directly executed. They are validated by parameterized tests.
    ///
    /// This method is REQUIRED for all protocols. Every protocol must provide
    /// valid startup examples for all three modes (llm, script, static).
    fn get_startup_examples(&self) -> StartupExamples;

    /// Get the group name for categorizing this protocol
    ///
    /// Protocols are grouped in documentation by category. Valid groups:
    /// - "Core" - Stable, well-tested protocols (TCP, HTTP, UDP, DNS, etc.)
    /// - "Application" - IRC, Telnet, SMTP, IMAP, MQTT, etc.
    /// - "Database" - MySQL, PostgreSQL, Redis, Kafka, etcd, etc.
    /// - "Web & File" - WebDAV, NFS, SMB, IPP, Git, S3
    /// - "Proxy & Network" - HTTP Proxy, SOCKS5, STUN, TURN
    /// - "VPN & Routing" - WireGuard, OpenVPN, IPSec, BGP
    /// - "AI & API" - OpenAI, gRPC, JSON-RPC, MCP, etc.
    /// - "Network Services" - VNC, Tor Directory, Tor Relay
    ///
    /// This method is mandatory and must be implemented by all protocols.
    fn group_name(&self) -> &'static str;

    /// Get runtime dependencies required for this protocol to function
    ///
    /// Returns a list of dependencies that must be available for this protocol
    /// to work at runtime. Examples:
    /// - ARP/DataLink: vec![ProtocolDependency::SystemLibrary("pcap"), ProtocolDependency::RawSocketAccess]
    /// - WireGuard: vec![ProtocolDependency::TunDeviceAccess, ProtocolDependency::RootAccess]
    /// - gRPC: vec![ProtocolDependency::ToolInPath("protoc")] (for .proto file support)
    /// - SSH on port 22: vec![ProtocolDependency::PrivilegedPort(22)]
    ///
    /// The default **derives dependencies from `metadata().privilege_requirement`** rather
    /// than returning an empty vector, so every protocol reports correct data without
    /// declaring anything twice.
    ///
    /// This mechanism was fully plumbed — `get_excluded_protocols()` is called from the event
    /// handler and the TUI footer — but not one protocol overrode this method, so the exclusion
    /// map was always empty and the whole feature did nothing. Deriving is better than asking
    /// 116 protocols to restate what they already declare: two sources of the same fact drift,
    /// and `privilege_requirement` is the one that already gates startup, so it is the one kept
    /// honest.
    ///
    /// Note the two consumers differ in force. `privilege_requirement` is a hard gate in
    /// `server_startup.rs` — fail it and the server refuses to start. Dependencies are mostly
    /// **informational**: they tell a user, and the model, why a protocol will not work here,
    /// with an installation hint. The one exception is narrow on purpose: startup refuses a
    /// system library or tool the probe *established* is absent
    /// (`protocol::dependencies::startup_blocker`, fed by [`Self::startup_dependencies`]); a
    /// probe that could not answer never refuses.
    ///
    /// `DeviceAccess` maps to nothing deliberately. There is no `ProtocolDependency` variant for
    /// a Bluetooth adapter, USB device or NFC reader, and no probe that would answer honestly;
    /// claiming an unmet dependency we cannot check would exclude protocols that work.
    ///
    /// Override this to add what privilege cannot express — a system library, or a tool in
    /// PATH. Call `default_dependencies_from_privilege(self)` and extend it rather than
    /// replacing it, so the privilege-derived entries are not silently dropped.
    fn get_dependencies(&self) -> Vec<ProtocolDependency> {
        default_dependencies_from_privilege(self)
    }

    /// The runtime dependencies a start with these `startup_params` actually needs.
    ///
    /// This is what the startup gate checks (`protocol::dependencies::startup_blocker`), so a
    /// protocol whose dependency applies to only some configurations can say so and not be
    /// refused a start that would work — gRPC needs `protoc` to compile `.proto` text, and not
    /// at all for a pre-compiled descriptor set. Defaults to [`Self::get_dependencies`].
    fn startup_dependencies(
        &self,
        _startup_params: Option<&serde_json::Value>,
    ) -> Vec<ProtocolDependency> {
        self.get_dependencies()
    }

    /// The privilege this particular start needs, given its startup parameters.
    ///
    /// This is what the startup privilege gate checks. It defaults to the declared
    /// `metadata().privilege_requirement`, which describes the transport an operator actually
    /// uses. A protocol with an unprivileged test transport — the same frames over a UDP socket
    /// instead of raw Ethernet or IP — overrides it with [`unless_udp_transport`], so a start
    /// that needs no privilege is not refused. Declaring `None` instead would misdescribe the
    /// real transport.
    fn startup_privilege_requirement(
        &self,
        _startup_params: Option<&serde_json::Value>,
    ) -> crate::protocol::metadata::PrivilegeRequirement {
        self.metadata().privilege_requirement
    }
}

/// `declared`, unless the startup parameters select the unprivileged UDP test transport
/// (`transport: "udp"`, or CDP's alias `"test"`), which needs nothing.
pub fn unless_udp_transport(
    declared: crate::protocol::metadata::PrivilegeRequirement,
    startup_params: Option<&serde_json::Value>,
) -> crate::protocol::metadata::PrivilegeRequirement {
    match startup_params
        .and_then(|p| p.get("transport"))
        .and_then(|t| t.as_str())
    {
        Some("udp" | "test") => crate::protocol::metadata::PrivilegeRequirement::None,
        _ => declared,
    }
}

/// Translate a protocol's declared `privilege_requirement` into runtime dependencies.
///
/// This is the body of [`Protocol::get_dependencies`]'s default. It is a free function so an
/// overriding protocol can extend the derived list instead of replacing it:
///
/// ```rust,ignore
/// fn get_dependencies(&self) -> Vec<ProtocolDependency> {
///     let mut deps = default_dependencies_from_privilege(self);
///     deps.push(ProtocolDependency::SystemLibrary("pcap"));
///     deps
/// }
/// ```
///
/// `DeviceAccess` yields nothing on purpose — see the note on `get_dependencies`.
pub fn default_dependencies_from_privilege<P: Protocol + ?Sized>(
    protocol: &P,
) -> Vec<ProtocolDependency> {
    use crate::protocol::metadata::PrivilegeRequirement as P9;

    match protocol.metadata().privilege_requirement {
        P9::None => Vec::new(),
        // A privileged *default* port is not a missing dependency: the port is a
        // startup parameter, so the protocol runs perfectly well on 1179, 8080 or
        // 5353 with no privilege at all. Treating it as a dependency excluded 26
        // protocols from the catalogue on any non-root run — DNS, HTTP, SMTP, SSH,
        // BGP and the rest — and `/env` said outright that they were "hidden from
        // the model", so the LLM could not choose them however the user phrased the
        // request. Nothing was unable to run; they were only unable to be picked.
        //
        // The check that matters still happens, and is the one that knows the real
        // port: `server_startup.rs` refuses a start only when the port actually
        // requested is below 1024 and privilege is absent, and its error names the
        // high ports to use instead. Advisory listing lives in
        // `privileged_default_ports()`.
        P9::PrivilegedPort(_) => Vec::new(),
        P9::RawSockets => vec![ProtocolDependency::RawSocketAccess],
        P9::PacketCapture => vec![ProtocolDependency::PromiscuousMode],
        // No probe can answer honestly for an adapter/reader, so claim nothing rather than
        // exclude a protocol that works.
        P9::DeviceAccess(_) => Vec::new(),
        P9::Root => vec![ProtocolDependency::RootAccess],
    }
}

/// Result of executing a protocol action
#[derive(Debug)]
pub enum ActionResult {
    /// Data to send over the connection/socket
    Output(Vec<u8>),

    /// Close the connection (connection-oriented protocols only)
    CloseConnection,

    /// Wait for more data before responding (accumulating state)
    WaitForMore,

    /// No action needed (e.g., logging, state update)
    NoAction,

    /// Multiple results (e.g., send data + close connection)
    Multiple(Vec<ActionResult>),

    /// Custom protocol-specific result with structured data
    ///
    /// This is used when a protocol needs to return structured information
    /// that isn't just "send these bytes". Protocols encode their responses
    /// as JSON in the 'data' field, and the protocol handler decodes and
    /// processes them.
    ///
    /// Examples:
    /// - SSH auth: {"name": "ssh_auth", "data": {"allowed": true}}
    /// - MySQL: {"name": "mysql_query", "data": {"columns": [...], "rows": [...]}}
    /// - Redis: {"name": "redis_string", "data": {"value": "OK"}}
    Custom {
        name: String,
        data: serde_json::Value,
    },
}

impl ActionResult {
    /// Check if this result contains output data
    pub fn has_output(&self) -> bool {
        match self {
            ActionResult::Output(_) => true,
            ActionResult::Multiple(results) => results.iter().any(|r| r.has_output()),
            _ => false,
        }
    }

    /// Check if this result closes the connection
    pub fn closes_connection(&self) -> bool {
        match self {
            ActionResult::CloseConnection => true,
            ActionResult::Multiple(results) => results.iter().any(|r| r.closes_connection()),
            _ => false,
        }
    }

    /// Check if this result waits for more data
    pub fn waits_for_more(&self) -> bool {
        match self {
            ActionResult::WaitForMore => true,
            ActionResult::Multiple(results) => results.iter().any(|r| r.waits_for_more()),
            _ => false,
        }
    }

    /// Extract all output data from results
    pub fn get_all_output(&self) -> Vec<Vec<u8>> {
        match self {
            ActionResult::Output(data) => vec![data.clone()],
            ActionResult::Multiple(results) => {
                results.iter().flat_map(|r| r.get_all_output()).collect()
            }
            _ => Vec::new(),
        }
    }
}

/// Trait for protocol server implementations
///
/// Each server protocol implements both the Protocol trait (for common functionality)
/// and this Server trait (for server-specific functionality like spawning).
///
/// The Server trait provides:
/// 1. Server spawning - how to start the protocol server
/// 2. Action executor - parses and executes protocol actions
pub trait Server: Protocol {
    /// Spawn a server instance for this protocol
    ///
    /// This is called when a server needs to be started. The implementation
    /// should bind to the listen address, set up any necessary resources,
    /// and return the actual bound address.
    ///
    /// # Arguments
    /// * `ctx` - Spawn context with all necessary dependencies
    ///
    /// # Returns
    /// * `Ok(SocketAddr)` - The actual address the server bound to
    /// * `Err(_)` - If server spawning failed
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    >;

    /// Execute a protocol-specific action
    ///
    /// # Arguments
    /// * `action` - The action JSON object from LLM
    ///
    /// # Returns
    /// * `Ok(ActionResult)` - Result of execution (data to send, close connection, etc.)
    /// * `Err(_)` - If action execution failed
    fn execute_action(&self, action: serde_json::Value) -> anyhow::Result<ActionResult>;

    /// Execute a protocol-specific action with access to application state.
    ///
    /// Actions are dispatched on the *stateless* protocol struct held by the registry — a
    /// zero-sized description with no channel, socket or peer table. That is fine for sync
    /// actions, which are answers carried back to the connection task that raised the event,
    /// but it leaves async actions (`list_peers`, `get_server_info` and their kin) with
    /// nothing to read from, so the only honest thing they could return was `NoAction`.
    ///
    /// Overriding this method is how a protocol reaches its running instance: call
    /// [`AppState::server_handle`] with the handle type its `spawn()` registered via
    /// [`AppState::register_server_handle`], and talk to the live server.
    ///
    /// The default delegates to [`Self::execute_action`], so every protocol that does not
    /// need live state is unaffected and nothing has to opt in.
    fn execute_action_with_state<'a>(
        &'a self,
        action: serde_json::Value,
        state: AppState,
        server_id: Option<crate::state::ServerId>,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<ActionResult>> + Send + 'a>,
    > {
        // AppState is an Arc internally, so taking it by value is cheap.
        let _ = (state, server_id);
        let result = self.execute_action(action);
        Box::pin(async move { result })
    }
}

/// Report event types that leave the model without a protocol vocabulary to answer them.
///
/// This is the item-56 defect: the model answering such an event is handed only
/// `set_memory`/`append_memory`/`notify_operator`/`append_to_log`, so every protocol action it
/// returns is rejected as unknown, retried twice, and fails. It silently disabled sixteen
/// protocols. An `EventType` that genuinely needs no actions declares that with
/// `.with_no_actions()`, which this ignores.
///
/// Returns one human-readable finding per offending event; empty means the protocol is clean.
///
/// # The hole this used to have
///
/// It early-returned when `get_sync_actions()` was empty, on the reasoning that "a protocol
/// with nothing to advertise is not withholding anything". That reasoning is backwards, and it
/// made the guard **pass hardest on the most broken protocol in the tree**: `usb-fido2`
/// declared zero sync actions *and* three events with no actions, so it could not answer any
/// event at all, and the audit waved it through with `0 findings`. A protocol that offers the
/// model nothing is the worst case, not the exempt case.
///
/// The one legitimate shape is **delegation**: `doh` and `dot` return `DnsProtocol`'s sync
/// actions from their own `get_sync_actions()` and attach them to their events, so they are
/// non-empty on both counts and never reach this branch. Delegation that forwards another
/// protocol's actions is therefore already covered — what is flagged is an event with an
/// empty, non-intentional action list, whether or not the protocol declares sync actions of
/// its own. The deliberate case is still `EventType::with_no_actions()`.
///
/// # Where this belongs
///
/// Call it **once per protocol at server-startup time** — `src/cli/server_startup.rs`, after
/// the protocol object is resolved from the registry and before `spawn()` — so a
/// misdeclared event is reported against a named server the user just tried to start, and
/// the failure is attributable. The equivalent check must not live on the per-event path:
/// that runs once per connection inside a tokio task, where a `debug_assert!` panic is
/// swallowed by the task and leaves the server still reporting `Running`.
///
/// `tests/event_action_declarations_test.rs` runs this over the whole registry, which
/// catches the defect in CI for every protocol rather than only for the ones a run happens
/// to start — though only for the features that run happens to compile in, which is why the
/// test also asserts a lower bound on how many protocols it inspected.
pub fn audit_event_action_declarations(protocol: &dyn Protocol) -> Vec<String> {
    let sync_action_count = protocol.get_sync_actions().len();

    protocol
        .get_event_types()
        .into_iter()
        .filter(|event_type| event_type.has_no_usable_actions())
        .map(|event_type| {
            if sync_action_count == 0 {
                format!(
                    "event '{}' of protocol '{}' declares no actions, and the protocol declares \
                     no sync actions either, so this protocol offers the model nothing: every \
                     protocol-specific action it could return would be rejected as unknown and \
                     the event cannot be answered at all. Fix by declaring sync actions and \
                     attaching them with .with_actions(...), by delegating another protocol's \
                     action set (as doh/dot do for DNS), or by .with_no_actions() if the event \
                     genuinely needs none.",
                    event_type.id,
                    protocol.protocol_name(),
                )
            } else {
                format!(
                    "event '{}' of protocol '{}' declares no actions of its own, so the model \
                     would be offered none of the protocol's {} sync action(s) and anything \
                     protocol-specific it returned would be rejected as an unknown action. Fix by \
                     adding .with_actions(...) to the event type, or .with_no_actions() if it \
                     genuinely needs none.",
                    event_type.id,
                    protocol.protocol_name(),
                    sync_action_count
                )
            }
        })
        .collect()
}
