//! OSPF protocol actions implementation

use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter, ParameterDefinition,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::EventType;
use crate::state::app_state::AppState;
use anyhow::{Context, Result};
use serde_json::json;
use std::sync::LazyLock;
use tracing::debug;

/// The interface configuration supplied through `get_startup_parameters()`.
///
/// Every one of the six declared startup parameters lands in this struct and is read:
///
/// * `router_id` / `area_id` / `network_mask` / `hello_interval` /
///   `router_dead_interval` / `router_priority` become the **defaults for every packet
///   the model sends** ([`apply_defaults`](Self::apply_defaults)). An action that names a
///   field still wins - the model can deliberately lie about its timers - but an action
///   that omits one now gets the operator's configured value instead of a hardcoded
///   constant.
/// * `hello_interval`, `router_dead_interval` and `network_mask` are additionally checked
///   against every received Hello ([`hello_mismatches`](Self::hello_mismatches)), because
///   RFC 2328 10.5 makes those three a precondition for accepting a Hello at all.
///
/// Before this existed, four of the six parameters were declared to the model and never
/// read anywhere.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OspfInterfaceConfig {
    pub router_id: String,
    pub area_id: String,
    pub network_mask: String,
    pub hello_interval: u16,
    pub router_dead_interval: u32,
    pub router_priority: u8,
}

impl Default for OspfInterfaceConfig {
    fn default() -> Self {
        // RFC 2328 Appendix C.3 defaults for a broadcast interface.
        Self {
            router_id: "0.0.0.0".to_string(),
            area_id: "0.0.0.0".to_string(),
            network_mask: "255.255.255.0".to_string(),
            hello_interval: 10,
            router_dead_interval: 40,
            router_priority: 1,
        }
    }
}

impl OspfInterfaceConfig {
    /// Fill in the fields the model left out of an outgoing packet action.
    ///
    /// `router_id` and `area_id` apply to every OSPF packet type; the Hello body fields
    /// are only added to `send_hello`, where they exist. Fields the action already
    /// carries are left untouched.
    pub fn apply_defaults(&self, action: &mut serde_json::Value) {
        let Some(obj) = action.as_object_mut() else {
            return;
        };

        obj.entry("router_id")
            .or_insert_with(|| json!(self.router_id));
        obj.entry("area_id").or_insert_with(|| json!(self.area_id));

        if obj.get("type").and_then(|t| t.as_str()) == Some("send_hello") {
            obj.entry("network_mask")
                .or_insert_with(|| json!(self.network_mask));
            obj.entry("hello_interval")
                .or_insert_with(|| json!(self.hello_interval));
            obj.entry("router_dead_interval")
                .or_insert_with(|| json!(self.router_dead_interval));
            obj.entry("priority")
                .or_insert_with(|| json!(self.router_priority));
        }
    }

    /// RFC 2328 10.5: a received Hello whose HelloInterval, RouterDeadInterval or network
    /// mask differs from the receiving interface's must be rejected - adjacency cannot form
    /// across such a mismatch on a broadcast network.
    ///
    /// Returns one human-readable line per mismatching field, empty when the Hello is
    /// compatible. The caller reports these to the model and refuses to advance the
    /// neighbour state machine, rather than pretending an adjacency is forming that a real
    /// router would never complete.
    pub fn hello_mismatches(
        &self,
        hello_interval: u16,
        router_dead_interval: u32,
        network_mask: &str,
    ) -> Vec<String> {
        let mut out = Vec::new();
        if hello_interval != self.hello_interval {
            out.push(format!(
                "hello_interval {} does not match our configured {}",
                hello_interval, self.hello_interval
            ));
        }
        if router_dead_interval != self.router_dead_interval {
            out.push(format!(
                "router_dead_interval {} does not match our configured {}",
                router_dead_interval, self.router_dead_interval
            ));
        }
        if network_mask != self.network_mask {
            out.push(format!(
                "network_mask {} does not match our configured {}",
                network_mask, self.network_mask
            ));
        }
        out
    }
}

/// OSPF protocol action handler
pub struct OspfProtocol;

impl OspfProtocol {
    pub fn new() -> Self {
        Self
    }

    fn execute_send_hello(&self, action: serde_json::Value) -> Result<ActionResult> {
        let router_id = action
            .get("router_id")
            .and_then(|v| v.as_str())
            .unwrap_or("0.0.0.0");

        let area_id = action
            .get("area_id")
            .and_then(|v| v.as_str())
            .unwrap_or("0.0.0.0");

        let _network_mask = action
            .get("network_mask")
            .and_then(|v| v.as_str())
            .unwrap_or("255.255.255.0");

        let _hello_interval = action
            .get("hello_interval")
            .and_then(|v| v.as_u64())
            .unwrap_or(10) as u16;

        let _router_dead_interval = action
            .get("router_dead_interval")
            .and_then(|v| v.as_u64())
            .unwrap_or(40) as u32;

        let priority = action.get("priority").and_then(|v| v.as_u64()).unwrap_or(1) as u8;

        let _dr = action
            .get("dr")
            .and_then(|v| v.as_str())
            .unwrap_or("0.0.0.0");

        let _bdr = action
            .get("bdr")
            .and_then(|v| v.as_str())
            .unwrap_or("0.0.0.0");

        let destination = action
            .get("destination")
            .and_then(|v| v.as_str())
            .unwrap_or("multicast")
            .to_string();

        debug!(
            "OSPF sending Hello: router_id={}, area={}, priority={}, dest={}",
            router_id, area_id, priority, destination
        );

        // Return structured action data - packet will be built in mod.rs
        Ok(ActionResult::Custom {
            name: "ospf_action".to_string(),
            data: action.clone(),
        })
    }

    fn execute_send_database_description(&self, action: serde_json::Value) -> Result<ActionResult> {
        let _router_id = action
            .get("router_id")
            .and_then(|v| v.as_str())
            .unwrap_or("0.0.0.0");

        let _area_id = action
            .get("area_id")
            .and_then(|v| v.as_str())
            .unwrap_or("0.0.0.0");

        let sequence = action.get("sequence").and_then(|v| v.as_u64()).unwrap_or(0) as u32;

        let init = action
            .get("init")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let more = action
            .get("more")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let master = action
            .get("master")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let destination = action
            .get("destination")
            .and_then(|v| v.as_str())
            .unwrap_or("multicast")
            .to_string();

        debug!(
            "OSPF sending Database Description: seq={}, init={}, more={}, master={}, dest={}",
            sequence, init, more, master, destination
        );

        // Return structured action data - packet will be built in mod.rs
        Ok(ActionResult::Custom {
            name: "ospf_action".to_string(),
            data: action.clone(),
        })
    }

    fn execute_send_link_state_request(&self, action: serde_json::Value) -> Result<ActionResult> {
        let _router_id = action
            .get("router_id")
            .and_then(|v| v.as_str())
            .unwrap_or("0.0.0.0");

        let _area_id = action
            .get("area_id")
            .and_then(|v| v.as_str())
            .unwrap_or("0.0.0.0");

        let destination = action
            .get("destination")
            .and_then(|v| v.as_str())
            .unwrap_or("multicast")
            .to_string();

        debug!("OSPF sending Link State Request to {}", destination);

        // Return structured action data - packet will be built in mod.rs
        Ok(ActionResult::Custom {
            name: "ospf_action".to_string(),
            data: action.clone(),
        })
    }

    fn execute_send_link_state_update(&self, action: serde_json::Value) -> Result<ActionResult> {
        let _router_id = action
            .get("router_id")
            .and_then(|v| v.as_str())
            .unwrap_or("0.0.0.0");

        let _area_id = action
            .get("area_id")
            .and_then(|v| v.as_str())
            .unwrap_or("0.0.0.0");

        let destination = action
            .get("destination")
            .and_then(|v| v.as_str())
            .unwrap_or("multicast")
            .to_string();

        debug!("OSPF sending Link State Update to {}", destination);

        // Return structured action data - packet will be built in mod.rs
        Ok(ActionResult::Custom {
            name: "ospf_action".to_string(),
            data: action.clone(),
        })
    }

    fn execute_send_link_state_ack(&self, action: serde_json::Value) -> Result<ActionResult> {
        let _router_id = action
            .get("router_id")
            .and_then(|v| v.as_str())
            .unwrap_or("0.0.0.0");

        let _area_id = action
            .get("area_id")
            .and_then(|v| v.as_str())
            .unwrap_or("0.0.0.0");

        let destination = action
            .get("destination")
            .and_then(|v| v.as_str())
            .unwrap_or("multicast")
            .to_string();

        debug!("OSPF sending Link State Acknowledgment to {}", destination);

        // Return structured action data - packet will be built in mod.rs
        Ok(ActionResult::Custom {
            name: "ospf_action".to_string(),
            data: action.clone(),
        })
    }

    /// Parse a dotted-quad into the four bytes every OSPF ID field carries.
    ///
    /// Strict on purpose. This used to fall back to `0.0.0.0` for anything it could not
    /// parse and return `Ok`, so `router_id: "1.1.1"`, `"999.1.1.1"` or a typo'd startup
    /// parameter produced a well-formed packet advertising Router ID 0.0.0.0 — a different
    /// router — with nothing logged anywhere. Every caller already uses `?`, so an error
    /// here surfaces as the "OSPF packet build error" the operator can act on, and no
    /// packet goes out claiming an identity nobody asked for.
    fn parse_ipv4(ip: &str) -> Result<[u8; 4]> {
        ip.parse::<std::net::Ipv4Addr>()
            .map(|addr| addr.octets())
            .map_err(|_| {
                anyhow::anyhow!("'{ip}' is not an IPv4 address in dotted-quad form (e.g. 1.1.1.1)")
            })
    }

    /// Parse the fixed 20-byte LSA headers that DD and LSAck packets carry, and that LSU
    /// packets carry ahead of each LSA body (RFC 2328 A.4.1).
    ///
    /// Returns structured fields, never raw bytes - models cannot read a hex blob (see
    /// CLAUDE.md, action & event design rules). The shape is exactly what
    /// [`Self::build_link_state_ack_packet`] consumes, so the model can acknowledge an
    /// update by handing back the `lsa_headers` the event gave it.
    ///
    /// Lives here rather than in the server loop because the OSPF *client* parses the same
    /// headers out of the Link State Updates it receives.
    pub fn parse_lsa_headers(body: &[u8], max: usize) -> Vec<serde_json::Value> {
        const LSA_HEADER_LEN: usize = 20;
        let mut out = Vec::new();
        let mut offset = 0;
        while offset + LSA_HEADER_LEN <= body.len() && out.len() < max {
            let h = &body[offset..offset + LSA_HEADER_LEN];
            let lsa_type = h[3];
            out.push(json!({
                "age": u16::from_be_bytes([h[0], h[1]]),
                "options": h[2],
                "lsa_type": lsa_type,
                "lsa_type_name": match lsa_type {
                    1 => "router",
                    2 => "network",
                    3 => "summary_network",
                    4 => "summary_asbr",
                    5 => "as_external",
                    7 => "nssa_external",
                    _ => "unknown",
                },
                "link_state_id": format!("{}.{}.{}.{}", h[4], h[5], h[6], h[7]),
                "advertising_router": format!("{}.{}.{}.{}", h[8], h[9], h[10], h[11]),
                "sequence": u32::from_be_bytes([h[12], h[13], h[14], h[15]]),
                // The LS checksum must be echoed verbatim in an acknowledgement: RFC 2328
                // 13.7 matches an LSAck against the retransmission list on the full header,
                // checksum included. Dropping it here made a correct ack unbuildable.
                "checksum": u16::from_be_bytes([h[16], h[17]]),
                "length": u16::from_be_bytes([h[18], h[19]]),
            }));
            offset += LSA_HEADER_LEN;
        }
        out
    }

    /// Serialise one LSA header (RFC 2328 A.4.1) from the same JSON shape
    /// [`Self::parse_lsa_headers`] produces.
    fn push_lsa_header(msg: &mut Vec<u8>, header: &serde_json::Value) -> Result<()> {
        let u16_field = |name: &str| header.get(name).and_then(|v| v.as_u64()).unwrap_or(0) as u16;
        let ip_field = |name: &str| -> Result<[u8; 4]> {
            Self::parse_ipv4(
                header
                    .get(name)
                    .and_then(|v| v.as_str())
                    .unwrap_or("0.0.0.0"),
            )
        };

        msg.extend_from_slice(&u16_field("age").to_be_bytes());
        msg.push(header.get("options").and_then(|v| v.as_u64()).unwrap_or(0) as u8);
        msg.push(header.get("lsa_type").and_then(|v| v.as_u64()).unwrap_or(1) as u8);
        msg.extend_from_slice(&ip_field("link_state_id")?);
        msg.extend_from_slice(&ip_field("advertising_router")?);
        msg.extend_from_slice(
            &(header
                .get("sequence")
                .and_then(|v| v.as_u64())
                .unwrap_or(0x8000_0001) as u32)
                .to_be_bytes(),
        );
        msg.extend_from_slice(&u16_field("checksum").to_be_bytes());
        // An LSA header echoed in an ack describes the original LSA's length, so 20 (the
        // header alone) is only the right default when the caller knows nothing else.
        let length = match header.get("length").and_then(|v| v.as_u64()) {
            Some(n) => n as u16,
            None => 20,
        };
        msg.extend_from_slice(&length.to_be_bytes());
        Ok(())
    }

    /// Compute the OSPF packet checksum (RFC 2328 Section A.3.1).
    ///
    /// This is the **standard IP (one's complement) checksum** over the entire packet with the
    /// checksum field itself treated as zero and the 64-bit authentication field (header bytes
    /// 16..24) excluded. It is *not* the Fletcher checksum of Section D.4 — that one applies to
    /// LSA headers, not to packet headers. A previous implementation here used Fletcher, which
    /// meant every packet NetGet emitted failed the receiver's validity check and was silently
    /// dropped by real routers (FRR/BIRD).
    ///
    /// The defining property, and how a receiver validates: recomputing this sum over the packet
    /// **with the checksum field left in place** must yield 0.
    ///
    /// That property is why this function does not special-case bytes 12..14. It sums the packet
    /// exactly as given, which makes one function serve both directions of the standard
    /// one's-complement idiom:
    ///
    /// * **Sending** — leave the checksum field zero, call this, store the result there. Every
    ///   `build_*_packet` here does that, and their headers already lay the field down as
    ///   `[0, 0]`.
    /// * **Receiving** — call this over the packet as it arrived. A valid packet yields 0.
    ///
    /// Zeroing bytes 12..14 unconditionally, as an earlier version did, collapses those two into
    /// one: the receiver then recomputes the sender's value instead of 0, so the validity check
    /// can never pass and a corrupted packet is indistinguishable from a good one. The doc
    /// comment claimed the property above while the code made it unsatisfiable.
    pub fn calculate_checksum(data: &[u8]) -> u16 {
        let mut sum: u32 = 0;
        // Accumulate 16-bit big-endian words, skipping the auth field. `pending` holds the
        // high byte of a word still being assembled, which matters because excluding bytes
        // 16..24 keeps 16-bit alignment intact only because that range is itself even-aligned
        // and even-length.
        let mut pending: Option<u8> = None;
        for (i, &byte) in data.iter().enumerate() {
            // Skip the 64-bit authentication field entirely.
            if (16..24).contains(&i) {
                continue;
            }
            match pending.take() {
                None => pending = Some(byte),
                Some(hi) => sum += u16::from_be_bytes([hi, byte]) as u32,
            }
        }
        // Odd-length packet: pad with a zero byte.
        if let Some(hi) = pending {
            sum += u16::from_be_bytes([hi, 0]) as u32;
        }
        while (sum >> 16) != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    /// Build OSPF Hello packet from action data
    pub fn build_hello_packet(action: &serde_json::Value) -> Result<Vec<u8>> {
        let router_id = action
            .get("router_id")
            .and_then(|v| v.as_str())
            .unwrap_or("0.0.0.0");
        let area_id = action
            .get("area_id")
            .and_then(|v| v.as_str())
            .unwrap_or("0.0.0.0");
        let network_mask = action
            .get("network_mask")
            .and_then(|v| v.as_str())
            .unwrap_or("255.255.255.0");
        let hello_interval = action
            .get("hello_interval")
            .and_then(|v| v.as_u64())
            .unwrap_or(10) as u16;
        let router_dead_interval = action
            .get("router_dead_interval")
            .and_then(|v| v.as_u64())
            .unwrap_or(40) as u32;
        let priority = action.get("priority").and_then(|v| v.as_u64()).unwrap_or(1) as u8;
        let dr = action
            .get("dr")
            .and_then(|v| v.as_str())
            .unwrap_or("0.0.0.0");
        let bdr = action
            .get("bdr")
            .and_then(|v| v.as_str())
            .unwrap_or("0.0.0.0");

        let mut msg = Vec::new();

        // OSPF Header (24 bytes)
        msg.push(2); // Version = 2 (OSPFv2)
        msg.push(1); // Type = 1 (Hello)
        msg.extend_from_slice(&[0, 0]); // Packet Length (placeholder)
        msg.extend_from_slice(&Self::parse_ipv4(router_id)?);
        msg.extend_from_slice(&Self::parse_ipv4(area_id)?);
        msg.extend_from_slice(&[0, 0]); // Checksum (placeholder)
        msg.extend_from_slice(&[0, 0]); // AuType = 0 (no authentication)
        msg.extend_from_slice(&[0; 8]); // Authentication (8 bytes, zeros)

        // Hello packet body
        msg.extend_from_slice(&Self::parse_ipv4(network_mask)?);
        msg.extend_from_slice(&hello_interval.to_be_bytes());
        msg.push(0); // Options
        msg.push(priority);
        msg.extend_from_slice(&router_dead_interval.to_be_bytes());
        msg.extend_from_slice(&Self::parse_ipv4(dr)?);
        msg.extend_from_slice(&Self::parse_ipv4(bdr)?);

        // Neighbor list
        if let Some(neighbors) = action.get("neighbors").and_then(|v| v.as_array()) {
            for neighbor in neighbors {
                if let Some(neighbor_id) = neighbor.as_str() {
                    msg.extend_from_slice(&Self::parse_ipv4(neighbor_id)?);
                }
            }
        }

        // Update packet length and checksum
        let packet_len = msg.len() as u16;
        msg[2..4].copy_from_slice(&packet_len.to_be_bytes());
        // Computed with its own field zeroed, so that a receiver summing the packet with the
        // checksum in place gets 0. The header lays the field down as [0, 0]; this makes that
        // a local guarantee rather than an assumption about code 30 lines up.
        msg[12..14].copy_from_slice(&[0, 0]);
        let checksum = Self::calculate_checksum(&msg);
        msg[12..14].copy_from_slice(&checksum.to_be_bytes());

        Ok(msg)
    }

    /// Build OSPF Database Description packet from action data
    pub fn build_database_description_packet(action: &serde_json::Value) -> Result<Vec<u8>> {
        let router_id = action
            .get("router_id")
            .and_then(|v| v.as_str())
            .unwrap_or("0.0.0.0");
        let area_id = action
            .get("area_id")
            .and_then(|v| v.as_str())
            .unwrap_or("0.0.0.0");
        let sequence = action.get("sequence").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
        let init = action
            .get("init")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let more = action
            .get("more")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let master = action
            .get("master")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let mut msg = Vec::new();

        // OSPF Header
        msg.push(2); // Version
        msg.push(2); // Type = 2 (Database Description)
        msg.extend_from_slice(&[0, 0]); // Packet Length (placeholder)
        msg.extend_from_slice(&Self::parse_ipv4(router_id)?);
        msg.extend_from_slice(&Self::parse_ipv4(area_id)?);
        msg.extend_from_slice(&[0, 0]); // Checksum (placeholder)
        msg.extend_from_slice(&[0, 0]); // AuType
        msg.extend_from_slice(&[0; 8]); // Authentication

        // DD packet body
        msg.extend_from_slice(&[0, 0]); // Interface MTU
        msg.push(0); // Options
        let mut flags: u8 = 0;
        if init {
            flags |= 0x04;
        }
        if more {
            flags |= 0x02;
        }
        if master {
            flags |= 0x01;
        }
        msg.push(flags);
        msg.extend_from_slice(&sequence.to_be_bytes());

        // Database summary: the LSA headers this router is advertising, in the shape
        // parse_lsa_headers emits.
        if let Some(headers) = action.get("lsa_headers").and_then(|v| v.as_array()) {
            for header in headers {
                Self::push_lsa_header(&mut msg, header)?;
            }
        }

        // Update packet length and checksum
        let packet_len = msg.len() as u16;
        msg[2..4].copy_from_slice(&packet_len.to_be_bytes());
        // Computed with its own field zeroed, so that a receiver summing the packet with the
        // checksum in place gets 0. The header lays the field down as [0, 0]; this makes that
        // a local guarantee rather than an assumption about code 30 lines up.
        msg[12..14].copy_from_slice(&[0, 0]);
        let checksum = Self::calculate_checksum(&msg);
        msg[12..14].copy_from_slice(&checksum.to_be_bytes());

        Ok(msg)
    }

    /// Build OSPF Link State Request packet from action data (RFC 2328 A.3.4).
    ///
    /// Body is a repeating triple: LSType(4) | LinkStateID(4) | AdvertisingRouter(4), taken
    /// from the action's `requests` array. The `ospf_link_state_update` event hands the model
    /// LSA headers carrying exactly those three fields, so a request can name real LSAs.
    pub fn build_link_state_request_packet(action: &serde_json::Value) -> Result<Vec<u8>> {
        let router_id = action
            .get("router_id")
            .and_then(|v| v.as_str())
            .unwrap_or("0.0.0.0");
        let area_id = action
            .get("area_id")
            .and_then(|v| v.as_str())
            .unwrap_or("0.0.0.0");

        let mut msg = Vec::new();

        // OSPF Header
        msg.push(2); // Version
        msg.push(3); // Type = 3 (Link State Request)
        msg.extend_from_slice(&[0, 0]); // Packet Length (placeholder)
        msg.extend_from_slice(&Self::parse_ipv4(router_id)?);
        msg.extend_from_slice(&Self::parse_ipv4(area_id)?);
        msg.extend_from_slice(&[0, 0]); // Checksum (placeholder)
        msg.extend_from_slice(&[0, 0]); // AuType
        msg.extend_from_slice(&[0; 8]); // Authentication

        // LSR body: one 12-byte triple per requested LSA.
        if let Some(requests) = action.get("requests").and_then(|v| v.as_array()) {
            for request in requests {
                let lsa_type = request
                    .get("lsa_type")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(1) as u32;
                msg.extend_from_slice(&lsa_type.to_be_bytes());
                msg.extend_from_slice(&Self::parse_ipv4(
                    request
                        .get("link_state_id")
                        .and_then(|v| v.as_str())
                        .unwrap_or("0.0.0.0"),
                )?);
                msg.extend_from_slice(&Self::parse_ipv4(
                    request
                        .get("advertising_router")
                        .and_then(|v| v.as_str())
                        .unwrap_or("0.0.0.0"),
                )?);
            }
        }

        // Update packet length and checksum
        let packet_len = msg.len() as u16;
        msg[2..4].copy_from_slice(&packet_len.to_be_bytes());
        // Computed with its own field zeroed, so that a receiver summing the packet with the
        // checksum in place gets 0. The header lays the field down as [0, 0]; this makes that
        // a local guarantee rather than an assumption about code 30 lines up.
        msg[12..14].copy_from_slice(&[0, 0]);
        let checksum = Self::calculate_checksum(&msg);
        msg[12..14].copy_from_slice(&checksum.to_be_bytes());

        Ok(msg)
    }

    /// Build OSPF Link State Update packet from action data
    pub fn build_link_state_update_packet(action: &serde_json::Value) -> Result<Vec<u8>> {
        let router_id = action
            .get("router_id")
            .and_then(|v| v.as_str())
            .unwrap_or("0.0.0.0");
        let area_id = action
            .get("area_id")
            .and_then(|v| v.as_str())
            .unwrap_or("0.0.0.0");

        let mut msg = Vec::new();

        // OSPF Header
        msg.push(2); // Version
        msg.push(4); // Type = 4 (Link State Update)
        msg.extend_from_slice(&[0, 0]); // Packet Length (placeholder)
        msg.extend_from_slice(&Self::parse_ipv4(router_id)?);
        msg.extend_from_slice(&Self::parse_ipv4(area_id)?);
        msg.extend_from_slice(&[0, 0]); // Checksum (placeholder)
        msg.extend_from_slice(&[0, 0]); // AuType
        msg.extend_from_slice(&[0; 8]); // Authentication

        // Number of LSAs
        msg.extend_from_slice(&[0, 0, 0, 0]); // 0 LSAs (simplified)

        // LSAs would go here

        // Update packet length and checksum
        let packet_len = msg.len() as u16;
        msg[2..4].copy_from_slice(&packet_len.to_be_bytes());
        // Computed with its own field zeroed, so that a receiver summing the packet with the
        // checksum in place gets 0. The header lays the field down as [0, 0]; this makes that
        // a local guarantee rather than an assumption about code 30 lines up.
        msg[12..14].copy_from_slice(&[0, 0]);
        let checksum = Self::calculate_checksum(&msg);
        msg[12..14].copy_from_slice(&checksum.to_be_bytes());

        Ok(msg)
    }

    /// Build OSPF Link State Acknowledgment packet from action data (RFC 2328 A.3.6).
    ///
    /// The body is the list of 20-byte LSA headers being acknowledged, taken from the
    /// action's `lsa_headers` array in the shape [`Self::parse_lsa_headers`] emits — so the
    /// model acknowledges an update by handing back the `lsa_headers` the
    /// `ospf_link_state_update` event gave it.
    ///
    /// An LSAck with an empty body is not a no-op: RFC 2328 13.7 matches an acknowledgement
    /// against the neighbour's retransmission list header by header, so a body-less LSAck
    /// acknowledges nothing and the peer keeps retransmitting every LSA each RxmtInterval
    /// until the adjacency fails. That is what this used to emit.
    pub fn build_link_state_ack_packet(action: &serde_json::Value) -> Result<Vec<u8>> {
        let router_id = action
            .get("router_id")
            .and_then(|v| v.as_str())
            .unwrap_or("0.0.0.0");
        let area_id = action
            .get("area_id")
            .and_then(|v| v.as_str())
            .unwrap_or("0.0.0.0");

        let mut msg = Vec::new();

        // OSPF Header
        msg.push(2); // Version
        msg.push(5); // Type = 5 (Link State Acknowledgment)
        msg.extend_from_slice(&[0, 0]); // Packet Length (placeholder)
        msg.extend_from_slice(&Self::parse_ipv4(router_id)?);
        msg.extend_from_slice(&Self::parse_ipv4(area_id)?);
        msg.extend_from_slice(&[0, 0]); // Checksum (placeholder)
        msg.extend_from_slice(&[0, 0]); // AuType
        msg.extend_from_slice(&[0; 8]); // Authentication

        // LSA headers being acknowledged.
        if let Some(headers) = action.get("lsa_headers").and_then(|v| v.as_array()) {
            for header in headers {
                Self::push_lsa_header(&mut msg, header)?;
            }
        }

        // Update packet length and checksum
        let packet_len = msg.len() as u16;
        msg[2..4].copy_from_slice(&packet_len.to_be_bytes());
        // Computed with its own field zeroed, so that a receiver summing the packet with the
        // checksum in place gets 0. The header lays the field down as [0, 0]; this makes that
        // a local guarantee rather than an assumption about code 30 lines up.
        msg[12..14].copy_from_slice(&[0, 0]);
        let checksum = Self::calculate_checksum(&msg);
        msg[12..14].copy_from_slice(&checksum.to_be_bytes());

        Ok(msg)
    }
}

// ============================================================================
// Action Definitions (shared between get_sync_actions() and the event types below).
//
// `call_llm` builds the model's tool list from `EventType::actions`, NOT from
// get_sync_actions(), so every event below must list the actions it accepts.
// ============================================================================

fn send_hello_action() -> ActionDefinition {
    ActionDefinition {
                name: "send_hello".to_string(),
                description: "Send OSPF Hello packet to discover/maintain neighbors".to_string(),
                parameters: vec![
                    Parameter {
                        name: "router_id".to_string(),
                        type_hint: "string".to_string(),
                        description: "OSPF router ID (IPv4 format)".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "area_id".to_string(),
                        type_hint: "string".to_string(),
                        description: "OSPF area ID (IPv4 format, 0.0.0.0 = backbone)".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "network_mask".to_string(),
                        type_hint: "string".to_string(),
                        description: "Network mask (e.g., 255.255.255.0)".to_string(),
                        required: false,
                    },
                    Parameter {
                        name: "hello_interval".to_string(),
                        type_hint: "number".to_string(),
                        description: "Hello interval in seconds (default 10)".to_string(),
                        required: false,
                    },
                    Parameter {
                        name: "router_dead_interval".to_string(),
                        type_hint: "number".to_string(),
                        description: "Router dead interval in seconds (default 40)".to_string(),
                        required: false,
                    },
                    Parameter {
                        name: "priority".to_string(),
                        type_hint: "number".to_string(),
                        description: "Router priority for DR election (0-255, default 1)".to_string(),
                        required: false,
                    },
                    Parameter {
                        name: "dr".to_string(),
                        type_hint: "string".to_string(),
                        description: "Designated Router IP (0.0.0.0 if none)".to_string(),
                        required: false,
                    },
                    Parameter {
                        name: "bdr".to_string(),
                        type_hint: "string".to_string(),
                        description: "Backup Designated Router IP (0.0.0.0 if none)".to_string(),
                        required: false,
                    },
                    Parameter {
                        name: "neighbors".to_string(),
                        type_hint: "array".to_string(),
                        description: "List of neighbor router IDs".to_string(),
                        required: false,
                    },
                    Parameter {
                        name: "destination".to_string(),
                        type_hint: "string".to_string(),
                        description: "Destination IP: 'multicast' (default, 224.0.0.5), 'dr_multicast' (224.0.0.6), or unicast IP".to_string(),
                        required: false,
                    },
                ],
                example: json!({
                    "type": "send_hello",
                    "router_id": "1.1.1.1",
                    "area_id": "0.0.0.0",
                    "priority": 1,
                    "neighbors": ["2.2.2.2"],
                    "destination": "multicast"
                }),
                log_template: Some(
                    LogTemplate::new()
                        .with_info("-> OSPF Hello router={router_id} area={area_id}")
                        .with_debug("OSPF send_hello: router_id={router_id} area={area_id} priority={priority}"),
                ),
            }
}

fn send_database_description_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_database_description".to_string(),
        description: "Send OSPF Database Description packet".to_string(),
        parameters: vec![
            Parameter {
                name: "router_id".to_string(),
                type_hint: "string".to_string(),
                description: "OSPF router ID".to_string(),
                required: true,
            },
            Parameter {
                name: "area_id".to_string(),
                type_hint: "string".to_string(),
                description: "OSPF area ID".to_string(),
                required: true,
            },
            Parameter {
                name: "sequence".to_string(),
                type_hint: "number".to_string(),
                description: "DD sequence number".to_string(),
                required: true,
            },
            Parameter {
                name: "init".to_string(),
                type_hint: "boolean".to_string(),
                description: "Init flag (true for first DD packet)".to_string(),
                required: false,
            },
            Parameter {
                name: "more".to_string(),
                type_hint: "boolean".to_string(),
                description: "More flag (true if more DD packets follow)".to_string(),
                required: false,
            },
            Parameter {
                name: "master".to_string(),
                type_hint: "boolean".to_string(),
                description: "Master flag (true if this router is master)".to_string(),
                required: false,
            },
            Parameter {
                name: "lsa_headers".to_string(),
                type_hint: "array".to_string(),
                description: "LSA headers summarising the database, each an object with \
                              lsa_type, link_state_id, advertising_router, sequence, age, \
                              options, checksum and length - the same shape the \
                              ospf_link_state_update event delivers. Omit for an empty \
                              summary."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "destination".to_string(),
                type_hint: "string".to_string(),
                description: "Destination IP: 'multicast' (default) or unicast IP".to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_database_description",
            "router_id": "1.1.1.1",
            "area_id": "0.0.0.0",
            "sequence": 1,
            "init": true,
            "master": true,
            "destination": "192.168.1.2"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> OSPF DD seq={sequence}")
                .with_debug(
                "OSPF send_database_description: router_id={router_id} seq={sequence} init={init}",
            ),
        ),
    }
}

fn send_link_state_request_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_link_state_request".to_string(),
        description: "Send OSPF Link State Request packet asking a neighbour for named LSAs"
            .to_string(),
        parameters: vec![
            Parameter {
                name: "router_id".to_string(),
                type_hint: "string".to_string(),
                description: "OSPF router ID".to_string(),
                required: true,
            },
            Parameter {
                name: "area_id".to_string(),
                type_hint: "string".to_string(),
                description: "OSPF area ID".to_string(),
                required: true,
            },
            Parameter {
                name: "requests".to_string(),
                type_hint: "array".to_string(),
                description: "LSAs to request, each an object with lsa_type (number), \
                              link_state_id and advertising_router (dotted quads). These are \
                              the fields the ospf_database_description and \
                              ospf_link_state_update events report for every LSA header. A \
                              request with no entries asks for nothing."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "destination".to_string(),
                type_hint: "string".to_string(),
                description: "Destination IP: 'multicast' (default) or unicast IP".to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_link_state_request",
            "router_id": "1.1.1.1",
            "area_id": "0.0.0.0",
            "requests": [{
                "lsa_type": 1,
                "link_state_id": "2.2.2.2",
                "advertising_router": "2.2.2.2"
            }],
            "destination": "192.168.1.2"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> OSPF LSR to {destination}")
                .with_debug(
                    "OSPF send_link_state_request: router_id={router_id} dest={destination}",
                ),
        ),
    }
}

fn send_link_state_update_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_link_state_update".to_string(),
        description: "Send OSPF Link State Update packet".to_string(),
        parameters: vec![
            Parameter {
                name: "router_id".to_string(),
                type_hint: "string".to_string(),
                description: "OSPF router ID".to_string(),
                required: true,
            },
            Parameter {
                name: "area_id".to_string(),
                type_hint: "string".to_string(),
                description: "OSPF area ID".to_string(),
                required: true,
            },
            Parameter {
                name: "destination".to_string(),
                type_hint: "string".to_string(),
                description: "Destination IP: 'multicast' (default) or unicast IP".to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_link_state_update",
            "router_id": "1.1.1.1",
            "area_id": "0.0.0.0",
            "destination": "multicast"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> OSPF LSU to {destination}")
                .with_debug(
                    "OSPF send_link_state_update: router_id={router_id} dest={destination}",
                ),
        ),
    }
}

fn send_link_state_ack_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_link_state_ack".to_string(),
        description: "Send OSPF Link State Acknowledgment for the LSAs a neighbour flooded"
            .to_string(),
        parameters: vec![
            Parameter {
                name: "router_id".to_string(),
                type_hint: "string".to_string(),
                description: "OSPF router ID".to_string(),
                required: true,
            },
            Parameter {
                name: "area_id".to_string(),
                type_hint: "string".to_string(),
                description: "OSPF area ID".to_string(),
                required: true,
            },
            Parameter {
                name: "lsa_headers".to_string(),
                type_hint: "array".to_string(),
                description: "The LSA headers being acknowledged - pass back the \
                              'lsa_headers' array exactly as the ospf_link_state_update \
                              event delivered it. An acknowledgement is matched header by \
                              header, so an empty list acknowledges nothing and the \
                              neighbour keeps retransmitting."
                    .to_string(),
                required: true,
            },
            Parameter {
                name: "destination".to_string(),
                type_hint: "string".to_string(),
                description: "Destination IP: 'multicast' (default) or unicast IP".to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_link_state_ack",
            "router_id": "1.1.1.1",
            "area_id": "0.0.0.0",
            "lsa_headers": [{
                "age": 1,
                "options": 2,
                "lsa_type": 1,
                "link_state_id": "2.2.2.2",
                "advertising_router": "2.2.2.2",
                "sequence": 2147483649_u32,
                "checksum": 65262,
                "length": 48
            }],
            "destination": "192.168.1.2"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> OSPF LSAck to {destination}")
                .with_debug("OSPF send_link_state_ack: router_id={router_id} dest={destination}"),
        ),
    }
}

fn wait_for_more_action() -> ActionDefinition {
    ActionDefinition {
        name: "wait_for_more".to_string(),
        description: "Wait for more OSPF packets before responding".to_string(),
        parameters: vec![],
        example: json!({
            "type": "wait_for_more"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> OSPF wait for more")
                .with_debug("OSPF wait_for_more"),
        ),
    }
}

// ============================================================================
// Event Types
//
// Every event advertises the actions it accepts. `call_llm` builds the model's
// tool list from `EventType::actions`; an event that leaves it empty offers the
// model nothing and trips a debug_assert. The response_example is rendered
// verbatim into the prompt, so it must be a real, executable action - never a
// `{"type": "placeholder"}` stub.
// ============================================================================

/// Actions any OSPF neighbor event can respond with.
fn ospf_response_actions() -> Vec<ActionDefinition> {
    vec![
        send_hello_action(),
        send_database_description_action(),
        send_link_state_request_action(),
        send_link_state_update_action(),
        send_link_state_ack_action(),
        wait_for_more_action(),
    ]
}

pub static OSPF_HELLO_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "ospf_hello",
        "OSPF Hello received. Answer with send_hello listing this neighbour in your own \
         neighbor list — until your Hello names it back, the neighbour stays in Init and the \
         adjacency never forms (RFC 2328 §10.5).",
        json!({
            "type": "send_hello",
            "router_id": "1.1.1.1",
            "area_id": "0.0.0.0",
            "network_mask": "255.255.255.0",
            "priority": 1,
            "dr": "0.0.0.0",
            "bdr": "0.0.0.0",
            "neighbors": ["2.2.2.2"],
            "destination": "multicast"
        }),
    )
    .with_actions(ospf_response_actions())
    .with_log_template(
        LogTemplate::new()
            .with_info("OSPF Hello from {neighbor_id}")
            .with_debug(
                "OSPF Hello: neighbor={neighbor_id} area={area_id} priority={router_priority}",
            )
            .with_trace("OSPF Hello: {json_pretty(.)}"),
    )
});

pub static OSPF_DATABASE_DESCRIPTION_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "ospf_database_description",
        "OSPF Database Description received (adjacency Exchange phase). Answer with \
         send_database_description to continue the exchange; silence leaves both routers in \
         ExStart retransmitting their DD packets.",
        json!({
            "type": "send_database_description",
            "router_id": "1.1.1.1",
            "area_id": "0.0.0.0",
            "sequence": 1,
            "init": false,
            "more": false,
            "master": false,
            "destination": "192.168.1.2"
        }),
    )
    .with_actions(ospf_response_actions())
    .with_log_template(
        LogTemplate::new()
            .with_info("OSPF DD from {neighbor_id} seq={dd_sequence}")
            .with_debug(
                "OSPF Database Description: neighbor={neighbor_id} seq={dd_sequence} \
                 init={init} more={more} master={master}",
            )
            .with_trace("OSPF DD: {json_pretty(.)}"),
    )
});

pub static OSPF_LINK_STATE_REQUEST_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "ospf_link_state_request",
        "OSPF Link State Request received: the neighbor is asking for LSAs it does not have. \
         A request left unanswered stalls the adjacency in Loading and it never reaches Full \
         (RFC 2328 §10.9). NetGet cannot build LSA bodies, so send_link_state_update carries \
         no LSAs and cannot satisfy the request — this server can hold an adjacency at 2-Way \
         but not complete one. Answer honestly rather than pretending: wait_for_more is the \
         truthful reply. Describing what you would send is not sending it.",
        json!({ "type": "wait_for_more" }),
    )
    .with_actions(ospf_response_actions())
    .with_log_template(
        LogTemplate::new()
            .with_info("OSPF LSR from {neighbor_id} ({request_count} LSAs)")
            .with_debug("OSPF Link State Request: neighbor={neighbor_id} requests={request_count}")
            .with_trace("OSPF LSR: {json_pretty(.)}"),
    )
});

pub static OSPF_LINK_STATE_UPDATE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "ospf_link_state_update",
        "OSPF Link State Update received: the neighbor is flooding LSAs. Answer with \
         send_link_state_ack, passing this event's 'lsa_headers' array straight back as the \
         action's 'lsa_headers' — every LSA must be acknowledged by header or the neighbor \
         retransmits it every RxmtInterval until the adjacency fails (RFC 2328 §13.5), and an \
         acknowledgement with no headers acknowledges nothing. Describing the acknowledgement \
         is not sending it: only the action puts a packet on the wire.",
        json!({
            "type": "send_link_state_ack",
            "router_id": "1.1.1.1",
            "area_id": "0.0.0.0",
            "lsa_headers": [{
                "age": 1,
                "options": 2,
                "lsa_type": 1,
                "link_state_id": "2.2.2.2",
                "advertising_router": "2.2.2.2",
                "sequence": 2147483649_u32,
                "checksum": 65262,
                "length": 48
            }],
            "destination": "192.168.1.2"
        }),
    )
    .with_actions(ospf_response_actions())
    .with_log_template(
        LogTemplate::new()
            .with_info("OSPF LSU from {neighbor_id} ({lsa_count} LSAs)")
            .with_debug("OSPF Link State Update: neighbor={neighbor_id} lsas={lsa_count}")
            .with_trace("OSPF LSU: {json_pretty(.)}"),
    )
});

pub static OSPF_LINK_STATE_ACK_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "ospf_link_state_ack",
        "OSPF Link State Acknowledgment packet received",
        json!({ "type": "wait_for_more" }),
    )
    .with_actions(ospf_response_actions())
    .with_log_template(
        LogTemplate::new()
            .with_info("OSPF LSAck from {neighbor_id} ({lsa_count} LSAs)")
            .with_debug("OSPF Link State Acknowledgment: neighbor={neighbor_id} lsas={lsa_count}")
            .with_trace("OSPF LSAck: {json_pretty(.)}"),
    )
});

// Implement Protocol trait (common functionality)
impl Protocol for OspfProtocol {
    /// Deliberately empty.
    ///
    /// This used to advertise `list_neighbors` and `list_lsdb`, and `execute_action` had no arm
    /// for either — so the model was offered two verbs and rejected with "Unknown OSPF action
    /// type" whenever it chose one. They are removed rather than implemented because neither
    /// can be answered honestly: NetGet keeps no neighbour table and no link-state database,
    /// and the project rule is that protocols do not implement storage — the model tracks that
    /// state in its own memory, where it already has everything these would report.
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            send_hello_action(),
            send_database_description_action(),
            send_link_state_request_action(),
            send_link_state_update_action(),
            send_link_state_ack_action(),
            wait_for_more_action(),
        ]
    }

    fn protocol_name(&self) -> &'static str {
        "OSPF"
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            OSPF_HELLO_EVENT.clone(),
            OSPF_DATABASE_DESCRIPTION_EVENT.clone(),
            OSPF_LINK_STATE_REQUEST_EVENT.clone(),
            OSPF_LINK_STATE_UPDATE_EVENT.clone(),
            OSPF_LINK_STATE_ACK_EVENT.clone(),
        ]
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP(89)>OSPF"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["ospf", "open shortest path first"]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{
            DevelopmentState, PrivilegeRequirement, ProtocolMetadataV2,
        };

        ProtocolMetadataV2::builder()
                .state(DevelopmentState::Experimental)
                // Deliberately silent: An OSPF Hello or LSA asserts adjacency and link state;
                // there is no error packet in the protocol.
                .deliberately_silent()
                // Raw socket on IP protocol 89 - CAP_NET_RAW is sufficient, full root is not
                // required, so declaring Root would refuse to start on a capability-only process.
                .privilege_requirement(PrivilegeRequirement::RawSockets)
                // OSPF has no connection to close: a neighbour entry is created on first sight
                // of a Router ID and nothing on the wire ever ends it, which is exactly what
                // AppState's idle sweep exists for. Without this the entries accumulated for
                // the life of the server.
                .connectionless()
                .implementation("Manual OSPFv2 (RFC 2328) over a raw IP-protocol-89 socket. Hello is parsed in full; DD/LSR/LSU/LSAck are parsed to their 20-byte LSA headers, never to LSA bodies. Outgoing DD, LSR and LSAck carry real bodies built from the model's structured fields (LSA headers per RFC 2328 A.4.1, request triples per A.3.4); outgoing LSU always advertises zero LSAs because NetGet cannot construct an LSA body.")
                .llm_control("Optional: whether to engage with an OSPF speaker (respond to a Hello, claim DR/BDR, act as a honeypot) is a policy decision. With no operator policy (no instruction, no handler) the server observes passively and does NOT respond, with no LLM round-trip per packet. When the operator opts in, every received packet type raises an event carrying parsed fields and the LLM chooses the reply packet. The model can acknowledge LSAs and request them by name - the LSA headers an event reports are the same shape send_link_state_ack and send_link_state_request consume - but it cannot supply LSA contents, so a Link State Request from a peer cannot be satisfied. Fields the reply omits are filled from the interface configuration given at startup (router_id, area_id, network_mask, hello_interval, router_dead_interval, router_priority).")
                .e2e_testing("None against a real router, and none against this server at all: OSPF needs a raw IP-89 socket, so spawn_with_llm_actions cannot run unprivileged and no test drives it. The three tests in tests/server/ospf/e2e_test.rs named 'E2E' start a *generic UDP server* (open_server protocol=UDP) and exchange OSPF-shaped bytes the test itself built over it, mocking udp_datagram_received/send_udp_response - they exercise src/server/udp/, not this protocol, and no test anywhere mocks an ospf_* event. What IS verified, as unit tests against the real code: the RFC 2328 A.3.1 packet checksum (recomputing over a built packet yields zero), that build_hello_packet writes the configured hello_interval, router_dead_interval, priority and network mask into the Hello body at RFC 2328 A.3.2 offsets when the action omits them and that an action-supplied value overrides them, that LSAck and LSR bodies serialise at the A.4.1/A.3.4 offsets and round-trip through parse_lsa_headers, that a malformed IPv4 field is rejected rather than silently becoming 0.0.0.0, and that the RFC 2328 10.5 mismatch check fires on exactly the three fields the RFC names.")
                .notes("Hello-level simulator, not a router. Whether to respond at all is policy, so with no operator policy the server is a passive listener (no response, no LLM call); the passive default is compile-verified since the raw-socket path needs root and no test touches it. No LSDB, no SPF, no routing table, no LSA body construction, no DR/BDR election and no periodic Hello timer. Adjacency cannot progress past 2-Way, and a Hello that fails the RFC 2328 10.5 interval/mask check does not advance it at all - the event still reaches the model, carrying the mismatch, so the refusal is visible rather than silent. Neighbours ARE aged out: one silent for RouterDeadInterval is dropped, which also bounds the neighbour table against a peer spraying Hellos with random Router IDs. On an LLM failure the server deliberately sends nothing: OSPF has no error or NAK packet, and every one of its five packet types is a positive routing assertion, so any fabricated reply would claim an adjacency, DR role or database state netget cannot back - the peer's own RouterDeadInterval covers a router that goes quiet. The failure is reported to the operator only, tagged decision=fail_closed_overloaded / fail_closed_unavailable and distinct from decision=model_wait / model_no_action.")
                .history(crate::protocol::metadata::HistoryMode::Off)
                .batching(crate::protocol::metadata::BatchingMode::Unsupported)
                .build()
    }
    fn description(&self) -> &'static str {
        "OSPF routing protocol server"
    }
    fn example_prompt(&self) -> &'static str {
        "Start an OSPF server on interface 192.168.1.100 as router 1.1.1.1 in area 0.0.0.0"
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        // All six are read in ProtocolConfig terms by OspfServer::spawn_with_llm_actions into
        // an OspfInterfaceConfig, which supplies the defaults for every outgoing packet and
        // the RFC 2328 10.5 acceptance check for every incoming Hello. Four of them used to
        // be declared here and read nowhere.
        vec![
            ParameterDefinition {
                name: "router_id".to_string(),
                type_hint: "string".to_string(),
                description: "OSPF router ID in IPv4 address format (e.g., 1.1.1.1). Used as the Router ID of every packet sent unless the action overrides it. Defaults to the interface address.".to_string(),
                required: false,
                example: json!("1.1.1.1"),
                default: None,
            },
            ParameterDefinition {
                name: "area_id".to_string(),
                type_hint: "string".to_string(),
                description: "OSPF area ID in IPv4 format (0.0.0.0 = backbone area). Used as the Area ID of every packet sent unless the action overrides it.".to_string(),
                required: false,
                example: json!("0.0.0.0"),
                default: None,
            },
            ParameterDefinition {
                name: "network_mask".to_string(),
                type_hint: "string".to_string(),
                description: "Network mask of this interface (e.g., 255.255.255.0). Placed in outgoing Hello packets, and compared against incoming ones: RFC 2328 10.5 requires a Hello whose mask differs to be rejected.".to_string(),
                required: false,
                example: json!("255.255.255.0"),
                default: None,
            },
            ParameterDefinition {
                name: "hello_interval".to_string(),
                type_hint: "integer".to_string(),
                description: "HelloInterval in seconds (default 10). Placed in outgoing Hello packets. A neighbour whose Hello advertises a different value is rejected per RFC 2328 10.5 and its adjacency is not advanced.".to_string(),
                required: false,
                example: json!(10),
                default: None,
            },
            ParameterDefinition {
                name: "router_dead_interval".to_string(),
                type_hint: "integer".to_string(),
                description: "RouterDeadInterval in seconds (default 40). Placed in outgoing Hello packets and, like hello_interval, must match a neighbour's for its Hello to be accepted.".to_string(),
                required: false,
                example: json!(40),
                default: None,
            },
            ParameterDefinition {
                name: "router_priority".to_string(),
                type_hint: "integer".to_string(),
                description: "Router priority for DR election (0-255, default 1). Placed in outgoing Hello packets unless the send_hello action sets its own 'priority'. No election algorithm runs - the value is advertised, nothing more.".to_string(),
                required: false,
                example: json!(1),
                default: None,
            },
        ]
    }
    fn group_name(&self) -> &'static str {
        "VPN & Routing"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;

        StartupExamples::new(
            // LLM mode: LLM simulates OSPF router behavior
            json!({
                "type": "open_server",
                "port": 0,
                "base_stack": "ospf",
                "instruction": "OSPF router with ID 192.168.1.1 in area 0. Respond to Hello packets from neighbors. Claim DR role with priority 100."
            }),
            // Script mode: Scripted OSPF Hello response
            json!({
                "type": "open_server",
                "port": 0,
                "base_stack": "ospf",
                "event_handlers": [{
                    "event_pattern": "ospf_hello",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "return {type='send_hello', router_id='192.168.1.1', area_id='0.0.0.0', network_mask='255.255.255.0', priority=100, dr='192.168.1.1', bdr='0.0.0.0', neighbors={event.neighbor_id}}"
                    }
                }]
            }),
            // Static mode: Fixed OSPF Hello response
            json!({
                "type": "open_server",
                "port": 0,
                "base_stack": "ospf",
                "event_handlers": [{
                    "event_pattern": "ospf_hello",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "send_hello",
                            "router_id": "192.168.1.1",
                            "area_id": "0.0.0.0",
                            "network_mask": "255.255.255.0",
                            "priority": 1,
                            "dr": "0.0.0.0",
                            "bdr": "0.0.0.0"
                        }]
                    }
                }]
            }),
        )
    }
}

// Implement Server trait (server-specific functionality)
impl Server for OspfProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::server::ospf::OspfServer;
            OspfServer::spawn_with_llm_actions(
                ctx.legacy_listen_addr(),
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.server_id,
                ctx.startup_params,
            )
            .await
        })
    }
    fn execute_action(&self, action: serde_json::Value) -> Result<ActionResult> {
        let action_type = action
            .get("type")
            .and_then(|v| v.as_str())
            .context("Missing action type")?;

        match action_type {
            "send_hello" => self.execute_send_hello(action),
            "send_database_description" => self.execute_send_database_description(action),
            "send_link_state_request" => self.execute_send_link_state_request(action),
            "send_link_state_update" => self.execute_send_link_state_update(action),
            "send_link_state_ack" => self.execute_send_link_state_ack(action),
            "wait_for_more" => Ok(ActionResult::WaitForMore),
            _ => Err(anyhow::anyhow!("Unknown OSPF action type: {}", action_type)),
        }
    }
}
