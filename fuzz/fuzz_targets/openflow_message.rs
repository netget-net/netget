//! `netget::server::openflow` — the OpenFlow 1.3 message codec both roles share, and the packet
//! describer that turns a PACKET_IN's bytes into headers for the model.
//!
//! The input is read as the body of every message type the controller or the switch decodes.
//! Whatever decodes is encoded again and must decode to the same value (a message carrying an
//! experimenter action or instruction is kept for reporting but not re-encoded, so those are
//! skipped). Nothing in the codec recurses; the corpus still carries the inputs that make the
//! walks long — a stack of VLAN tags and a chain of IPv6 extension headers (`vlan_bomb`,
//! `ipv6_ext_chain`) — which `packet::describe` must stop at its bounds.

#![no_main]

use libfuzzer_sys::fuzz_target;
use netget::server::openflow::{fields, packet, wire};

fn plain(instructions: &[wire::Instruction]) -> bool {
    instructions.iter().all(|i| match i {
        wire::Instruction::Other { .. } => false,
        wire::Instruction::ApplyActions(a) | wire::Instruction::WriteActions(a) => {
            a.iter().all(|x| !matches!(x, wire::Action::Other { .. }))
        }
        _ => true,
    })
}

fuzz_target!(|data: &[u8]| {
    if let Ok(fm) = wire::FlowMod::parse(data) {
        let _ = fields::match_to_json(&fm.matched);
        let _ = fields::instructions_to_json(&fm.instructions);
        let _ = fields::check_prerequisites(&fm.matched);
        if plain(&fm.instructions) {
            let again = wire::FlowMod::parse(&fm.encode()).expect("re-encoded FLOW_MOD parses");
            assert_eq!(again, fm, "encode then parse changed the FLOW_MOD");
        }
    }
    if let Ok(pi) = wire::PacketIn::parse(data) {
        let _ = packet::describe(&pi.data);
        let again = wire::PacketIn::parse(&pi.encode()).expect("re-encoded PACKET_IN parses");
        assert_eq!(again, pi, "encode then parse changed the PACKET_IN");
    }
    if let Ok(po) = wire::PacketOut::parse(data) {
        if po
            .actions
            .iter()
            .all(|x| !matches!(x, wire::Action::Other { .. }))
        {
            let again = wire::PacketOut::parse(&po.encode()).expect("re-encoded PACKET_OUT parses");
            assert_eq!(again, po, "encode then parse changed the PACKET_OUT");
        }
    }
    if let Ok(fr) = wire::FlowRemoved::parse(data) {
        let again = wire::FlowRemoved::parse(&fr.encode()).expect("re-encoded FLOW_REMOVED parses");
        assert_eq!(again, fr, "encode then parse changed the FLOW_REMOVED");
    }
    let _ = wire::ErrorMsg::parse(data);
    let _ = wire::Features::parse(data);
    let _ = wire::parse_hello_bitmap(data);
    let _ = wire::parse_port_status(data);
    let _ = wire::parse_ports(data);
    let _ = wire::parse_desc(data);
    let _ = wire::FlowStats::parse_all(data);
    let _ = wire::TableStats::parse_all(data);
    let _ = wire::PortStats::parse_all(data);
    let _ = wire::FlowStatsRequest::parse(data);
    if let Ok((_, _, body)) = wire::parse_multipart(data) {
        let _ = wire::FlowStats::parse_all(body);
    }
    let _ = packet::describe(data);
});
