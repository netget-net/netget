//! `netget::server::zigbee` — everything the co-processor runs on what a host sends: the ASH
//! deframer and frame decoder, the NCP's side of the link (frame numbers, NAKs, the window),
//! the EZSP header and every command's parameter reader in `ncp::handle`, and the simulated
//! device's ZDO and ZCL decoders.
//!
//! What is checked: the deframer never holds more than one maximal frame, every decoded DATA
//! frame's EZSP payload is within ASH's bound, no response or callback exceeds what one DATA
//! frame carries, and nothing panics on any byte sequence. None of these decoders recurses;
//! the corpus still carries the shapes that defeat a byte bound (`escape_run`, a megabyte of
//! escapes without a flag, and `deep_attributes`, a Write Attributes frame of nested-looking
//! string lengths) so a future recursive decoder meets them on its first run.

#![no_main]

use libfuzzer_sys::fuzz_target;
use netget::server::zigbee::{ash, device, ezsp, ncp};
use serde_json::json;

fuzz_target!(|data: &[u8]| {
    // The wire, as a host would send it, through the deframer and the link.
    let mut d = ash::Deframer::new();
    let mut units = Vec::new();
    d.push(data, &mut units);
    assert!(d.held() <= ash::MAX_FRAME);
    let mut link = ash::Link::new();
    let now = std::time::Instant::now();
    let mut ram = ncp::Ram::new();
    let mut nv = nvram();
    let mut out = ash::Output::default();
    let mut rst = ash::Output::default();
    let mut deframer = ash::Deframer::new();
    let mut rst_units = Vec::new();
    deframer.push(&ash::rst_frame(), &mut rst_units);
    for u in rst_units {
        link.receive(u, now, &mut rst);
    }
    for u in units {
        if let ash::Deframed::Frame(raw) = &u {
            if let Ok(ash::Frame::Data { ezsp, .. }) = ash::Frame::parse(raw) {
                assert!(ezsp.len() <= ash::MAX_DATA);
            }
        }
        link.receive(u, now, &mut out);
    }
    for frame in std::mem::take(&mut out.delivered) {
        command(&mut ram, &mut nv, &frame);
    }
    link.timeout(now + std::time::Duration::from_secs(10), &mut out);

    // The bytes as one EZSP frame, before and after a version is negotiated.
    command(&mut ram, &mut nv, data);
    ram.version = Some(ezsp::DEFAULT_VERSION);
    ram.up = true;
    command(&mut ram, &mut nv, data);

    // The bytes as a ZDO request and a ZCL frame to a described device.
    let dev = lamp();
    if let Some(first) = data.first() {
        let cluster = u16::from(*first)
            | if data.len() > 1 {
                u16::from(data[1] & 0x7F) << 8
            } else {
                0
            };
        let rest = data.get(2..).unwrap_or(&[]);
        if let Some(r) = device::zdo(&dev, cluster, rest, false) {
            assert!(r.payload.len() <= device::MAX_APS_PAYLOAD + 32);
        }
        let _ = device::zdo(&dev, cluster, rest, true);
        if let device::ZclOutcome::Reply(r) = device::zcl(&dev, 1, cluster, rest) {
            assert!(r.len() <= device::MAX_APS_PAYLOAD);
        }
    }
    let _ = device::zcl(&dev, 1, 0x0006, data);
    let _ = device::zcl(&dev, 1, 0x0000, data);
});

fn command(ram: &mut ncp::Ram, nv: &mut ncp::Nvram, frame: &[u8]) {
    if let Ok(cmd) = ezsp::parse_command(frame) {
        let h = ncp::handle(ezsp::DEFAULT_VERSION, ram, nv, &cmd);
        assert!(h.response.len() <= ash::MAX_DATA);
        for cb in &h.callbacks {
            assert!(cb.params.len() + 5 <= ash::MAX_DATA);
        }
    }
}

fn nvram() -> ncp::Nvram {
    ncp::Nvram {
        eui64: ncp::DEFAULT_EUI64,
        network: None,
        nwk_frame_counter: 0,
        aps_frame_counter: 0,
        joined: vec![lamp()],
        waiting: Vec::new(),
        link_keys: Vec::new(),
    }
}

fn lamp() -> device::Device {
    device::parse_device(
        &json!({"name": "lamp", "ieee": "00:12:4b:00:01:02:03:04", "nwk": "0x1234",
                "manufacturer": "NetGet", "model": "Lamp-1",
                "endpoints": [{"id": 1, "in_clusters": ["basic", "on_off", "level_control"], "out_clusters": ["ota"],
                               "attributes": [{"cluster": "on_off", "attribute": 0, "type": "bool", "value": true},
                                              {"cluster": "level_control", "attribute": 0, "type": "uint8", "value": 9}]}]}),
        &[],
    )
    .expect("the fuzz device parses")
}
