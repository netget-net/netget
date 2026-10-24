//! `netget::server::zigbee` in its Z-Stack dialect — everything the co-processor runs on what a
//! host sends it: the MT deframer and frame decoder, and the firmware's answer to every frame
//! (`znp::handle`: the NV memory, the ZDO and AF request readers, BDB formation, reset) and the
//! indications it raises for the network (`znp::up_frames`).
//!
//! What is checked, each a promise the code makes: the deframer never holds more than one
//! maximal frame and never yields a frame with more than `MAX_DATA` bytes; an SREQ gets exactly
//! one SRSP and nothing else gets any; no SRSP or indication carries more than one MT frame can
//! (so `Frame::encode` never has to cut one); the NV memory never holds more items, or a longer
//! item, than its bounds. The corpus carries `length_bomb` (SOF then 0xFF, then a megabyte of
//! SOFs) and `nv_write_past_end`, the shapes that defeat a byte bound and an offset check.

#![no_main]

use libfuzzer_sys::fuzz_target;
use netget::server::zigbee::mt::{self, Deframed, Frame};
use netget::server::zigbee::network::Up;
use netget::server::zigbee::{device, ezsp, ncp, znp};
use serde_json::json;

fuzz_target!(|data: &[u8]| {
    let mut nv = nvram();
    let mut flash = znp::Flash::initial(&nv);
    let mut ram = znp::Ram::new();
    ram.state = znp::state::COORDINATOR;

    // The wire, as a host would send it.
    let mut d = mt::Deframer::new();
    let mut units = Vec::new();
    for chunk in data.chunks(97) {
        d.push(chunk, &mut units);
        assert!(d.held() <= mt::MAX_FRAME);
    }
    for u in units {
        if let Deframed::Frame(f) = u {
            assert!(f.data.len() <= mt::MAX_DATA);
            answer(&mut ram, &mut flash, &mut nv, &f);
        }
    }

    // The bytes as one command's data, for the subsystem and command the first two name.
    if data.len() >= 2 {
        let body = data[2..data.len().min(2 + mt::MAX_DATA)].to_vec();
        for k in [mt::kind::SREQ, mt::kind::AREQ] {
            let f = Frame::new(k, data[0] & 0x1F, data[1], body.clone());
            answer(&mut ram, &mut flash, &mut nv, &f);
        }
    }

    // The bytes as a frame from the network, through the indications the firmware raises.
    for profile in [device::PROFILE_ZDO, device::PROFILE_HA] {
        let up = Up::Incoming {
            broadcast: data.first().is_some_and(|b| b & 1 == 1),
            aps: ezsp::ApsFrame {
                profile_id: profile,
                cluster_id: data
                    .get(..2)
                    .map(|b| u16::from_le_bytes([b[0], b[1]]))
                    .unwrap_or(0),
                ..Default::default()
            },
            nwk: 0x4a21,
            ieee: 0x0012_4b00_0102_0304,
            payload: data[..data.len().min(device::MAX_APS_PAYLOAD)].to_vec(),
        };
        for f in znp::up_frames(&mut ram, &up) {
            assert!(
                f.data.len() <= mt::MAX_DATA,
                "an indication over one frame: {f:?}"
            );
        }
    }
});

fn answer(ram: &mut znp::Ram, flash: &mut znp::Flash, nv: &mut ncp::Nvram, f: &Frame) {
    let h = znp::handle(ram, flash, nv, f);
    assert_eq!(
        h.response.is_some(),
        f.kind == mt::kind::SREQ,
        "one SRSP for an SREQ, none for anything else"
    );
    if let Some(r) = &h.response {
        assert_eq!(r.kind, mt::kind::SRSP);
        assert!(
            r.data.len() <= mt::MAX_DATA,
            "an SRSP over one frame: {r:?}"
        );
    }
    for a in &h.areqs {
        assert_eq!(a.kind, mt::kind::AREQ);
        assert!(
            a.data.len() <= mt::MAX_DATA,
            "an indication over one frame: {a:?}"
        );
    }
    assert!(flash.osal.len() + flash.ex.len() <= znp::MAX_NV_ITEMS + 32);
    assert!(flash
        .osal
        .values()
        .chain(flash.ex.values())
        .all(|v| v.len() <= znp::MAX_NV_ITEM_LEN));
}

fn nvram() -> ncp::Nvram {
    ncp::Nvram {
        eui64: znp::DEFAULT_EUI64,
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
        &json!({"name": "lamp", "ieee": "00:12:4b:00:01:02:03:04", "nwk": "0x4a21",
                "manufacturer": "NetGet", "model": "Lamp-1",
                "endpoints": [{"id": 1, "in_clusters": ["basic", "on_off"], "out_clusters": ["ota"],
                               "attributes": [{"cluster": "on_off", "attribute": 0, "type": "bool", "value": true}]}]}),
        &[],
    )
    .expect("the fuzz device parses")
}
