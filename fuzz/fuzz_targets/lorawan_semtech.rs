//! `netget::server::lorawan` — every decoder the network server and the gateway client run on
//! what a peer sends: the Semtech UDP packet-forwarder datagram (header, gateway EUI, the
//! rxpk/stat/txpk/txpk_ack JSON), the base64 PHYPayload inside it, and the LoRaWAN MAC layer
//! (Join Request, Join Accept decryption and MIC, data frames, FOpts and FPort-0 MAC commands).
//!
//! What parses is checked to stay within the declared bounds: a datagram ≤ MAX_DATAGRAM, at
//! most MAX_RXPK frames, frame data ≤ a 255-byte PHYPayload. The JSON is scanned for depth
//! iteratively before serde sees it, so the corpus carries a depth bomb (`depth_bomb`, 4 000
//! nested arrays inside a PUSH_DATA) that must be refused rather than walked.

#![no_main]

use libfuzzer_sys::fuzz_target;
use netget::server::lorawan::{mac, semtech};

const KEY: mac::Key = [0x2b; 16];

fuzz_target!(|data: &[u8]| {
    if let Ok(p) = semtech::parse(data) {
        assert!(data.len() <= semtech::MAX_DATAGRAM);
        match p {
            semtech::Packet::PushData { rxpk, .. } => {
                assert!(rxpk.len() <= semtech::MAX_RXPK);
                for r in rxpk {
                    let _ = semtech::lora_data_rate(&r.modu, &r.datr);
                    if let Ok(phy) = semtech::b64_decode(&r.data) {
                        assert!(phy.len() <= mac::MAX_PHY_PAYLOAD);
                        phy_layer(&phy);
                    }
                }
            }
            semtech::Packet::PullResp { txpk, .. } => {
                if let Ok(phy) = semtech::b64_decode(&txpk.data) {
                    phy_layer(&phy);
                }
            }
            _ => {}
        }
    }
    phy_layer(data);
    let _ = mac::decode_mac_commands(data, true);
    let _ = mac::decode_mac_commands(data, false);
});

fn phy_layer(phy: &[u8]) {
    let _ = mac::mtype_of(phy);
    if let Ok(jr) = mac::parse_join_request(phy) {
        let _ = mac::join_request_mic_ok(phy, &KEY);
        let _ = jr.dev_nonce;
    }
    let _ = mac::decode_join_accept(phy, &KEY);
    if let Ok(f) = mac::parse_data(phy) {
        assert!(f.f_opts.len() <= mac::MAX_FOPTS);
        for wire in [0u16, f.f_cnt] {
            let full = mac::full_fcnt(Some(wire as u32), f.f_cnt);
            let _ = mac::data_mic_ok(phy, &KEY, mac::DIR_UP, f.dev_addr, full);
            let _ = mac::crypt_frm(&KEY, mac::DIR_DOWN, f.dev_addr, full, &f.frm_payload);
        }
        let _ = mac::decode_mac_commands(&f.f_opts, f.uplink());
    }
}
