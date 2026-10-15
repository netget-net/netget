//! Shared pieces for the SS7 (SCCP / TCAP / MAP / CAP) suites: messages Restcomm jSS7 8.0.112
//! put on the wire, a capture writer, and tshark's reading of what NetGet sends.
#![allow(dead_code)]

use netget::server::m3ua::codec::{self, ProtocolData};

/// SCCP user parts (the Protocol Data payload of M3UA DATA) captured from jSS7 8.0.112 over SCTP:
/// its MAP/CAP client (OPC 1, SSN 8 / 146, GT 31600000100) talking to its own server (OPC 2,
/// SSN 6 / 146, GT 31600000200), recorded with dumpcap and cut out with tshark. They are a third
/// party's encoding, byte for byte; nothing here came from NetGet.
pub mod jss7 {
    /// TC-BEGIN sendRoutingInfoForSM (shortMsgGatewayContext v3): msisdn 31628838002, sm-RP-PRI
    /// true, service centre 31611111111; otid 00000001.
    pub const SRI_SM_BEGIN: &str = "090103101d0d530200060011041306000002000d530100080011041306000001004962474804000000016b1e281c060700118605010101a011600f80020780a1090607040000010014036c1fa11d02010002012d30158007911326888300f28101ff8207911316111111f1";
    /// jSS7's own answer to it: imsi 001010123456789, networkNode-Number 31600000001.
    pub const SRI_SM_END: &str = "090103101d0d530100080011041306000001000d530200060011041306000002005764554904000000016b2a2828060700118605010101a01d611b80020780a109060704000001001403a203020100a305a1030201006c21a21f020100301a02012d3015040800010121436587f9a0098107911306000000f1";
    /// TC-BEGIN anyTimeInterrogation (anyTimeEnquiryContext v3) for msisdn 31628838002, asking
    /// location information and subscriber state, gsmSCF 31699999999; otid 00000002.
    pub const ATI_BEGIN: &str = "090103101d0d530200060011041306000002000d530100080011041306000001004e624c4804000000026b1e281c060700118605010101a011600f80020780a109060704000001001d036c24a122020100020147301aa0098107911326888300f2a104800081008307911396999999f9";
    /// Its answer: assumedIdle, VLR 31600000002, age 5, CGI 001-01 LAC 0x1234 CI 0x5678.
    pub const ATI_END: &str = "090103101d0d530100080011041306000001000d5302000600110413060000020061645f4904000000026b2a2828060700118605010101a01d611b80020780a109060704000001001d03a203020100a305a1030201006c2ba2290201003024020147301f301da0170201058107911306000000f2a309800700f11012345678a1028000";
    /// TC-BEGIN processUnstructuredSS-Request (networkUnstructuredSsContext v2) "*100#" with
    /// MAP-OpenInfo (destination reference 31628838002, origination 31600000100); otid 00000003.
    pub const USSD_BEGIN: &str = "090103101d0d530200060011041306000002000d530100080011041306000001006a62684804000000036b41283f060700118605010101a034603280020780a109060704000001001302be21281f060704000001010101a014a0128007911326888300f28107911306000001f06c1da11b02010002013b301304010f0405aa180c36028007911326888300f2";
    /// Its answer: "You sent *100#".
    pub const USSD_END: &str = "090103101d0d530100080011041306000001000d530200060011041306000002005464524904000000036b2a2828060700118605010101a01d611b80020780a109060704000001001302a203020100a305a1030201006c1ea21c020100301702013b301204010f040dd9771d342fbbe920550c061b01";
    /// TC-BEGIN mo-forwardSM (shortMsgMORelayContext v3): DA service centre 31611111111, OA msisdn
    /// 31628838002, an SMS-SUBMIT to 31622222222 "Hello from jSS7"; otid 00000004.
    pub const MO_FSM_BEGIN: &str = "090103101d0d530200060011041306000002000d530100080011041306000001006462624804000000046b1e281c060700118605010101a011600f80020780a1090607040000010015036c3aa13802010002012e30308407911316111111f18207911326888300f2041c11010b911326222222f20000a70fc8329bfd0699e5ef36483d9dde00";
    /// Its answer: an empty ReturnResultLast.
    pub const MO_FSM_END: &str = "090103101d0d530100080011041306000001000d530200060011041306000002003b64394904000000046b2a2828060700118605010101a01d611b80020780a109060704000001001503a203020100a305a1030201006c05a203020100";
    /// TC-BEGIN mt-forwardSM (shortMsgMTRelayContext v3): DA imsi 001010123456789, OA service
    /// centre 31611111111, an SMS-DELIVER from 31633333333 "Hello from jSS7"; otid 00000005.
    pub const MT_FSM_BEGIN: &str = "090103101d0d530200060011041306000002000d530100080011041306000001006a62684804000000056b1e281c060700118605010101a011600f80020780a1090607040000010019036c40a13e02010002012c3036800800010121436587f98407911316111111f10421040b911336333333f30000620151210000000fc8329bfd0699e5ef36483d9dde00";
    pub const MT_FSM_END: &str = "090103101d0d530100080011041306000001000d530200060011041306000002003b64394904000000056b2a2828060700118605010101a01d611b80020780a109060704000001001903a203020100a305a1030201006c05a203020100";
    /// TC-BEGIN CAP v2 initialDP: service key 100, called 31644444444, calling 31655555555,
    /// collectedInfo, IMSI 001010123456789, MSC 31600000003; SSN 146 both ends; otid 00000001.
    pub const IDP_BEGIN: &str = "090103101d0d530200920011041306000002000d530100920011041306000001006362614804000000016b1e281c060700118605010101a011600f80020780a1090607040000010032016c39a137020100020100302f80016482088410134644444404830884131356555555059c01029f320800010121436587f99f3707911306000000f3";
    /// jSS7's gsmSCF answering it: TC-CONTINUE with requestReportBCSMEvent (oAnswer
    /// notifyAndContinue, oDisconnect interrupted, both leg 2) and continue.
    pub const IDP_CONTINUE: &str = "090103101d0d530100920011041306000001000d530200920011041306000002006a65684804000000014904000000016b2a2828060700118605010101a01d611b80020780a109060704000001003201a203020100a305a1030201006c2ea124020100020117301ca01a300b800107810101a203800102300b800109810100a203800102a10602010102011f";
    /// The gsmSSF's eventReportBCSM oAnswer (notification), TC-CONTINUE otid 00000001 dtid
    /// 00000001 — the dtid is the gsmSCF's transaction and is rewritten by the tests.
    pub const ERB_ANSWER: &str = "090103101d0d530200920011041306000002000d530100920011041306000001002765254804000000014904000000016c17a115020101020118300d800107a303810102a403800101";
    /// eventReportBCSM oDisconnect (request: the gsmSSF waits for an instruction).
    pub const ERB_DISCONNECT: &str = "090103101d0d530200920011041306000002000d530100920011041306000001002f652d4804000000014904000000016c1fa11d0201020201183015800109a206a70480028090a303810102a403800100";
}

pub fn unhex(s: &str) -> Vec<u8> {
    let clean: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    hex::decode(clean).expect("test vector is hex")
}

/// The Protocol Data jSS7's client put each of these in: OPC 1 → DPC 2, SI 3, NI 2.
pub fn from_jss7(sccp_hex: &str, sls: u8) -> ProtocolData {
    ProtocolData {
        opc: 1,
        dpc: 2,
        si: 3,
        ni: 2,
        mp: 0,
        sls,
        payload: unhex(sccp_hex),
    }
}

/// Replace the destination transaction id in a captured TCAP message (tag 49 04 ...).
pub fn with_dtid(sccp_hex: &str, dtid: u32) -> String {
    let needle = "490400000001";
    assert!(sccp_hex.contains(needle), "vector has no dtid 00000001");
    sccp_hex.replacen(needle, &format!("4904{dtid:08x}"), 1)
}

/// CRC-32C (Castagnoli), as SCTP's checksum (RFC 4960 appendix B), computed here so the
/// checksum is not the code under test's.
pub fn crc32c(data: &[u8]) -> u32 {
    let mut crc: u32 = !0;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0x82F6_3B78
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

/// One IPv4 packet carrying one SCTP DATA chunk with PPID 3 (M3UA).
pub fn ip_sctp_m3ua(src: u16, dst: u16, tsn: u32, stream: u16, m3ua: &[u8]) -> Vec<u8> {
    let mut chunk = vec![0x00, 0x03];
    chunk.extend_from_slice(&((16 + m3ua.len()) as u16).to_be_bytes());
    chunk.extend_from_slice(&tsn.to_be_bytes());
    chunk.extend_from_slice(&stream.to_be_bytes());
    chunk.extend_from_slice(&(tsn as u16).to_be_bytes());
    chunk.extend_from_slice(&3u32.to_be_bytes());
    chunk.extend_from_slice(m3ua);
    while chunk.len() % 4 != 0 {
        chunk.push(0);
    }
    let mut sctp = Vec::new();
    sctp.extend_from_slice(&src.to_be_bytes());
    sctp.extend_from_slice(&dst.to_be_bytes());
    sctp.extend_from_slice(&0x1234_5678u32.to_be_bytes());
    sctp.extend_from_slice(&[0, 0, 0, 0]);
    sctp.extend_from_slice(&chunk);
    let crc = crc32c(&sctp);
    sctp[8..12].copy_from_slice(&crc.to_le_bytes());
    let total = 20 + sctp.len();
    let mut ip = vec![
        0x45,
        0,
        (total >> 8) as u8,
        total as u8,
        0,
        1,
        0x40,
        0,
        64,
        132,
        0,
        0,
        127,
        0,
        0,
        1,
        127,
        0,
        0,
        2,
    ];
    let mut sum: u32 = 0;
    for c in ip.chunks(2) {
        sum += u16::from_be_bytes([c[0], c[1]]) as u32;
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let check = !(sum as u16);
    ip[10..12].copy_from_slice(&check.to_be_bytes());
    ip.extend(sctp);
    ip
}

/// Write `packets` (raw IPv4) as a pcap with LINKTYPE_RAW and return tshark's verbose dissection
/// of it plus every expert info at Warn or above. tshark missing is a failure, not a skip.
pub fn tshark_verbose(packets: &[Vec<u8>]) -> (String, Vec<String>) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ss7.pcap");
    let mut pcap = Vec::new();
    pcap.extend_from_slice(&0xa1b2_c3d4u32.to_le_bytes());
    pcap.extend_from_slice(&2u16.to_le_bytes());
    pcap.extend_from_slice(&4u16.to_le_bytes());
    pcap.extend_from_slice(&0u32.to_le_bytes());
    pcap.extend_from_slice(&0u32.to_le_bytes());
    pcap.extend_from_slice(&65535u32.to_le_bytes());
    pcap.extend_from_slice(&101u32.to_le_bytes());
    for (i, p) in packets.iter().enumerate() {
        pcap.extend_from_slice(&(1_700_000_000u32 + i as u32).to_le_bytes());
        pcap.extend_from_slice(&0u32.to_le_bytes());
        pcap.extend_from_slice(&(p.len() as u32).to_le_bytes());
        pcap.extend_from_slice(&(p.len() as u32).to_le_bytes());
        pcap.extend_from_slice(p);
    }
    std::fs::write(&path, pcap).unwrap();
    let run = |args: &[&str]| {
        let out = std::process::Command::new("tshark")
            .arg("-r")
            .arg(&path)
            .args(args)
            .output()
            .expect(
                "tshark is required for the SS7 oracle: brew install wireshark / sudo apt-get \
                 install tshark. This test fails rather than skips.",
            );
        assert!(
            out.status.success(),
            "tshark: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).to_string()
    };
    let verbose = run(&["-n", "-V"]);
    let experts = run(&[
        "-n",
        "-T",
        "fields",
        "-e",
        "_ws.expert.severity",
        "-e",
        "_ws.expert.message",
    ]);
    let bad: Vec<String> = experts
        .lines()
        .filter(|l| {
            l.split('\t')
                .next()
                .unwrap_or("")
                .split(',')
                .filter_map(|s| s.trim().parse::<u32>().ok())
                .any(|s| s >= 0x0060_0000)
        })
        .map(str::to_string)
        .collect();
    (verbose, bad)
}

/// Wrap NetGet's outgoing Protocol Data in M3UA DATA, as the session does.
pub fn m3ua_data(pd: &ProtocolData, rc: Option<u32>) -> Vec<u8> {
    codec::data(pd, None, rc, None).unwrap()
}
