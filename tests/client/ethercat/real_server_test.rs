//! NetGet's EtherCAT master on real Ethernet against an independent slave: KickCAT's
//! `network_simulator` (leducp/KickCAT, C++) on the other end of a veth, running the emulated
//! CiA 402 servo drive of `simulation/slave_configs/ecat402-drive.json` — a software ESC with
//! its SII compiled from Ingenia's ESI, KickCAT's slave stack and CoE dictionary, and a drive
//! state machine that answers the controlword with the statusword.
//!
//! The model (a python policy) walks the drive to OP and through the CiA 402 enable sequence
//! (controlword 6, then 7, then 15) by reading the statusword each step; reaching "operation
//! enabled" is the drive's own answer to outputs only the model chose. tshark captures the
//! master's end and judges every frame NetGet sent.
//!
//! Needs Linux, root, iproute2, tshark, and `network_simulator` on `PATH` with
//! `KICKCAT_CONFIGS` naming KickCAT's `simulation/slave_configs` directory
//! (`scripts/test-peers/build-kickcat.sh` builds both). Missing is a failure naming the fix.
use super::support::*;
use crate::helpers::live_capture::LiveCapture;
use crate::helpers::netns::VethPair;
use serde_json::json;
use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::time::Duration;

const DRIVE_POLICY: &str = r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']; e=i['event']
a=[]
if t=='ethercat_segment_scanned' and e['count']>0:
  a=[{'type':'ethercat_request_state','state':'safeop'}]
elif t=='ethercat_state_result' and e['requested']=='safeop' and e['ok']:
  a=[{'type':'ethercat_sdo_read','slave':0,'index':0x1018,'subindex':1,'data_type':'u32'},
     {'type':'ethercat_set_outputs','slave':0,'values':{'Control Word':6}},
     {'type':'ethercat_request_state','state':'op'}]
elif t=='ethercat_inputs_changed':
  sw=e['inputs'].get('Status Word',0) & 0x6F
  if sw==0x21: a=[{'type':'ethercat_set_outputs','slave':0,'values':{'Control Word':7}}]
  elif sw==0x23: a=[{'type':'ethercat_set_outputs','slave':0,'values':{'Control Word':15}}]
print(json.dumps({'actions':a}))"#;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kickcat_drive_is_scanned_configured_and_enabled() {
    let configs = std::env::var("KICKCAT_CONFIGS").unwrap_or_else(|_| {
        panic!(
            "KICKCAT_CONFIGS must name KickCAT's simulation/slave_configs directory: build it \
             with `sh scripts/test-peers/build-kickcat.sh /some/dir`"
        )
    });
    let config = format!("{configs}/ecat402-drive.json");
    assert!(
        std::path::Path::new(&config).is_file(),
        "{config} is missing"
    );
    let veth = VethPair::create("k");
    let mut cap = LiveCapture::start(&veth.a);
    let mut sim = Command::new("network_simulator")
        .args(["-i", &veth.b, "-s", &config])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| {
            panic!(
                "cannot run network_simulator ({e}): build it with \
                 `sh scripts/test-peers/build-kickcat.sh /some/dir` and put it on PATH"
            )
        });
    let out = sim.stdout.take().unwrap();
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut r = BufReader::new(out);
        let mut buf = Vec::new();
        while r
            .read_until(b'\n', &mut buf)
            .map(|n| n > 0)
            .unwrap_or(false)
        {
            let _ = ready_tx.send(String::from_utf8_lossy(&buf).to_string());
            buf.clear();
        }
    });
    let mut started = String::new();
    while !started.contains("Opening nominal interface") {
        match ready_rx.recv_timeout(Duration::from_secs(30)) {
            Ok(l) => started.push_str(&l),
            Err(_) => panic!("network_simulator did not start: {started}"),
        }
    }
    tokio::time::sleep(Duration::from_millis(500)).await;

    let (state, tx, log) = new_state();
    let m = start_master_in(
        state,
        tx,
        log,
        &veth.a,
        script(DRIVE_POLICY),
        json!({"transport": "raw", "cycle_ms": 2}),
    )
    .await
    .unwrap();
    let scanned = m
        .wait_event("ethercat_segment_scanned", 60, |_| true)
        .await
        .unwrap_or_else(|| panic!("no scan\n{}", m.log_text()));
    assert_eq!(scanned["count"], json!(1), "{scanned}");
    let s = &scanned["slaves"][0];
    assert_eq!(s["vendor_id"], json!(0x29C), "Ingenia, from the SII: {s}");
    assert_eq!(s["product_code"], json!(61935618), "{s}");
    assert_eq!(s["coe"], json!(true), "{s}");
    let op = m
        .wait_event("ethercat_state_result", 60, |e| e["requested"] == "op")
        .await
        .unwrap_or_else(|| panic!("no OP\n{}", m.log_text()));
    assert_eq!(op["ok"], json!(true), "{op}\n{}", m.log_text());
    let id = m
        .wait_event("ethercat_sdo_result", 30, |e| e["index"] == json!(0x1018))
        .await
        .unwrap();
    assert_eq!(id["value"], json!(0x29C), "{id}");
    let enabled = m
        .wait_event("ethercat_inputs_changed", 60, |e| {
            e["inputs"]["Status Word"]
                .as_u64()
                .is_some_and(|w| w & 0x6F == 0x27)
        })
        .await
        .unwrap_or_else(|| {
            panic!(
                "the drive never reported operation enabled\n{}",
                m.log_text()
            )
        });
    assert!(
        enabled["inputs"].get("Actual position").is_some(),
        "{enabled}"
    );
    let mac = veth.mac(&veth.a);
    assert!(
        cap.wait_for(&mac, "ecat.cmd", "12", 10),
        "no LRW in the capture"
    );
    let _ = sim.kill();
    let _ = sim.wait();
    cap.stop();
    let chains = cap.assert_clean_from(&mac);
    assert!(chains.iter().all(|c| c.contains("ecatf")), "{chains:?}");
    assert!(
        chains.iter().any(|c| c.contains("ecat_mailbox")),
        "{chains:?}"
    );
}
