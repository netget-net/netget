//! NetGet's PROFINET IO controller against rt-labs' p-net — an independent C device stack —
//! running its sample application (`pn_dev`) in a network namespace at the other end of a
//! veth, on real Ethernet frames.
//!
//! The policy (standing in for the model) renames the device over DCP, finds it again under
//! the new name, connects with the sample's access point and three of its modules (8 digital
//! inputs, 8 digital outputs, and the echo module) writing the echo module's gain parameter
//! before PrmEnd, then drives outputs and reads I&M0. What p-net does with each is observed
//! from p-net's side: its data LED file (bit 7 of the output byte), the echo module's answer
//! (output × the gain the controller wrote), its digital input counter, its I&M0 values.
//! tshark captures the veth throughout and judges every frame NetGet sent.
//!
//! Needs Linux, root, iproute2, tshark and p-net's `pn_dev` on `PATH` (with the two scripts
//! `scripts/test-peers/build-pnet.sh` leaves beside it). Missing is a failure naming the fix,
//! not a skip.
use super::support::*;
use crate::helpers::live_capture::LiveCapture;
use crate::helpers::netns::Netns;
use netget::state::AccessLogOwner;
use serde_json::{json, Value};
use std::time::Duration;

const POLICY: &str = r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']; e=i['event']
dap=[{'slot':0,'subslot':1,'module_ident':'0x1','submodule_ident':'0x1'},
     {'slot':0,'subslot':32768,'module_ident':'0x1','submodule_ident':'0x8000'},
     {'slot':0,'subslot':32769,'module_ident':'0x1','submodule_ident':'0x8001'}]
mods=[{'slot':1,'subslot':1,'module_ident':'0x30','submodule_ident':'0x130','inputs':[{'name':'buttons','type':'u8'}]},
      {'slot':2,'subslot':1,'module_ident':'0x31','submodule_ident':'0x131','outputs':[{'name':'leds','type':'u8'}]},
      {'slot':3,'subslot':1,'module_ident':'0x40','submodule_ident':'0x140',
       'inputs':[{'name':'echo_float','type':'f32'},{'name':'echo_int','type':'u32'}],
       'outputs':[{'name':'float','type':'f32'},{'name':'int','type':'u32'}]}]
a=[]
names=[d.get('name_of_station') for d in e.get('devices',[])]
if t=='profinet_devices_discovered' and 'rt-labs-dev' in names:
  mac=[d['mac'] for d in e['devices'] if d.get('name_of_station')=='rt-labs-dev'][0]
  a=[{'type':'profinet_dcp_set','mac':mac,'new_name_of_station':'netget-pnet'}]
elif t=='profinet_dcp_set_result' and all(r['ok'] for r in e.get('results',[{'ok':False}])):
  a=[{'type':'profinet_identify','name_of_station':'netget-pnet'}]
elif t=='profinet_devices_discovered' and 'netget-pnet' in names:
  a=[{'type':'profinet_connect','name_of_station':'netget-pnet','submodules':dap+mods,'cycle_ms':16,
      'parameters':[{'slot':3,'subslot':1,'index':125,'fields':[{'type':'u32','value':3}]}]}]
elif t=='profinet_ar_established':
  a=[{'type':'profinet_set_outputs','slot':2,'subslot':1,'values':{'leds':128}},
     {'type':'profinet_set_outputs','slot':3,'subslot':1,'values':{'float':1.5,'int':7}},
     {'type':'profinet_read_record','index':'im0'}]
print(json.dumps({'actions':a}))"#;

fn require_pn_dev() {
    let ok = std::process::Command::new("pn_dev")
        .arg("-h")
        .output()
        .is_ok();
    assert!(
        ok,
        "this test needs rt-labs' p-net sample device on PATH: `sh \
         scripts/test-peers/build-pnet.sh /tmp/pnet` and put /tmp/pnet/build on PATH"
    );
}

fn mac_of(iface: &str) -> String {
    std::fs::read_to_string(format!("/sys/class/net/{iface}/address"))
        .expect("interface address")
        .trim()
        .to_string()
}

struct PnDev {
    child: tokio::process::Child,
    dir: tempfile::TempDir,
}

impl Drop for PnDev {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn netget_controller_runs_p_net() {
    require_pn_dev();
    // SAFETY: geteuid has no preconditions.
    assert_eq!(
        unsafe { libc::geteuid() },
        0,
        "raw PROFINET needs CAP_NET_RAW: run as root"
    );
    let ns = Netns::create("pnc", 42);
    let mut capture = LiveCapture::start(&ns.host_if);
    let dir = tempfile::tempdir().unwrap();
    // pn_dev prints through stdio, which a pipe would block-buffer until exit.
    let mut cmd = tokio::process::Command::from(ns.command(&[
        "stdbuf",
        "-oL",
        "-eL",
        "pn_dev",
        "-v",
        "-i",
        &ns.ns_if,
        "-s",
        "rt-labs-dev",
        "-p",
        dir.path().to_str().unwrap(),
    ]));
    cmd.current_dir(dir.path())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);
    let mut child = cmd.spawn().expect("starting pn_dev");
    let stdout = child.stdout.take().unwrap();
    let pnet_log = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
    let sink = pnet_log.clone();
    tokio::spawn(async move {
        use tokio::io::AsyncBufReadExt;
        let mut lines = tokio::io::BufReader::new(stdout).lines();
        while let Ok(Some(l)) = lines.next_line().await {
            let mut s = sink.lock().unwrap();
            s.push_str(&l);
            s.push('\n');
        }
    });
    let pnet = PnDev { child, dir };
    let pnet_text = || pnet_log.lock().unwrap().clone();
    tokio::time::timeout(Duration::from_secs(30), async {
        while !(pnet_text().contains("Waiting for PLC connect request")
            || pnet_text().contains("Link went up on port 1"))
        {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("pn_dev did not come up:\n{}", pnet_text()));

    let (state, tx, log) = new_state();
    let id = start_controller(
        &state,
        tx,
        &ns.host_if,
        script(POLICY),
        json!({"station_name": "netget-plc", "identify_ms": 2000}),
    )
    .await
    .unwrap_or_else(|e| panic!("controller did not start: {e:#}\n{}", text(&log)));
    let c = AccessLogOwner::Client(id.as_u32());

    // DCP: found as rt-labs-dev, renamed, found again by the new name.
    let found = wait_until(&state, c, "profinet_devices_discovered", 30, |e| {
        e["devices"]
            .as_array()
            .unwrap()
            .iter()
            .any(|d| d["name_of_station"] == "netget-pnet")
    })
    .await;
    let first = &found[0]["devices"][0];
    assert_eq!(
        first["name_of_station"],
        "rt-labs-dev",
        "{found:?}\n{}",
        text(&log)
    );
    assert_eq!(
        (first["vendor_id"].as_u64(), first["device_id"].as_u64()),
        (Some(0x0493), Some(0x0002))
    );
    let ns_mac = String::from_utf8_lossy(
        &ns.exec(&["cat", &format!("/sys/class/net/{}/address", ns.ns_if)])
            .stdout,
    )
    .trim()
    .to_string();
    assert_eq!(first["mac"], ns_mac);
    let set = events(&state, c, "profinet_dcp_set_result").await;
    assert_eq!(set[0]["results"][0]["ok"], true, "{set:?}");

    // The AR runs.
    let up = wait_until(&state, c, "profinet_ar_established", 60, |_| true).await;
    assert!(
        !up.is_empty(),
        "no AR with p-net:\n{}\n--- pn_dev ---\n{}",
        text(&log),
        pnet_text()
    );
    assert!(
        up[0]["module_diff"].as_array().unwrap().is_empty(),
        "{up:?}"
    );

    // p-net's echo module answers output × the gain we wrote before PrmEnd (3).
    let ins = wait_until(&state, c, "profinet_inputs_changed", 60, |e| {
        e["inputs"]
            .as_array()
            .unwrap()
            .iter()
            .any(|x| x["slot"] == 3 && x["values"]["echo_int"] == 21)
    })
    .await;
    let echo = ins
        .iter()
        .flat_map(|e| e["inputs"].as_array().unwrap().clone())
        .filter(|x| x["slot"] == 3 && x["values"]["echo_int"] == 21)
        .last()
        .unwrap_or_else(|| {
            panic!(
                "p-net never echoed int 7 × gain 3 = 21:\n{ins:?}\n{}\n--- pn_dev ---\n{}",
                text(&log),
                pnet_text()
            )
        });
    assert_eq!(echo["iops"], "good");
    assert_eq!(echo["values"]["echo_float"], 4.5, "{echo}");
    // The digital input module's counter moves, IOPS good.
    let counters: std::collections::BTreeSet<u64> = ins
        .iter()
        .flat_map(|e| e["inputs"].as_array().unwrap().clone())
        .filter(|x| x["slot"] == 1 && x["iops"] == "good")
        .filter_map(|x| x["values"]["buttons"].as_u64())
        .collect();
    assert!(
        counters.len() >= 2,
        "p-net's input counter did not move: {counters:?}"
    );

    // Output bit 7 is p-net's data LED, which its script writes to pnet_led_1.txt.
    let led = pnet.dir.path().join("pnet_led_1.txt");
    tokio::time::timeout(Duration::from_secs(20), async {
        while std::fs::read_to_string(&led)
            .map(|s| s.trim().to_string())
            .unwrap_or_default()
            != "1"
        {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("p-net's data LED never came on:\n{}", pnet_text()));

    // I&M0 as p-net's sample application defines it.
    let read = wait_until(&state, c, "profinet_record_read", 30, |_| true).await;
    assert_eq!(read[0]["ok"], true, "{read:?}");
    assert_eq!(read[0]["im0"]["order_id"], "12345 Abcdefghijk");
    assert_eq!(read[0]["im0"]["serial_number"], "007");
    assert_eq!(read[0]["im0"]["vendor_id"], 0x0493);

    // Release: p-net sees the controller go.
    let out = state
        .send_to_client(
            id,
            json!({"type": "profinet_release"}),
            Duration::from_secs(10),
        )
        .await
        .unwrap();
    assert!(
        matches!(
            out,
            netget::state::client_handles::ClientSendOutcome::Executed { .. }
        ),
        "{out:?}"
    );
    let closed = wait_until(&state, c, "profinet_ar_closed", 30, |_| true).await;
    assert_eq!(closed[0]["reason"], "released", "{closed:?}");

    capture.wait_for(&mac_of(&ns.host_if), "pn_io.block_type", "0x0114", 15);
    capture.stop();
    let ours = mac_of(&ns.host_if);
    let chains = capture.assert_clean_from(&ours);
    assert!(chains.iter().any(|c| c.contains("pn_dcp")), "{chains:?}");
    assert!(chains.iter().any(|c| c.contains("pn_rt")), "{chains:?}");
    let blocks: Vec<String> = capture
        .fields(&["pn_io.block_type"])
        .into_iter()
        .filter(|r| r[0].eq_ignore_ascii_case(&ours))
        .map(|r| r[1].clone())
        .collect();
    for want in [
        "0x0101", "0x0102", "0x0104", "0x0008", "0x0110", "0x8112", "0x0009", "0x0114",
    ] {
        assert!(
            blocks.iter().any(|b| b.contains(want)),
            "tshark read no {want} from NetGet: {blocks:?}"
        );
    }
    let _: Value = json!(null);
    drop(pnet);
}
