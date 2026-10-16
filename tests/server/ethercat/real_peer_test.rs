//! NetGet's EtherCAT slave on real Ethernet (one end of a veth pair), driven from the other end
//! by two independent masters:
//!
//! * **SOEM** 2.0.1 (rt-labs / OpenEtherCATsociety, C) — `slaveinfo -map` (scan, SII identity,
//!   mailbox, PDO mapping read over CoE, PRE-OP and SAFE-OP) and `simple_ng` (walk to OP and
//!   cyclic LRW, printing the working counter and the input octets).
//! * **ethercrab** 0.7 (Rust) on its own raw socket — scan, SDO, SAFE-OP, OP, process data.
//!
//! tshark captures the master's end for the whole run and judges every frame NetGet sent.
//!
//! Needs Linux, root (raw sockets, `ip link`), iproute2, tshark, and SOEM's `slaveinfo` and
//! `simple_ng` on `PATH` (`scripts/test-peers/build-soem.sh` builds them). Any of them missing is
//! a failure naming the fix, not a skip.
use super::support::*;
use crate::helpers::live_capture::LiveCapture;
use crate::helpers::netns::VethPair;
use netget::cli::management::ServerForm;
use serde_json::json;
use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn require_tool(bin: &str) -> String {
    let found = std::env::var_os("PATH")
        .and_then(|p| {
            std::env::split_paths(&p)
                .map(|d| d.join(bin))
                .find(|p| p.is_file())
        })
        .unwrap_or_else(|| {
            panic!(
                "{bin} is not on PATH: build SOEM with `sh scripts/test-peers/build-soem.sh \
                 /some/dir` and put its bin directory on PATH"
            )
        });
    found.to_string_lossy().into_owned()
}

/// A slave segment on the raw transport, on `iface`.
async fn start_raw(iface: &str) -> Segment {
    let (state, tx, log) = new_state();
    let mut params = slave_params();
    params["transport"] = json!("raw");
    let id = ServerForm {
        protocol: "ethercat".into(),
        interface: Some(iface.into()),
        instruction: Some("Be an EtherCAT slave".into()),
        event_handlers: script(SLAVE_POLICY),
        startup_params: Some(params),
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .unwrap();
    assert!(
        wait_for(&log, "EtherCAT segment of 1 slave", 30).await,
        "{}",
        log_text(&log)
    );
    Segment {
        state,
        id,
        addr: "0.0.0.0:0".parse().unwrap(),
        log,
    }
}

/// Run a SOEM sample to completion (or `secs`), returning its output.
fn run_for(bin: &str, args: &[&str], secs: u64, stop_when: &str) -> String {
    let mut child = Command::new(bin)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("cannot run {bin}: {e}"));
    let out = child.stdout.take().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        // simple_ng rewrites one line with '\r'; split on both.
        let mut r = BufReader::new(out);
        let mut buf = Vec::new();
        while r
            .read_until(b'\r', &mut buf)
            .map(|n| n > 0)
            .unwrap_or(false)
        {
            for l in String::from_utf8_lossy(&buf).split('\n') {
                let _ = tx.send(l.to_string());
            }
            buf.clear();
        }
    });
    let deadline = Instant::now() + Duration::from_secs(secs);
    let mut text = String::new();
    while Instant::now() < deadline {
        match rx.recv_timeout(Duration::from_millis(200)) {
            Ok(l) => {
                text.push_str(&l);
                text.push('\n');
                if !stop_when.is_empty() && text.contains(stop_when) {
                    break;
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
            Err(_) => {}
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    text
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn soem_scans_maps_and_runs_the_slave_on_a_veth() {
    let slaveinfo = require_tool("slaveinfo");
    let simple_ng = require_tool("simple_ng");
    let veth = VethPair::create("s");
    let mut cap = LiveCapture::start(&veth.b);
    let seg = start_raw(&veth.a).await;
    let b = veth.b.clone();
    let info = tokio::task::spawn_blocking(move || {
        run_for(&slaveinfo, &[&b, "-map"], 120, "End slaveinfo")
    })
    .await
    .unwrap();
    assert!(
        info.contains("1 slaves found and configured"),
        "{info}\n{}",
        seg.log_text()
    );
    assert!(info.contains("Name:NetGet Test Slave"), "{info}");
    assert!(
        info.contains("Man: 00000abc ID: 00012345 Rev: 00000007"),
        "SOEM read the identity from the SII: {info}"
    );
    assert!(info.contains("Calculated workcounter 3"), "{info}");
    assert!(
        info.contains("PDO mapping according to CoE"),
        "SOEM read the mapping over CoE: {info}"
    );
    assert!(
        info.contains("0x7000:0x02 0x10"),
        "setpoint, 16 bits: {info}"
    );
    assert!(info.contains("0x6000:0x02 0x01"), "ready, 1 bit: {info}");
    assert!(
        !info.contains("Not all slaves reached safe operational state"),
        "{info}\n{}",
        seg.log_text()
    );

    let b = veth.b.clone();
    let run =
        tokio::task::spawn_blocking(move || run_for(&simple_ng, &[&b], 120, "Iteration  200"))
            .await
            .unwrap();
    assert!(
        run.contains("all slaves are now operational"),
        "{run}\n{}",
        seg.log_text()
    );
    // simple_ng prints the working counter and the input octets of every cycle.
    assert!(run.contains("WKC 3"), "{run}");
    assert!(
        run.contains("I: 2A 00 01"),
        "count 42 and ready, as the model set them: {run}"
    );
    assert!(!run.contains("wrong (expected"), "{run}");
    let log = seg.log_text();
    assert!(log.contains("decision=model_accept"), "{log}");

    // Every frame NetGet sent back has SOEM's source address with the U/L bit an ESC sets.
    let ours = "03:01:01:01:01:01";
    assert!(
        cap.wait_for(ours, "ecat.cnt", "3", 10),
        "no LRW answer in the capture"
    );
    cap.stop();
    let chains = cap.assert_clean_from(ours);
    assert!(chains.iter().all(|c| c.contains("ecatf")), "{chains:?}");
    assert!(
        chains.iter().any(|c| c.contains("ecat_mailbox")),
        "{chains:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ethercrab_on_its_own_raw_socket_runs_the_slave_to_op() {
    use ethercrab::std::{ethercat_now, tx_rx_task};
    use ethercrab::{MainDevice, MainDeviceConfig, PduStorage, Timeouts};
    let veth = VethPair::create("c");
    let mut cap = LiveCapture::start(&veth.b);
    let seg = start_raw(&veth.a).await;
    let storage: &'static crab::Storage = Box::leak(Box::new(PduStorage::new()));
    let (tx, rx, pdu_loop) = storage.try_split().unwrap();
    let md = MainDevice::new(
        pdu_loop,
        Timeouts {
            state_transition: Duration::from_secs(20),
            mailbox_response: Duration::from_secs(10),
            ..Default::default()
        },
        MainDeviceConfig::default(),
    );
    let task = tokio::spawn(tx_rx_task(&veth.b, tx, rx).expect("ethercrab raw socket"));
    let group = md
        .init_single_group::<4, 64>(ethercat_now)
        .await
        .unwrap_or_else(|e| panic!("init: {e}\n{}", seg.log_text()));
    {
        let s = group.iter(&md).next().unwrap();
        assert_eq!(s.name(), "NetGet Test Slave");
        assert_eq!(s.identity().vendor_id, 0xABC);
        assert_eq!(s.sdo_read::<u16>(0x8000, 1).await.unwrap(), 1500);
    }
    let group = group.into_safe_op(&md).await.unwrap();
    group
        .subdevice(&md, 0)
        .unwrap()
        .outputs_raw_mut()
        .copy_from_slice(&[0x59, 0x02, 0x00]);
    for _ in 0..5 {
        group.tx_rx(&md).await.unwrap();
    }
    let group = group.request_into_op(&md).await.unwrap();
    let mut done = false;
    for _ in 0..1000 {
        let r = group.tx_rx(&md).await.unwrap();
        assert_eq!(r.working_counter, 3);
        let s = group.subdevice(&md, 0).unwrap();
        if r.all_op() && s.inputs_raw()[..2] == [0x2D, 0x01] {
            done = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(
        done,
        "OP, and count = setpoint + 1 from the model\n{}",
        seg.log_text()
    );
    task.abort();
    let ours = "12:10:10:10:10:10";
    assert!(cap.wait_for(ours, "ecat.cnt", "3", 10));
    cap.stop();
    cap.assert_clean_from(ours);
}
