//! NetGet's PROFINET IO device on real Ethernet (a veth whose other end is in a network
//! namespace), driven by two independent Python implementations running in that namespace:
//!
//! * **profinet-py** (f0rw4rd, GPL-3.0; an IO controller library written from the IEC 61158
//!   documents, not from NetGet) — DCP discovery by name, Connect with an IOCR layout,
//!   PrmEnd, ApplicationReady (it serves the CControl endpoint itself), RT_CLASS_1 cyclic
//!   data both ways, an I&M0 read through the AR, Release; and its CLI's `read-inm0`, which
//!   opens a supervisor AR of its own.
//! * **pnio_dcp** (Codewerk, MIT) — DCP Identify All, Identify by MAC, Set NameOfStation
//!   (one the model takes, one it refuses), Set IP, and Signal.
//!
//! tshark captures the veth for the whole run and judges every frame NetGet sent.
//!
//! Needs Linux, root (raw sockets, and `ip netns`), iproute2, tshark, and a Python with
//! `profinet-py==0.6.6` and `pnio-dcp==1.2.0` as the `python3` on `PATH`. Any of them missing
//! is a failure naming the fix, not a skip.
use crate::helpers::live_capture::LiveCapture;
use crate::helpers::netns::Netns;
use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use netget::state::{AccessLogOwner, ServerId};
use serde_json::{json, Value};
use std::process::Command;
use std::time::Duration;

const POLICY: &str = r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']; e=i['event']
a=[]
if t=='profinet_connect_request':
  a=[{'type':'profinet_accept_connect'},{'type':'profinet_set_inputs','slot':1,'subslot':1,'values':{'inputs':42}}]
elif t=='profinet_dcp_set_request':
  n=e.get('name_of_station')
  a=[{'type':'profinet_refuse_dcp_set','reason':'locked'}] if n is not None and not n.startswith('line-') else [{'type':'profinet_accept_dcp_set'}]
elif t=='profinet_read_record':
  if e['index']==0xAFF0:
    a=[{'type':'profinet_read_response','im0':{'order_id':'NG-PN-1','serial_number':'SN-0042','hardware_revision':3,'software_revision':'V2.1.0','im_supported':[1]}}]
  else:
    a=[{'type':'profinet_refuse_record','error':'invalid_index'}]
elif t=='profinet_outputs_changed':
  for o in e['outputs']:
    if o['slot']==1 and o['iops']=='good':
      a=[{'type':'profinet_set_inputs','slot':1,'subslot':1,'values':{'inputs':(o['values']['outputs']+1)%256}}]
print(json.dumps({'actions':a}))"#;

/// pnio_dcp, run in the namespace: argv = our IP, the device's name, the device's IP.
const PNIO_DCP: &str = r#"import json,sys
import pnio_dcp
ip,name,dev_ip=sys.argv[1],sys.argv[2],sys.argv[3]
d=pnio_dcp.DCP(ip)
out={}
found=[x for x in d.identify_all(timeout=3) if x.name_of_station==name]
out['identify_all']=[{'name':x.name_of_station,'mac':x.MAC,'ip':x.IP,'netmask':x.netmask} for x in found]
mac=found[0].MAC
out['set_name_ok']=bool(d.set_name_of_station(mac,'line-7'))
out['set_name_refused']=not bool(d.set_name_of_station(mac,'forbidden'))
out['set_ip_ok']=bool(d.set_ip_address(mac,[dev_ip,'255.255.255.252','0.0.0.0']))
out['blink_ok']=bool(d.blink(mac))
again=d.identify(mac)
out['after']={'name':again.name_of_station,'ip':again.IP}
out['get_name']=d.get_name_of_station(mac)
print(json.dumps(out))"#;

/// profinet-py as the IO controller: argv = interface, station name.
const PROFINET_PY: &str = r#"import json,sys,time
from profinet import IOCRSetup, IOSlot, RPCCon, ethernet_socket, get_mac, get_station_info
from profinet.cyclic import CyclicController
from profinet.rt import build_iocr_configs
iface,name=sys.argv[1],sys.argv[2]
out={}
sock=ethernet_socket(iface); src=get_mac(iface)
info=get_station_info(sock,src,name,timeout_sec=5); sock.close()
out['discovered']={'name':info.name,'ip':info.ip,'vendor':(info.vendor_high<<8)|info.vendor_low,'device':(info.device_high<<8)|info.device_low}
setup=IOCRSetup(slots=[IOSlot(slot=1,subslot=1,module_ident=0x32,submodule_ident=0x132,input_length=1,output_length=1)],
                send_clock_factor=32,reduction_ratio=32,watchdog_factor=10,data_hold_factor=10)
rpc=RPCCon(info,timeout=10.0)
res=rpc.connect(src_mac=src,with_alarm_cr=True,iocr_setup=setup)
out['frame_ids']=[res.input_frame_id,res.output_frame_id]
rpc.prm_end()
rpc.application_ready(timeout=30.0)
dst=info.mac if isinstance(info.mac,bytes) else bytes.fromhex(info.mac.replace(':',''))
i_cfg,o_cfg=build_iocr_configs(setup.slots,res.input_frame_id,res.output_frame_id,send_clock_factor=32,reduction_ratio=32,watchdog_factor=10)
cyc=CyclicController(interface=iface,src_mac=src,dst_mac=dst,input_iocr=i_cfg,output_iocr=o_cfg,max_consecutive_timeouts=50)
cyc.set_output_data(1,1,bytes([5]))
cyc.start()
seen=[]
deadline=time.time()+20
while time.time()<deadline:
  v=cyc.get_input_data(1,1)
  if v and (not seen or seen[-1]!=v[0]): seen.append(v[0])
  if v and v[0]==6: break
  time.sleep(0.05)
out['inputs_seen']=seen
s=cyc.stats
out['frames']={'sent':s.frames_sent,'received':s.frames_received}
im0=rpc.read_im0()
out['im0']={'order_id':im0.order_id.strip(),'serial':im0.im_serial_number.strip(),'hw':im0.im_hardware_revision,
            'sw':[im0.im_sw_revision_functional_enhancement,im0.im_sw_revision_bug_fix,im0.im_sw_revision_internal_change]}
cyc.stop()
rpc.close()
print(json.dumps(out,default=lambda v: v.decode("latin-1") if isinstance(v,bytes) else str(v)))"#;

fn require_peers() {
    let out = Command::new("python3")
        .args(["-c", "import profinet, pnio_dcp"])
        .output()
        .unwrap_or_else(|e| panic!("cannot run python3 ({e})"));
    assert!(
        out.status.success(),
        "this test needs profinet-py and pnio_dcp in the python3 on PATH: `python3 -m venv \
         /tmp/pn && /tmp/pn/bin/pip install profinet-py==0.6.6 pnio-dcp==1.2.0` and put \
         /tmp/pn/bin first on PATH ({})",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        Command::new("tshark")
            .arg("--version")
            .output()
            .is_ok_and(|o| o.status.success()),
        "this test needs tshark: apt-get install tshark"
    );
    // SAFETY: geteuid has no preconditions.
    assert_eq!(
        unsafe { libc::geteuid() },
        0,
        "raw PROFINET needs CAP_NET_RAW: run this test as root (CI uses a sudo test runner)"
    );
}

async fn run_in_ns(ns: &Netns, script: &str, args: &[&str]) -> Value {
    let mut argv: Vec<String> = vec!["python3".into(), "-I".into(), "-c".into(), script.into()];
    argv.extend(args.iter().map(|s| s.to_string()));
    let argv: Vec<&str> = argv.iter().map(String::as_str).collect();
    let out = tokio::time::timeout(Duration::from_secs(120), ns.output(&argv))
        .await
        .expect("the python peer hung");
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(
        out.status.success(),
        "python peer failed\nstdout: {stdout}\nstderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_str(stdout.lines().last().unwrap_or(""))
        .unwrap_or_else(|e| panic!("python peer printed no JSON ({e}): {stdout}"))
}

async fn events(state: &AppState, id: ServerId, kind: &str) -> Vec<Value> {
    let mut v: Vec<Value> = state
        .list_access_logs_for(Some(AccessLogOwner::Server(id.as_u32())), None)
        .await
        .iter()
        .map(|e| serde_json::to_value(e).unwrap())
        .filter(|e| e["event_type"] == kind)
        .collect();
    v.sort_by_key(|e| e["id"].as_u64().unwrap_or(0));
    v.into_iter().map(|e| e["request"].clone()).collect()
}

fn mac_of(iface: &str) -> String {
    std::fs::read_to_string(format!("/sys/class/net/{iface}/address"))
        .expect("interface address")
        .trim()
        .to_string()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn profinet_py_and_pnio_dcp_drive_the_raw_device() {
    require_peers();
    let ns = Netns::create("pnd", 41);
    let mut capture = LiveCapture::start(&ns.host_if);
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    let log = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let sink = log.clone();
    tokio::spawn(async move {
        while let Some(l) = rx.recv().await {
            sink.lock().unwrap().push(l);
        }
    });
    let id = ServerForm {
        protocol: "profinet".into(),
        interface: Some(ns.host_if.clone()),
        host: Some(ns.host_ip.to_string()),
        port: Some(34964),
        instruction: Some("Be a PROFINET IO device".into()),
        event_handlers: Some(vec![
            json!({"event_pattern": "*", "handler": {"type": "script", "language": "python", "code": POLICY}}),
        ]),
        startup_params: Some(json!({"name_of_station": "netget-dev", "vendor_id": 42, "device_id": 9,
                                    "netmask": "255.255.255.252"})),
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .unwrap();
    let logs = || log.lock().unwrap().join("\n");
    tokio::time::timeout(Duration::from_secs(30), async {
        while !logs().contains("PNIO RPC on") {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("the device did not start: {}", logs()));
    let host_ip = ns.host_ip.to_string();
    let ns_ip = ns.ns_ip.to_string();

    // pnio_dcp: discovery and configuration.
    let dcp = run_in_ns(&ns, PNIO_DCP, &[&ns_ip, "netget-dev", &host_ip]).await;
    assert_eq!(dcp["identify_all"][0]["ip"], host_ip, "{dcp}");
    assert_eq!(dcp["identify_all"][0]["netmask"], "255.255.255.252");
    assert_eq!(dcp["identify_all"][0]["mac"], mac_of(&ns.host_if));
    assert_eq!(
        (
            &dcp["set_name_ok"],
            &dcp["set_name_refused"],
            &dcp["set_ip_ok"],
            &dcp["blink_ok"]
        ),
        (&json!(true), &json!(true), &json!(true), &json!(true)),
        "{dcp}\n{}",
        logs()
    );
    assert_eq!(dcp["after"]["name"], "line-7");
    assert_eq!(dcp["get_name"], "line-7");
    let sets = events(&state, id, "profinet_dcp_set_request").await;
    assert!(
        sets.iter().any(|e| e["name_of_station"] == "forbidden"),
        "{sets:?}"
    );
    assert!(sets.iter().any(|e| e["signal"] == true), "{sets:?}");

    // profinet-py: an AR with cyclic data and a record read.
    let pp = run_in_ns(&ns, PROFINET_PY, &[&ns.ns_if, "line-7"]).await;
    assert_eq!(pp["discovered"]["vendor"], 42, "{pp}");
    assert_eq!(pp["discovered"]["device"], 9);
    let seen: Vec<u64> = pp["inputs_seen"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_u64)
        .collect();
    assert_eq!(
        seen.last(),
        Some(&6),
        "the model's answer to output 5 did not reach profinet-py: {pp}\n{}",
        logs()
    );
    assert_eq!(pp["im0"]["order_id"], "NG-PN-1");
    assert_eq!(pp["im0"]["serial"], "SN-0042");
    assert_eq!(pp["im0"]["sw"], json!([2, 1, 0]));
    let connects = events(&state, id, "profinet_connect_request").await;
    assert_eq!(connects[0]["ar_type"], "io_controller");
    let outs = events(&state, id, "profinet_outputs_changed").await;
    assert!(outs.iter().any(|e| e["outputs"][0]["values"]["outputs"] == 5 && e["outputs"][0]["iops"] == "good"), "{outs:?}");
    tokio::time::timeout(Duration::from_secs(30), async {
        while events(&state, id, "profinet_ar_closed").await.is_empty() {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "the AR never closed after profinet-py released it: {}",
            logs()
        )
    });

    // profinet-py's CLI reads I&M0 through a supervisor AR of its own.
    let cli = ns
        .output(&[
            "python3",
            "-I",
            "-c",
            "import sys; from profinet.cli import main; sys.argv[0]='profinet'; sys.exit(main())",
            "-i",
            &ns.ns_if,
            "read-inm0",
            "line-7",
        ])
        .await;
    let cli_out = String::from_utf8_lossy(&cli.stdout).to_string();
    assert!(
        cli.status.success() && cli_out.contains("NG-PN-1"),
        "{cli_out}\n{}",
        String::from_utf8_lossy(&cli.stderr)
    );
    let sup = events(&state, id, "profinet_connect_request").await;
    assert!(
        sup.iter()
            .any(|e| e["ar_type"] == "supervisor_device_access"),
        "{sup:?}"
    );

    // tshark: every frame NetGet sent, both families.
    capture.wait_for(&mac_of(&ns.host_if), "pn_io.block_type", "0x8114", 15);
    capture.stop();
    let chains = capture.assert_clean_from(&mac_of(&ns.host_if));
    assert!(chains.iter().any(|c| c.contains("pn_dcp")), "{chains:?}");
    assert!(chains.iter().any(|c| c.contains("pn_rt")), "{chains:?}");
    let pnio: Vec<String> = capture
        .fields(&["pn_io.block_type"])
        .into_iter()
        .filter(|r| r[0].eq_ignore_ascii_case(&mac_of(&ns.host_if)))
        .map(|r| r[1].clone())
        .collect();
    for want in ["0x8101", "0x8110", "0x0112", "0x8009", "0x8114"] {
        assert!(
            pnio.iter().any(|b| b.contains(want)),
            "tshark read no {want} from NetGet: {pnio:?}"
        );
    }
}
