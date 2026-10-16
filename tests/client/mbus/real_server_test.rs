//! NetGet's M-Bus master against two independent slaves, and its decoder against libmbus's
//! own reading of telegrams captured from real meters.
//!
//! - **pyMbusSlave** (Python, its own encoder) listens on TCP itself.
//! - **mbus-device** (Addiva Elektronik, C, on Addiva's fork of libmbus) speaks to a serial
//!   port; `serial_gateway.py` bridges a pty to TCP byte for byte, which is exactly what an
//!   M-Bus/IP gateway is. It answers with telegrams libmbus's test suite captured from real
//!   meters (Kamstrup, Landis+Gyr, Eastron, Itron, ...), so the master reads real meters'
//!   bytes, and what it decodes is checked against libmbus's normalised XML for the same
//!   telegram.
//!
//! Neither slave implements multi-telegram readouts or collisions; those run against NetGet's
//! own gateway only (`e2e_test.rs`), as a regression rather than as evidence.
//!
//! These tests fail, rather than skip, when a peer is missing:
//!
//! ```text
//! sh scripts/test-peers/fetch-pymbusslave.sh /abs/dir   # PYMBUSSLAVE=/abs/dir/pyMbusSlave/slave.py
//! sh scripts/test-peers/build-mbus-device.sh /abs/dir   # MBUS_DEVICE=/abs/dir/bin/mbus-device
//! sh scripts/test-peers/build-libmbus.sh /abs/dir       # LIBMBUS_BIN=/abs/dir/bin (frames beside it)
//! python3 -m venv /abs/venv && /abs/venv/bin/pip install pyserial   # MBUS_PYTHON=/abs/venv/bin/python
//! ```
use super::support;
use netget::server::mbus::{frame, records};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};

fn python() -> String {
    let py = std::env::var("MBUS_PYTHON").unwrap_or_else(|_| "python3".into());
    let ok = std::process::Command::new(&py)
        .args(["-I", "-c", "import serial"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    assert!(
        ok,
        "pyserial is required for pyMbusSlave: `python3 -m venv /abs/venv && /abs/venv/bin/pip \
         install pyserial`, then MBUS_PYTHON=/abs/venv/bin/python"
    );
    py
}

fn env_file(var: &str, how: &str) -> PathBuf {
    let p = std::env::var(var)
        .map(PathBuf::from)
        .unwrap_or_else(|_| panic!("{var} is required: {how}"));
    assert!(p.exists(), "{var}={} does not exist: {how}", p.display());
    p
}

fn mbus_device() -> PathBuf {
    if let Ok(p) = std::env::var("MBUS_DEVICE") {
        return env_file("MBUS_DEVICE", &p);
    }
    std::env::var_os("PATH")
        .and_then(|path| {
            std::env::split_paths(&path)
                .map(|d| d.join("mbus-device"))
                .find(|p| p.is_file())
        })
        .unwrap_or_else(|| {
            panic!(
                "mbus-device (Addiva Elektronik) is required: `sh \
                 scripts/test-peers/build-mbus-device.sh /abs/dir`, then \
                 MBUS_DEVICE=/abs/dir/bin/mbus-device"
            )
        })
}

/// libmbus's captured telegrams and its normalised XML for each.
fn frames_dir() -> PathBuf {
    let how = "build libmbus with `sh scripts/test-peers/build-libmbus.sh /abs/dir` and set \
               LIBMBUS_BIN=/abs/dir/bin (or LIBMBUS_FRAMES to its test/test-frames)";
    let dir = match std::env::var("LIBMBUS_FRAMES") {
        Ok(d) => PathBuf::from(d),
        Err(_) => {
            let bin = std::env::var("LIBMBUS_BIN").unwrap_or_else(|_| panic!("{how}"));
            PathBuf::from(bin).join("../libmbus/test/test-frames")
        }
    };
    assert!(
        dir.join("kamstrup_multical_601.hex").is_file(),
        "{} holds no libmbus test frames: {how}",
        dir.display()
    );
    dir
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A child process whose output lines are collected.
struct Peer {
    child: Child,
    lines: Arc<Mutex<Vec<String>>>,
}

/// Close the peer's standard input first: `serial_gateway.py` then stops the slave program it
/// started. Killing the gateway outright would orphan that program, which on macOS does not
/// notice its pty closing.
impl Drop for Peer {
    fn drop(&mut self) {
        drop(self.child.stdin.take());
        for _ in 0..40 {
            if matches!(self.child.try_wait(), Ok(Some(_))) {
                return;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        let _ = self.child.start_kill();
    }
}

impl Peer {
    fn spawn(mut cmd: Command) -> Peer {
        let mut child = cmd
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .expect("the peer starts");
        let lines = Arc::new(Mutex::new(Vec::new()));
        for stream in [
            child
                .stdout
                .take()
                .map(|s| Box::new(s) as Box<dyn tokio::io::AsyncRead + Unpin + Send>),
            child
                .stderr
                .take()
                .map(|s| Box::new(s) as Box<dyn tokio::io::AsyncRead + Unpin + Send>),
        ]
        .into_iter()
        .flatten()
        {
            let sink = lines.clone();
            tokio::spawn(async move {
                let mut r = BufReader::new(stream).lines();
                while let Ok(Some(l)) = r.next_line().await {
                    sink.lock().unwrap().push(l);
                }
            });
        }
        Peer { child, lines }
    }

    fn text(&self) -> String {
        self.lines.lock().unwrap().join("\n")
    }

    async fn wait_for(&self, needle: &str) -> bool {
        for _ in 0..400 {
            if self.text().contains(needle) {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        false
    }
}

/// The master's model: scan primary 0-5, read every meter found, search by secondary address.
const SCAN_AND_READ: &str = r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']; e=i['event']
a=[]
if t=='mbus_connected': a=[{'type':'mbus_scan_primary','from':0,'to':5}]
elif t=='mbus_scan_result' and e['kind']=='primary':
  a=[{'type':'mbus_read','address':n} for n in e['found']]+[{'type':'mbus_scan_secondary'}]
elif t=='mbus_scan_result':
  a=[{'type':'mbus_read','secondary_address':m['secondary_address']} for m in e['found']]
print(json.dumps({'actions':a}))"#;

#[tokio::test]
async fn pymbusslave_is_found_by_both_scans_and_its_records_are_decoded() {
    let py = python();
    let slave = env_file(
        "PYMBUSSLAVE",
        "`sh scripts/test-peers/fetch-pymbusslave.sh /abs/dir`, then \
         PYMBUSSLAVE=/abs/dir/pyMbusSlave/slave.py",
    );
    let port = free_port();
    let mut cmd = Command::new(&py);
    cmd.arg("-I")
        .arg(&slave)
        .args(["--device", &format!("tcp:127.0.0.1:{port}"), "--addr", "3"]);
    let peer = Peer::spawn(cmd);
    assert!(peer.wait_for("Listening").await, "{}", peer.text());
    let m = support::connect(
        &format!("127.0.0.1:{port}"),
        support::script(SCAN_AND_READ),
        500,
    )
    .await;
    let scans = m.wait_for_events("mbus_scan_result", 2, 120).await;
    assert_eq!(scans.len(), 2, "{}\n{}", m.log_text(), peer.text());
    assert_eq!(scans[0]["found"], json!([3]), "{scans:?}");
    let found = scans[1]["found"].as_array().unwrap();
    assert_eq!(found.len(), 1, "{scans:?}");
    // pyMbusSlave's defaults. (Its --id and --manuf flags change what selection matches but
    // not the RSP_UD header, whose builder bound the defaults when it was defined, so they are
    // not used here.)
    assert_eq!(found[0]["id"], "12345678");
    assert_eq!(found[0]["manufacturer"], "TST");
    let data = m.wait_for_events("mbus_data", 2, 60).await;
    assert_eq!(data.len(), 2, "{}\n{}", m.log_text(), peer.text());
    for d in &data {
        assert_eq!(d["meter"]["id"], "12345678");
        let r = d["records"].as_array().unwrap();
        assert_eq!(r.len(), 2, "{d}");
        assert_eq!(
            (
                r[0]["quantity"].clone(),
                r[0]["unit"].clone(),
                r[0]["value"].clone()
            ),
            (json!("voltage"), json!("V"), json!(1234)),
            "{d}"
        );
        assert_eq!(
            (
                r[1]["quantity"].clone(),
                r[1]["unit"].clone(),
                r[1]["value"].clone()
            ),
            (json!("volume"), json!("m3"), json!(456)),
            "{d}"
        );
    }
    assert_eq!(
        data[1]["target"]["secondary_address"],
        found[0]["secondary_address"]
    );
    // From the slave's side: what the master put on the wire because the model said so.
    let log = peer.text();
    assert!(log.contains("Slave Initialization"), "{log}");
    assert!(log.contains("Request for User Data 2"), "{log}");
    assert!(log.contains("Secondary selected"), "{log}");
}

/// The records of libmbus's normalised XML, minus the manufacturer-specific tail it reports as
/// a record of its own: (function, storage, tariff, quantity, unit, value).
fn norm_records(xml: &str) -> Vec<(String, u64, u64, String, String, String)> {
    let tag = |block: &str, t: &str| -> String {
        block
            .split(&format!("<{t}>"))
            .nth(1)
            .and_then(|s| s.split(&format!("</{t}>")).next())
            .unwrap_or("")
            .trim()
            .replace("&amp;", "&")
    };
    xml.split("<DataRecord")
        .skip(1)
        .map(|b| {
            (
                tag(b, "Function"),
                tag(b, "StorageNumber").parse().unwrap_or(0),
                tag(b, "Tariff").parse().unwrap_or(0),
                tag(b, "Quantity"),
                tag(b, "Unit"),
                tag(b, "Value"),
            )
        })
        .filter(|r| r.0 != "Manufacturer specific" && r.0 != "More records follow")
        .collect()
}

/// libmbus's normalised quantity and unit for each of ours whose base unit it shares.
fn libmbus_name(quantity: &str, unit: &str) -> Option<(&'static str, &'static str)> {
    Some(match (quantity, unit) {
        ("energy", "Wh") => ("Energy", "Wh"),
        ("energy", "J") => ("Energy", "J"),
        ("volume", "m3") => ("Volume", "m^3"),
        ("power", "W") => ("Power", "W"),
        ("volume_flow", "m3/h") => ("Volume flow", "m^3/h"),
        ("flow_temperature", "°C") => ("Flow temperature", "°C"),
        ("return_temperature", "°C") => ("Return temperature", "°C"),
        ("external_temperature", "°C") => ("External temperature", "°C"),
        ("temperature_difference", "K") => ("Temperature difference", "K"),
        ("voltage", "V") => ("Voltage", "V"),
        ("current", "A") => ("Current", "A"),
        _ => return None,
    })
}

/// Compare one decoded telegram with libmbus's reading of it: the identity, every record's
/// storage and tariff, and every value both read as the same physical quantity.
fn compare(name: &str, decoded: &(records::Header, records::Decoded), xml: &str) -> usize {
    let (h, d) = decoded;
    let id = xml
        .split("<Id>")
        .nth(1)
        .and_then(|s| s.split("</Id>").next())
        .unwrap_or("");
    // libmbus prints the identification number as an integer, without leading zeros.
    assert_eq!(
        frame::id_hex(&h.address.id).trim_start_matches('0'),
        id.trim_start_matches('0'),
        "{name}: identification"
    );
    let theirs = norm_records(xml);
    let ours = &d.records;
    assert_eq!(
        ours.len(),
        theirs.len(),
        "{name}: record count\nours: {ours:#?}\nlibmbus: {theirs:#?}"
    );
    let mut values = 0;
    for (i, (r, t)) in ours.iter().zip(&theirs).enumerate() {
        assert_eq!(
            r["storage"].as_u64(),
            Some(t.1),
            "{name} record {i} storage: {r} {t:?}"
        );
        assert_eq!(
            r["tariff"].as_u64().unwrap_or(0),
            t.2,
            "{name} record {i} tariff: {r} {t:?}"
        );
        let (q, u) = (
            r["quantity"].as_str().unwrap_or(""),
            r["unit"].as_str().unwrap_or(""),
        );
        let Some((lq, lu)) = libmbus_name(q, u) else {
            continue;
        };
        assert_eq!(
            (t.3.as_str(), t.4.as_str()),
            (lq, lu),
            "{name} record {i}: {r} {t:?}"
        );
        if r["value"].is_null() {
            // A-F nibbles in a BCD field: no value. libmbus normalises the remaining digits
            // into a number; NetGet reports the digits and no number.
            assert!(r["bcd_digits"].is_string(), "{name} record {i}: {r}");
            continue;
        }
        let ours_v = r["value"].as_f64().unwrap_or(f64::NAN);
        let theirs_v: f64 = t.5.parse().unwrap_or(f64::NAN);
        let close = (ours_v - theirs_v).abs() <= 1e-6 * theirs_v.abs().max(1.0);
        assert!(
            close,
            "{name} record {i}: ours {ours_v} libmbus {theirs_v}: {r} {t:?}"
        );
        values += 1;
    }
    values
}

#[tokio::test]
async fn the_decoder_reads_libmbus_s_real_meter_captures_as_libmbus_does() {
    let dir = frames_dir();
    let mut compared = 0usize;
    let mut values = 0usize;
    let mut refused = Vec::new();
    let mut names: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|e| e == "hex"))
        .collect();
    names.sort();
    for path in names {
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        let norm = path.with_extension("norm.xml");
        let Ok(xml) = std::fs::read_to_string(&norm) else {
            continue;
        };
        let text = std::fs::read_to_string(&path).unwrap();
        let bytes: Vec<u8> = text
            .split_whitespace()
            .filter_map(|h| u8::from_str_radix(h, 16).ok())
            .collect();
        let frame::Parsed::Frame(f, _) = frame::parse(&bytes) else {
            refused.push(format!("{name}: not a whole telegram"));
            continue;
        };
        let (Some(ci), data) = (f.ci(), f.data()) else {
            continue;
        };
        if ci != frame::ci::RSP_VARIABLE {
            // Fixed data (CI 0x73) and the rest: not decoded by NetGet, and said so.
            continue;
        }
        match records::decode_response(ci, data) {
            Ok(decoded) => {
                values += compare(&name, &decoded, &xml);
                compared += 1;
            }
            Err(e) => refused.push(format!("{name}: {e:#}")),
        }
    }
    eprintln!("compared {compared} telegrams, {values} values; refused: {refused:#?}");
    assert!(
        compared >= 70,
        "only {compared} telegrams compared; refused {refused:#?}"
    );
    assert!(values >= 550, "only {values} values compared");
    assert!(
        refused.is_empty(),
        "NetGet refused telegrams libmbus reads: {refused:#?}"
    );
}

#[tokio::test]
async fn mbus_device_serves_real_meter_telegrams_that_the_master_reads_over_tcp() {
    let py = python();
    let device = mbus_device();
    let dir = frames_dir();
    let bridge =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/client/mbus/serial_gateway.py");
    for name in [
        "kamstrup_multical_601",
        "landis+gyr_ultraheat_t230",
        "eastron_sdm630",
        "itron_cyble_m-bus_v1.4_water",
    ] {
        let hex = dir.join(format!("{name}.hex"));
        let xml = std::fs::read_to_string(dir.join(format!("{name}.norm.xml"))).unwrap();
        let mut cmd = Command::new(&py);
        cmd.arg("-I").arg(&bridge).arg("0").arg(&device).args([
            "-d",
            "-a",
            "5",
            "-f",
            hex.to_str().unwrap(),
            "PTY",
        ]);
        let peer = Peer::spawn(cmd);
        assert!(peer.wait_for("LISTENING").await, "{}", peer.text());
        let port: u16 = peer
            .text()
            .lines()
            .find_map(|l| l.strip_prefix("LISTENING "))
            .and_then(|p| p.trim().parse().ok())
            .unwrap();
        assert!(peer.wait_for("Starting up").await, "{}", peer.text());
        let m = support::connect(
            &format!("127.0.0.1:{port}"),
            support::script(
                "import json,sys\ni=json.load(sys.stdin)\na=[{'type':'mbus_read','address':5}] if i['event_type_id']=='mbus_connected' else []\nprint(json.dumps({'actions':a}))",
            ),
            2000,
        )
        .await;
        let data = m.wait_for_events("mbus_data", 1, 60).await;
        let errors = m.events("mbus_error").await;
        assert_eq!(
            data.len(),
            1,
            "{name}: {errors:?}\n{}\n{}",
            m.log_text(),
            peer.text()
        );
        // The same telegram, decoded from the file, must equal what came over the wire.
        let bytes: Vec<u8> = std::fs::read_to_string(&hex)
            .unwrap()
            .split_whitespace()
            .filter_map(|h| u8::from_str_radix(h, 16).ok())
            .collect();
        let frame::Parsed::Frame(f, _) = frame::parse(&bytes) else {
            panic!("{name}")
        };
        let decoded = records::decode_response(f.ci().unwrap(), f.data()).unwrap();
        compare(name, &decoded, &xml);
        assert_eq!(
            data[0]["records"],
            Value::Array(decoded.1.records.clone()),
            "{name}"
        );
        assert_eq!(data[0]["meter"]["id"], frame::id_hex(&decoded.0.address.id));
        // mbus-device saw the SND_NKE and the REQ_UD2 the model's read asked for.
        assert!(peer.wait_for("REQ_UD2").await, "{name}: {}", peer.text());
        assert!(peer.text().contains("SND_NKE"), "{name}: {}", peer.text());
    }
}
