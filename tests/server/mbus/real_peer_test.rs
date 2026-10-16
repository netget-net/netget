//! Two independent M-Bus masters against NetGet's gateway: rSCADA **libmbus** 0.10.3 (C), whose
//! `mbus-tcp-*` tools are what M-Bus/IP gateways are usually driven with, and **pyMeterBus**
//! 0.8.5 (Python), whose framing helpers and record decoder share no code with libmbus or with
//! NetGet. Every tool talks to a real socket; nothing here is mocked except the model, which is
//! the python policy of `support.rs`.
//!
//! These tests fail, rather than skip, when a peer is missing:
//!
//! ```text
//! sh scripts/test-peers/build-libmbus.sh /abs/dir     # then LIBMBUS_BIN=/abs/dir/bin
//! python3 -m venv /abs/venv && /abs/venv/bin/pip install pyMeterBus==0.8.5
//!                                                     # then MBUS_PYTHON=/abs/venv/bin/python
//! ```
//!
//! libmbus waits a fixed four seconds for every answer that does not come (and after every
//! answer, to see whether a second meter answered too), so a wildcard search here takes about a
//! minute. That is the tool's own timing, not NetGet's.
use super::support::{self, Gateway, HEAT, WATER};
use serde_json::Value;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;

fn libmbus(tool: &str) -> PathBuf {
    if let Ok(dir) = std::env::var("LIBMBUS_BIN") {
        let p = PathBuf::from(dir).join(tool);
        assert!(
            p.is_file(),
            "LIBMBUS_BIN is set but {} does not exist; build libmbus with \
             `sh scripts/test-peers/build-libmbus.sh <dir>`",
            p.display()
        );
        return p;
    }
    if let Some(p) = std::env::var_os("PATH").and_then(|path| {
        std::env::split_paths(&path)
            .map(|d| d.join(tool))
            .find(|p| p.is_file())
    }) {
        return p;
    }
    panic!(
        "{tool} (rSCADA libmbus) is required and was not found. Neither Homebrew nor Ubuntu \
         package libmbus; build the pinned 0.10.3 tools with \
         `sh scripts/test-peers/build-libmbus.sh /abs/dir` and set LIBMBUS_BIN=/abs/dir/bin. \
         Skipping would leave the M-Bus slave's evidence resting on nothing."
    )
}

fn python() -> String {
    let py = std::env::var("MBUS_PYTHON").unwrap_or_else(|_| "python3".into());
    let ok = std::process::Command::new(&py)
        .args(["-I", "-c", "import meterbus, serial"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    assert!(
        ok,
        "pyMeterBus is required: `python3 -m venv /abs/venv && /abs/venv/bin/pip install \
         pyMeterBus==0.8.5`, then MBUS_PYTHON=/abs/venv/bin/python ({py} cannot import \
         meterbus and serial)"
    );
    py
}

/// Run a tool to completion: (exit status, stdout, stderr).
async fn run(tool: &str, args: &[String], limit: Duration) -> (i32, String, String) {
    let out = tokio::time::timeout(
        limit,
        Command::new(libmbus(tool))
            .args(args)
            .kill_on_drop(true)
            .output(),
    )
    .await
    .unwrap_or_else(|_| panic!("{tool} {args:?} did not finish in {limit:?}"))
    .unwrap_or_else(|e| panic!("{tool} could not run: {e}"));
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn args(g: &Gateway, rest: &[&str]) -> Vec<String> {
    let mut v = vec!["127.0.0.1".to_string(), g.port.to_string()];
    v.extend(rest.iter().map(|s| s.to_string()));
    v
}

/// The text of every `<tag>` in `xml`, in order.
fn all(xml: &str, tag: &str) -> Vec<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    xml.split(&open)
        .skip(1)
        .filter_map(|s| s.split(&close).next())
        .map(|s| s.trim().to_string())
        .collect()
}

#[tokio::test]
async fn libmbus_reads_the_models_readings_with_the_right_units() {
    let g = support::start(support::policy(), support::params()).await;
    let (code, xml, err) = run(
        "mbus-tcp-request-data",
        &args(&g, &["1"]),
        Duration::from_secs(60),
    )
    .await;
    assert_eq!(code, 0, "{err}\n{xml}");
    assert_eq!(all(&xml, "Id"), ["12345678"], "{xml}");
    assert_eq!(all(&xml, "Manufacturer"), ["KAM"], "{xml}");
    assert_eq!(all(&xml, "Version"), ["1"], "{xml}");
    assert_eq!(all(&xml, "Medium"), ["Heat: Outlet"], "{xml}");
    let units = all(&xml, "Unit");
    let values = all(&xml, "Value");
    assert_eq!(
        units,
        [
            "Energy (kWh)",
            "Volume (m m^3)",
            "Flow temperature (1e-1 deg C)",
            "Energy (10 kWh)",
            "Time Point (date)"
        ],
        "{xml}"
    );
    assert_eq!(
        values,
        ["12345", "456789", "654", "1100", "2026-09-30"],
        "{xml}"
    );
    assert_eq!(
        all(&xml, "StorageNumber"),
        ["0", "0", "0", "1", "1"],
        "{xml}"
    );
    assert_eq!(all(&xml, "Tariff"), ["1"], "{xml}");

    // The water meter by secondary address: a real in litres, a negative BCD value marked as
    // a value during error state, and the power-low status bit.
    let (code, xml, err) = run(
        "mbus-tcp-request-data",
        &args(&g, &[WATER]),
        Duration::from_secs(60),
    )
    .await;
    assert_eq!(code, 0, "{err}\n{xml}");
    assert_eq!(all(&xml, "Id"), ["12345679"], "{xml}");
    assert_eq!(all(&xml, "Manufacturer"), ["ELS"], "{xml}");
    assert_eq!(all(&xml, "Medium"), ["Water"], "{xml}");
    assert_eq!(all(&xml, "Status"), ["04"], "{xml}");
    // libmbus's (unnormalised) XML prints a BCD value's digits as stored: F042 is the sign
    // nibble F and the digits 042 — negative 42 litres. pyMeterBus reads the sign below.
    assert_eq!(all(&xml, "Value"), ["1234.500000", "F042"], "{xml}");
    assert_eq!(
        all(&xml, "Unit"),
        ["Volume (m m^3)", "Volume (m m^3)"],
        "{xml}"
    );
    assert_eq!(
        all(&xml, "Function"),
        ["Instantaneous value", "Value during error state"],
        "{xml}"
    );

    // A mask matching both meters: libmbus sees the second answer and refuses to guess.
    let (code, out, err) = run(
        "mbus-tcp-request-data",
        &args(&g, &["1234567FFFFFFFFF"]),
        Duration::from_secs(60),
    )
    .await;
    assert_ne!(code, 0, "{out}");
    assert!(err.contains("matches more than one device"), "{err}\n{out}");

    let events = g.events("mbus_request_data").await;
    assert_eq!(events[1]["addressed_by"], "secondary");
    assert_eq!(events[1]["meter"]["secondary_address"], WATER);
}

#[tokio::test]
async fn libmbus_finds_the_meters_by_primary_scan_and_by_wildcard_search() {
    let g = support::start(support::policy(), support::params()).await;
    // The primary scan pings 0-250 and waits four seconds on every silent address; with -d it
    // flushes as it goes, so it is stopped once it has moved past the last meter.
    let mut scan = Command::new(libmbus("mbus-tcp-scan"))
        .args(["-d", "127.0.0.1", &g.port.to_string()])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("mbus-tcp-scan runs");
    let mut lines = BufReader::new(scan.stdout.take().unwrap()).lines();
    let mut seen = String::new();
    let finished = tokio::time::timeout(Duration::from_secs(90), async {
        while let Ok(Some(line)) = lines.next_line().await {
            seen.push_str(&line);
            seen.push('\n');
            if seen.contains("Found a M-Bus device at address 2") {
                return true;
            }
        }
        false
    })
    .await;
    let _ = scan.kill().await;
    assert!(matches!(finished, Ok(true)), "the scan output:\n{seen}");
    assert!(seen.contains("Found a M-Bus device at address 1"), "{seen}");
    assert!(!seen.contains("address 0"), "{seen}");
    assert!(!seen.contains("Collision"), "{seen}");

    // The wildcard search narrows the last identification digit and reads each meter for its
    // whole secondary address.
    let (code, out, err) = run(
        "mbus-tcp-scan-secondary",
        &args(&g, &["1234567FFFFFFFFF"]),
        Duration::from_secs(180),
    )
    .await;
    assert_eq!(code, 0, "{err}\n{out}");
    assert!(
        out.contains(&format!("Found a device on secondary address {HEAT}")),
        "{out}\n{err}"
    );
    assert!(
        out.contains(&format!("Found a device on secondary address {WATER}")),
        "{out}\n{err}"
    );
}

#[tokio::test]
async fn libmbus_reads_a_multi_telegram_readout_by_toggling_the_fcb() {
    let g = support::start(support::script(support::BIG_POLICY), support::params()).await;
    let (code, xml, err) = run(
        "mbus-tcp-request-data-multi-reply",
        &args(&g, &["1"]),
        Duration::from_secs(180),
    )
    .await;
    assert_eq!(code, 0, "{err}\n{xml}");
    let storages: Vec<u64> = all(&xml, "StorageNumber")
        .iter()
        .map(|s| s.parse().unwrap())
        .collect();
    assert_eq!(storages, (0..120).collect::<Vec<u64>>(), "{xml}");
    let values: Vec<String> = all(&xml, "Value");
    assert_eq!(values.first().map(String::as_str), Some("1000"));
    assert_eq!(values.last().map(String::as_str), Some("1119"));
    assert_eq!(
        g.events("mbus_request_data").await.len(),
        1,
        "every telegram after the first comes from the same readout"
    );
}

#[tokio::test]
async fn libmbus_resets_and_writes_are_the_models_to_accept() {
    let g = support::start(support::policy(), support::params()).await;
    let (code, out, err) = run(
        "mbus-tcp-application-reset",
        &args(&g, &["1"]),
        Duration::from_secs(60),
    )
    .await;
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("Successful reset device"), "{out}\n{err}");
    assert_eq!(g.events("mbus_application_reset").await.len(), 1);

    // A SND_UD setting the bus address (DIF 01, VIF 7A, 07), written out by hand from
    // EN 13757-3 and parsed by libmbus before it sends it.
    let dir = std::env::temp_dir().join(format!("netget-mbus-raw-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let heat = dir.join("heat.hex");
    std::fs::write(&heat, "68 06 06 68 53 01 51 01 7A 07 27 16").unwrap();
    let (code, out, err) = run(
        "mbus-tcp-raw-send",
        &args(&g, &["1", heat.to_str().unwrap()]),
        Duration::from_secs(60),
    )
    .await;
    assert_eq!(code, 0, "the heat meter acknowledges: {err}\n{out}");
    let (code, xml, err) = run(
        "mbus-tcp-request-data",
        &args(&g, &["7"]),
        Duration::from_secs(60),
    )
    .await;
    assert_eq!(code, 0, "the meter answers at its new address: {err}");
    assert_eq!(all(&xml, "Id"), ["12345678"]);
    // The water meter refuses every write: libmbus gets no answer.
    let water = dir.join("water.hex");
    std::fs::write(&water, "68 06 06 68 53 02 51 01 7A 09 2A 16").unwrap();
    let (code, out, err) = run(
        "mbus-tcp-raw-send",
        &args(&g, &["2", water.to_str().unwrap()]),
        Duration::from_secs(60),
    )
    .await;
    assert_ne!(code, 0, "the water meter refused: {out}");
    assert!(err.contains("Failed to receive"), "{err}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn pymeterbus_decodes_the_same_telegrams_with_its_own_decoder() {
    let py = python();
    let g = support::start(support::policy(), support::params()).await;
    let script =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/server/mbus/pymeterbus_master.py");
    let out = tokio::time::timeout(
        Duration::from_secs(120),
        Command::new(&py)
            .arg("-I")
            .arg(&script)
            .args([g.port.to_string(), HEAT.to_string(), WATER.to_string()])
            .kill_on_drop(true)
            .output(),
    )
    .await
    .expect("pyMeterBus master finished")
    .expect("pyMeterBus master ran");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "{}\n{stdout}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| panic!("{e}: {stdout}"));
    assert_eq!(v["ping"], serde_json::json!([0xE5]));
    let heat = &v["heat"]["body"];
    assert_eq!(heat["header"]["manufacturer"], "KAM", "{v}");
    let records = heat["records"].as_array().unwrap();
    let pairs: Vec<(String, String)> = records
        .iter()
        .map(|r| (r["type"].to_string(), r["value"].to_string()))
        .collect();
    assert_eq!(pairs.len(), 5, "{pairs:?}");
    assert_eq!(
        pairs[0],
        ("\"VIFUnit.ENERGY_WH\"".into(), "12345000".into()),
        "{pairs:?}"
    );
    assert_eq!(
        pairs[1],
        ("\"VIFUnit.VOLUME\"".into(), "456.789".into()),
        "{pairs:?}"
    );
    assert_eq!(
        pairs[2],
        ("\"VIFUnit.FLOW_TEMPERATURE\"".into(), "65.4".into()),
        "{pairs:?}"
    );
    assert_eq!(
        pairs[3],
        ("\"VIFUnit.ENERGY_WH\"".into(), "11000000".into()),
        "{pairs:?}"
    );
    assert_eq!(
        pairs[4],
        ("\"VIFUnit.DATE\"".into(), "\"2026-09-30\"".into()),
        "{pairs:?}"
    );
    assert_eq!(records[3]["storage_number"], 1, "{v}");
    assert_eq!(records[3]["tariff"], 1, "{v}");
    assert_eq!(v["fcb_repeat_identical"], true, "{v}");
    let access = v["fcb_access_numbers"].as_array().unwrap();
    assert_eq!(access[0], access[1], "{v}");
    assert_eq!(v["select_water"], serde_json::json!([0xE5]));
    assert_eq!(v["water"]["body"]["header"]["manufacturer"], "ELS", "{v}");
    let water = v["water"]["body"]["records"].as_array().unwrap();
    assert_eq!(water[0]["value"].as_f64(), Some(1.2345), "{v}");
    assert_eq!(water[1]["value"].as_f64(), Some(-0.042), "{v}");
    assert_eq!(
        water[1]["function"], "FunctionType.ERROR_STATE_VALUE",
        "{v}"
    );
    assert_eq!(v["select_heat"], serde_json::json!([0xE5]));
    assert_eq!(
        v["heat_secondary"]["body"]["header"]["manufacturer"], "KAM",
        "{v}"
    );
}
