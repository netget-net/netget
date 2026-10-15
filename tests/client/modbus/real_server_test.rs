//! The Modbus client against a real **pymodbus** device — the evidence its maturity rating
//! rests on.
//!
//! NetGet frames Modbus/TCP with the codec its own server uses (`src/server/modbus/codec.rs`).
//! The device here is **pymodbus 3.15**, a Python implementation with its own framer and its
//! own datastore, run as a subprocess `StartAsyncTcpServer` over a `SimDevice` on a probed
//! loopback port. What the device holds is read back with **`mbpoll`**, a C master on
//! libmodbus. Nothing on the wire was written by this repository except NetGet.
//!
//! Condition 4 of the client bar — the client acts on the model's answer, asserted on the wire
//! — is asserted from the device's side: `mbpoll` reads back registers the mocked model wrote
//! with values computed from a read it was shown, and a coil it turned on.
//!
//! **No test here skips.** A missing `python3`, `pymodbus` or `mbpoll` fails with the install
//! command.
//!
//! LLM calls: 7 in the first test. None in the second, whose model endpoint is unreachable on
//! purpose: every event it raises fails with `decision=llm_error` and the injected actions do not
//! care.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features modbus --test client -- modbus::real_server_test --test-threads=100

use crate::helpers::real_server::{run_tool, InstallHint, RealServer};
use crate::helpers::*;
use serde_json::json;
use std::process::Command;
use std::time::Duration;

const PYMODBUS: InstallHint = InstallHint {
    brew: "python@3.12 && python3 -m pip install 'pymodbus==3.15.*'",
    apt: "python3-pip && python3 -m pip install 'pymodbus==3.15.*'",
};
const MBPOLL: InstallHint = InstallHint {
    brew: "mbpoll",
    apt: "mbpoll",
};

/// A pymodbus 3.15 device, unit 1, with separate coil / discrete-input / holding / input
/// blocks of 100 items each at address 0. Discrete inputs 0-2 are `1 0 1` and input registers
/// 0-2 are `100 200 300`; everything else starts at zero. Address 100 and up does not exist,
/// so a read there is answered with exception 2, illegal data address.
const DEVICE_PY: &str = r#"
import asyncio, logging, sys
from pymodbus.server import StartAsyncTcpServer
from pymodbus.simulator import SimData, SimDevice, DataType

logging.basicConfig(level=logging.INFO, stream=sys.stdout)
port = int(sys.argv[1])
device = SimDevice(
    id=1,
    simdata=(
        [SimData(0, values=[False] * 100, datatype=DataType.BITS)],
        [SimData(0, values=[True, False, True] + [False] * 97, datatype=DataType.BITS)],
        [SimData(0, values=[0] * 100, datatype=DataType.REGISTERS)],
        [SimData(0, values=[100, 200, 300] + [0] * 97, datatype=DataType.REGISTERS)],
    ),
)
asyncio.run(StartAsyncTcpServer(context=device, address=("127.0.0.1", port)))
"#;

async fn start_device() -> E2EResult<RealServer> {
    RealServer::builder("python3", PYMODBUS)
        .config_file("device.py", DEVICE_PY)
        .args(["{dir}/device.py", "{port}"])
        .ready_when_log_matches("Server listening")
        .start()
        .await
}

/// `mbpoll` reading `count` items of `table` (0 coil, 1 discrete input, 3 input register,
/// 4 holding register) from 0-based `address`, as `(address, value)` pairs.
async fn mbpoll_read(
    device: &RealServer,
    table: &str,
    address: u16,
    count: u16,
) -> E2EResult<Vec<(u16, i64)>> {
    let mut cmd = Command::new("mbpoll");
    cmd.args([
        "-m",
        "tcp",
        "-p",
        &device.port.to_string(),
        "-a",
        "1",
        "-t",
        table,
        "-r",
        &address.to_string(),
        "-c",
        &count.to_string(),
        "-0",
        "-1",
        "127.0.0.1",
    ]);
    let out = run_tool(cmd, "mbpoll", MBPOLL).await?;
    let mut values = Vec::new();
    for line in out.lines() {
        // "[10]: 	101"
        let Some(rest) = line.trim().strip_prefix('[') else {
            continue;
        };
        let Some((addr, value)) = rest.split_once("]:") else {
            continue;
        };
        if let (Ok(a), Ok(v)) = (addr.trim().parse(), value.trim().parse()) {
            values.push((a, v));
        }
    }
    Ok(values)
}

/// Read, compute, write — and the device, read by `mbpoll`, holds what the model decided.
///
/// 1. On `modbus_connected` the model reads input registers 0-2 (FC 4).
/// 2. Shown `[100, 200, 300]`, it writes each plus one to holding registers 10-12 (FC 16).
/// 3. On that acknowledgement it turns coil 4 on (FC 5).
/// 4. On that acknowledgement it reads discrete inputs 0-2 (FC 2), shown `[true, false, true]`,
///    and then reads holding register 200, which does not exist (FC 3).
/// 5. It is shown `modbus_exception` code 2, `illegal_data_address`.
///
/// Then `mbpoll` must read `101 201 301` from holding registers 10-12 and `1` from coil 4.
///
/// LLM calls: 7 (startup, connected, five responses).
#[tokio::test]
async fn modbus_client_reads_computes_and_writes_against_pymodbus() -> E2EResult<()> {
    let device = start_device().await?;
    let result = reads_computes_and_writes(&device).await;
    device.with_log(result)
}

async fn reads_computes_and_writes(device: &RealServer) -> E2EResult<()> {
    let addr = device.addr();
    let config = NetGetConfig::new(format!(
        "Connect to the Modbus device at {addr}. MODBUS-REAL-SERVER-STARTUP."
    ))
    .with_mock(move |mock| {
        mock.on_instruction_containing("MODBUS-REAL-SERVER-STARTUP")
            .respond_with_actions(json!([{
                "type": "open_client",
                "protocol": "Modbus",
                "remote_addr": addr,
                "instruction": "Copy the input registers into holding registers 10-12 plus one, \
                                start the pump, then check the inputs.",
                "startup_params": {"unit_id": 1}
            }]))
            .expect_calls(1)
            .and()
            .on_event("modbus_connected")
            .and_event_data_contains("unit_id", "1")
            .respond_with_actions(json!([{
                "type": "modbus_read_input_registers",
                "address": 0,
                "quantity": 3
            }]))
            .expect_calls(1)
            .and()
            .on_event("modbus_read_response")
            .and_event_data_contains("function", "read_input_registers")
            .and_event_data_contains("values", "[100,200,300]")
            .respond_with_actions_from_event(|event| {
                let plus_one: Vec<u64> = event["values"]
                    .as_array()
                    .map(|a| a.iter().filter_map(|v| v.as_u64()).map(|v| v + 1).collect())
                    .unwrap_or_default();
                json!([{
                    "type": "modbus_write_multiple_registers",
                    "address": 10,
                    "values": plus_one
                }])
            })
            .expect_calls(1)
            .and()
            .on_event("modbus_write_response")
            .and_event_data_contains("function", "write_multiple_registers")
            .and_event_data_contains("values", "[101,201,301]")
            .respond_with_actions(json!([{
                "type": "modbus_write_single_coil",
                "address": 4,
                "value": true
            }]))
            .expect_calls(1)
            .and()
            .on_event("modbus_write_response")
            .and_event_data_contains("function", "write_single_coil")
            .respond_with_actions(json!([
                {"type": "modbus_read_discrete_inputs", "address": 0, "quantity": 3},
                {"type": "modbus_read_holding_registers", "address": 200, "quantity": 1}
            ]))
            .expect_calls(1)
            .and()
            .on_event("modbus_read_response")
            .and_event_data_contains("function", "read_discrete_inputs")
            .and_event_data_contains("values", "[true,false,true]")
            .respond_with_actions(json!([]))
            .expect_calls(1)
            .and()
            .on_event("modbus_exception")
            .and_event_data_contains("function", "read_holding_registers")
            .and_event_data_contains("name", "illegal_data_address")
            .and_event_data_contains("code", "2")
            .respond_with_actions(json!([]))
            .expect_calls(1)
            .and()
    });

    let client = start_netget_client(config).await?;
    client.wait_for_mocks(30).await;
    client.verify_mocks().await?;

    assert_eq!(
        mbpoll_read(device, "4", 10, 3).await?,
        vec![(10, 101), (11, 201), (12, 301)],
        "the device must hold the registers the model computed from its read"
    );
    assert_eq!(
        mbpoll_read(device, "0", 4, 1).await?,
        vec![(4, 1)],
        "the device must hold the coil the model turned on"
    );

    client.stop().await?;
    Ok(())
}

/// The dashboard's `[ send ]` / MCP `send_to_client` path, against the same device: FC 6 and
/// FC 15 injected and read back by `mbpoll`, and two requests the codec refuses before the wire.
#[tokio::test]
async fn injected_modbus_writes_reach_pymodbus() -> E2EResult<()> {
    let device = start_device().await?;
    let result = injected_writes(&device).await;
    device.with_log(result)
}

async fn injected_writes(device: &RealServer) -> E2EResult<()> {
    use ::netget::cli::management::ClientForm;
    use ::netget::state::app_state::AppState;
    use ::netget::state::client_handles::ClientSendOutcome;
    use ::netget::state::ClientStatus;

    let state = AppState::new_with_options(false, "http://127.0.0.1:1".to_string());
    let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
    let client_id = ClientForm {
        protocol: "modbus".to_string(),
        remote_addr: Some(device.addr()),
        instruction: Some("test client".to_string()),
        ..Default::default()
    }
    .create(
        &state,
        ::netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
        tx,
    )
    .await
    .map_err(|e| format!("create modbus client: {e}"))?;
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    while !state.has_client_handle(client_id).await {
        if std::time::Instant::now() > deadline {
            return Err("modbus client never registered a command handle".into());
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }

    let send = |action: serde_json::Value| {
        let state = &state;
        async move {
            state
                .send_to_client(client_id, action, Duration::from_secs(10))
                .await
        }
    };

    // MBAP (7) + FC 6 PDU (5).
    let outcome = send(json!({
        "type": "modbus_write_single_register", "address": 20, "value": 4242
    }))
    .await?;
    assert!(
        matches!(outcome, ClientSendOutcome::Sent { bytes_sent: 12 }),
        "expected Sent{{12}}, got {outcome:?}"
    );
    // MBAP (7) + FC 15 PDU (6 + one data octet) — or queued behind the FC 6 if the device has
    // not answered it yet, since the client keeps one transaction on the wire at a time.
    let outcome = send(json!({
        "type": "modbus_write_multiple_coils", "address": 30, "values": [true, false, true, true]
    }))
    .await?;
    assert!(
        matches!(&outcome, ClientSendOutcome::Sent { bytes_sent: 14 })
            || matches!(&outcome, ClientSendOutcome::Executed { detail } if detail.contains("queued")),
        "expected Sent{{14}} or queued, got {outcome:?}"
    );
    for refused in [
        json!({"type": "modbus_write_single_register", "address": 20, "value": 70000}),
        json!({"type": "modbus_read_holding_registers", "address": 0, "quantity": 0}),
    ] {
        let outcome = send(refused.clone()).await?;
        assert!(
            matches!(outcome, ClientSendOutcome::Rejected { .. }),
            "{refused} must be refused before the wire, got {outcome:?}"
        );
    }

    let mut register = Vec::new();
    let mut coils = Vec::new();
    for _ in 0..100 {
        register = mbpoll_read(device, "4", 20, 1).await?;
        coils = mbpoll_read(device, "0", 30, 4).await?;
        if register == vec![(20, 4242)] && coils == vec![(30, 1), (31, 0), (32, 1), (33, 1)] {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(
        register,
        vec![(20, 4242)],
        "the injected FC 6 must reach the device"
    );
    assert_eq!(
        coils,
        vec![(30, 1), (31, 0), (32, 1), (33, 1)],
        "the injected FC 15 must reach the device with its bits in order"
    );

    let outcome = send(json!({"type": "disconnect"})).await?;
    assert!(
        matches!(outcome, ClientSendOutcome::Disconnected),
        "expected Disconnected, got {outcome:?}"
    );
    for _ in 0..300 {
        let status = state.get_client(client_id).await.map(|c| c.status);
        if matches!(status, Some(ClientStatus::Disconnected))
            && !state.has_client_handle(client_id).await
        {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    Err("client should be Disconnected with no command handle".into())
}
