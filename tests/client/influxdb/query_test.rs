//! NetGet's Flux and InfluxQL queries against the official InfluxDB 2.9.1 daemon, plus the
//! reader's edge cases and the reporting bound.
//!
//! The daemon is the third-party server. NetGet writes the series through its own write
//! action, then queries them back in both dialects; what is asserted is the typed structure
//! NetGet built from the daemon's annotated CSV and v1 JSON. The daemon is required — a
//! missing one fails naming `install_daemon.py`.
use super::e2e_test::{response_logs, start};
use netget::client::influxdb::query::{csv_records, read_flux, MAX_REPORTED_ROWS};
use netget::state::{
    app_state::AppState, client_handles::ClientSendOutcome, AccessLogOwner, ClientId,
};
use serde_json::{json, Value};
use std::{process::Stdio, time::Duration};

/// The official daemon on a loopback port in a temp dir of its own, set up with one org and
/// one bucket.
struct Daemon {
    url: String,
    token: String,
    child: tokio::process::Child,
    _root: tempfile::TempDir,
}

async fn daemon() -> Daemon {
    let binary = std::env::var("NETGET_INFLUX_DAEMON").expect(
        "NETGET_INFLUX_DAEMON required; run python3 tests/client/influxdb/install_daemon.py <dir>",
    );
    let root = tempfile::Builder::new()
        .prefix("netget-influx-query-")
        .tempdir()
        .unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let log = std::fs::File::create(root.path().join("daemon.log")).unwrap();
    let mut child = tokio::process::Command::new(&binary)
        .args(["--http-bind-address", &addr.to_string(), "--bolt-path"])
        .arg(root.path().join("influxd.bolt"))
        .arg("--sqlite-path")
        .arg(root.path().join("influxd.sqlite"))
        .arg("--engine-path")
        .arg(root.path().join("engine"))
        .arg("--reporting-disabled")
        .stdout(Stdio::from(log.try_clone().unwrap()))
        .stderr(Stdio::from(log))
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let url = format!("http://{addr}");
    let http = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if http
                .get(format!("{url}/health"))
                .send()
                .await
                .is_ok_and(|r| r.status().is_success())
            {
                break;
            }
            assert!(
                child.try_wait().unwrap().is_none(),
                "daemon exited: {}",
                std::fs::read_to_string(root.path().join("daemon.log")).unwrap()
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("official daemon readiness");
    let setup = http
        .post(format!("{url}/api/v2/setup"))
        .json(&json!({"username":"testuser","password":"owned-test-password","org":"netget","bucket":"telegraf","retentionPeriodSeconds":0}))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    Daemon {
        url,
        token: setup["auth"]["token"].as_str().unwrap().into(),
        child,
        _root: root,
    }
}

async fn send(state: &AppState, id: ClientId, action: Value) {
    let outcome = state
        .send_to_client(id, action, Duration::from_secs(40))
        .await
        .unwrap();
    assert!(
        matches!(outcome, ClientSendOutcome::Executed { .. }),
        "{outcome:?}"
    );
}

/// The query-response events, oldest first, once there are `count`.
async fn answers(state: &AppState, id: ClientId, count: usize) -> Vec<Value> {
    tokio::time::timeout(Duration::from_secs(40), async {
        loop {
            let mut entries = state
                .list_access_logs_for(Some(AccessLogOwner::Client(id.as_u32())), None)
                .await
                .into_iter()
                .filter(|e| e.event_type == "influx_query_response")
                .collect::<Vec<_>>();
            if entries.len() >= count {
                entries.sort_by_key(|e| e.id);
                break entries.into_iter().map(|e| e.request).collect();
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap()
}

fn point(host: &str, ts: i64, usage: f64, count: i64, ok: bool, note: Option<&str>) -> Value {
    let mut fields = json!({
        "usage": {"type": "float", "value": usage},
        "count": {"type": "integer", "value": count},
        "ok": {"type": "boolean", "value": ok},
    });
    if let Some(note) = note {
        fields["note"] = json!({"type": "string", "value": note});
    }
    json!({"measurement": "cpu", "tags": {"host": host}, "fields": fields, "timestamp": ts})
}

const T0: i64 = 1_767_225_600_000_000_000; // 2026-01-01T00:00:00Z

#[tokio::test]
async fn official_daemon_answers_flux_and_influxql_read_into_typed_tables() {
    let mut daemon = daemon().await;
    let (state, id) = start(daemon.url.clone(), None, Some(&daemon.token)).await;
    send(&state, id, json!({"type":"write_influx_points","batch":{"org":"netget","bucket":"telegraf","precision":"ns","points":[
        point("a", T0, 0.5, 3, true, Some("x, \"y\" z")),
        point("a", T0 + 10_000_000_000, 1.25, 7, false, None),
        point("b", T0, 2.5, -1, true, None),
    ]}})).await;
    assert_eq!(response_logs(&state, id, 1).await[0].request["status"], 204);

    // Flux: one table per series and field, typed by the daemon's #datatype annotations.
    let range = "range(start: 2026-01-01T00:00:00Z, stop: 2026-01-02T00:00:00Z)";
    send(&state, id, json!({"type":"query_influx_flux","org":"netget","query":format!("from(bucket: \"telegraf\") |> {range} |> filter(fn: (r) => r._measurement == \"cpu\")")})).await;
    // InfluxQL through the bucket's virtual DBRP mapping: two statements, times as seconds.
    send(&state, id, json!({"type":"query_influxql","db":"telegraf","epoch":"s","query":"SELECT usage, \"count\" FROM cpu WHERE host = 'a'; SELECT usage FROM cpu GROUP BY host"})).await;
    // The daemon's own refusals, in each dialect.
    send(
        &state,
        id,
        json!({"type":"query_influx_flux","org":"netget","query":"frmo(bucket: \"telegraf\")"}),
    )
    .await;
    send(
        &state,
        id,
        json!({"type":"query_influxql","db":"telegraf","query":"SELEC usage FROM cpu"}),
    )
    .await;
    send(&state, id, json!({"type":"query_influx_flux","org":"no-such-org","query":format!("from(bucket: \"telegraf\") |> {range}")})).await;

    let events = answers(&state, id, 5).await;
    let flux = &events[0];
    assert_eq!(flux["status"], 200, "{flux}");
    assert_eq!(flux["error"], Value::Null);
    let tables = flux["tables"].as_array().unwrap();
    assert_eq!(tables.len(), 7, "host a: 4 fields, host b: 3; {flux}");
    assert_eq!(flux["row_count"], 10, "a: 2+2+2+1, b: 1+1+1");
    assert_eq!(flux["truncated"], false);
    let column = |t: &Value, name: &str| -> (usize, Value) {
        let at = t["columns"]
            .as_array()
            .unwrap()
            .iter()
            .position(|c| c["name"] == name)
            .unwrap_or_else(|| panic!("no {name} in {t}"));
        (at, t["columns"][at].clone())
    };
    let table = |host: &str, field: &str| -> &Value {
        tables
            .iter()
            .find(|t| {
                let row = &t["rows"][0];
                row[column(t, "host").0] == host && row[column(t, "_field").0] == field
            })
            .unwrap_or_else(|| panic!("no table {host}/{field}"))
    };
    let values = |t: &Value| -> Vec<Value> {
        let at = column(t, "_value").0;
        t["rows"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r[at].clone())
            .collect()
    };
    assert_eq!(values(table("a", "usage")), vec![json!(0.5), json!(1.25)]);
    assert_eq!(values(table("a", "count")), vec![json!(3), json!(7)]);
    assert_eq!(values(table("a", "ok")), vec![json!(true), json!(false)]);
    assert_eq!(values(table("a", "note")), vec![json!("x, \"y\" z")]);
    assert_eq!(values(table("b", "count")), vec![json!(-1)]);
    let usage = table("a", "usage");
    assert_eq!(column(usage, "_value").1["type"], "double");
    assert_eq!(column(usage, "_value").1["group"], false);
    assert_eq!(column(usage, "host").1["group"], true);
    assert_eq!(column(table("a", "count"), "_value").1["type"], "long");
    assert_eq!(column(usage, "_time").1["type"], "dateTime:RFC3339");
    let times: Vec<Value> = usage["rows"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r[column(usage, "_time").0].clone())
        .collect();
    assert_eq!(
        times,
        vec![json!("2026-01-01T00:00:00Z"), json!("2026-01-01T00:00:10Z")]
    );
    assert!(tables.iter().all(|t| t["result"] == "_result"));

    let ql = &events[1];
    assert_eq!(ql["status"], 200, "{ql}");
    let statements = ql["statements"].as_array().unwrap();
    assert_eq!(statements.len(), 2);
    assert_eq!(
        statements[0]["series"],
        json!([{"name":"cpu","columns":["time","usage","count"],"values":[[1767225600,0.5,3],[1767225610,1.25,7]]}])
    );
    let grouped = statements[1]["series"].as_array().unwrap();
    assert_eq!(
        grouped
            .iter()
            .map(|s| (
                s["tags"]["host"].clone(),
                s["values"].as_array().unwrap().len()
            ))
            .collect::<Vec<_>>(),
        vec![(json!("a"), 2), (json!("b"), 1)]
    );
    assert_eq!(ql["row_count"], 5);

    assert_eq!(events[2]["status"], 400);
    assert_eq!(events[2]["error"]["code"], "invalid");
    assert!(
        events[2]["error"]["message"]
            .as_str()
            .unwrap()
            .contains("frmo"),
        "{}",
        events[2]
    );
    assert_eq!(events[3]["status"], 400);
    assert!(
        events[3]["error"]["message"]
            .as_str()
            .unwrap()
            .contains("expected SELECT"),
        "{}",
        events[3]
    );
    assert_eq!(events[4]["status"], 400, "{}", events[4]);
    assert!(
        events[4]["error"]["message"]
            .as_str()
            .unwrap()
            .contains("\"no-such-org\" not found"),
        "{}",
        events[4]
    );
    for e in &events {
        assert!(!e.to_string().contains(&daemon.token));
    }
    state.remove_client(id).await;

    // A wrong token is the daemon's 401, reported rather than ending the session.
    let (state, id) = start(daemon.url.clone(), None, Some("wrong-token")).await;
    send(
        &state,
        id,
        json!({"type":"query_influxql","db":"telegraf","query":"SELECT usage FROM cpu"}),
    )
    .await;
    assert_eq!(answers(&state, id, 1).await[0]["status"], 401);
    state.remove_client(id).await;
    daemon.child.kill().await.unwrap();
}

/// The answer to a query reaches the model's handlers, and its follow-up runs: connect →
/// write → write response → query → answer, with no model at all.
#[tokio::test]
async fn query_answers_drive_handler_followups() {
    let mut daemon = daemon().await;
    let handlers = vec![
        json!({"event_pattern":"influx_connected","handler":{"type":"static","actions":[{"type":"write_influx_points","batch":{"org":"netget","bucket":"telegraf","points":[point("c", T0, 9.5, 1, true, None)]}}]}}),
        json!({"event_pattern":"influx_write_response","handler":{"type":"static","actions":[{"type":"query_influxql","db":"telegraf","query":"SELECT usage FROM cpu WHERE host = 'c'"}]}}),
    ];
    let (state, id) = start(daemon.url.clone(), Some(handlers), Some(&daemon.token)).await;
    let answer = &answers(&state, id, 1).await[0];
    assert_eq!(
        answer["statements"][0]["series"][0]["values"],
        json!([["2026-01-01T00:00:00Z", 9.5]])
    );
    state.remove_client(id).await;
    daemon.child.kill().await.unwrap();
}

#[test]
fn flux_reader_handles_quoting_defaults_blocks_and_in_band_errors() {
    assert_eq!(
        csv_records("a,\"b,\"\"c\"\"\r\nd\",e\r\n\r\nf\n").unwrap(),
        vec![
            vec!["a".to_string(), "b,\"c\"\r\nd".into(), "e".into()],
            vec![],
            vec!["f".into()]
        ]
    );
    assert!(csv_records("a,\"open").is_err());
    let text = "#datatype,string,long,double,string\r\n#group,false,false,false,true\r\n#default,_result,,7.5,x\r\n,result,table,v,k\r\n,,0,1,a\r\n,,0,,a\r\n,,1,2,\r\n\r\n#datatype,string,long,boolean\r\n#group,false,false,false\r\n#default,_result,,\r\n,result,table,b\r\n,,2,true\r\n";
    let tables = read_flux(text).unwrap();
    assert_eq!(tables.len(), 3);
    assert_eq!(tables[0].rows, vec![json!([1.0, "a"]), json!([7.5, "a"])]);
    assert_eq!(tables[1].rows, vec![json!([2.0, "x"])]);
    assert_eq!(tables[2].rows, vec![json!([true])]);
    assert_eq!(
        tables[0].columns[1],
        json!({"name":"k","type":"string","group":true})
    );
    let failed = "#datatype,string,string\r\n#group,true,true\r\n#default,,\r\n,error,reference\r\n,panic: runtime error,897\r\n";
    assert!(read_flux(failed)
        .unwrap_err()
        .to_string()
        .contains("panic: runtime error"));
    assert!(read_flux("#datatype,string,long\r\n,result,table\r\n,,notanumber\r\n").is_err());
}

/// An answer larger than an event may carry is cut at the bound and says so.
#[tokio::test]
async fn reported_rows_stop_at_the_bound() {
    let rows: Vec<Value> = (0..MAX_REPORTED_ROWS + 1).map(|n| json!([n])).collect();
    let handler = json!({"event_pattern":"influx_query","handler":{"type":"static","actions":[{"type":"send_influx_query_result","tables":[{"columns":[{"name":"n","type":"long"}],"rows":rows}]}]}});
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    let (tx, _) = tokio::sync::mpsc::unbounded_channel();
    let server = netget::cli::management::ServerForm {
        protocol: "influxdb".into(),
        host: Some("127.0.0.1".into()),
        port: Some(0),
        instruction: Some(String::new()),
        event_handlers: Some(vec![handler]),
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .unwrap();
    let addr = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Some(addr) = state.get_server(server).await.and_then(|s| s.local_addr) {
                break addr;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let (client_state, id) = start(addr.to_string(), None, None).await;
    send(
        &client_state,
        id,
        json!({"type":"query_influx_flux","org":"o","query":"from(bucket: \"b\")"}),
    )
    .await;
    send(
        &client_state,
        id,
        json!({"type":"query_influxql","query":"SELECT n FROM b"}),
    )
    .await;
    let events = answers(&client_state, id, 2).await;
    for e in &events {
        assert_eq!(e["row_count"], MAX_REPORTED_ROWS + 1, "{}", e["error"]);
        assert_eq!(e["reported_rows"], MAX_REPORTED_ROWS);
        assert_eq!(e["truncated"], true);
    }
    assert_eq!(
        events[0]["tables"][0]["rows"].as_array().unwrap().len(),
        MAX_REPORTED_ROWS
    );
    assert_eq!(
        events[1]["statements"][0]["series"][0]["values"]
            .as_array()
            .unwrap()
            .len(),
        MAX_REPORTED_ROWS
    );
    client_state.remove_client(id).await;
    state.remove_server(server).await;
}
