//! Flux and InfluxQL queries against four independent clients, two per dialect, plus the
//! bounds and the fail-closed paths.
//!
//! NetGet holds no series, so every answer here comes from one script handler that plays the
//! store: it reads the `influx_query` event and returns tables. What the tests check is what
//! each client made of NetGet's bytes — the Flux annotated CSV through InfluxData's Python and
//! JavaScript parsers, the v1 JSON through InfluxData's v1 Python client and node-influx.
//!
//! Every peer is required: a missing one fails the test naming `install_peers.py`.
use super::e2e_test::{logs, start};
use serde_json::{json, Value};
use std::{net::SocketAddr, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

const TOKEN: &str = "query-secret";

/// The store: Flux answers two tables of different shapes; InfluxQL answers each statement by
/// what it selects from, and a statement it does not know is a per-statement error. A query
/// containing DENY is refused as a whole.
const STORE: &str = r#"
import json,sys
x=json.load(sys.stdin)['event']
cpu={"measurement":"cpu","tags":{"host":"a,\"b\""},"columns":[
 {"name":"_time","type":"dateTime:RFC3339"},{"name":"_value","type":"double"},
 {"name":"_field","type":"string","group":True},{"name":"count","type":"long"},
 {"name":"big","type":"unsignedLong"},{"name":"ok","type":"boolean"}],
 "rows":[["2026-01-01T00:00:00Z",0.5,"usage",-3,18446744073709551615,True],
         ["2026-01-01T00:00:10.5Z",1.25,"usage",None,0,False]]}
mem={"measurement":"mem","tags":{"host":"b"},"columns":[
 {"name":"_time","type":"dateTime:RFC3339"},{"name":"_value","type":"long"}],
 "rows":[["2026-01-01T00:01:00Z",4096]]}
def v1(s):
  if 'FROM cpu' in s:
    return {"tables":[{"measurement":"cpu","tags":{"host":"a"},"columns":[
      {"name":"time","type":"dateTime:RFC3339"},{"name":"usage","type":"double"},
      {"name":"count","type":"long"},{"name":"ok","type":"boolean"},{"name":"note","type":"string"}],
      "rows":[["2026-01-01T00:00:00Z",0.5,-3,True,"x, \"y\""],["2026-01-01T00:00:10Z",1.25,7,False,None]]}]}
  if 'FROM mem' in s:
    return {"tables":[{"measurement":"mem","tags":{"host":h},"columns":[
      {"name":"time","type":"dateTime:RFC3339"},{"name":"mean","type":"double"}],
      "rows":[["2026-01-01T00:00:00Z",m]]} for h,m in [("a",10.5),("b",20.25)]]}
  if 'FROM missing' in s:
    return {"tables":[]}
  return {"error":"error parsing query: found "+s.split()[0]+", expected SELECT"}
if 'DENY' in x['query']:
  a={"type":"send_influx_query_error","status":403,"message":"query denied by policy"}
elif x['language']=='flux':
  if 'frmo' in x['query']:
    a={"type":"send_influx_query_error","status":400,"message":"error @1:1-1:5: undefined identifier frmo"}
  else:
    a={"type":"send_influx_query_result","tables":[] if 'empty' in x['query'] else [cpu,mem]}
else:
  a={"type":"send_influx_query_result","statements":[v1(s) for s in x['statements']]}
print(json.dumps({"actions":[a]}))
"#;

async fn start_store() -> (
    netget::state::app_state::AppState,
    netget::state::ServerId,
    SocketAddr,
) {
    start(
        Some(vec![json!({"event_pattern":"influx_query","handler":{"type":"script","language":"python","code":STORE}})]),
        Some(json!({"auth_token": TOKEN})),
    )
    .await
}

fn required(var: &str) -> String {
    std::env::var(var).unwrap_or_else(|_| {
        panic!(
            "{var} is required; run python3 tests/server/influxdb/install_peers.py <dir> \
             and export what it prints"
        )
    })
}

async fn run(program: String, args: &[&str], envs: &[(&str, String)]) {
    let mut command = tokio::process::Command::new(&program);
    command.args(args).kill_on_drop(true);
    for (k, v) in envs {
        command.env(k, v);
    }
    let out = tokio::time::timeout(Duration::from_secs(60), command.output())
        .await
        .expect("peer timed out")
        .unwrap_or_else(|e| panic!("{program} could not run: {e}"));
    assert!(
        out.status.success(),
        "peer failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

async fn python(script: &str, addr: SocketAddr) {
    run(
        required("NETGET_INFLUX_PYTHON"),
        &["-c", script, &addr.port().to_string()],
        &[],
    )
    .await
}

async fn node(script: &str, addr: SocketAddr) {
    run(
        "node".into(),
        &["-e", script, "--", &addr.port().to_string()],
        &[("NODE_PATH", required("NETGET_INFLUX_NODE_MODULES"))],
    )
    .await
}

/// One raw request; the status and the body as text.
async fn raw(
    addr: SocketAddr,
    method: &str,
    target: &str,
    headers: &str,
    body: &[u8],
) -> (u16, String) {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(
            format!(
                "{method} {target} HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n{headers}\r\n",
                body.len()
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    stream.write_all(body).await.unwrap();
    let mut bytes = Vec::new();
    tokio::time::timeout(Duration::from_secs(20), stream.read_to_end(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    let wire = String::from_utf8(bytes).unwrap();
    let (head, body) = wire.split_once("\r\n\r\n").unwrap();
    (
        head.split_whitespace().nth(1).unwrap().parse().unwrap(),
        body.into(),
    )
}

/// The access log lists newest first.
fn oldest(
    entries: &[netget::state::app_state::AccessLogEntry],
) -> &netget::state::app_state::AccessLogEntry {
    entries.last().expect("no access log entries")
}

#[tokio::test]
async fn flux_through_influxdatas_python_client_parses_types_groups_and_errors() {
    let (state, id, addr) = start_store().await;
    let script = r#"
import importlib.metadata,json,sys,datetime
assert importlib.metadata.version('influxdb-client')=='1.50.0'
from influxdb_client import InfluxDBClient
from influxdb_client.rest import ApiException
utc=datetime.timezone.utc
with InfluxDBClient(url='http://127.0.0.1:'+sys.argv[1],token='query-secret',org='my org',timeout=10000) as c:
  q=c.query_api()
  tables=q.query('from(bucket:"telegraf") |> range(start:-1h)')
  assert len(tables)==2, tables
  cpu,mem=tables
  r0,r1=cpu.records
  assert r0.get_time()==datetime.datetime(2026,1,1,tzinfo=utc), r0.get_time()
  assert r1.get_time()==datetime.datetime(2026,1,1,0,0,10,500000,tzinfo=utc), r1.get_time()
  assert r0.get_value()==0.5 and isinstance(r0.get_value(),float)
  assert r0.get_measurement()=='cpu' and r0.get_field()=='usage'
  assert r0.values['host']=='a,"b"', r0.values
  assert r0.values['count']==-3 and r1.values['count'] is None
  assert r0.values['big']==2**64-1 and r1.values['big']==0
  assert r0.values['ok'] is True and r1.values['ok'] is False
  assert r0.values['result']=='_result' and r0.values['table']==0
  assert sorted(c.label for c in cpu.get_group_key())==['_field','_measurement','host'], cpu.get_group_key()
  m=mem.records[0]
  assert m.get_value()==4096 and isinstance(m.get_value(),int) and m.values['table']==1
  assert q.query('from(bucket:"empty") |> range(start:-1h)')==[]
  try: q.query('frmo(bucket:"x")')
  except ApiException as e:
    assert e.status==400, e.status
    assert json.loads(e.body)=={'code':'invalid','message':'error @1:1-1:5: undefined identifier frmo'}, e.body
  else: raise AssertionError('error reported as success')
with InfluxDBClient(url='http://127.0.0.1:'+sys.argv[1],token='wrong',org='my org',timeout=10000) as c:
  try: c.query_api().query('from(bucket:"x")')
  except ApiException as e: assert e.status==401
  else: raise AssertionError('wrong token answered')
"#;
    python(script, addr).await;
    let entries = logs(&state, id, 3).await;
    let first = &oldest(&entries).request;
    assert_eq!(first["language"], "flux");
    assert_eq!(first["org"], "my org");
    assert_eq!(
        first["query"],
        "from(bucket:\"telegraf\") |> range(start:-1h)"
    );
    assert!(entries
        .iter()
        .all(|e| !e.request.to_string().contains(TOKEN)));
    state.remove_server(id).await;
}

#[tokio::test]
async fn flux_through_influxdatas_javascript_client() {
    let (state, id, addr) = start_store().await;
    let script = r#"
const assert=require('assert');
const {InfluxDB,HttpError}=require('@influxdata/influxdb-client');
(async()=>{
  const api=new InfluxDB({url:'http://127.0.0.1:'+process.argv.at(-1),token:'query-secret'}).getQueryApi('my org');
  const rows=await api.collectRows('from(bucket:"telegraf") |> range(start:-1h)');
  assert.strictEqual(rows.length,3);
  const [r0,r1,m]=rows;
  assert.strictEqual(r0._time,'2026-01-01T00:00:00Z');
  assert.strictEqual(r1._time,'2026-01-01T00:00:10.5Z');
  assert.strictEqual(r0._value,0.5);
  assert.strictEqual(r0.count,-3);
  assert.strictEqual(r1.count,null);
  assert.strictEqual(r0.ok,true); assert.strictEqual(r1.ok,false);
  assert.strictEqual(r0.host,'a,"b"');
  assert.strictEqual(r0._measurement,'cpu'); assert.strictEqual(r0.table,0);
  assert.strictEqual(m._measurement,'mem'); assert.strictEqual(m._value,4096); assert.strictEqual(m.table,1);
  const lines=await api.collectLines('from(bucket:"telegraf") |> range(start:-1h)');
  assert.ok(lines.includes('#group,false,false,false,false,true,false,false,false,true,true'), lines.join('\n'));
  assert.deepStrictEqual(await api.collectRows('from(bucket:"empty") |> range(start:-1h)'),[]);
  try { await api.collectRows('frmo(bucket:"x")'); assert.fail('error reported as success'); }
  catch(e){ assert.ok(e instanceof HttpError, e); assert.strictEqual(e.statusCode,400);
            assert.strictEqual(e.json.message,'error @1:1-1:5: undefined identifier frmo'); }
})().catch(e=>{console.error(e);process.exit(1)});
"#;
    node(script, addr).await;
    assert!(logs(&state, id, 4).await.len() >= 4);
    state.remove_server(id).await;
}

#[tokio::test]
async fn influxql_through_influxdatas_v1_python_client() {
    let (state, id, addr) = start_store().await;
    let script = r#"
import importlib.metadata,sys
assert importlib.metadata.version('influxdb')=='5.3.2'
from influxdb import InfluxDBClient
from influxdb.exceptions import InfluxDBClientError
c=InfluxDBClient(host='127.0.0.1',port=int(sys.argv[1]),username='anyone',password='query-secret',database='telegraf',timeout=10)
cpu,mem=c.query('SELECT usage,count FROM cpu WHERE time > now() - 1h; SELECT mean(used) FROM mem GROUP BY host')
points=list(cpu.get_points('cpu'))
assert points[0]=={'time':'2026-01-01T00:00:00Z','usage':0.5,'count':-3,'ok':True,'note':'x, "y"'}, points
assert points[1]['note'] is None and points[1]['ok'] is False
assert list(cpu.keys())==[('cpu',{'host':'a'})], list(cpu.keys())
assert [p['mean'] for p in mem.get_points(tags={'host':'b'})]==[20.25]
assert sorted(t['host'] for _,t in mem.keys())==['a','b']
ms=c.query('SELECT usage FROM cpu', epoch='ms')
assert [p['time'] for p in ms.get_points()]==[1767225600000,1767225610000], list(ms.get_points())
assert list(c.query('SELECT usage FROM missing').get_points())==[]
try: c.query('SELECT usage FROM cpu; DROP everything')
except InfluxDBClientError as e: assert 'expected SELECT' in str(e), e
else: raise AssertionError('statement error reported as success')
try: c.query('SELECT DENY FROM cpu')
except InfluxDBClientError as e: assert e.code==403 and 'denied' in e.content, (e.code, e.content)
else: raise AssertionError('refusal reported as success')
bad=InfluxDBClient(host='127.0.0.1',port=int(sys.argv[1]),username='anyone',password='wrong',database='telegraf',timeout=10)
try: bad.query('SELECT usage FROM cpu')
except InfluxDBClientError as e: assert e.code==401, e.code
else: raise AssertionError('wrong password answered')
"#;
    python(script, addr).await;
    let entries = logs(&state, id, 5).await;
    let first = &oldest(&entries).request;
    assert_eq!(first["language"], "influxql");
    assert_eq!(first["db"], "telegraf");
    assert_eq!(
        first["statements"],
        json!([
            "SELECT usage,count FROM cpu WHERE time > now() - 1h",
            "SELECT mean(used) FROM mem GROUP BY host"
        ])
    );
    assert!(entries.iter().any(|e| e.request["epoch"] == "ms"));
    assert!(entries
        .iter()
        .all(|e| !e.request.to_string().contains(TOKEN)));
    state.remove_server(id).await;
}

#[tokio::test]
async fn influxql_through_node_influx() {
    let (state, id, addr) = start_store().await;
    let script = r#"
const assert=require('assert');
const Influx=require('influx');
(async()=>{
  const influx=new Influx.InfluxDB({host:'127.0.0.1',port:+process.argv.at(-1),database:'telegraf',username:'anyone',password:'query-secret'});
  const [cpu,mem]=await influx.query(['SELECT usage,count FROM cpu','SELECT mean(used) FROM mem GROUP BY host']);
  assert.strictEqual(cpu.length,2);
  assert.strictEqual(cpu[0].time.toNanoISOString(),'2026-01-01T00:00:00.000000000Z');
  assert.strictEqual(cpu[0].usage,0.5); assert.strictEqual(cpu[0].count,-3);
  assert.strictEqual(cpu[0].host,'a'); assert.strictEqual(cpu[0].note,'x, "y"');
  assert.deepStrictEqual(mem.groups().map(g=>[g.tags.host,g.rows[0].mean]),[['a',10.5],['b',20.25]]);
  const s=await influx.query('SELECT usage FROM cpu',{precision:'s'});
  assert.strictEqual(s[0].time.getNanoTime(),'1767225600000000000');
  assert.deepStrictEqual([...await influx.query('SELECT usage FROM missing')],[]);
  await assert.rejects(influx.query('SELECT usage FROM cpu; DROP everything'),/expected SELECT/);
  const bad=new Influx.InfluxDB({host:'127.0.0.1',port:+process.argv.at(-1),database:'telegraf',username:'anyone',password:'wrong'});
  await assert.rejects(bad.query('SELECT usage FROM cpu'),/401|unauthorized/);
})().catch(e=>{console.error(e);process.exit(1)});
"#;
    node(script, addr).await;
    assert!(logs(&state, id, 4).await.len() >= 4);
    state.remove_server(id).await;
}

/// Without a handler, and without the model opted in, nothing can answer: 503 in each
/// dialect's own shape, never an empty result standing in for "no data".
#[tokio::test]
async fn unanswerable_and_invalid_answers_fail_closed_in_each_dialect() {
    let (state, id, addr) = start(None, None).await;
    let (status, body) = raw(
        addr,
        "POST",
        "/api/v2/query?org=o",
        "Content-Type: application/json\r\n",
        br#"{"query":"from(bucket:\"b\")"}"#,
    )
    .await;
    assert_eq!(status, 503);
    assert_eq!(
        serde_json::from_str::<Value>(&body).unwrap()["code"],
        "unavailable"
    );
    let (status, body) = raw(addr, "GET", "/query?db=d&q=SELECT%20a%20FROM%20b", "", b"").await;
    assert_eq!(status, 503);
    assert!(serde_json::from_str::<Value>(&body).unwrap()["error"].is_string());
    state.remove_server(id).await;

    // A long column holding a fraction is refused, not rounded onto the wire.
    let lie = json!({"event_pattern":"influx_query","handler":{"type":"static","actions":[{"type":"send_influx_query_result","tables":[{"columns":[{"name":"n","type":"long"}],"rows":[[0.5]]}]}]}});
    // One table for a two-statement InfluxQL query does not say which statement it answers.
    let (state, id, addr) = start(Some(vec![lie]), None).await;
    let (status, _) = raw(
        addr,
        "POST",
        "/api/v2/query",
        "Content-Type: application/vnd.flux\r\n",
        b"from(bucket:\"b\")",
    )
    .await;
    assert_eq!(status, 503);
    state.remove_server(id).await;
    let one = json!({"event_pattern":"influx_query","handler":{"type":"static","actions":[{"type":"send_influx_query_result","tables":[]}]}});
    let (state, id, addr) = start(Some(vec![one]), None).await;
    let (status, _) = raw(addr, "GET", "/query?q=SELECT%201%3B%20SELECT%202", "", b"").await;
    assert_eq!(status, 503);
    let (status, body) = raw(addr, "GET", "/query?q=SELECT%201", "", b"").await;
    assert_eq!(
        (status, body.as_str()),
        (200, r#"{"results":[{"statement_id":0}]}"#)
    );
    state.remove_server(id).await;
}

/// Each declared bound, one past it.
#[tokio::test]
async fn query_and_answer_bounds_are_enforced() {
    use netget::server::influxdb::query::*;
    let echo = json!({"event_pattern":"influx_query","handler":{"type":"static","actions":[{"type":"send_influx_query_result","tables":[]}]}});
    let (state, id, addr) = start(Some(vec![echo]), None).await;
    let at = "a".repeat(MAX_QUERY_BYTES);
    let past = "a".repeat(MAX_QUERY_BYTES + 1);
    for (query, want) in [(&at, 200), (&past, 400)] {
        let body = json!({ "query": query }).to_string();
        let (status, _) = raw(
            addr,
            "POST",
            "/api/v2/query",
            "Content-Type: application/json\r\n",
            body.as_bytes(),
        )
        .await;
        assert_eq!(status, want, "Flux of {} bytes", query.len());
    }
    let statements = |n: usize| vec!["SELECT 1"; n].join(";");
    for (n, want) in [(MAX_STATEMENTS, 503), (MAX_STATEMENTS + 1, 400)] {
        // At the bound the request is admitted (and then the one-table answer fails closed).
        let body = format!("q={}", statements(n).replace(' ', "+").replace(';', "%3B"));
        let (status, _) = raw(
            addr,
            "POST",
            "/query",
            "Content-Type: application/x-www-form-urlencoded\r\n",
            body.as_bytes(),
        )
        .await;
        assert_eq!(status, want, "{n} statements");
    }
    let (status, _) = raw(addr, "GET", "/query?q=SELECT+1&chunked=true", "", b"").await;
    assert_eq!(
        status, 400,
        "chunked is refused rather than answered unchunked"
    );
    state.remove_server(id).await;

    let column = json!({"name": "v", "type": "long"});
    let table = |columns: usize, rows: usize| json!({"columns": vec![column.clone(); columns], "rows": vec![vec![json!(1); columns]; rows]});
    let validate =
        |tables: Vec<Value>| tables_from_json(&json!(tables), &mut 0, &mut 0).map(|_| ());
    assert!(validate(vec![table(1, 1); MAX_RESULT_TABLES]).is_ok());
    assert!(validate(vec![table(1, 1); MAX_RESULT_TABLES + 1]).is_err());
    assert!(validate(vec![table(MAX_RESULT_COLUMNS, 1)]).is_ok());
    assert!(validate(vec![table(MAX_RESULT_COLUMNS + 1, 1)]).is_err());
    assert!(validate(vec![table(1, MAX_RESULT_ROWS)]).is_ok());
    assert!(validate(vec![
        table(1, MAX_RESULT_ROWS / 2 + 1),
        table(1, MAX_RESULT_ROWS / 2)
    ])
    .is_err());
    let cell = |n: usize| json!([{"columns": [{"name": "s", "type": "string"}], "rows": [[ "x".repeat(n) ]]}]);
    assert!(tables_from_json(&cell(MAX_CELL_BYTES), &mut 0, &mut 0).is_ok());
    assert!(tables_from_json(&cell(MAX_CELL_BYTES + 1), &mut 0, &mut 0).is_err());

    // The rendered answer: 70 cells of 64 KiB pass every per-value bound and 4 MiB together.
    let big = json!([{"columns": [{"name": "s", "type": "string"}], "rows": vec![json!(["x".repeat(MAX_CELL_BYTES)]); 70]}]);
    let tables = tables_from_json(&big, &mut 0, &mut 0).unwrap();
    assert!(render_flux(&tables).is_err());
    assert!(render_influxql(&[StatementResult::Tables(tables)], None).is_err());
    let handler = json!({"event_pattern":"influx_query","handler":{"type":"static","actions":[{"type":"send_influx_query_result","tables":big}]}});
    let (state, id, addr) = start(Some(vec![handler]), None).await;
    let (status, _) = raw(
        addr,
        "POST",
        "/api/v2/query",
        "Content-Type: application/vnd.flux\r\n",
        b"x",
    )
    .await;
    assert_eq!(status, 503);
    state.remove_server(id).await;
}

/// `/ping` answers as InfluxDB does, and the v1 credential forms reach only InfluxQL.
#[tokio::test]
async fn ping_and_credential_forms() {
    let (state, id, addr) = start(None, Some(json!({"auth_token": TOKEN}))).await;
    let (status, body) = raw(addr, "GET", "/ping", "", b"").await;
    assert_eq!((status, body.as_str()), (204, ""));
    // `p` is the v1 form; on the Flux endpoint it is not a credential at all.
    let (status, _) = raw(
        addr,
        "POST",
        "/api/v2/query?p=query-secret",
        "Content-Type: application/vnd.flux\r\n",
        b"x",
    )
    .await;
    assert_eq!(status, 401);
    let (status, _) = raw(addr, "GET", "/query?q=SELECT+1&p=wrong", "", b"").await;
    assert_eq!(status, 401);
    // Right credential, no handler: admitted, and then nothing can answer.
    let (status, _) = raw(addr, "GET", "/query?q=SELECT+1&p=query-secret", "", b"").await;
    assert_eq!(status, 503);
    state.remove_server(id).await;
}
