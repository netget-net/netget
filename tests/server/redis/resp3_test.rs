//! RESP3 against two clients that implement it independently: **redis-cli** with `-3` (the C
//! client, hiredis's RESP3 reader) and **redis-py** 5 with `protocol=3` (its pure-Python
//! `_RESP3Parser`).
//!
//! Both open with `HELLO 3`, which the server answers itself. redis-py also sends its
//! credentials inside `HELLO` (`HELLO 3 AUTH user pass`), which goes to the handler: a wrong
//! password is refused and the connection stays on RESP2, the right one switches it. Every
//! RESP3 reply type is then read back as each client renders or parses it — map, set, double,
//! boolean, big number, verbatim string, null — a push is delivered out of band ahead of the
//! reply it precedes, and the same commands on a RESP2 connection come back downgraded the
//! way Redis downgrades them. `HELLO 4` is refused with `NOPROTO`.
//!
//! redis-cli and a Python with `redis` 5 installed (`NETGET_REDIS_PYTHON`, default `python3`)
//! are required; the tests fail rather than skip without them. No LLM calls: a python handler
//! answers every command.

use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use serde_json::{json, Value};
use std::process::Stdio;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;

/// One reply per command name; `HELLO … AUTH` accepted only with the right password.
const HANDLER: &str = r#"import json,sys
i=json.load(sys.stdin); e=i['event']; c=e['command'].split(); n=c[0].upper() if c else ''
A={'NG.MAP':{'type':'redis_map','entries':[['name','Ada'],['visits',3],['ratio',0.5],['admin',True],['tags',['a','b']],['none',None]]},
 'NG.SET':{'type':'redis_set','values':['red','green']},
 'NG.DOUBLE':{'type':'redis_double','value':3.25},
 'NG.BOOL':{'type':'redis_boolean','value':True},
 'NG.BIG':{'type':'redis_big_number','value':'3492890328409238509324850943850943825024385'},
 'NG.VERBATIM':{'type':'redis_verbatim_string','text':'# Server','format':'txt'},
 'NG.NULL':{'type':'redis_null'},
 'NG.PROTO':{'type':'redis_integer','value':e['protocol']}}
if n=='HELLO':
  a=[{'type':'redis_simple_string','value':'OK'}] if 'lovelace' in c else [{'type':'redis_error','message':'WRONGPASS invalid username-password pair or user is disabled.'}]
elif n=='NG.NOTIFY':
  a=[{'type':'redis_push','values':['message','news','hello']},{'type':'redis_simple_string','value':'OK'}]
elif n in A: a=[A[n]]
else: a=[{'type':'redis_error','message':'ERR unknown command'}]
print(json.dumps({'actions':a}))"#;

/// redis-py: credentials in HELLO, every RESP3 type, a push, a refused password, and RESP2.
const REDIS_PY: &str = r#"import json,sys,redis
port=int(sys.argv[1]); out={}
def conn(proto, password):
    r=redis.Redis(host='127.0.0.1',port=port,protocol=proto,username='ada',password=password,decode_responses=True,socket_timeout=20)
    return r.connection_pool.get_connection('PING')
def cmd(c,*a):
    c.send_command(*a); return c.read_response()
pushes=[]
c=conn(3,'lovelace')
c._parser.set_pubsub_push_handler(pushes.append)
out['hello']=c.handshake_metadata
for n in ['NG.MAP','NG.SET','NG.DOUBLE','NG.BOOL','NG.BIG','NG.VERBATIM','NG.NULL','NG.PROTO','NG.NOTIFY']:
    v=cmd(c,n); out[n]={'type':type(v).__name__,'value':v if not isinstance(v,int) or isinstance(v,bool) else str(v)}
out['pushes']=pushes
try:
    conn(3,'wrong'); out['wrong']='accepted'
except redis.AuthenticationError as e:
    out['wrong']='AuthenticationError: '+str(e)
except redis.ResponseError as e:
    out['wrong']='ResponseError: '+str(e)
c2=redis.Redis(host='127.0.0.1',port=port,protocol=2,decode_responses=True,socket_timeout=20).connection_pool.get_connection('PING')
for n in ['NG.MAP','NG.DOUBLE','NG.BOOL','NG.BIG','NG.PROTO']:
    out['resp2 '+n]=cmd(c2,n)
print(json.dumps(out))"#;

async fn redis_server() -> (AppState, u16) {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    let (tx, _) = mpsc::unbounded_channel();
    let id = ServerForm {
        protocol: "redis".into(),
        port: Some(0),
        host: Some("127.0.0.1".into()),
        instruction: Some("Answer RESP3 test commands".into()),
        event_handlers: Some(vec![
            json!({"event_pattern":"*","handler":{"type":"script","language":"python","code":HANDLER}}),
        ]),
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .unwrap();
    let port = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if let Some(a) = state.get_server(id).await.and_then(|s| s.local_addr) {
                break a.port();
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the Redis server never bound");
    (state, port)
}

/// One redis-cli session, `--no-raw`, commands on stdin, every non-empty line it printed.
async fn redis_cli(port: u16, protocol: &str, commands: &str) -> Vec<String> {
    let mut child = tokio::process::Command::new("redis-cli")
        .args([
            protocol,
            "--no-raw",
            "-h",
            "127.0.0.1",
            "-p",
            &port.to_string(),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("redis-cli is required: apt install redis-tools / brew install redis");
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(commands.as_bytes()).await.unwrap();
    stdin.shutdown().await.unwrap();
    drop(stdin);
    let out = tokio::time::timeout(Duration::from_secs(60), child.wait_with_output())
        .await
        .expect("redis-cli did not finish")
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(
        out.status.success(),
        "redis-cli failed:\n{stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    stdout
        .lines()
        .map(str::trim_end)
        .filter(|l| !l.trim().is_empty())
        .filter(|l| !is_latency_line(l))
        .map(str::to_string)
        .collect()
}

/// redis-cli prints a command's wall time, e.g. `(0.59s)`, on a line of its own whenever the
/// reply took more than half a second. That is the CLI timing itself, not a reply, and on a
/// loaded runner it lands between any two of them, so it is dropped before comparing.
fn is_latency_line(line: &str) -> bool {
    line.strip_prefix('(')
        .and_then(|l| l.strip_suffix("s)"))
        .is_some_and(|n| !n.is_empty() && n.parse::<f64>().is_ok())
}

#[tokio::test]
async fn redis_cli_reads_every_resp3_type_and_its_resp2_downgrade() {
    let (_state, port) = redis_server().await;

    // No big number here: redis-cli 7.0 has no case for hiredis's BIGNUM reply and stops with
    // "Unknown reply type: 13" (redis-py below reads it). Its RESP2 downgrade is checked here.
    let resp3 = redis_cli(
        port,
        "-3",
        "NG.MAP\nNG.SET\nNG.DOUBLE\nNG.BOOL\nNG.VERBATIM\nNG.NULL\nNG.PROTO\n",
    )
    .await;
    let expected = [
        "1# \"name\" => \"Ada\"",
        "2# \"visits\" => (integer) 3",
        "3# \"ratio\" => (double) 0.5",
        "4# \"admin\" => (true)",
        "5# \"tags\" =>",
        "   1) \"a\"",
        "   2) \"b\"",
        "6# \"none\" => (nil)",
        "1~ \"red\"",
        "2~ \"green\"",
        "(double) 3.25",
        "(true)",
        // A verbatim string is printed as its text, unquoted, unlike a bulk string.
        "# Server",
        "(nil)",
        "(integer) 3",
    ];
    assert_eq!(
        resp3,
        expected,
        "redis-cli -3 printed:\n{}",
        resp3.join("\n")
    );

    // The same commands on a connection that never sent HELLO 3.
    let resp2 = redis_cli(
        port,
        "-2",
        "NG.MAP\nNG.SET\nNG.DOUBLE\nNG.BOOL\nNG.BIG\nNG.PROTO\nNG.NOTIFY\nHELLO 4\n",
    )
    .await;
    // A map downgrades to the flat key/value array Redis sends on RESP2 (redis-cli pads the
    // indices of a twelve-element array to one width).
    let expected = [
        " 1) \"name\"",
        " 2) \"Ada\"",
        " 3) \"visits\"",
        " 4) (integer) 3",
        " 5) \"ratio\"",
        " 6) \"0.5\"",
        " 7) \"admin\"",
        " 8) \"1\"",
        " 9) \"tags\"",
        "10) \"[\\\"a\\\",\\\"b\\\"]\"",
        "11) \"none\"",
        "12) (nil)",
        "1) \"red\"",
        "2) \"green\"",
        "\"3.25\"",
        "(integer) 1",
        "\"3492890328409238509324850943850943825024385\"",
        "(integer) 2",
        // The push is refused on RESP2 (no out-of-band frame); the reply after it still comes.
        "OK",
        "(error) NOPROTO unsupported protocol version",
    ];
    assert_eq!(
        resp2,
        expected,
        "redis-cli -2 printed:\n{}",
        resp2.join("\n")
    );
}

#[tokio::test]
async fn redis_py_negotiates_resp3_with_credentials_and_parses_every_type() {
    let python = std::env::var("NETGET_REDIS_PYTHON").unwrap_or_else(|_| "python3".into());
    let probe = std::process::Command::new(&python)
        .args([
            "-c",
            "import redis,sys; sys.exit(0 if int(redis.__version__.split('.')[0])>=5 else 1)",
        ])
        .output();
    assert!(
        probe.is_ok_and(|o| o.status.success()),
        "{python} with redis-py 5 is required: pip install 'redis>=5,<6' (or set NETGET_REDIS_PYTHON)"
    );
    let (_state, port) = redis_server().await;
    let out = tokio::time::timeout(
        Duration::from_secs(60),
        tokio::process::Command::new(&python)
            .args(["-c", REDIS_PY, &port.to_string()])
            .kill_on_drop(true)
            .output(),
    )
    .await
    .expect("redis-py did not finish")
    .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "redis-py failed:\n{stderr}");
    let r: Value = serde_json::from_slice(&out.stdout).unwrap();

    assert_eq!(r["hello"]["server"], "redis", "{r}");
    assert_eq!(r["hello"]["proto"], 3, "{r}");
    assert_eq!(r["hello"]["mode"], "standalone", "{r}");
    assert_eq!(
        r["NG.MAP"],
        json!({"type": "dict", "value": {"name": "Ada", "visits": 3, "ratio": 0.5, "admin": true, "tags": ["a", "b"], "none": null}}),
        "{r}"
    );
    assert_eq!(
        r["NG.SET"],
        json!({"type": "list", "value": ["red", "green"]}),
        "{r}"
    );
    assert_eq!(
        r["NG.DOUBLE"],
        json!({"type": "float", "value": 3.25}),
        "{r}"
    );
    assert_eq!(r["NG.BOOL"], json!({"type": "bool", "value": true}), "{r}");
    assert_eq!(
        r["NG.BIG"],
        json!({"type": "int", "value": "3492890328409238509324850943850943825024385"}),
        "{r}"
    );
    assert_eq!(
        r["NG.VERBATIM"],
        json!({"type": "str", "value": "# Server"}),
        "{r}"
    );
    assert_eq!(
        r["NG.NULL"],
        json!({"type": "NoneType", "value": null}),
        "{r}"
    );
    assert_eq!(r["NG.PROTO"], json!({"type": "int", "value": "3"}), "{r}");
    // The push arrived out of band, before the reply it preceded, which was still read.
    assert_eq!(r["NG.NOTIFY"], json!({"type": "str", "value": "OK"}), "{r}");
    assert_eq!(r["pushes"], json!([["message", "news", "hello"]]), "{r}");
    // A refused password in HELLO is the handler's error, and no switch happened.
    assert!(
        r["wrong"]
            .as_str()
            .unwrap()
            .contains("invalid username-password pair"),
        "{r}"
    );
    // RESP2: Redis's downgrades, as redis-py's RESP2 parser reads them.
    assert_eq!(
        r["resp2 NG.MAP"],
        json!([
            "name",
            "Ada",
            "visits",
            3,
            "ratio",
            "0.5",
            "admin",
            "1",
            "tags",
            "[\"a\",\"b\"]",
            "none",
            null
        ]),
        "{r}"
    );
    assert_eq!(r["resp2 NG.DOUBLE"], "3.25", "{r}");
    assert_eq!(r["resp2 NG.BOOL"], 1, "{r}");
    assert_eq!(
        r["resp2 NG.BIG"], "3492890328409238509324850943850943825024385",
        "{r}"
    );
    assert_eq!(r["resp2 NG.PROTO"], 2, "{r}");
}
