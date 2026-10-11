//! The X11 client against **Xvfb**, the X.Org server with a virtual framebuffer. Every effect
//! is read back with the X.Org utilities `xprop` and `xwininfo`, which are separate clients of
//! the same server, so what NetGet did is asserted from the server's side of the wire.
//!
//! The chain: read a property `xprop` set on the root window, create a window titled from it,
//! then label that window (WM_CLASS, a CARDINAL) and list the root's children. Injected actions
//! cover an X error, a resize and disconnecting (the server then destroys the window). A
//! second Xvfb runs with access control on: no cookie is refused with the server's reason, the
//! right MIT-MAGIC-COOKIE-1 connects, over the server's Unix socket.
//!
//! Fails rather than skips without Xvfb, xprop, xwininfo and xauth
//! (`apt-get install xvfb x11-utils xauth`). No LLM calls.
use crate::helpers::real_server::{find_binary, InstallHint, RealServer};
use netget::{
    cli::management::ClientForm,
    state::{
        app_state::AppState, client_handles::ClientSendOutcome, AccessLogOwner, ClientId,
        ClientStatus,
    },
};
use serde_json::{json, Value};
use std::time::Duration;
use tokio::sync::mpsc;

const XVFB: InstallHint = InstallHint {
    brew: "xquartz (which ships Xvfb)",
    apt: "xvfb",
};
const COOKIE: &str = "00112233445566778899aabbccddeeff";

/// An Xvfb on a display nobody holds, with `extra` arguments. Xvfb prints the display on fd 1
/// once it is listening, which is the readiness signal; a display another test took in the
/// meantime is retried on a different number.
///
/// `-noreset` matters: an X server resets when its last client disconnects, dropping every
/// property and atom, so a value `xprop` sets would be gone before NetGet connects.
pub async fn xvfb(extra: &[&str]) -> (RealServer, u16) {
    for _ in 0..5 {
        let display = loop {
            let n = 1000 + rand::random::<u16>() % 8000;
            let free = std::net::TcpListener::bind(("127.0.0.1", 6000 + n)).is_ok()
                && !std::path::Path::new(&format!("/tmp/.X{n}-lock")).exists();
            if free {
                break n;
            }
        };
        let mut args: Vec<String> = [
            format!(":{display}"),
            "-displayfd".into(),
            "1".into(),
            "-listen".into(),
            "tcp".into(),
            "-nolisten".into(),
            "inet6".into(),
            "-noreset".into(),
            "-screen".into(),
            "0".into(),
            "800x600x24".into(),
        ]
        .to_vec();
        args.extend(extra.iter().map(|s| s.to_string()));
        let started = RealServer::builder("Xvfb", XVFB)
            .args(args)
            .without_tcp_readiness()
            .ready_when_log_matches(&format!("(?m)^{display}\\s*$"))
            .startup_timeout(Duration::from_secs(30))
            .start()
            .await;
        match started {
            Ok(server) => return (server, display),
            // How a lost race for the display reads depends on which socket Xvfb lost it on:
            // the lock file ("already active"), the TCP port ("Address already in use"), or
            // every listener at once ("Cannot establish any listening sockets", which Xvfb
            // prefixes with "server already running").
            Err(e)
                if [
                    "already active",
                    "Address already in use",
                    "server already running",
                    "Cannot establish any listening sockets",
                ]
                .iter()
                .any(|lost| e.to_string().contains(lost)) =>
            {
                continue
            }
            Err(e) => panic!("Xvfb: {e}"),
        }
    }
    panic!("no free X display after 5 attempts");
}

/// Run an X.Org utility against the display; its standard output.
pub fn tool(bin: &str, display: u16, args: &[&str]) -> String {
    let path = find_binary(bin).unwrap_or_else(|| {
        panic!("{bin} is required: apt-get install x11-utils xauth (brew install xquartz)")
    });
    let out = std::process::Command::new(path)
        .arg("-display")
        .arg(format!("127.0.0.1:{display}"))
        .args(args)
        .output()
        .unwrap();
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

pub async fn client(
    remote: String,
    params: Value,
    handlers: Vec<Value>,
) -> anyhow::Result<(AppState, ClientId)> {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    let (tx, _) = mpsc::unbounded_channel();
    let id = ClientForm {
        protocol: "x11".into(),
        remote_addr: Some(remote),
        instruction: Some("Manage windows".into()),
        event_handlers: Some(handlers),
        startup_params: Some(params),
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1"),
        tx,
    )
    .await?;
    Ok((state, id))
}

/// The first event of `event_type` whose data satisfies `pred`, waiting for it.
pub async fn wait_match(
    state: &AppState,
    id: ClientId,
    event_type: &str,
    pred: impl Fn(&Value) -> bool,
) -> Value {
    let found = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let found = state
                .list_access_logs_for(Some(AccessLogOwner::Client(id.as_u32())), None)
                .await
                .iter()
                .map(|e| serde_json::to_value(e).unwrap())
                .filter(|e| e["event_type"] == event_type)
                .map(|e| e["request"].clone())
                .find(|r| pred(r));
            if let Some(e) = found {
                return e;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    match found {
        Ok(e) => e,
        Err(_) => {
            let seen: Vec<String> = state
                .list_access_logs_for(Some(AccessLogOwner::Client(id.as_u32())), None)
                .await
                .iter()
                .map(|e| serde_json::to_string(e).unwrap())
                .collect();
            panic!(
                "no matching {event_type} event; the client recorded:\n{}",
                seen.join("\n")
            )
        }
    }
}

const CHAIN: &str = r#"import json,sys
e=json.load(sys.stdin)['event']
a=[]
if e['action']=='x11_get_property' and e.get('exists'):
  a=[{'type':'x11_create_window','width':320,'height':200,'x':10,'y':20,'title':'netget: '+e['value'],'watch':['structure']}]
elif e['action']=='x11_create_window':
  w=e['window']
  a=[{'type':'x11_set_property','window':w,'property':'WM_CLASS','property_type':'STRING','value':['netget','NetGet']},
     {'type':'x11_set_property','window':w,'property':'NETGET_SIZE','property_type':'CARDINAL','value':[e['width'],e['height']]},
     {'type':'x11_query_tree'}]
print(json.dumps({'actions':a}))"#;

fn chain() -> Vec<Value> {
    vec![
        json!({"event_pattern":"x11_connected","handler":{"type":"static","actions":[
            {"type":"x11_get_property","window":"root","property":"NETGET_GREETING"}]}}),
        json!({"event_pattern":"x11_result","handler":{"type":"script","language":"python","code":CHAIN}}),
        json!({"event_pattern":"*","handler":{"type":"static","actions":[]}}),
    ]
}

async fn send(state: &AppState, id: ClientId, action: Value) -> String {
    match state
        .send_to_client(id, action.clone(), Duration::from_secs(30))
        .await
        .unwrap()
    {
        ClientSendOutcome::Executed { detail } => detail,
        other => panic!("{action}: {other:?}"),
    }
}

#[tokio::test]
async fn netget_against_xvfb() {
    let (xvfb, display) = xvfb(&["-ac"]).await;
    let set = tool(
        "xprop",
        display,
        &[
            "-root",
            "-f",
            "NETGET_GREETING",
            "8u",
            "-set",
            "NETGET_GREETING",
            "hello from xprop",
        ],
    );
    assert!(set.trim().is_empty(), "xprop -set: {set}");
    let (state, id) = client(format!("127.0.0.1:{}", 6000 + display), json!({}), chain())
        .await
        .expect("connect");

    let connected = wait_match(&state, id, "x11_connected", |_| true).await;
    assert_eq!(connected["screen"]["width"], 800, "{connected}");
    assert_eq!(connected["vendor"], "The X.Org Foundation", "{connected}");
    let tree = wait_match(&state, id, "x11_result", |r| {
        r["action"] == "x11_query_tree"
    })
    .await;
    let created = wait_match(&state, id, "x11_result", |r| {
        r["action"] == "x11_create_window"
    })
    .await;
    let window = created["window"].as_str().unwrap().to_string();
    assert!(
        tree["children"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["window"] == window && c["title"] == "netget: hello from xprop"),
        "{tree}"
    );
    // The X server's own view, through other clients.
    let listed = tool("xwininfo", display, &["-root", "-tree"]);
    assert!(
        listed.contains(&format!("{window} \"netget: hello from xprop\"")),
        "{listed}\n{}",
        xvfb.log()
    );
    let props = tool("xprop", display, &["-id", &window]);
    assert!(
        props.contains("WM_CLASS(STRING) = \"netget\", \"NetGet\""),
        "{props}"
    );
    assert!(
        props.contains("_NET_WM_NAME(UTF8_STRING) = \"netget: hello from xprop\""),
        "{props}"
    );
    assert!(
        props.contains("NETGET_SIZE(CARDINAL) = 320, 200"),
        "{props}"
    );
    // The window was created watching its structure, so mapping it was reported.
    wait_match(&state, id, "x11_event", |e| {
        e["event"] == "MapNotify" && e["window"] == window
    })
    .await;

    // A window that does not exist: the server's refusal reaches the model. GetGeometry takes
    // any drawable, so X names it BadDrawable.
    let refused = send(
        &state,
        id,
        json!({"type":"x11_get_geometry","window":"0x1"}),
    )
    .await;
    let refused: Value = serde_json::from_str(&refused).unwrap();
    assert_eq!(
        (&refused["error"], &refused["request"]),
        (&json!("BadDrawable"), &json!("GetGeometry")),
        "{refused}"
    );
    wait_match(&state, id, "x11_error", |e| e["error"] == "BadDrawable").await;
    // An error on a request that has no reply is matched to its action by the sync.
    let refused = send(&state, id, json!({"type":"x11_map_window","window":"0x2"})).await;
    assert!(
        refused.contains("BadWindow") && refused.contains("MapWindow"),
        "{refused}"
    );

    // Resize, then read the geometry back from the server.
    send(
        &state,
        id,
        json!({"type":"x11_configure_window","window":window,"width":640,"height":480}),
    )
    .await;
    let info = tool("xwininfo", display, &["-id", &window]);
    assert!(
        info.contains("Width: 640") && info.contains("Height: 480"),
        "{info}"
    );
    let geometry: Value = serde_json::from_str(
        &send(
            &state,
            id,
            json!({"type":"x11_get_geometry","window":window}),
        )
        .await,
    )
    .unwrap();
    assert_eq!(
        (&geometry["width"], &geometry["height"]),
        (&json!(640), &json!(480)),
        "{geometry}"
    );
    // Read back a property NetGet wrote, through NetGet.
    let read: Value = serde_json::from_str(
        &send(
            &state,
            id,
            json!({"type":"x11_get_property","window":window,"property":"WM_CLASS"}),
        )
        .await,
    )
    .unwrap();
    assert_eq!(read["value"], json!(["netget", "NetGet"]), "{read}");

    // Disconnecting: the server destroys the client's window.
    assert!(matches!(
        state
            .send_to_client(id, json!({"type":"disconnect"}), Duration::from_secs(10))
            .await
            .unwrap(),
        ClientSendOutcome::Disconnected
    ));
    tokio::time::timeout(Duration::from_secs(10), async {
        while tool("xwininfo", display, &["-root", "-tree"]).contains(&window) {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("the window outlived the connection");
}

#[tokio::test]
async fn mit_magic_cookie_over_the_unix_socket() {
    let dir = tempfile::tempdir().unwrap();
    let auth = dir.path().join("Xauthority");
    let xauth = find_binary("xauth").expect("xauth is required: apt-get install xauth");
    let added = std::process::Command::new(xauth)
        .args(["-f", auth.to_str().unwrap(), "add", ":0", ".", COOKIE])
        .output()
        .unwrap();
    assert!(added.status.success(), "{added:?}");
    let (_xvfb, display) = xvfb(&["-auth", auth.to_str().unwrap()]).await;
    let socket = format!("/tmp/.X11-unix/X{display}");

    let e = client(String::new(), json!({"socket_path": socket}), vec![])
        .await
        .err()
        .expect("connected without a cookie");
    assert!(format!("{e:#}").contains("Authorization required"), "{e:#}");
    let wrong = client(
        String::new(),
        json!({"socket_path": socket, "auth_cookie": "ffeeddccbbaa99887766554433221100"}),
        vec![],
    )
    .await;
    assert!(wrong.is_err(), "connected with the wrong cookie");

    let (state, id) = client(
        String::new(),
        json!({"socket_path": socket, "auth_cookie": COOKIE}),
        vec![json!({"event_pattern":"*","handler":{"type":"static","actions":[]}})],
    )
    .await
    .expect("the right cookie connects");
    let extensions: Value =
        serde_json::from_str(&send(&state, id, json!({"type":"x11_list_extensions"})).await)
            .unwrap();
    assert!(
        extensions["extensions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e == "BIG-REQUESTS"),
        "{extensions}"
    );
    assert!(matches!(
        state.get_client(id).await.unwrap().status,
        ClientStatus::Connected
    ));
}
