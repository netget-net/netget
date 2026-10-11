//! Shared by the Observe / Block-wise tests: an in-process CoAP server whose every request is
//! answered by a script handler, so no model is involved and every count is exact.
//!
//! The handler plays a small device:
//!
//! - `GET /temp` → 2.05 `t=20` (observable);
//! - `PUT /temp` → 2.04, **and** `coap_notify` of `/temp` with `t=<body>` — the action path a
//!   model would take when a write changes state others observe;
//! - `GET /big` and `GET /big/<n>` → 2.05 with [`body`], 3000 bytes: three Block2 blocks;
//! - `PUT /upload` (or `/upload/<n>`) → 2.04 `got <size> bytes in <blocks> blocks`;
//! - anything else → 4.04.

use netget::cli::management::ServerForm;
use netget::server::coap::CoapServerHandle;
use netget::state::app_state::AppState;
use netget::state::{AccessLogOwner, ServerId};
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

/// The handler, in Python. `BODY` is the same LCG string as [`body`].
pub const HANDLER: &str = r#"import json,sys
x=1; L=[]
for _ in range(3000):
    x=(x*1103515245+12345)%2**31; L.append(chr(97+(x>>16)%26))
BODY=''.join(L)
i=json.load(sys.stdin); e=i['event']; p=e['path']; m=e['method']
if p=='/temp' and m=='GET':
    a=[{'type':'send_coap_response','code':'2.05','payload':'t=20','content_format':'text/plain'}]
elif p=='/temp' and m=='PUT':
    a=[{'type':'send_coap_response','code':'2.04'},
       {'type':'coap_notify','path':'/temp','payload':'t='+e.get('payload',''),'content_format':'text/plain'}]
elif p=='/big' or p.startswith('/big/'):
    a=[{'type':'send_coap_response','code':'2.05','payload':BODY,'content_format':'text/plain'}]
elif (p=='/upload' or p.startswith('/upload/')) and m in ('PUT','POST'):
    a=[{'type':'send_coap_response','code':'2.04','payload':'got %d bytes in %s blocks'%(e.get('payload_size',0),e.get('blocks',1))}]
else:
    a=[{'type':'send_coap_response','code':'4.04'}]
print(json.dumps({'actions':a}))"#;

/// 3000 pseudo-random lowercase letters (an LCG): no short period, so a block served from the
/// wrong offset cannot line up by accident. The peers build the same string.
pub fn body() -> String {
    let mut x: u64 = 1;
    (0..3000)
        .map(|_| {
            x = (x * 1103515245 + 12345) % (1 << 31);
            (b'a' + ((x >> 16) % 26) as u8) as char
        })
        .collect()
}

/// A running server and the handle the actions reach.
pub struct Device {
    pub state: AppState,
    pub id: ServerId,
    pub port: u16,
}

impl Device {
    pub async fn start(startup_params: Option<Value>) -> Device {
        let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
        let (tx, _) = mpsc::unbounded_channel();
        let id = ServerForm {
            protocol: "coap".into(),
            port: Some(0),
            host: Some("127.0.0.1".into()),
            instruction: Some("A small device".into()),
            startup_params,
            event_handlers: Some(vec![json!({
                "event_pattern": "coap_request",
                "handler": {"type": "script", "language": "python", "code": HANDLER}
            })]),
            ..Default::default()
        }
        .create(&state, tx)
        .await
        .expect("the CoAP server did not start");
        let port = tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                if let Some(a) = state.get_server(id).await.and_then(|s| s.local_addr) {
                    break a.port();
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("the CoAP server never bound");
        Device { state, id, port }
    }

    pub async fn handle(&self) -> Arc<CoapServerHandle> {
        self.state
            .server_handle::<CoapServerHandle>(self.id)
            .await
            .expect("the CoAP server registered no handle")
    }

    /// Every `coap_request` the handler answered, oldest first: the event data.
    pub async fn requests(&self) -> Vec<Value> {
        let mut rows: Vec<Value> = self
            .state
            .list_access_logs_for(Some(AccessLogOwner::Server(self.id.as_u32())), None)
            .await
            .iter()
            .map(|e| serde_json::to_value(e).unwrap())
            .filter(|e| e["event_type"] == "coap_request")
            .collect();
        rows.sort_by_key(|e| e["id"].as_u64());
        rows.into_iter().map(|e| e["request"].clone()).collect()
    }

    /// How many requests for `path` reached the handler.
    pub async fn asked(&self, path: &str) -> usize {
        self.requests()
            .await
            .iter()
            .filter(|r| r["path"] == path)
            .count()
    }

    /// Wait until `n` observers are registered.
    pub async fn wait_for_observers(&self, n: usize) {
        let handle = self.handle().await;
        tokio::time::timeout(Duration::from_secs(15), async {
            while handle.observers().len() != n {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap_or_else(|_| {
            panic!(
                "expected {n} observers, have {:?}",
                handle.observers().len()
            )
        });
    }
}
