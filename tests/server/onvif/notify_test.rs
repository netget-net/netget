//! NetGet's ONVIF device delivering Basic Notification (WS-BaseNotification push) to consumers
//! run by two independent ONVIF clients, each a subprocess that binds its own loopback consumer:
//!
//! - **python onvif-zeep-async** 4.3.0's NotificationManager (Home Assistant's webhook path),
//!   reading each Notify with the manager's own `process()` — `peer/zeep_notify.py`;
//! - **Go github.com/use-go/onvif** v0.0.9's `event.Subscribe`, its consumer a net/http server —
//!   `peer/go`, mode `notify`.
//!
//! Each client subscribes; the model accepts (and raises the motion alarm in its answer); when
//! the client prints that it is subscribed the test raises a DigitalInput through
//! `onvif_raise_event`, as the model or an operator would; both must arrive at the consumer with
//! their topic, source and data. Then Renew, Unsubscribe, and Subscribes naming a consumer
//! outside the device's allowlist and an https one, refused before the model is asked. The tests
//! fail, not skip, without the clients. No LLM calls.
use super::real_client_test::{credentials, env, events, policy, start_logged, PASSWORD, USER};
use super::services_test::{raise, run_streaming, sent};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

/// Every message every Notify carried, as the client read it.
fn delivered(r: &Value, key: &str) -> Vec<Value> {
    r["notifies"]
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|n| n[key].as_array().cloned().unwrap_or_default())
        .collect()
}

fn find<'a>(messages: &'a [Value], topic: &str) -> &'a Value {
    messages
        .iter()
        .find(|m| m["topic"] == topic)
        .unwrap_or_else(|| panic!("no {topic} in {messages:?}"))
}

fn digital_input() -> Value {
    json!({"type": "onvif_raise_event", "topic": "tns1:Device/Trigger/DigitalInput",
           "source": {"InputToken": "door_contact"}, "data": {"LogicalState": true}})
}

/// The consumer refusals the device logged, by reason.
async fn refusals(
    state: &netget::state::app_state::AppState,
    id: netget::state::ServerId,
) -> Vec<String> {
    events(state, id, "onvif_notify_refused")
        .await
        .iter()
        .map(|e| e["reason"].as_str().unwrap_or_default().to_string())
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn onvif_zeep_async_notification_manager_receives_the_notify() {
    let (state, id, port, log) = start_logged(policy(), credentials()).await;
    let script = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/server/onvif/peer/zeep_notify.py"
    );
    let raised = Arc::new(Mutex::new(None));
    let r = {
        let (state, raised) = (state.clone(), raised.clone());
        run_streaming(
            &env("NETGET_ONVIF_PYTHON"),
            &[
                "-I".into(),
                script.into(),
                "127.0.0.1".into(),
                port.to_string(),
                USER.into(),
                PASSWORD.into(),
            ],
            move |line| {
                let (state, raised) = (state.clone(), raised.clone());
                let subscribed = line.contains("\"subscribed\"");
                Box::pin(async move {
                    if subscribed {
                        *raised.lock().unwrap() = Some(raise(&state, id, digital_input()).await);
                    }
                })
            },
        )
        .await
    };
    sent(
        "onvif-zeep-async",
        &log,
        &["events:Subscribe", "events:Renew", "events:Unsubscribe"],
    );
    assert!(r.get("timed_out").is_none(), "{r}");
    assert_eq!(
        raised.lock().unwrap().clone(),
        Some(json!({"delivered": 1}))
    );
    let consumer = r["consumer"].as_str().unwrap_or_default().to_string();
    let address = r["subscription_address"].as_str().unwrap_or_default();
    assert!(
        address.starts_with(&format!(
            "http://127.0.0.1:{port}/onvif/events/subscription/"
        )),
        "{r}"
    );
    let notifies = r["notifies"].as_array().cloned().unwrap_or_default();
    assert!(!notifies.is_empty(), "{r}");
    for n in &notifies {
        assert_eq!(n["path"], "/zeep-consumer", "{r}");
        assert!(n.get("process_error").is_none(), "{r}");
        assert!(
            n["content_type"]
                .as_str()
                .is_some_and(|c| c.starts_with("application/soap+xml")),
            "{r}"
        );
    }
    let messages = delivered(&r, "messages");
    // The motion alarm the model raised in its answer to the Subscribe.
    let motion = find(&messages, "tns1:VideoSource/MotionAlarm");
    assert_eq!(motion["source"], json!({"Source": "lobby_cam"}), "{r}");
    assert_eq!(motion["data"], json!({"State": "true"}), "{r}");
    assert_eq!(motion["property_operation"], "Changed", "{r}");
    assert_eq!(motion["subscription"], address, "{r}");
    // The DigitalInput raised while the subscription was live.
    let input = find(&messages, "tns1:Device/Trigger/DigitalInput");
    assert_eq!(
        input["source"],
        json!({"InputToken": "door_contact"}),
        "{r}"
    );
    assert_eq!(input["data"], json!({"LogicalState": "true"}), "{r}");
    assert!(r["renew"]["termination"].is_string(), "{r}");
    assert_eq!(
        r["renew_after_unsubscribe"]["subcodes"],
        json!(["InvalidArgVal"]),
        "{r}"
    );
    // Consumers the device will not deliver to: refused, and the model never asked.
    assert_eq!(
        r["subscribe_outside_allowlist"]["subcodes"],
        json!(["InvalidArgVal"]),
        "{r}"
    );
    assert_eq!(
        r["subscribe_https"]["subcodes"],
        json!(["InvalidArgVal"]),
        "{r}"
    );
    assert_eq!(
        refusals(&state, id).await,
        vec!["not_allowlisted", "https_refused"]
    );
    let asked = events(&state, id, "onvif_create_subscription").await;
    assert_eq!(asked.len(), 1, "{asked:?}");
    assert_eq!(asked[0]["consumer"], consumer, "{asked:?}");
    let ok = events(&state, id, "onvif_notify_delivered").await;
    assert!(!ok.is_empty(), "{ok:?}");
    assert!(ok.iter().all(|d| d["consumer"] == consumer), "{ok:?}");
    assert!(events(&state, id, "onvif_notify_dropped").await.is_empty());
    assert!(events(&state, id, "onvif_not_authorized").await.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn use_go_onvif_subscribe_receives_the_notify() {
    let (state, id, port, log) = start_logged(policy(), credentials()).await;
    let raised = Arc::new(Mutex::new(None));
    let r = {
        let (state, raised) = (state.clone(), raised.clone());
        run_streaming(
            &env("NETGET_ONVIF_GO_CLIENT"),
            &[
                format!("127.0.0.1:{port}"),
                USER.into(),
                PASSWORD.into(),
                "notify".into(),
            ],
            move |line| {
                let (state, raised) = (state.clone(), raised.clone());
                let subscribed = line.contains("\"subscribed\"");
                Box::pin(async move {
                    if subscribed {
                        *raised.lock().unwrap() = Some(raise(&state, id, digital_input()).await);
                    }
                })
            },
        )
        .await
    };
    // use-go's Renew and Unsubscribe carry no namespace.
    sent(
        "use-go/onvif",
        &log,
        &["events:Subscribe", "other:Renew", "other:Unsubscribe"],
    );
    assert_eq!(r["subscribe"]["status"], 200, "{r}");
    assert_eq!(
        raised.lock().unwrap().clone(),
        Some(json!({"delivered": 1}))
    );
    let consumer = r["consumer"].as_str().unwrap_or_default().to_string();
    let address = r["address"].as_str().unwrap_or_default();
    assert!(
        address.starts_with(&format!(
            "http://127.0.0.1:{port}/onvif/events/subscription/"
        )),
        "{r}"
    );
    let notifies = r["notifies"].as_array().cloned().unwrap_or_default();
    assert!(!notifies.is_empty(), "{r}");
    for n in &notifies {
        assert_eq!(n["method"], "POST", "{r}");
        assert_eq!(n["path"], "/use-go-consumer", "{r}");
        assert_eq!(n["parse_error"], "<nil>", "{r}");
        assert_eq!(
            n["action"], "http://docs.oasis-open.org/wsn/bw-2/NotificationConsumer/Notify",
            "{r}"
        );
        assert_eq!(n["to"], consumer, "{r}");
    }
    let messages = delivered(&r, "messages");
    let motion = find(&messages, "tns1:VideoSource/MotionAlarm");
    assert_eq!(motion["data"], json!({"State": "true"}), "{r}");
    assert_eq!(motion["subscription"], address, "{r}");
    assert_eq!(
        motion["producer"],
        format!("http://127.0.0.1:{port}/onvif/events_service"),
        "{r}"
    );
    let input = find(&messages, "tns1:Device/Trigger/DigitalInput");
    assert_eq!(
        input["source"],
        json!({"InputToken": "door_contact"}),
        "{r}"
    );
    assert_eq!(input["data"], json!({"LogicalState": "true"}), "{r}");
    assert_eq!(input["property_operation"], "Changed", "{r}");
    assert_eq!(r["renew"]["status"], 200, "{r}");
    assert_eq!(r["unsubscribe"]["status"], 200, "{r}");
    assert_eq!(
        r["renew_after_unsubscribe"]["fault"], "env:Sender/ter:InvalidArgVal",
        "{r}"
    );
    assert_eq!(
        r["subscribe_outside_allowlist"]["fault"], "env:Sender/ter:InvalidArgVal",
        "{r}"
    );
    assert_eq!(
        r["subscribe_https"]["fault"], "env:Sender/ter:InvalidArgVal",
        "{r}"
    );
    assert_eq!(
        refusals(&state, id).await,
        vec!["not_allowlisted", "https_refused"]
    );
    let asked = events(&state, id, "onvif_create_subscription").await;
    assert_eq!(asked.len(), 1, "{asked:?}");
    assert_eq!(asked[0]["consumer"], consumer, "{asked:?}");
    assert!(events(&state, id, "onvif_notify_dropped").await.is_empty());
}
