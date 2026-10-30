//! Claims are recoverable and producer cancellation cannot leave ghost work.
use netget::llm::agent_queue::LlmRequestQueue;
use netget::llm::{
    ActionDefinition, ConversationHandler, OllamaClient, Parameter, RateLimiter, RateLimiterConfig,
    RequestSource,
};
use netget::state::app_state::WebSearchMode;
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;

#[tokio::test]
async fn release_and_expired_lease_preserve_request_but_reject_the_old_owner() {
    let queue = Arc::new(LlmRequestQueue::new(None));
    let (id, reply) = queue.submit("agent".into(), vec![], vec![]);
    let _cleanup = queue.guard(id);
    let first = queue.claim_next().unwrap();
    assert_eq!(queue.get(id).unwrap().claim_token, first.claim_token);
    queue.release(id, first.claim_token.as_deref()).unwrap();
    let second = queue.claim_next_with_lease(Duration::from_secs(1)).unwrap();
    assert_ne!(first.claim_token, second.claim_token);
    assert!(queue
        .answer_with_claim(id, first.claim_token.as_deref(), vec![])
        .is_err());
    // The blocking listener must wake for an expiring lease even with no new submissions.
    let recovered = queue
        .wait_and_claim_with_lease(Duration::from_secs(3), Duration::from_secs(10))
        .await
        .unwrap();
    assert_eq!(recovered.id, id);
    assert_ne!(second.claim_token, recovered.claim_token);
    assert!(queue
        .answer_with_claim(id, second.claim_token.as_deref(), vec![])
        .is_err());
    queue
        .answer_with_claim(
            id,
            recovered.claim_token.as_deref(),
            vec![json!({"type":"send_tcp_data","data":"ok"})],
        )
        .unwrap();
    assert_eq!(reply.await.unwrap()[0]["data"], "ok");
    assert!(queue.list().is_empty());
    let status = queue.status();
    let timing = &status["recent_requests"][0];
    assert_eq!(timing["outcome"], "answered");
    assert!(timing["queue_wait_ms"].is_number());
    assert!(timing["agent_wait_ms"].as_u64().unwrap() >= 1000);
}

#[tokio::test]
async fn dropping_the_model_future_removes_claimed_work_and_records_cancellation() {
    for native in [false, true] {
        let queue = Arc::new(LlmRequestQueue::new(None));
        let client = OllamaClient::new_queue(queue.clone(), Duration::from_secs(300));
        let task = tokio::spawn(async move {
            let actions = vec![ActionDefinition {
                name: "send_tcp_data".into(),
                description: "send data".into(),
                parameters: vec![Parameter {
                    name: "data".into(),
                    type_hint: "string".into(),
                    description: "payload".into(),
                    required: true,
                }],
                example: json!({"type":"send_tcp_data","data":"pong"}),
                log_template: None,
            }];
            let mut conversation = ConversationHandler::new(
                "test".into(),
                Arc::new(client),
                "agent".into(),
                RateLimiter::new(RateLimiterConfig::default()),
                RequestSource::Network,
            );
            if native {
                conversation = conversation.with_native_tools(&actions);
            }
            conversation.add_user_message("ping".into());
            conversation
                .generate_with_tools_and_retry(None, WebSearchMode::Off, actions)
                .await
        });
        let request = queue
            .wait_and_claim(Duration::from_secs(3))
            .await
            .expect("request queued");
        assert!(request.actions.iter().any(|a| a["name"] == "send_tcp_data"));
        task.abort();
        let _ = task.await;
        assert!(
            queue.list().is_empty(),
            "aborting the future must run queue cleanup"
        );
        assert!(queue.get(request.id).is_err());
        assert_eq!(queue.status()["recent_requests"][0]["outcome"], "cancelled");
    }
}

#[tokio::test]
async fn cancelling_a_listener_resets_its_liveness_count() {
    let queue = Arc::new(LlmRequestQueue::new(None));
    let q = queue.clone();
    let task = tokio::spawn(async move { q.wait_and_claim(Duration::from_secs(60)).await });
    tokio::time::timeout(Duration::from_secs(3), async {
        while queue.status()["waiting_consumers"] != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(queue.status()["state"], "waiting");
    task.abort();
    let _ = task.await;
    assert_eq!(queue.status()["waiting_consumers"], 0);
}

#[test]
fn form_query_decoding_distinguishes_spaces_and_literal_pluses() {
    use netget::server::http_common::handler::parse_query;
    assert_eq!(
        parse_query(Some(
            "q=Banana+chocolate+cake&literal=%2B&x=&flag&repeat=one&repeat=two&%E2%9C%93=%E2%9C%93"
        )),
        json!({"q":"Banana chocolate cake","literal":"+","x":"","flag":"","repeat":"two","✓":"✓"})
    );
    assert_eq!(parse_query(None), json!({}));
}
