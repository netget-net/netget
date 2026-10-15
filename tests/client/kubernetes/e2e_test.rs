//! Registry and action-surface tests for the Kubernetes client.
//!
//! **There is no test here against a real cluster, and that is the honest state of things.**
//! This file used to hold three `#[ignore]`d "E2E" tests that checked `kubectl cluster-info`,
//! printed `Full E2E test implementation requires NetGet binary integration` and asserted
//! nothing at all — green whether the client worked or not, on a machine with a cluster or
//! without one. They were deleted rather than left as a maturity claim resting on a `println!`;
//! the client's `metadata().e2e_testing` now says so in as many words.
//!
//! The real wire coverage is `command_channel_test.rs`: an injected `k8s_list_pods` is asserted
//! to have reached `/api/v1/namespaces/default/pods` on a loopback stub, with `KUBECONFIG`
//! pinned to a throwaway file so the developer's own cluster cannot be touched.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features kubernetes \
//!       --test client -- --test-threads=100 kubernetes

mod kubernetes_client_tests {
    /// The protocol is registered and reports the identity the rail and the resolver use.
    #[test]
    fn test_kubernetes_protocol_registered() {
        use netget::protocol::CLIENT_REGISTRY;

        assert!(
            CLIENT_REGISTRY.has_protocol("Kubernetes"),
            "Kubernetes protocol should be registered"
        );

        let protocol = CLIENT_REGISTRY
            .get("Kubernetes")
            .expect("Should get Kubernetes protocol");
        assert_eq!(protocol.protocol_name(), "Kubernetes");
        assert_eq!(protocol.stack_name(), "ETH>IP>TCP>TLS>HTTP>K8s API");
        assert!(protocol.keywords().contains(&"kubernetes"));
        assert!(protocol.keywords().contains(&"k8s"));
    }

    /// Every verb the client can execute is also advertised to the model.
    #[test]
    fn test_kubernetes_client_actions() {
        use netget::protocol::CLIENT_REGISTRY;
        use netget::state::app_state::AppState;

        let state = AppState::new();

        let protocol = CLIENT_REGISTRY
            .get("Kubernetes")
            .expect("Should get Kubernetes protocol");

        let async_actions = protocol.get_async_actions(&state);
        let action_names: Vec<&str> = async_actions.iter().map(|a| a.name.as_str()).collect();

        for expected in [
            "k8s_list_pods",
            "k8s_get_pod",
            "k8s_get_logs",
            "k8s_create_pod",
            "k8s_delete_pod",
            "k8s_list_deployments",
            "k8s_list_services",
            "disconnect",
        ] {
            assert!(
                action_names.contains(&expected),
                "Should have {expected} action"
            );
        }
    }

    /// `get_event_types()` must hand back the same `EventType`s the client actually raises.
    ///
    /// It used to build a second copy of each by hand, with different wording and **no
    /// parameters**, so the model was shown a `k8s_connected` with no fields while the event
    /// that fires declares `cluster_url` as required. Two declarations of one event drift the
    /// moment either is edited.
    #[test]
    fn declared_event_types_are_the_ones_that_fire() {
        use netget::client::kubernetes::actions::{
            K8S_CLIENT_CONNECTED_EVENT, K8S_CLIENT_RESOURCE_RECEIVED_EVENT,
        };
        use netget::protocol::CLIENT_REGISTRY;

        let protocol = CLIENT_REGISTRY
            .get("Kubernetes")
            .expect("Should get Kubernetes protocol");
        let declared = protocol.get_event_types();

        let connected = declared
            .iter()
            .find(|e| e.id == K8S_CLIENT_CONNECTED_EVENT.id)
            .expect("k8s_connected must be declared");
        assert_eq!(
            connected.description, K8S_CLIENT_CONNECTED_EVENT.description,
            "the declared k8s_connected must be the static one, not a second copy"
        );
        assert!(
            connected.parameters.iter().any(|p| p.name == "cluster_url"),
            "k8s_connected declares cluster_url; a copy without parameters hides it \
             from the model"
        );

        let received = declared
            .iter()
            .find(|e| e.id == K8S_CLIENT_RESOURCE_RECEIVED_EVENT.id)
            .expect("k8s_resource_received must be declared");
        assert_eq!(
            received.parameters.len(),
            K8S_CLIENT_RESOURCE_RECEIVED_EVENT.parameters.len(),
            "k8s_resource_received must carry its declared parameters"
        );
    }

    /// Each advertised verb turns into a `k8s_operation` the connection loop knows how to run,
    /// and an unknown one is refused rather than silently eaten.
    #[test]
    fn test_kubernetes_action_execution() {
        use netget::llm::actions::client_trait::ClientActionResult;
        use netget::protocol::CLIENT_REGISTRY;
        use serde_json::json;

        let protocol = CLIENT_REGISTRY
            .get("Kubernetes")
            .expect("Should get Kubernetes protocol");

        let cases = [
            (
                json!({"type": "k8s_list_pods", "namespace": "default"}),
                "list",
                "pods",
            ),
            (
                json!({"type": "k8s_get_pod", "name": "test-pod", "namespace": "default"}),
                "get",
                "pod",
            ),
            (
                json!({"type": "k8s_get_logs", "name": "test-pod"}),
                "logs",
                "pod",
            ),
            (
                json!({"type": "k8s_delete_pod", "name": "test-pod"}),
                "delete",
                "pod",
            ),
            (
                json!({"type": "k8s_list_deployments", "namespace": "default"}),
                "list",
                "deployments",
            ),
            (
                json!({"type": "k8s_list_services", "namespace": "default"}),
                "list",
                "services",
            ),
        ];

        for (action, operation, resource_type) in cases {
            let label = action["type"].as_str().unwrap_or("?").to_string();
            match protocol.execute_action(action) {
                Ok(ClientActionResult::Custom { name, data }) => {
                    assert_eq!(
                        name, "k8s_operation",
                        "{label} must produce a k8s_operation"
                    );
                    assert_eq!(
                        data.get("operation").and_then(|v| v.as_str()),
                        Some(operation),
                        "{label} operation"
                    );
                    assert_eq!(
                        data.get("resource_type").and_then(|v| v.as_str()),
                        Some(resource_type),
                        "{label} resource_type"
                    );
                }
                other => panic!("{label} produced {other:?}"),
            }
        }

        assert!(
            matches!(
                protocol.execute_action(json!({"type": "disconnect"})),
                Ok(ClientActionResult::Disconnect)
            ),
            "disconnect must be a Disconnect, not a Custom the loop would ignore"
        );

        assert!(
            protocol
                .execute_action(json!({"type": "k8s_no_such_verb"}))
                .is_err(),
            "an unknown verb must be refused"
        );
    }
}
