//! The TUN/TAP pipeline, end to end, without root.
//!
//! Creating a TUN interface needs root on every platform, so the transport cannot run here.
//! The pipeline can: `TunTapEngine::spawn_over_channels` runs the *same* `run()` the real
//! device calls, with the file descriptor replaced by a pair of `mpsc` ends. Frames go in one
//! side, the decision path runs in full — decode, filter, event handlers, escalation budget,
//! the model, action execution — and whatever NetGet decided to write comes out the other.
//!
//! **The important test in this file is `the_escalation_bound_holds_under_a_flood`.** The
//! design problem this protocol exists to solve is that a per-packet LLM call is unusable, so
//! the claim that only a bounded few packets ever reach the model has to be *measured*, not
//! asserted in a comment. It is measured the way `tests/empty_static_handler_test.rs` measures
//! its claim: point NetGet at a mock model that records every call, flood it, and count.
//!
//! A zero on its own would prove nothing — the mock might simply be unreachable — so
//! `the_model_is_consulted_when_nothing_else_answers` is the negative control and must be
//! non-zero. Read them together or neither means anything.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features tuntap \
//!       --test server -- server::tuntap::e2e_test --test-threads=100

#[cfg(unix)]
mod tests {
    use crate::helpers::mock_builder::MockLlmBuilder;
    use crate::helpers::mock_ollama::MockOllamaServer;
    use netget::llm::OllamaClient;
    use netget::scripting::{EventHandler, EventHandlerConfig, EventHandlerType, EventPattern};
    use netget::server::tuntap::packet::{decode, LinkMode, PacketInformation, Transport};
    use netget::server::tuntap::{
        ChannelLink, EscalationBudget, TunTapConfig, TunTapEngine, TunTapProtocol, TunTapStats,
    };
    use netget::state::app_state::AppState;
    use netget::state::server::ServerInstance;
    use netget::state::ServerId;
    use serde_json::{json, Value};
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    use tokio::sync::mpsc;

    // -----------------------------------------------------------------------
    // Fixtures and harness
    // -----------------------------------------------------------------------

    /// An IPv4 ICMP echo request from 10.7.0.1 to 10.7.0.2 with the given id and sequence.
    fn ping(id: u16, seq: u16) -> Vec<u8> {
        let mut p = vec![
            0x45, 0x00, 0x00, 0x1c, // total length 28 = 20 + 8, no payload
            0xab, 0xcd, 0x40, 0x00, 0x40, 0x01, 0x00, 0x00, //
            0x0a, 0x07, 0x00, 0x01, // 10.7.0.1
            0x0a, 0x07, 0x00, 0x02, // 10.7.0.2
            0x08, 0x00, 0x00, 0x00, // echo request, code 0, checksum
        ];
        p.extend_from_slice(&id.to_be_bytes());
        p.extend_from_slice(&seq.to_be_bytes());
        p
    }

    /// An IPv4 TCP SYN to port 80, which the default `icmp` filter must never surface.
    fn tcp_syn(source_port: u16) -> Vec<u8> {
        let mut p = vec![
            0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, //
            0x0a, 0x07, 0x00, 0x01, 0x0a, 0x07, 0x00, 0x02,
        ];
        p.extend_from_slice(&source_port.to_be_bytes());
        p.extend_from_slice(&80u16.to_be_bytes());
        p.extend_from_slice(&[
            0x00, 0x00, 0x00, 0x01, // seq
            0x00, 0x00, 0x00, 0x00, // ack
            0x50, 0x02, // offset 5, SYN
            0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
        ]);
        p
    }

    /// Turn a `startup_params` object into the config the engine runs on, through exactly the
    /// declared-parameter machinery a real start uses — so a parameter this test sets that the
    /// protocol never declared is an error here too.
    fn config_from(params: Value) -> TunTapConfig {
        use netget::llm::actions::protocol_trait::Protocol;
        let schema = TunTapProtocol::new().get_startup_parameters();
        let params = netget::protocol::StartupParams::new(params, schema)
            .expect("startup params must validate against the declared schema");
        TunTapConfig::from_params(&Some(params)).expect("config resolves")
    }

    /// A running pipeline plus everything needed to assert about it.
    struct Harness {
        link: ChannelLink,
        mock: MockOllamaServer,
        state: AppState,
        server_id: ServerId,
        _status_rx: mpsc::UnboundedReceiver<String>,
    }

    impl Harness {
        /// Start a pipeline with the given startup parameters, routing rules and mock model.
        async fn start(
            params: Value,
            handlers: Vec<(&str, EventHandlerType)>,
            mock: MockOllamaServer,
        ) -> Self {
            let state = AppState::new_with_options(false, mock.base_url());
            state
                .set_llm_client(OllamaClient::new(mock.base_url()))
                .await;

            let mut server = ServerInstance::new(
                ServerId::new(0),
                0,
                "TUN/TAP".to_string(),
                // Non-empty on purpose: an empty instruction makes the server model-free, and
                // then the escalation measurements would be measuring the wrong thing.
                "You are the far end of a TUN interface.".to_string(),
            );
            if !handlers.is_empty() {
                let mut config = EventHandlerConfig::new();
                for (pattern, handler) in handlers {
                    config.add_handler(EventHandler::new(EventPattern::specific(pattern), handler));
                }
                server.event_handler_config = Some(config);
            }
            let server_id = state.add_server(server).await;

            let (status_tx, _status_rx) = mpsc::unbounded_channel();
            let link = TunTapEngine::new(
                config_from(params),
                "utun-test",
                OllamaClient::new(mock.base_url()),
                Arc::new(state.clone()),
                status_tx,
                server_id,
            )
            .spawn_over_channels();

            Self {
                link,
                mock,
                state,
                server_id,
                _status_rx,
            }
        }

        async fn inject(&self, frame: Vec<u8>) {
            self.link
                .ingress
                .send(frame)
                .await
                .expect("the pipeline is running");
        }

        fn stats(&self) -> Arc<TunTapStats> {
            self.link.stats.clone()
        }

        /// Wait until every injected frame has been accounted for, or give up.
        ///
        /// A count, not a sleep: the pipeline finishes a frame when it has decided about it,
        /// which is exactly the condition being waited on. Suites that slept a fixed second
        /// instead were the load-flakiness the root `CLAUDE.md` records.
        async fn wait_for_received(&self, n: u64, budget: Duration) {
            let deadline = Instant::now() + budget;
            while Instant::now() < deadline {
                if TunTapStats::get(&self.link.stats.received) >= n {
                    // The counter is bumped before the decision; give the last frame room to
                    // finish deciding.
                    tokio::time::sleep(Duration::from_millis(120)).await;
                    return;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }

        /// Wait until one of the pipeline's own counters reaches `n`, or give up.
        ///
        /// [`Harness::wait_for_received`] can only wait for a frame to *arrive*: its counter
        /// is bumped before the pipeline decides anything, which is why it has to sleep a
        /// fixed moment afterwards to let the decision land. That settle is enough when this
        /// file runs alone and is not enough when the whole suite runs at `--test-threads=100`
        /// — the load-flakiness the root `CLAUDE.md` records, and it cost two failures here.
        ///
        /// So any assertion *about a decision* waits on that decision's own counter instead.
        /// Prefer the last counter in the chain (`sent`, `refused_layer`), because reaching it
        /// implies everything before it, including the model round trip.
        async fn wait_for_stat<F>(&self, read: F, n: u64, budget: Duration)
        where
            F: Fn(&TunTapStats) -> u64,
        {
            let deadline = Instant::now() + budget;
            let stats = self.stats();
            while Instant::now() < deadline {
                if read(&stats) >= n {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }

        /// Collect everything the pipeline wrote back to the "interface".
        fn drain_egress(&mut self) -> Vec<Vec<u8>> {
            let mut out = Vec::new();
            while let Ok(frame) = self.link.egress.try_recv() {
                out.push(frame);
            }
            out
        }

        async fn finish(self) -> Result<(), Box<dyn std::error::Error>> {
            // Dropping ingress ends the pipeline, which raises tuntap_interface_down.
            drop(self.link.ingress);
            let _ = self.state.remove_server(self.server_id).await;
            self.mock.wait_for_expectations(30).await;
            self.mock.verify_calls().await?;
            Ok(())
        }
    }

    /// Static rules that answer the two lifecycle events with nothing.
    ///
    /// They exist so the LLM call counts in these tests are about *packets*. This is also gate
    /// 2 working: a static handler answers in-process and the model is never asked.
    fn lifecycle_handled() -> Vec<(&'static str, EventHandlerType)> {
        vec![
            (
                "tuntap_interface_up",
                EventHandlerType::static_response(vec![json!({"type": "no_response"})]),
            ),
            (
                "tuntap_interface_down",
                EventHandlerType::static_response(vec![json!({"type": "no_response"})]),
            ),
        ]
    }

    /// Assert a frame is an ICMP echo reply carrying the given id and sequence.
    fn assert_echo_reply(frame: &[u8], id: u16, seq: u16) {
        let p = decode(frame, PacketInformation::None, LinkMode::Tun)
            .expect("what NetGet wrote must itself decode");
        assert_eq!(p.protocol_name(), "icmp");
        assert_eq!(
            p.transport,
            Transport::Icmp {
                icmp_type: 0,
                code: 0,
                id: Some(id),
                sequence: Some(seq),
            },
            "an echo reply that does not carry the request's id and sequence is ignored by \
             the sender, so the correlation has to survive the whole pipeline"
        );
        assert_eq!(p.source.to_string(), "10.7.0.2");
        assert_eq!(p.destination.to_string(), "10.7.0.1");
    }

    // -----------------------------------------------------------------------
    // The escalation bound — the reason this protocol is shippable
    // -----------------------------------------------------------------------

    /// **The most important test in this protocol.**
    ///
    /// Forty packets go in. Twenty are TCP and must be absorbed by gate 1 without any handler
    /// or model involvement at all; twenty are pings and pass gate 1, but the budget allows
    /// three consultations a minute, so exactly three may reach the model and seventeen must be
    /// dropped as `fail_closed_rate_limited`.
    ///
    /// If this ever measures more than three, a busy interface is a runaway LLM bill and the
    /// protocol is not usable.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn the_escalation_bound_holds_under_a_flood() -> Result<(), Box<dyn std::error::Error>> {
        let mock = MockOllamaServer::start(
            MockLlmBuilder::new()
                .on_event("tuntap_packet_received")
                .respond_with_actions_from_event(|e| {
                    json!([{
                        "type": "send_packet",
                        "source": e["destination"],
                        "destination": e["source"],
                        "protocol": "icmp",
                        "icmp_type": "echo_reply",
                        "icmp_id": e["icmp_id"],
                        "icmp_sequence": e["icmp_sequence"],
                    }])
                })
                .expect_calls(3)
                .build(),
        )
        .await?;

        let mut h = Harness::start(
            json!({
                "packet_filter": "icmp",
                "llm_escalation": "unhandled",
                "llm_max_per_minute": 3,
            }),
            lifecycle_handled(),
            mock,
        )
        .await;

        for i in 0..20u16 {
            h.inject(ping(0x1000 + i, i)).await;
            h.inject(tcp_syn(40000 + i)).await;
        }
        h.wait_for_received(40, Duration::from_secs(60)).await;
        // `wait_for_received` counts frames *arriving*; its counter is bumped before the
        // decision path runs, so it backs itself with a fixed 120ms and that is a deadline
        // rather than a condition. Wait for the terminal counter and for the mock's own
        // expectations instead — the last packet's decision is what this test measures.
        h.wait_for_stat(
            |s| TunTapStats::get(&s.dropped_over_budget),
            17,
            Duration::from_secs(60),
        )
        .await;
        h.mock.wait_for_expectations(30).await;

        let s = h.stats();
        assert_eq!(TunTapStats::get(&s.received), 40);
        assert_eq!(
            TunTapStats::get(&s.filtered_out),
            20,
            "gate 1 must absorb every TCP packet in native code — no event, no handler, no model"
        );
        assert_eq!(
            TunTapStats::get(&s.escalated_to_llm),
            3,
            "gate 3 must cap consultations at llm_max_per_minute"
        );
        assert_eq!(
            TunTapStats::get(&s.dropped_over_budget),
            17,
            "everything above the ceiling is dropped, not queued"
        );

        let calls = h.mock.call_count().await;
        assert_eq!(
            calls, 3,
            "the model must have been consulted exactly 3 times for 40 packets; measured {calls}"
        );

        let sent = h.drain_egress();
        assert_eq!(
            sent.len(),
            3,
            "only the escalated packets can produce a reply"
        );
        assert_echo_reply(&sent[0], 0x1000, 0);

        h.finish().await
    }

    /// A handler that cannot answer must not keep its exemption from the escalation bound.
    ///
    /// Gate 2 used to decide exemption by **inspecting the configuration**: a `Script` rule
    /// existing was taken as proof that the packet would be answered in-process, so gate 3 was
    /// skipped entirely — no `llm_escalation` check, no budget debit, and the counters reported
    /// `handled_by_rule`. But `execute_script_handler` returns `FallbackToLlm` when the
    /// language is not installed, when the language name is unknown, or when the script
    /// throws, and by then the gate had already been passed. The shipped script-mode startup
    /// example on a box without `python3` was therefore an **uncounted model call per admitted
    /// packet**, at wire rate, with `llm_escalation: "never"` inert.
    ///
    /// `"never"` is the sharpest way to state it: its documented meaning is that no LLM budget
    /// is *ever* spent, so any number above zero here is the whole claim failing.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_script_handler_that_cannot_answer_does_not_bypass_the_bound(
    ) -> Result<(), Box<dyn std::error::Error>> {
        // The mock answers if it is reached. Reaching it is the failure.
        let mock = MockOllamaServer::start(
            MockLlmBuilder::new()
                .on_event("tuntap_packet_received")
                .respond_with_actions(json!([{"type": "no_response"}]))
                .expect_calls(0)
                .build(),
        )
        .await?;

        let mut handlers = lifecycle_handled();
        handlers.push((
            "tuntap_packet_received",
            // A language the dispatcher does not recognise, which is the deterministic stand-in
            // for the realistic case (python3 absent). Both take the same `FallbackToLlm` exit.
            EventHandlerType::Script {
                language: "brainfuck".to_string(),
                code: "+[----->+++<]>+.".to_string(),
                resident: false,
                scope: None,
            },
        ));

        let mut h = Harness::start(
            json!({
                "packet_filter": "icmp",
                "llm_escalation": "never",
            }),
            handlers,
            mock,
        )
        .await;

        for i in 0..10u16 {
            h.inject(ping(0x2000 + i, i)).await;
        }
        h.wait_for_received(10, Duration::from_secs(60)).await;
        h.wait_for_stat(
            |s| TunTapStats::get(&s.dropped_escalation_disabled),
            10,
            Duration::from_secs(60),
        )
        .await;

        let calls = h.mock.call_count().await;
        assert_eq!(
            calls, 0,
            "`llm_escalation: \"never\"` promises no model call ever; a script handler that \
             could not answer produced {calls} of them"
        );

        let s = h.stats();
        assert_eq!(TunTapStats::get(&s.received), 10);
        assert_eq!(
            TunTapStats::get(&s.handled_by_rule),
            0,
            "a handler that fell back to the model did not handle anything, and counting it as \
             `handled_by_rule` is what hid this"
        );
        assert_eq!(
            TunTapStats::get(&s.dropped_escalation_disabled),
            10,
            "every packet must land on gate 3 and be dropped there"
        );
        assert_eq!(TunTapStats::get(&s.escalated_to_llm), 0);
        assert!(
            h.drain_egress().is_empty(),
            "nothing may reach the interface"
        );

        h.finish().await
    }

    /// The same hole under a budget rather than an outright ban.
    ///
    /// With `llm_escalation: "unhandled"` and a ceiling of two, a script handler that cannot
    /// answer must consume the budget like any other unanswered packet — bounded, not exempt.
    /// Before the fix this measured ten.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_failing_script_handler_is_charged_to_the_budget(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mock = MockOllamaServer::start(
            MockLlmBuilder::new()
                .on_event("tuntap_packet_received")
                .respond_with_actions(json!([{"type": "no_response"}]))
                .expect_calls(2)
                .build(),
        )
        .await?;

        let mut handlers = lifecycle_handled();
        handlers.push((
            "tuntap_packet_received",
            EventHandlerType::Script {
                language: "brainfuck".to_string(),
                code: "+[----->+++<]>+.".to_string(),
                resident: false,
                scope: None,
            },
        ));

        let mut h = Harness::start(
            json!({
                "packet_filter": "icmp",
                "llm_escalation": "unhandled",
                "llm_max_per_minute": 2,
            }),
            handlers,
            mock,
        )
        .await;

        for i in 0..10u16 {
            h.inject(ping(0x3000 + i, i)).await;
        }
        h.wait_for_received(10, Duration::from_secs(60)).await;
        h.wait_for_stat(
            |s| TunTapStats::get(&s.dropped_over_budget),
            8,
            Duration::from_secs(60),
        )
        .await;
        h.mock.wait_for_expectations(30).await;

        let calls = h.mock.call_count().await;
        assert_eq!(
            calls, 2,
            "the ceiling is 2 consultations a minute; measured {calls} for 10 packets"
        );
        let s = h.stats();
        assert_eq!(TunTapStats::get(&s.escalated_to_llm), 2);
        assert_eq!(TunTapStats::get(&s.dropped_over_budget), 8);

        h.finish().await
    }

    /// A script handler that *does* answer stays exempt, so the fix is not a ban on scripts.
    ///
    /// Without this, the two tests above would pass just as well if gate 2 had been deleted —
    /// and script mode is the whole point of the protocol being usable at all.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_static_handler_that_answers_still_costs_nothing(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mock = MockOllamaServer::start(
            MockLlmBuilder::new()
                .on_event("tuntap_packet_received")
                .respond_with_actions(json!([{"type": "no_response"}]))
                .expect_calls(0)
                .build(),
        )
        .await?;

        let mut handlers = lifecycle_handled();
        handlers.push((
            "tuntap_packet_received",
            EventHandlerType::static_response(vec![json!({
                "type": "send_packet",
                "source": "10.7.0.2",
                "destination": "10.7.0.1",
                "protocol": "icmp",
                "icmp_type": "echo_reply",
                "icmp_id": 1,
                "icmp_sequence": 1,
            })]),
        ));

        let mut h = Harness::start(
            json!({
                "packet_filter": "icmp",
                // The strictest setting there is: if the handler were charged, nothing would
                // be answered at all.
                "llm_escalation": "never",
            }),
            handlers,
            mock,
        )
        .await;

        for i in 0..5u16 {
            h.inject(ping(0x4000 + i, i)).await;
        }
        h.wait_for_received(5, Duration::from_secs(60)).await;
        h.wait_for_stat(
            |s| TunTapStats::get(&s.handled_by_rule),
            5,
            Duration::from_secs(60),
        )
        .await;

        assert_eq!(h.mock.call_count().await, 0, "a static handler is free");
        let s = h.stats();
        assert_eq!(
            TunTapStats::get(&s.handled_by_rule),
            5,
            "every packet must be credited to the handler that actually answered it"
        );
        assert_eq!(TunTapStats::get(&s.dropped_escalation_disabled), 0);
        assert_eq!(
            h.drain_egress().len(),
            5,
            "the handler's replies must still reach the interface"
        );

        h.finish().await
    }

    /// The negative control. Without it, every zero in this file is indistinguishable from a
    /// mock the pipeline never tried to reach.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn the_model_is_consulted_when_nothing_else_answers(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mock = MockOllamaServer::start(
            MockLlmBuilder::new()
                .on_event("tuntap_packet_received")
                .respond_with_actions_from_event(|e| {
                    json!([{
                        "type": "send_packet",
                        "source": e["destination"],
                        "destination": e["source"],
                        "protocol": "icmp",
                        "icmp_type": "echo_reply",
                        "icmp_id": e["icmp_id"],
                        "icmp_sequence": e["icmp_sequence"],
                    }])
                })
                .expect_calls(1)
                .build(),
        )
        .await?;

        let mut h = Harness::start(
            json!({"packet_filter": "icmp", "llm_escalation": "unhandled"}),
            lifecycle_handled(),
            mock,
        )
        .await;

        h.inject(ping(0x2222, 9)).await;
        // `sent` is the end of this chain — model consulted, answer built, frame written —
        // so waiting on it means all three assertions below are about a finished decision.
        h.wait_for_stat(|s| TunTapStats::get(&s.sent), 1, Duration::from_secs(30))
            .await;

        assert!(
            h.mock.call_count().await > 0,
            "a packet that passes the filter with no handler and budget to spare MUST reach \
             the model — if this is 0 nothing else in this file is measuring anything"
        );
        assert_eq!(TunTapStats::get(&h.stats().escalated_to_llm), 1);

        let sent = h.drain_egress();
        assert_eq!(sent.len(), 1, "the model's send_packet must reach the wire");
        assert_echo_reply(&sent[0], 0x2222, 9);

        h.finish().await
    }

    /// Gate 2: a static handler answers in-process, and the model is never asked.
    ///
    /// This is the path the protocol is designed around — `packet_filter` can be widened
    /// freely once a deterministic rule is answering, because a rule costs nothing.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_static_handler_answers_every_packet_with_no_model_call(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mock = MockOllamaServer::start(
            MockLlmBuilder::new()
                .on_any()
                .respond_with_actions(json!([{"type": "no_response"}]))
                .expect_calls(0)
                .build(),
        )
        .await?;

        let mut handlers = lifecycle_handled();
        handlers.push((
            "tuntap_packet_received",
            EventHandlerType::static_response(vec![json!({
                "type": "send_packet",
                "source": "{{event.destination}}",
                "destination": "{{event.source}}",
                "protocol": "icmp",
                "icmp_type": "echo_reply",
                "icmp_id": "{{event.icmp_id}}",
                "icmp_sequence": "{{event.icmp_sequence}}"
            })]),
        ));

        // Note the budget: one a minute. A rule is exempt from it, so all five must still be
        // answered — if handlers were charged to the budget this would answer one.
        let mut h = Harness::start(
            json!({"packet_filter": "all", "llm_max_per_minute": 1}),
            handlers,
            mock,
        )
        .await;

        for seq in 0..5u16 {
            h.inject(ping(0x3333, seq)).await;
        }
        h.wait_for_received(5, Duration::from_secs(30)).await;

        assert_eq!(
            h.mock.call_count().await,
            0,
            "a static handler answers in-process; the model must not be consulted at all"
        );
        let s = h.stats();
        assert_eq!(TunTapStats::get(&s.handled_by_rule), 5);
        assert_eq!(TunTapStats::get(&s.escalated_to_llm), 0);
        assert_eq!(TunTapStats::get(&s.dropped_over_budget), 0);

        let sent = h.drain_egress();
        assert_eq!(
            sent.len(),
            5,
            "every packet a rule answered reaches the wire"
        );
        for (seq, frame) in sent.iter().enumerate() {
            assert_echo_reply(frame, 0x3333, seq as u16);
        }

        h.finish().await
    }

    /// `llm_escalation: "never"` makes the server purely deterministic.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn escalation_never_spends_no_llm_budget_at_all() -> Result<(), Box<dyn std::error::Error>>
    {
        let mock = MockOllamaServer::start(
            MockLlmBuilder::new()
                .on_any()
                .respond_with_actions(json!([{"type": "no_response"}]))
                .expect_calls(0)
                .build(),
        )
        .await?;

        // No packet handler at all, and no lifecycle handlers either: "never" has to cover the
        // lifecycle events too, or starting the server would be a model call.
        let mut h = Harness::start(
            json!({"packet_filter": "all", "llm_escalation": "never"}),
            vec![],
            mock,
        )
        .await;

        for seq in 0..8u16 {
            h.inject(ping(0x4444, seq)).await;
        }
        h.wait_for_received(8, Duration::from_secs(30)).await;

        assert_eq!(
            h.mock.call_count().await,
            0,
            "escalation \"never\" means the model is never reached, for packets or lifecycle"
        );
        let s = h.stats();
        assert_eq!(TunTapStats::get(&s.dropped_escalation_disabled), 8);
        assert_eq!(TunTapStats::get(&s.escalated_to_llm), 0);
        assert!(
            h.drain_egress().is_empty(),
            "nothing answered, so nothing may be written"
        );

        h.finish().await
    }

    /// The filter is the first gate, and it must reject before any handler runs.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn the_filter_runs_before_the_handler() -> Result<(), Box<dyn std::error::Error>> {
        let mock = MockOllamaServer::start(
            MockLlmBuilder::new()
                .on_any()
                .respond_with_actions(json!([{"type": "no_response"}]))
                .expect_calls(0)
                .build(),
        )
        .await?;

        // A wildcard-shaped rule that would answer everything — except that gate 1 only admits
        // new TCP connections, so the pings never reach it.
        let mut handlers = lifecycle_handled();
        handlers.push((
            "tuntap_packet_received",
            EventHandlerType::static_response(vec![json!({"type": "drop_packet",
                                                          "reason": "seen"})]),
        ));

        let h = Harness::start(json!({"packet_filter": "tcp-syn"}), handlers, mock).await;

        for i in 0..6u16 {
            h.inject(ping(0x5555, i)).await;
        }
        h.inject(tcp_syn(41000)).await;
        h.wait_for_received(7, Duration::from_secs(30)).await;

        let s = h.stats();
        assert_eq!(
            TunTapStats::get(&s.filtered_out),
            6,
            "six pings must be absorbed by the filter, not offered to the rule"
        );
        assert_eq!(
            TunTapStats::get(&s.handled_by_rule),
            1,
            "only the SYN reaches gate 2"
        );
        assert_eq!(h.mock.call_count().await, 0);

        h.finish().await
    }

    /// An LLM failure must write nothing at all.
    ///
    /// No mock here on purpose: the client points at a closed port, so `call_llm` fails the way
    /// a real backend outage does. A fabricated packet on a real interface is indistinguishable
    /// from a spoof, so the only correct answer is silence — and the assertion is that the
    /// interface stayed silent, not that some error packet was well-formed.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn an_llm_failure_writes_nothing_to_the_interface() {
        let dead = "http://127.0.0.1:1".to_string();
        let state = AppState::new_with_options(false, dead.clone());
        state.set_llm_client(OllamaClient::new(dead.clone())).await;

        let server = ServerInstance::new(
            ServerId::new(0),
            0,
            "TUN/TAP".to_string(),
            "You are the far end of a TUN interface.".to_string(),
        );
        let server_id = state.add_server(server).await;

        let (status_tx, _status_rx) = mpsc::unbounded_channel();
        let mut link = TunTapEngine::new(
            config_from(json!({"packet_filter": "icmp", "llm_max_per_minute": 10})),
            "utun-test",
            OllamaClient::new(dead),
            Arc::new(state.clone()),
            status_tx,
            server_id,
        )
        .spawn_over_channels();

        for seq in 0..3u16 {
            link.ingress.send(ping(0x6666, seq)).await.expect("running");
        }

        let deadline = Instant::now() + Duration::from_secs(60);
        while Instant::now() < deadline && TunTapStats::get(&link.stats.received) < 3 {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;

        assert_eq!(TunTapStats::get(&link.stats.received), 3);
        assert_eq!(
            TunTapStats::get(&link.stats.sent),
            0,
            "an unreachable model must produce silence, never an invented packet"
        );
        assert!(
            link.egress.try_recv().is_err(),
            "nothing may be written to the interface when the model could not be reached"
        );

        drop(link.ingress);
        let _ = state.remove_server(server_id).await;
    }

    /// An answer NetGet cannot build is refused, and again nothing is written.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn an_unbuildable_answer_writes_nothing() -> Result<(), Box<dyn std::error::Error>> {
        let mock = MockOllamaServer::start(
            MockLlmBuilder::new()
                .on_event("tuntap_packet_received")
                // Mixed address families: there is no honest packet for this.
                .respond_with_actions(json!([{
                    "type": "send_packet",
                    "source": "10.7.0.2",
                    "destination": "2001:db8::1",
                    "protocol": "icmp",
                    "icmp_type": "echo_reply"
                }]))
                .expect_calls(1)
                .build(),
        )
        .await?;

        let mut h =
            Harness::start(json!({"packet_filter": "icmp"}), lifecycle_handled(), mock).await;

        h.inject(ping(0x7777, 1)).await;
        h.wait_for_received(1, Duration::from_secs(30)).await;

        assert_eq!(TunTapStats::get(&h.stats().sent), 0);
        assert!(
            h.drain_egress().is_empty(),
            "a refused build is a dropped packet, not a best-effort one"
        );

        h.finish().await
    }

    /// A TUN interface must refuse an answer that produced an Ethernet frame, rather than
    /// stripping or inventing a link header.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_layer_two_answer_on_a_layer_three_interface_is_refused(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mock = MockOllamaServer::start(
            MockLlmBuilder::new()
                .on_event("tuntap_packet_received")
                .respond_with_actions(json!([{
                    "type": "send_packet",
                    "source": "10.7.0.2",
                    "destination": "10.7.0.1",
                    "protocol": "icmp",
                    "icmp_type": "echo_reply",
                    "source_mac": "aa:bb:cc:dd:ee:02",
                    "destination_mac": "aa:bb:cc:dd:ee:01"
                }]))
                .expect_calls(1)
                .build(),
        )
        .await?;

        let mut h = Harness::start(
            json!({"mode": "tun", "packet_filter": "icmp"}),
            lifecycle_handled(),
            mock,
        )
        .await;

        h.inject(ping(0x8888, 1)).await;
        // The refusal is the end of this chain: the model answered and the pipeline rejected
        // its layer-two frame. Waiting on `received` would only prove the packet arrived.
        h.wait_for_stat(
            |s| TunTapStats::get(&s.refused_layer),
            1,
            Duration::from_secs(30),
        )
        .await;

        assert_eq!(TunTapStats::get(&h.stats().refused_layer), 1);
        assert!(h.drain_egress().is_empty());

        h.finish().await
    }

    // -----------------------------------------------------------------------
    // Configuration
    // -----------------------------------------------------------------------

    #[test]
    fn the_defaults_are_the_conservative_ones_the_parameters_promise() {
        let cfg = TunTapConfig::default();
        assert_eq!(cfg.filter.as_str(), "icmp");
        assert_eq!(cfg.llm_max_per_minute, 6);
        assert_eq!(cfg.mtu, 1500);
        assert_eq!(cfg.address, "10.7.0.1");
        assert_eq!(cfg.mode, LinkMode::Tun);
        assert_eq!(cfg.packet_information, PacketInformation::None);
    }

    #[test]
    fn every_declared_startup_parameter_is_actually_read() {
        use netget::llm::actions::protocol_trait::Protocol;

        let cfg = config_from(json!({
            "interface_name": "utun9",
            "mode": "tap",
            "address": "10.9.0.1",
            "netmask": "255.255.0.0",
            "mtu": 9000,
            "packet_filter": "tcp:443, icmpv6",
            "llm_escalation": "never",
            "llm_max_per_minute": 42,
            "packet_information": "macos_utun",
        }));

        assert_eq!(cfg.interface_name.as_deref(), Some("utun9"));
        assert_eq!(cfg.mode, LinkMode::Tap);
        assert_eq!(cfg.address, "10.9.0.1");
        assert_eq!(cfg.netmask, "255.255.0.0");
        assert_eq!(cfg.mtu, 9000);
        assert_eq!(cfg.filter.as_str(), "tcp:443, icmpv6");
        assert_eq!(cfg.escalation.as_str(), "never");
        assert_eq!(cfg.llm_max_per_minute, 42);
        assert_eq!(cfg.packet_information, PacketInformation::MacOsUtun);

        // And the nine set above are exactly the nine declared: a parameter declared and never
        // read is an advertised knob that does nothing when turned.
        let declared: Vec<String> = TunTapProtocol::new()
            .get_startup_parameters()
            .into_iter()
            .map(|p| p.name)
            .collect();
        assert_eq!(
            declared.len(),
            9,
            "if a parameter was added, read it and assert it here: {declared:?}"
        );
    }

    #[test]
    fn a_bad_startup_parameter_is_an_error_not_a_default() {
        use netget::llm::actions::protocol_trait::Protocol;
        let schema = || TunTapProtocol::new().get_startup_parameters();

        for bad in [
            json!({"packet_filter": "nonsense-term"}),
            json!({"mode": "tup"}),
            json!({"llm_escalation": "sometimes"}),
            json!({"llm_max_per_minute": 100000}),
            json!({"mtu": 3}),
            json!({"address": "not-an-address"}),
            json!({"packet_information": "maybe"}),
        ] {
            let params = netget::protocol::StartupParams::new(bad.clone(), schema())
                .expect("the key itself is declared");
            assert!(
                TunTapConfig::from_params(&Some(params)).is_err(),
                "{bad} must be refused at startup, not silently replaced by a default"
            );
        }

        // An undeclared key is refused by StartupParams itself, before the protocol sees it.
        assert!(
            netget::protocol::StartupParams::new(json!({"packet_filtre": "icmp"}), schema())
                .is_err()
        );
    }

    // -----------------------------------------------------------------------
    // The budget, on a controlled clock
    // -----------------------------------------------------------------------

    #[test]
    fn the_budget_is_a_rolling_window_not_a_refilling_bucket() {
        let start = Instant::now();
        let mut budget = EscalationBudget::new(3);

        for i in 0..3 {
            assert!(
                budget.try_take_at(start + Duration::from_millis(i)),
                "the first three in a window are allowed"
            );
        }
        assert!(
            !budget.try_take_at(start + Duration::from_millis(4)),
            "the fourth in the same window is refused"
        );
        assert!(
            !budget.try_take_at(start + Duration::from_secs(59)),
            "still refused at 59s — a rolling minute, not a bucket that drips"
        );
        assert!(
            budget.try_take_at(start + Duration::from_secs(61)),
            "once the earlier consultations have aged out, there is room again"
        );
        assert_eq!(
            budget.remaining_at(start + Duration::from_secs(61)),
            2,
            "all three original consultations aged out together, and one has been spent"
        );
        assert_eq!(
            budget.remaining_at(start + Duration::from_secs(200)),
            3,
            "a quiet minute restores the whole allowance"
        );
    }

    #[test]
    fn a_zero_budget_forbids_everything() {
        let mut budget = EscalationBudget::new(0);
        assert!(!budget.try_take());
        assert_eq!(budget.max_per_minute(), 0);
    }
}
