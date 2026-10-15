//! The SCTP refusal is a feature, so it gets a test.
//!
//! M3UA's transport is SCTP (RFC 4666 section 1.4.1). macOS has no SCTP stack at all, and macOS
//! is where this code is developed and run. The `bluetooth_ble_beacon` precedent in the root
//! `CLAUDE.md` says what to do about that: **hiding a protocol is not the same as refusing to
//! start it.** Refused, the operator gets `ServerStatus::Error` naming the reason; hidden,
//! nobody ever learns why the thing does not work.
//!
//! So `spawn()` must fail, and fail *legibly*: naming SCTP, naming the RFC, and naming the
//! non-standard TCP escape hatch. An errno on its own ("Protocol not supported") tells an
//! operator nothing about what to do next.
//!
//! These tests bind no ports of consequence and make no LLM calls.

#[cfg(unix)]
mod m3ua_transport_test {
    use netget::server::m3ua::{bind_listener, M3uaTransport};
    use std::net::SocketAddr;

    fn loopback() -> SocketAddr {
        "127.0.0.1:0".parse().expect("literal address")
    }

    /// The refusal, and the one thing it must never be: a silent fallback to TCP.
    ///
    /// The check is a **probe, not a `cfg`** — `bind_listener` really asks the kernel for a
    /// `SOCK_STREAM`/`IPPROTO_SCTP` socket. That is deliberate, and it is the same lesson the
    /// privilege model learned: `SystemCapabilities` used to *infer* raw-socket access and the
    /// check never fired. A Linux kernel with the `sctp` module unloaded is diagnosed here
    /// exactly like macOS, and a Linux kernel that has it gets a working SCTP listener.
    #[tokio::test]
    async fn sctp_transport_either_works_or_refuses_by_name() {
        let outcome = bind_listener(loopback(), M3uaTransport::Sctp).await;

        match outcome {
            Err(error) => {
                let message = format!("{error:#}");
                assert!(
                    message.contains("SCTP"),
                    "the refusal must name SCTP, not just relay an errno: {message}"
                );
                assert!(
                    message.contains("RFC 4666"),
                    "the refusal must say where the requirement comes from: {message}"
                );
                assert!(
                    message.contains("transport=\"tcp\""),
                    "the refusal must name the lab escape hatch, or an operator on macOS has \
                     no way forward: {message}"
                );
                assert!(
                    message.contains("NON-STANDARD"),
                    "and it must say in the same breath that the escape hatch is not SIGTRAN, \
                     so nobody reads it as an equivalent option: {message}"
                );
            }
            Ok(listener) => {
                // Read at runtime rather than through `cfg!`, so this is an assertion about the
                // host the test is running on rather than a constant the compiler folds away.
                let host_os = std::env::consts::OS;
                assert_ne!(
                    host_os, "macos",
                    "macOS ships no SCTP stack, so a successful SOCK_STREAM/IPPROTO_SCTP socket \
                     here means the probe is not probing — most likely the protocol number or \
                     the socket type is wrong and this is a plain TCP socket wearing an SCTP \
                     label. That is the exact failure this protocol must not have."
                );
                let bound = listener
                    .local_addr()
                    .expect("a bound listener has an address");
                assert_ne!(bound.port(), 0, "the SCTP listener must be bound");
            }
        }
    }

    /// macOS is the machine that tests this protocol, and the refusal is what it must produce.
    /// Stated separately from the test above so the platform fact is asserted rather than
    /// merely allowed for.
    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn sctp_transport_is_refused_on_macos() {
        let outcome = bind_listener(loopback(), M3uaTransport::Sctp).await;
        assert!(
            outcome.is_err(),
            "macOS has no SCTP kernel support and no headers for it; anything that binds here \
             is not an SCTP socket"
        );
    }

    /// The lab transport does bind — that is what makes any of the layers above testable here.
    #[tokio::test]
    async fn tcp_lab_transport_binds() {
        let listener = bind_listener(loopback(), M3uaTransport::Tcp)
            .await
            .expect("the TCP lab transport must bind on any host");
        assert_ne!(listener.local_addr().expect("bound").port(), 0);
    }

    /// Wherever the transport is named to a human or to the model, TCP has to carry its own
    /// warning: this string reaches the startup log, the connection row in the dashboard and
    /// every event's `transport` field.
    #[tokio::test]
    async fn the_tcp_label_says_it_is_not_sigtran() {
        let label = M3uaTransport::Tcp.label();
        assert!(
            label.contains("NON-STANDARD"),
            "someone reading a connection row must not come away believing they have SCTP: \
             {label}"
        );
        assert!(label.contains("not SIGTRAN"), "{label}");
        assert!(
            M3uaTransport::Sctp.label().contains("RFC 4666"),
            "the real transport should name its spec"
        );
    }

    #[tokio::test]
    async fn transport_parameter_accepts_only_the_two_transports() {
        assert_eq!(
            M3uaTransport::parse("sctp").expect("sctp"),
            M3uaTransport::Sctp
        );
        assert_eq!(
            M3uaTransport::parse("SCTP").expect("case insensitive"),
            M3uaTransport::Sctp
        );
        assert_eq!(
            M3uaTransport::parse("tcp").expect("tcp"),
            M3uaTransport::Tcp
        );

        // Not a typo-tolerant field: "udp" or "sctp-lite" silently becoming SCTP would be the
        // same class of mistake as falling back to TCP.
        let error = M3uaTransport::parse("udp").expect_err("udp is not an M3UA transport");
        let message = format!("{error:#}");
        assert!(message.contains("sctp"), "{message}");
        assert!(message.contains("non-standard"), "{message}");
    }

    /// The default is the real transport. If this ever flipped, an operator on a host with SCTP
    /// would get the lab framing without asking for it, which is the failure mode the whole
    /// refusal exists to prevent.
    #[tokio::test]
    async fn nothing_defaults_to_the_lab_transport() {
        let declared = netget::server::m3ua::actions::M3uaProtocol::new();
        use netget::llm::actions::protocol_trait::Protocol;
        let transport = declared
            .get_startup_parameters()
            .into_iter()
            .find(|p| p.name == "transport")
            .expect("transport must be a declared startup parameter");
        assert_eq!(
            transport.example,
            serde_json::json!("sctp"),
            "the advertised example is what a model copies"
        );
        assert!(
            transport.description.contains("NON-STANDARD"),
            "the parameter description must warn about TCP where the model reads it: {}",
            transport.description
        );
    }
}
