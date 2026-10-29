//! NetGet's NVMe/TCP target over a secure channel, against the Linux kernel's NVMe/TCP host.
//!
//! nvme-cli generates the configured PSK and inserts the TLS PSK it derives into the kernel's
//! `.nvme` keyring; `nvme discover --tls` and `nvme connect --tls` hand the handshake to tlshd,
//! which runs it with GnuTLS — a TLS stack, a key derivation and a host none of which are
//! NetGet's. The kernel then identifies the controller and makes block devices, whose bytes are
//! read and compared with what the model described. A host holding another key is refused
//! before any NVMe/TCP.
//!
//! Linux, as root, with nvme-tcp loaded and a current nvme-cli and tlshd (`tls_support.rs`):
//! the `nvme-tcp` pair job. Fails, never skips, without them.
#[cfg(target_os = "linux")]
mod kernel_tls {
    use super::super::real_client_test::kernel_host::*;
    use super::super::support::*;
    use super::super::tls_support;
    use serde_json::json;
    use std::path::Path;
    use std::time::Duration;

    const TLS_HOST: &str = "nqn.2026-10.net.netget:kernel-tls-host";
    const TLS_HOSTID: &str = "7d4f0a2e-91c3-4b5e-8f60-2a1b3c4d5e6f";

    async fn logged(srv: &Started, needle: &str) -> bool {
        for _ in 0..400 {
            if srv.logs().iter().any(|l| l.contains(needle)) {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        false
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn the_linux_kernel_host_connects_through_tls_and_reads_the_namespace() {
        require_root();
        require_module();
        tls_support::require_tlshd();
        let nvme = tls_support::nvme();
        let key = tls_support::gen_key(&nvme);
        tls_support::insert(&nvme, &key, TLS_HOST, DISK0);
        tls_support::insert(&nvme, &key, TLS_HOST, DISCOVERY);
        let srv = start_on(
            "127.0.0.1",
            0,
            policy(REAL_POLICY),
            Some(json!({"tls_key": key})),
        )
        .await;
        let port = srv.port.to_string();
        let common = [
            "-t", "tcp", "-a", "127.0.0.1", "-s", &port, "-q", TLS_HOST, "-I", TLS_HOSTID,
            "--tls",
        ];

        let mut args = vec!["discover"];
        args.extend(common);
        let out = run(&nvme, &args).await;
        let o = text(&out.stdout);
        assert!(
            out.status.success() && o.contains(DISK0),
            "nvme discover --tls: {o}\n{}\n{:#?}",
            text(&out.stderr),
            srv.logs()
        );
        println!("{o}");
        assert!(
            o.contains("tls13") || o.to_lowercase().contains("tls 1.3"),
            "the discovery log's security type reaches the kernel host: {o}"
        );

        let mut args = vec!["connect", "-n", DISK0];
        args.extend(common);
        let out = run(&nvme, &args).await;
        let _disconnect = Disconnect(nvme.clone());
        assert!(
            out.status.success(),
            "nvme connect --tls: {}\n{}\n{}\n{:#?}",
            text(&out.stdout),
            text(&out.stderr),
            diagnostics(&nvme).await,
            srv.logs()
        );
        settle().await;
        let (_, namespaces) = devices(DISK0);
        let ns1 = match namespaces.iter().find(|(nsid, _)| *nsid == 1) {
            Some((_, n)) => format!("/dev/{n}"),
            None => panic!("no namespace 1: {}", diagnostics(&nvme).await),
        };
        let dev = ns1.clone();
        let head = until_ok("reading namespace 1", move || {
            read_direct(Path::new(&dev), 0, 4096)
        })
        .await
        .unwrap();
        assert_eq!(&head[..17], b"hello from netget", "{ns1} through TLS");

        // Every queue the kernel opened was its own TLS session under this host's identity.
        assert!(
            logged(
                &srv,
                &format!("operation=tls decision=protocol_accept TLS 1.3 secure channel, PSK identity NVMe1R01 {TLS_HOST} {DISK0} ")
            )
            .await,
            "{:#?}",
            srv.logs()
        );
        assert!(
            !srv.logs().iter().any(|l| l.contains("fail_closed_tls")),
            "{:#?}",
            srv.logs()
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_kernel_host_holding_another_key_is_refused_before_nvme_tcp() {
        require_root();
        require_module();
        tls_support::require_tlshd();
        let nvme = tls_support::nvme();
        let ours = tls_support::gen_key(&nvme);
        let theirs = tls_support::gen_key(&nvme);
        let host = "nqn.2026-10.net.netget:kernel-tls-stranger";
        tls_support::insert(&nvme, &theirs, host, DISK0);
        let srv = start_on(
            "127.0.0.1",
            0,
            policy(REAL_POLICY),
            Some(json!({"tls_key": ours})),
        )
        .await;
        let port = srv.port.to_string();
        let out = run(
            &nvme,
            &[
                "connect", "-n", DISK0, "-t", "tcp", "-a", "127.0.0.1", "-s", &port, "-q", host,
                "--tls",
            ],
        )
        .await;
        assert!(
            !out.status.success(),
            "connected with a key the target does not hold: {}",
            text(&out.stdout)
        );
        assert!(
            logged(&srv, "the PSK digest does not match").await,
            "{:#?}",
            srv.logs()
        );
        assert!(events(&srv.state, srv.id, "nvme_tcp_connect").await.is_empty());
    }
}
