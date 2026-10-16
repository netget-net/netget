//! NetGet's NIS server against **yp-tools** 4.2 and **ypbind-mt** 2.7 (Linux; libnsl and
//! libtirpc), the clients every Linux NIS deployment is driven and debugged with, with NetGet
//! registered as ypserv in the system **rpcbind** and **rpcinfo** reading the registration.
//!
//! - `rpcinfo -p`, `-t`, `-u`: the registration NetGet made (tcp and udp, its own port) and a
//!   NULL over each transport.
//! - `ypcat -h` (ALL over TCP, found through rpcbind; `-k`, nickname translation, a missing
//!   map, a refused domain) and `yppoll -h` (DOMAIN, ORDER and MASTER over UDP) — the paths
//!   that bypass ypbind.
//! - `ypbind` bound to NetGet from a temporary config, in a UTS namespace of its own so the
//!   host's domain name is untouched; then `ypwhich`, `ypmatch` (MATCH, a missing key),
//!   `ypwhich -m` (MAPLIST then MASTER per map) and `yptest` (FIRST, NEXT, ORDER, MAPLIST,
//!   ALL through libnsl's own calls).
//! - At stop NetGet removes its registration, and rpcinfo shows that too.
//!
//! Needs root or passwordless sudo (ypbind writes /var/yp/binding and registers with rpcbind;
//! stale registrations are removed as root), rpcbind running, and yp-tools, ypbind-mt and
//! util-linux's unshare installed. Fails rather than skips without them. Program 100004 is
//! one row in rpcbind, so the test holds a lock the client suite's ypserv test also takes.
//! No LLM calls: the python policy in `support.rs` plays the model.
use super::support::{self, linux, DOMAIN};
use crate::helpers::netns::privileged;
use std::process::Command;
use std::time::Duration;

const ALICE: &str = "alice:x:1000:1000:Alice Liddell:/home/alice:/bin/bash";
const BOB: &str = "bob:x:1001:100::/home/bob:/bin/sh";

fn yp(binary: &'static str, args: &[&str]) -> Command {
    let mut c = Command::new(binary);
    c.args(args);
    c
}

/// ypbind, killed (as root, since it runs as root) and its binding files removed on drop.
struct Ypbind {
    config: tempfile::NamedTempFile,
}

impl Drop for Ypbind {
    fn drop(&mut self) {
        let path = self.config.path().to_string_lossy().to_string();
        let _ = privileged("pkill")
            .args(["-f", &format!("ypbind -n -no-ping -f {path}")])
            .output();
        for v in ["1", "2", "3"] {
            let _ = privileged("rm")
                .args(["-f", &format!("/var/yp/binding/{DOMAIN}.{v}")])
                .output();
        }
    }
}

#[tokio::test]
async fn yp_tools_and_ypbind_read_netget() {
    let _lock = linux::lock_program();
    linux::require_rpcbind();
    linux::clear_ypserv_registrations();
    let s0 = support::start(
        support::policy(),
        Some(serde_json::json!({"portmapper": "127.0.0.1:111"})),
    )
    .await;
    let port = s0.port.to_string();

    // The registration, as rpcbind holds it.
    let (ok, text) = linux::rpcinfo(&["-p", "127.0.0.1"]);
    assert!(ok, "{text}");
    let mut rows = linux::ypserv_rows(&text);
    rows.sort();
    assert_eq!(
        rows,
        [
            ("2".to_string(), "tcp".to_string(), port.clone()),
            ("2".to_string(), "udp".to_string(), port.clone())
        ],
        "{text}"
    );
    for t in ["-t", "-u"] {
        let (ok, text) = linux::rpcinfo(&[t, "127.0.0.1", "ypserv", "2"]);
        assert!(
            ok && text.contains("program 100004 version 2 ready and waiting"),
            "rpcinfo {t}: {text}"
        );
    }

    // ypcat -h: ALL over TCP, found through rpcbind, no ypbind involved.
    let (ok, text) = linux::run_async(
        yp(
            "ypcat",
            &["-h", "127.0.0.1", "-d", DOMAIN, "-k", "passwd.byname"],
        ),
        "ypcat",
        linux::YP_TOOLS,
    )
    .await;
    assert!(ok, "{text}");
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(
        lines,
        [format!("alice {ALICE}"), format!("bob {BOB}")],
        "{text}"
    );
    // "hosts" is a nickname for hosts.byname: one line per key, so per host name.
    let (ok, text) = linux::run_async(
        yp("ypcat", &["-h", "127.0.0.1", "-d", DOMAIN, "hosts"]),
        "ypcat",
        linux::YP_TOOLS,
    )
    .await;
    assert!(ok, "{text}");
    assert_eq!(
        text.lines().collect::<Vec<_>>(),
        [
            "10.0.0.1\tgateway gw",
            "10.0.0.1\tgateway gw",
            "10.0.0.2\tfiles"
        ],
        "{text}"
    );
    let (ok, text) = linux::run_async(
        yp("ypcat", &["-h", "127.0.0.1", "-d", DOMAIN, "shadow.byname"]),
        "ypcat",
        linux::YP_TOOLS,
    )
    .await;
    assert!(!ok && text.contains("No such map"), "{text}");
    let (ok, text) = linux::run_async(
        yp(
            "ypcat",
            &["-h", "127.0.0.1", "-d", "other.test", "passwd.byname"],
        ),
        "ypcat",
        linux::YP_TOOLS,
    )
    .await;
    assert!(!ok, "a domain the model does not serve: {text}");

    // yppoll -h: DOMAIN, ORDER and MASTER over UDP.
    let (ok, text) = linux::run_async(
        yp(
            "yppoll",
            &["-h", "127.0.0.1", "-d", DOMAIN, "passwd.byname"],
        ),
        "yppoll",
        linux::YP_TOOLS,
    )
    .await;
    assert!(ok, "{text}");
    assert!(
        text.contains(&format!("Domain {DOMAIN} is supported")),
        "{text}"
    );
    assert!(text.contains("order number 1790000000"), "{text}");
    assert!(text.contains("The master server is nis-master"), "{text}");

    // ypbind, bound to NetGet from a temporary config.
    let config = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(config.path(), format!("domain {DOMAIN} server 127.0.0.1\n")).unwrap();
    let path = config.path().to_string_lossy().to_string();
    let bind = Ypbind { config };
    let mut start = privileged("unshare");
    start.args([
        "--uts",
        "sh",
        "-c",
        &format!("domainname {DOMAIN} && exec ypbind -n -no-ping -f {path}"),
    ]);
    let ypbind = crate::helpers::real_server::ToolProcess::spawn(start, "ypbind", linux::YPBIND)
        .expect("ypbind starts");
    let bound = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let (ok, text) =
                linux::run_async(yp("ypwhich", &["-d", DOMAIN]), "ypwhich", linux::YP_TOOLS).await;
            if ok {
                return text;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("ypbind never bound: {:?}", ypbind.lines()));
    assert_eq!(bound.trim(), "127.0.0.1");

    let (ok, text) = linux::run_async(
        yp("ypmatch", &["-d", DOMAIN, "alice", "passwd.byname"]),
        "ypmatch",
        linux::YP_TOOLS,
    )
    .await;
    assert!(ok && text.trim() == ALICE, "{text}");
    let (ok, text) = linux::run_async(
        yp("ypmatch", &["-d", DOMAIN, "-k", "100", "10", "group.bygid"]),
        "ypmatch",
        linux::YP_TOOLS,
    )
    .await;
    assert!(ok, "{text}");
    assert_eq!(
        text.lines().collect::<Vec<_>>(),
        ["100 staff:x:100:alice,bob", "10 wheel:x:10:alice"],
        "{text}"
    );
    let (ok, text) = linux::run_async(
        yp("ypmatch", &["-d", DOMAIN, "mallory", "passwd.byname"]),
        "ypmatch",
        linux::YP_TOOLS,
    )
    .await;
    assert!(!ok && text.contains("No such key"), "{text}");

    // ypwhich -m: MAPLIST, then MASTER for each map.
    let (ok, text) = linux::run_async(
        yp("ypwhich", &["-d", DOMAIN, "-m"]),
        "ypwhich",
        linux::YP_TOOLS,
    )
    .await;
    assert!(ok, "{text}");
    let mut masters: Vec<&str> = text.lines().collect();
    masters.sort();
    assert_eq!(masters.len(), 8, "{text}");
    assert!(masters.iter().all(|l| l.ends_with(" nis-master")), "{text}");
    assert!(masters.contains(&"netgroup nis-master"), "{text}");

    // yptest: libnsl's own yp_match, yp_first, yp_next, yp_master, yp_order, yp_maplist and
    // yp_all against the bound server.
    let (_, text) = linux::run_async(
        yp(
            "yptest",
            &["-d", DOMAIN, "-m", "passwd.byname", "-u", "alice"],
        ),
        "yptest",
        linux::YP_TOOLS,
    )
    .await;
    for (test, expect) in [
        ("Test 3: yp_match", ALICE.to_string()),
        ("Test 4: yp_first", format!("alice {ALICE}")),
        ("Test 5: yp_next", format!("bob {BOB}")),
        ("Test 6: yp_master", "nis-master".to_string()),
        ("Test 7: yp_order", "1790000000".to_string()),
    ] {
        let after = text
            .split(test)
            .nth(1)
            .unwrap_or_else(|| panic!("no {test}: {text}"));
        assert_eq!(
            after.lines().nth(1).map(str::trim),
            Some(expect.as_str()),
            "{test}: {text}"
        );
    }
    assert!(
        text.split("Test 8: yp_maplist")
            .nth(1)
            .is_some_and(|t| t.contains("passwd.byuid")),
        "{text}"
    );
    drop(ypbind);
    drop(bind);

    // What NetGet's model was shown: every procedure the tools used.
    let walks = support::events(&s0.state, s0.id, "nis_map_read").await;
    let procedures: std::collections::BTreeSet<&str> = walks
        .iter()
        .map(|w| w["procedure"].as_str().unwrap())
        .collect();
    assert_eq!(
        procedures.into_iter().collect::<Vec<_>>(),
        ["all", "first", "next"],
        "{walks:?}"
    );
    assert!(
        !support::events(&s0.state, s0.id, "nis_domain_query")
            .await
            .is_empty(),
        "ypbind and yppoll ask DOMAIN"
    );

    // At stop the registration goes.
    s0.state.remove_server(s0.id).await;
    let gone = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let (_, text) = linux::rpcinfo(&["-p", "127.0.0.1"]);
            if linux::ypserv_rows(&text).is_empty() {
                return text;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await;
    assert!(
        gone.is_ok(),
        "ypserv still registered after the server stopped"
    );
}
