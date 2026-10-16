//! NetGet's AFP client against **netatalk 4.6's afpd**, an independent AFP server, run
//! unprivileged in a temporary directory: one guest volume whose files the test writes to disk
//! before the client connects and reads back from disk after. afpd reaches NetGet through a
//! recording relay, so tshark's `dsi` and `afp` dissectors read every byte both ways.
//!
//! Guest access (`uams_guest.so`, `guest account` = the user running the test) is the least
//! privileged honest configuration: a Cleartxt Passwrd login would need a PAM account and
//! afpd running as root to switch to it. NetGet's cleartext login is exercised against its own
//! server in `e2e_test.rs` — a regression, not evidence.
//!
//! Fails, rather than skips, when afpd is missing: `brew install netatalk` on macOS; on Ubuntu
//! `sh scripts/test-peers/build-netatalk.sh <dir>` (Ubuntu's netatalk package is 3.x) and put
//! `<dir>/sbin` on `PATH`. No LLM calls: the python policy in `support.rs` plays the model.
use super::support::{self, TOUR};
use crate::helpers::real_server::{InstallHint, RealServer};
use crate::helpers::recording_relay;
use crate::helpers::E2EResult;
use serde_json::json;
use std::time::Duration;

const NETATALK: InstallHint = InstallHint {
    brew: "netatalk",
    apt: "netatalk 4.x (Ubuntu's package is 3.x): run `sh scripts/test-peers/build-netatalk.sh \
          <dir>` and put <dir>/sbin on PATH",
};

const AFP_CONF: &str = "[Global]
afp port = {port}
afp listen = 127.0.0.1
uam list = uams_guest.so
guest account = {user}
log level = default:note
log file = /dev/stdout
vol dbpath = {dir}/db/
zeroconf = no
server name = NetatalkTest

[Share]
path = {dir}/vol
";

async fn afpd() -> E2EResult<RealServer> {
    let user = std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .map_err(|_| "USER is not set; afpd's guest account must be the user running the test")?;
    RealServer::builder("afpd", NETATALK)
        .setup_command("mkdir", NETATALK, ["-p", "{dir}/vol/sub", "{dir}/db"])
        .config_file("afp.conf", &AFP_CONF.replace("{user}", &user))
        .args(["-d", "-F", "{dir}/afp.conf"])
        .ready_when_log_matches("Netatalk AFP/TCP listening on")
        .start()
        .await
}

fn netatalk_version() -> String {
    std::process::Command::new(
        crate::helpers::real_server::find_binary("afpd").unwrap_or_else(|| "afpd".into()),
    )
    .arg("-v")
    .output()
    .map(|o| {
        String::from_utf8_lossy(&o.stdout)
            .lines()
            .next()
            .unwrap_or("")
            .to_string()
    })
    .unwrap_or_default()
}

#[tokio::test]
async fn netget_tours_a_netatalk_volume_and_its_effects_land_on_disk() -> E2EResult<()> {
    let server = afpd().await?;
    println!("{}", netatalk_version());
    let vol = server.dir().join("vol");
    std::fs::write(vol.join("hello.txt"), "hello from netatalk\n")?;
    std::fs::write(vol.join("bin.dat"), [0u8, 1, 2, 255])?;
    std::fs::write(vol.join("todelete.txt"), "x")?;
    std::fs::write(vol.join("sub/inner.txt"), "abc")?;
    let upstream: std::net::SocketAddr = server.addr().parse()?;
    let (relay, streams) = recording_relay::tcp_relay(upstream).await;

    let c = support::connect(&relay.to_string(), support::script(TOUR), json!({})).await;
    let connected = c.wait_for_events("afp_connected", 1, 30).await;
    assert_eq!(connected.len(), 1, "{}\n{}", c.log_text(), server.log());
    let srv = &connected[0]["server"];
    assert!(
        srv["machine_type"]
            .as_str()
            .unwrap_or("")
            .starts_with("Netatalk"),
        "{srv}"
    );
    assert_eq!(srv["name"], "NetatalkTest");
    assert_eq!(connected[0]["user"], "guest");
    assert_eq!(connected[0]["uam"], "No User Authent");

    let vols = c.wait_for_events("afp_volumes", 1, 30).await;
    assert!(
        vols[0]["volumes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v["name"] == "share"),
        "{vols:?}"
    );

    // The last step of the tour: `sub` listed after the delete.
    let dirs = c.wait_for_events("afp_directory", 2, 60).await;
    assert_eq!(dirs.len(), 2, "{}\n{}", c.log_text(), server.log());
    let root = &dirs[0]["entries"];
    let entry = |name: &str| {
        root.as_array()
            .unwrap()
            .iter()
            .find(|e| e["name"] == name)
            .cloned()
            .unwrap_or_else(|| panic!("{name} not in {root}"))
    };
    assert_eq!(entry("hello.txt")["size"], 20);
    assert_eq!(entry("hello.txt")["type"], "file");
    assert_eq!(entry("bin.dat")["size"], 4);
    assert_eq!(entry("sub")["type"], "directory");
    assert_eq!(entry("sub")["offspring"], 1);
    assert!(entry("hello.txt")["id"].as_u64().unwrap() >= 17);
    assert!(entry("hello.txt")["modified"]
        .as_str()
        .unwrap()
        .starts_with("20"));
    let inner = &dirs[1];
    assert_eq!(inner["path"], "sub");
    assert_eq!(inner["entries"][0]["name"], "inner.txt");
    assert_eq!(inner["entries"][0]["size"], 3);

    // What was read is what the test put on disk, text and bytes alike.
    let files = c.wait_for_events("afp_file", 2, 30).await;
    let file = |p: &str| files.iter().find(|f| f["path"] == p).cloned().unwrap();
    assert_eq!(file("hello.txt")["content"], "hello from netatalk\n");
    assert_eq!(file("hello.txt")["encoding"], "utf8");
    assert_eq!(file("hello.txt")["truncated"], false);
    assert_eq!(file("bin.dat")["content"], "000102ff");
    assert_eq!(file("bin.dat")["encoding"], "hex");
    let info = c.wait_for_events("afp_info", 1, 30).await;
    assert_eq!(info[0]["item"]["type"], "directory");

    // What was written, created and deleted is what is on disk now.
    let done = c.wait_for_events("afp_done", 3, 30).await;
    assert_eq!(done.len(), 3, "{}", c.log_text());
    assert_eq!(done[0]["bytes_written"], 18);
    assert_eq!(
        std::fs::read_to_string(vol.join("written.txt"))?,
        "written by NetGet\n"
    );
    assert!(vol.join("made").is_dir());
    assert!(!vol.join("todelete.txt").exists());

    // A refusal arrives as an event with the server's code.
    c.send(json!({"type": "afp_read_file", "volume": "share", "path": "missing.txt"}))
        .await;
    let errors = c.wait_for_events("afp_error", 1, 30).await;
    assert_eq!(errors[0]["code"], -5018, "{errors:?}");
    assert_eq!(errors[0]["error"], "kFPObjectNotFound");
    let errors_before = errors.len();
    c.send(json!({"type": "afp_list_directory", "volume": "NoSuchVolume", "path": ""}))
        .await;
    let errors = c.wait_for_events("afp_error", errors_before + 1, 30).await;
    assert_eq!(errors.last().unwrap()["operation"], "afp_list_directory");

    // A clean logout.
    let out = c.send(json!({"type": "disconnect"})).await;
    assert!(
        matches!(
            out,
            netget::state::client_handles::ClientSendOutcome::Disconnected
        ),
        "{out:?}"
    );
    tokio::time::timeout(Duration::from_secs(10), async {
        while streams.lock().unwrap().len() < 2 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await?;
    let streams = streams.lock().unwrap().clone();
    for s in streams {
        let chunks = s.lock().unwrap().clone();
        if !chunks.is_empty() {
            oracle_of(&chunks).assert_clean();
        }
    }
    Ok(())
}

fn oracle_of(chunks: &[(bool, Vec<u8>)]) -> crate::helpers::pcap_oracle::PcapOracle {
    let mut o = crate::helpers::pcap_oracle::PcapOracle::tcp("afp")
        .also_named("afp")
        .port(548);
    for (to_server, bytes) in chunks {
        o = if *to_server {
            o.to_server(bytes)
        } else {
            o.from_server(bytes)
        };
    }
    o
}
