//! Real H.323 stacks for NetGet's H.323 suites, two independent families:
//!
//! - **ooh323c**, Objective Systems' stack, as Asterisk's `chan_ooh323` (Ubuntu:
//!   `asterisk asterisk-ooh323`). An endpoint that registers with a gatekeeper, places calls
//!   (`channel originate`) and answers them from a dialplan.
//! - **H323Plus**: GNU Gatekeeper (`gnugk`) and H323Plus's own sample endpoint `simph323`.
//!   Neither is packaged for Ubuntu 24.04 or Homebrew;
//!   `tests/server/h323/install_peers.py` builds both (with PTLib) at pinned tags.
//!
//! Every peer runs on loopback in a temporary directory of its own and is killed when the test
//! ends. A missing binary FAILS the test naming how to install it — never a skip.
#![allow(dead_code)]

use super::real_server::{InstallHint, RealServer};
use super::E2EResult;
use std::time::Duration;

pub const ASTERISK: InstallHint = InstallHint {
    brew: "(no formula: run the suite on Linux)",
    apt: "asterisk asterisk-ooh323",
};

pub const H323PLUS: InstallHint = InstallHint {
    brew: "(no formula: python3 tests/server/h323/install_peers.py <dir>, then put <dir>/bin on PATH)",
    apt: "(not packaged: python3 tests/server/h323/install_peers.py <dir>, then put <dir>/bin on PATH)",
};

/// Where Ubuntu (and Debian) put Asterisk's modules, whatever the architecture.
fn asterisk_modules() -> String {
    for dir in [
        "/usr/lib/x86_64-linux-gnu/asterisk/modules",
        "/usr/lib/aarch64-linux-gnu/asterisk/modules",
        "/usr/lib/asterisk/modules",
    ] {
        if std::path::Path::new(dir).join("chan_ooh323.so").is_file() {
            return dir.to_string();
        }
    }
    "/usr/lib/asterisk/modules".to_string()
}

/// How an Asterisk / chan_ooh323 peer is set up.
pub struct AsteriskSpec<'a> {
    /// `gatekeeper =` in ooh323.conf: an IP (the gatekeeper's RAS port is always 1719 there),
    /// or `DISABLE`.
    pub gatekeeper: &'a str,
    pub h323id: &'a str,
    pub e164: &'a str,
    pub faststart: bool,
    pub tunneling: bool,
}

/// Asterisk with only chan_ooh323 and what a call needs, its H.225.0 listener on `{port}`.
/// Incoming calls to any number are answered and sent a 1004 Hz tone (Milliwatt) for four
/// seconds, then hung up — so a caller that negotiated media correctly receives RTP. A call
/// originated into extension `s@tone` does the same towards whoever answers it. Without a
/// gatekeeper chan_ooh323 refuses a caller that matches no `type=user` profile ("Unacceptable
/// ip"), so one profile admits everything from 127.0.0.1.
pub async fn asterisk(spec: AsteriskSpec<'_>) -> E2EResult<RealServer> {
    let ooh323 = format!(
        "[general]\nport={{port}}\nbindaddr=127.0.0.1\nh323id={h323id}\ne164={e164}\n\
         callerid={h323id}\ngatekeeper={gk}\ncontext=default\ndisallow=all\nallow=ulaw\n\
         faststart={fs}\nh245tunneling={tun}\ndtmfmode=rfc2833\nlogfile={{dir}}/h323_log\n\
         directmedia=no\ntracelevel=6\n\
         [loopback]\ntype=user\nhost=127.0.0.1\ncontext=default\ndisallow=all\nallow=ulaw\n",
        h323id = spec.h323id,
        e164 = spec.e164,
        gk = spec.gatekeeper,
        fs = if spec.faststart { "yes" } else { "no" },
        tun = if spec.tunneling { "yes" } else { "no" },
    );
    RealServer::builder("asterisk", ASTERISK)
        .config_file(
            "asterisk.conf",
            &format!(
                "[directories]\nastetcdir => {{dir}}\nastmoddir => {}\nastvarlibdir => {{dir}}\n\
                 astdbdir => {{dir}}\nastkeydir => {{dir}}\nastdatadir => /usr/share/asterisk\n\
                 astagidir => {{dir}}\nastspooldir => {{dir}}\nastrundir => {{dir}}\n\
                 astlogdir => {{dir}}\n[options]\nnofork = yes\n",
                asterisk_modules()
            ),
        )
        .config_file(
            "modules.conf",
            "[modules]\nautoload=no\nload => res_sorcery_config.so\n\
             load => res_sorcery_memory.so\nload => res_pjproject.so\nload => res_rtp_asterisk.so\n\
             load => codec_ulaw.so\nload => pbx_config.so\nload => app_milliwatt.so\n\
             load => func_timeout.so\nload => res_clioriginate.so\nload => res_timing_timerfd.so\n\
             load => chan_ooh323.so\n",
        )
        .config_file("ooh323.conf", &ooh323)
        .config_file(
            "extensions.conf",
            "[default]\nexten => _X.,1,Answer()\nsame => n,Set(TIMEOUT(absolute)=4)\n\
             same => n,Milliwatt()\n\
             [tone]\nexten => s,1,Answer()\nsame => n,Set(TIMEOUT(absolute)=4)\n\
             same => n,Milliwatt()\n",
        )
        .config_file(
            "logger.conf",
            "[logfiles]\nconsole => notice,warning,error,verbose\n",
        )
        .config_file("rtp.conf", "[general]\nrtpstart=30000\nrtpend=31000\n")
        // Asterisk's XML documentation lives under the package's data directory, and without it
        // Stasis refuses to start, so astdatadir is the package's own.
        .args(["-C", "{dir}/asterisk.conf", "-f", "-vvv", "-n"])
        .ready_when_log_matches(r"(?i)Asterisk Ready")
        .startup_timeout(Duration::from_secs(60))
        .start()
        .await
}

/// Run one Asterisk CLI command against `ast` and return its output.
pub async fn asterisk_cli(ast: &RealServer, command: &str) -> E2EResult<String> {
    let mut c = std::process::Command::new("asterisk");
    c.arg("-C")
        .arg(ast.dir().join("asterisk.conf"))
        .arg("-rx")
        .arg(command);
    super::real_server::run_tool(c, "asterisk", ASTERISK).await
}

/// ooh323c's own log: every H.225.0 and H.245 message it sent and received, by name.
pub fn ooh323_log(ast: &RealServer) -> String {
    std::fs::read_to_string(ast.dir().join("h323_log")).unwrap_or_default()
}

/// GNU Gatekeeper in direct mode, its RAS on `{port}` and its status port on `{port1}`, every
/// endpoint allowed to register.
pub async fn gnugk() -> E2EResult<RealServer> {
    RealServer::builder("gnugk", H323PLUS)
        .config_file(
            "gnugk.ini",
            "[Gatekeeper::Main]\nName=GnuGkTest\nHome=127.0.0.1\nUnicastRasPort={port}\n\
             StatusPort={port1}\nUseBroadcastListener=0\nUseMulticastListener=0\nTimeToLive=300\n\
             [RoutedMode]\nGKRouted=0\nH245Routed=0\nCallSignalPort=0\n\
             [GkStatus::Auth]\nrule=allow\n\
             [Gatekeeper::Auth]\ndefault=allow\n",
        )
        .extra_ports(1)
        .args(["-c", "{dir}/gnugk.ini", "-ttt", "-o", "{dir}/gnugk.trace"])
        .without_tcp_readiness()
        .ready_when_log_matches(r"(?i)(startup|listening|gatekeeper)")
        .startup_timeout(Duration::from_secs(30))
        .start()
        .await
}

/// One command on GnuGk's status port, its answer up to the closing `;`.
pub async fn gnugk_status(gk: &RealServer, command: &str) -> E2EResult<String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let port = gk.extra_ports[0];
    let mut s = tokio::time::timeout(
        Duration::from_secs(10),
        tokio::net::TcpStream::connect(("127.0.0.1", port)),
    )
    .await
    .map_err(|_| "GnuGk's status port did not accept")??;
    s.write_all(format!("{command}\r\n").as_bytes()).await?;
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    let _ = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match s.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    out.extend_from_slice(&buf[..n]);
                    let text = String::from_utf8_lossy(&out);
                    if text.contains(command) && text.trim_end().ends_with(';') {
                        break;
                    }
                }
            }
        }
    })
    .await;
    let _ = s.write_all(b"quit\r\n").await;
    Ok(String::from_utf8_lossy(&out).into_owned())
}

/// GnuGk's own trace.
pub fn gnugk_trace(gk: &RealServer) -> String {
    std::fs::read_to_string(gk.dir().join("gnugk.trace")).unwrap_or_default()
}
