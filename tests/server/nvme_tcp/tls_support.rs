//! The Linux side of an NVMe/TCP secure channel: nvme-cli makes and inserts the keys, and
//! tlshd (ktls-utils) runs the kernel's TLS handshakes, as the host and as the target.
//!
//! Both need to be current. Ubuntu 24.04's nvme-cli 2.8 (libnvme 1.8 on OpenSSL 3.0) derives
//! every key from an HKDF info of the host NQN alone, which no implementation of the
//! specification can match, and its tlshd 0.9 cannot find a key on the target side. The
//! `nvme-tcp` pair job builds both from source; [`insert`] checks the first before anything
//! depends on it, so an old nvme-cli fails here saying so rather than as a handshake that never
//! completes.
#![cfg(target_os = "linux")]

use netget::server::nvme_tcp::tls_psk::{host_offer, ConfiguredKey};
use std::path::{Path, PathBuf};
use std::process::Command;

/// nvme-cli: `NETGET_NVME_CLI`, or the first `nvme` on PATH (the job puts the one it built
/// first), or a failure that says how to get one.
pub fn nvme() -> PathBuf {
    if let Some(p) = std::env::var_os("NETGET_NVME_CLI") {
        return PathBuf::from(p);
    }
    let mut dirs: Vec<PathBuf> =
        std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()).collect();
    dirs.extend(["/usr/local/sbin".into(), "/usr/sbin".into(), "/usr/bin".into()]);
    dirs.into_iter()
        .map(|d| d.join("nvme"))
        .find(|p| p.is_file())
        .expect(
            "nvme (nvme-cli) is not installed. It makes and inserts the TLS keys for the \
             independent host and target this test exists for; build a current one (see \
             tests/server/nvme_tcp/AGENTS.md) — Ubuntu 24.04's 2.8 derives keys no other \
             implementation matches",
        )
}

fn run(bin: &Path, args: &[&str]) -> (bool, String, String) {
    let out = Command::new(bin)
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("running {}: {e}", bin.display()));
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).trim().to_string(),
        String::from_utf8_lossy(&out.stderr).trim().to_string(),
    )
}

/// tlshd is running, or a failure that says how to start it.
pub fn require_tlshd() {
    let (running, _, _) = run(Path::new("pgrep"), &["-x", "tlshd"]);
    assert!(
        running,
        "tlshd (ktls-utils) is not running. The kernel hands every NVMe/TCP TLS handshake to \
         it, as host and as target; start a current one with keyrings=.nvme in its config (see \
         tests/server/nvme_tcp/AGENTS.md)"
    );
}

/// A configured PSK from nvme-cli's own generator, SHA-256.
pub fn gen_key(nvme: &Path) -> String {
    let (ok, key, err) = run(nvme, &["gen-tls-key", "--hmac=1"]);
    assert!(ok && key.starts_with("NVMeTLSkey-1:01:"), "nvme gen-tls-key: {key} {err}");
    key
}

/// Put the TLS PSK for (host, subsystem) in the kernel's `.nvme` keyring under a version 1
/// identity, after checking libnvme derives the identity NetGet does. Returns the key's serial.
pub fn insert(nvme: &Path, key: &str, hostnqn: &str, subnqn: &str) -> String {
    let ours = host_offer(
        &ConfiguredKey::parse(key).expect("nvme-cli's key parses"),
        hostnqn,
        subnqn,
        1,
    )
    .0
    .text();
    let (ok, theirs, err) = run(
        nvme,
        &[
            "check-tls-key",
            &format!("--keydata={key}"),
            &format!("--hostnqn={hostnqn}"),
            &format!("--subsysnqn={subnqn}"),
            "--identity=1",
        ],
    );
    let theirs = theirs.lines().last().unwrap_or_default().to_string();
    assert!(
        ok && theirs == ours,
        "libnvme's PSK identity is not NetGet's.\n  libnvme: {theirs}\n  NetGet:  {ours}\n{err}\n\
         A digest that differs means libnvme derived another retained PSK: nvme-cli 2.8 with \
         libnvme 1.8 on OpenSSL 3.0 (Ubuntu 24.04) does, and nothing that follows the \
         specification can interoperate with it. Use a current nvme-cli."
    );
    let (ok, out, err) = run(
        nvme,
        &[
            "keys",
            "insert-tls-psk",
            &format!("--keydata={key}"),
            &format!("--hostnqn={hostnqn}"),
            &format!("--subsysnqn={subnqn}"),
            "--identity=1",
        ],
    );
    let serial = out
        .split_whitespace()
        .last()
        .filter(|s| s.len() == 8 && s.bytes().all(|b| b.is_ascii_hexdigit()))
        .unwrap_or_else(|| panic!("nvme keys insert-tls-psk: {ok} {out} {err}"))
        .to_string();
    // nvme-cli inserts the key readable by its possessor alone, and tlshd on the target side
    // searches .nvme for it. Changing a key's permissions takes possession of it, which a shell
    // gets by linking .nvme into its own session keyring.
    let keyring = std::fs::read_to_string("/proc/keys")
        .unwrap_or_default()
        .lines()
        .find(|l| l.split_whitespace().nth(8) == Some(".nvme:"))
        .and_then(|l| l.split_whitespace().next())
        .map(str::to_string)
        .expect("the kernel's .nvme keyring (CONFIG_NVME_KEYRING)");
    let (ok, out, err) = run(
        Path::new("sh"),
        &[
            "-c",
            &format!("keyctl link 0x{keyring} @s && keyctl setperm 0x{serial} 0x3f3f0000"),
        ],
    );
    assert!(ok, "keyctl setperm 0x{serial}: {out} {err}");
    serial
}
