//! A network namespace joined to the host by a veth pair, for tests whose peer is the Linux
//! kernel itself (its vxlan driver, say). The kernel's sockets live inside the namespace, so
//! NetGet can bind the same well-known port on the host side without colliding.
//!
//! Creating one needs root, so outside root every `ip` command goes through `sudo -n`, which
//! is passwordless on CI runners. Neither available is a **failure** naming what to do, not a
//! skip. Linux only.
#![allow(dead_code)] // compiled into every test target with the features; used by a few
use std::net::Ipv4Addr;
use std::process::{Command, Output};

/// `ip` (or anything else) as root: directly when we are root, through `sudo -n` otherwise.
pub fn privileged(program: &str) -> Command {
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } == 0 {
        Command::new(program)
    } else {
        let mut c = Command::new("sudo");
        c.args(["-n", program]);
        c
    }
}

fn run(mut c: Command, what: &str) -> Output {
    let out = c.output().unwrap_or_else(|e| {
        panic!("{what}: cannot run ({e}); this test needs iproute2 (apt-get install iproute2) and root or passwordless sudo")
    });
    assert!(
        out.status.success(),
        "{what} failed: {}{}\nThis test needs root or passwordless sudo, and iproute2.",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    out
}

pub struct Netns {
    pub name: String,
    /// The host end of the veth: 198.18.<subnet>.1.
    pub host_ip: Ipv4Addr,
    /// The namespace end: 198.18.<subnet>.2, on interface `ns_if`.
    pub ns_ip: Ipv4Addr,
    pub ns_if: String,
    /// The host end of the veth, for a test that captures on it or binds a raw socket to it.
    pub host_if: String,
}

impl Netns {
    /// `tag` keeps names apart between tests (≤ 4 characters); `subnet` picks 198.18.<subnet>.0/30.
    pub fn create(tag: &str, subnet: u8) -> Self {
        let pid = std::process::id() % 100_000;
        let name = format!("ng{tag}{pid}");
        let (host_if, ns_if) = (format!("ngh{tag}{pid}"), format!("ngn{tag}{pid}"));
        let host_ip = Ipv4Addr::new(198, 18, subnet, 1);
        let ns_ip = Ipv4Addr::new(198, 18, subnet, 2);
        let ns = Netns {
            name: name.clone(),
            host_ip,
            ns_ip,
            ns_if: ns_if.clone(),
            host_if: host_if.clone(),
        };
        // Leftovers from a run that was killed would make every step below fail.
        let _ = privileged("ip").args(["netns", "del", &name]).output();
        let _ = privileged("ip").args(["link", "del", &host_if]).output();
        let ip = |args: &[&str]| {
            let mut c = privileged("ip");
            c.args(args);
            run(c, &format!("ip {}", args.join(" ")));
        };
        ip(&["netns", "add", &name]);
        ip(&[
            "link", "add", &host_if, "type", "veth", "peer", "name", &ns_if, "netns", &name,
        ]);
        ip(&["addr", "add", &format!("{host_ip}/30"), "dev", &host_if]);
        ip(&["link", "set", &host_if, "up"]);
        ns.exec(&["ip", "addr", "add", &format!("{ns_ip}/30"), "dev", &ns_if]);
        ns.exec(&["ip", "link", "set", &ns_if, "up"]);
        ns.exec(&["ip", "link", "set", "lo", "up"]);
        ns
    }

    /// A command inside the namespace, as root.
    pub fn command(&self, args: &[&str]) -> Command {
        let mut c = privileged("ip");
        c.args(["netns", "exec", &self.name]);
        c.args(args);
        c
    }

    /// Run inside the namespace; a failure is a test failure.
    pub fn exec(&self, args: &[&str]) -> Output {
        run(self.command(args), &args.join(" "))
    }

    /// Run inside the namespace without blocking the runtime, whatever the exit status.
    pub async fn output(&self, args: &[&str]) -> Output {
        tokio::process::Command::from(self.command(args))
            .output()
            .await
            .expect("ip netns exec")
    }

    /// Run inside the namespace and return the output whatever the exit status.
    pub fn try_exec(&self, args: &[&str]) -> Output {
        self.command(args).output().expect("ip netns exec")
    }
}

impl Drop for Netns {
    fn drop(&mut self) {
        let _ = privileged("ip").args(["netns", "del", &self.name]).output();
        let _ = privileged("ip")
            .args(["link", "del", &self.host_if])
            .output();
    }
}
