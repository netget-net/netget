//! Protocol dependency system
//!
//! Defines runtime dependencies that protocols may require and provides
//! checking logic to determine if dependencies are available.

use std::process::Command;
use tracing::debug;

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
use tracing::warn;

/// What a dependency probe could establish.
///
/// Three answers, not two, because the startup gate must be able to tell "absent" from "could
/// not tell": only [`DependencyStatus::Missing`] refuses a start. A probe that cannot run —
/// no `PATH` to search, a platform with no loader query — answers
/// [`DependencyStatus::Unknown`], and that is logged and let through, never turned into "no".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DependencyStatus {
    /// The probe found it.
    Available,
    /// The probe ran and established it is not there.
    Missing,
    /// The probe could not answer; the string says why.
    Unknown(String),
}

/// A runtime dependency that a protocol requires
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ProtocolDependency {
    /// Requires a system library (e.g., libpcap, libsmbclient, libgit2)
    /// The string is the library name without prefix/suffix (e.g., "pcap" not "libpcap.so")
    SystemLibrary(&'static str),

    /// Requires a tool to be available in PATH (e.g., "protoc", "openssl")
    ToolInPath(&'static str),

    /// Requires a program at a fixed absolute path, not looked up on `PATH` (FUSE-T's
    /// `go-nfsv4`, which FUSE-T's own libraries start from `/usr/local/bin` whatever `PATH`
    /// says — a process launched by launchd has no `/usr/local/bin` on it). When `env` is set in
    /// the environment it names the program instead, as it does for the code that starts it.
    ProgramAt {
        path: &'static str,
        env: Option<&'static str>,
    },

    /// Requires raw socket access (CAP_NET_RAW on Linux, or root)
    RawSocketAccess,

    /// Requires ability to bind to a privileged port < 1024
    PrivilegedPort(u16),

    /// Requires full root/administrator access
    RootAccess,

    /// Requires TUN/TAP device creation (CAP_NET_ADMIN on Linux, or root)
    /// Used by VPN protocols like WireGuard, OpenVPN
    TunDeviceAccess,

    /// Requires promiscuous mode access (CAP_NET_RAW on Linux, or root)
    /// Used by packet capture protocols like ARP, DataLink
    PromiscuousMode,
}

impl ProtocolDependency {
    /// Get a human-readable name for this dependency
    pub fn name(&self) -> String {
        match self {
            Self::SystemLibrary(name) => format!("lib{}", name),
            Self::ToolInPath(name) => name.to_string(),
            Self::ProgramAt { path, .. } => std::path::Path::new(path)
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| path.to_string()),
            Self::RawSocketAccess => "raw socket access".to_string(),
            Self::PrivilegedPort(port) => format!("port {}", port),
            Self::RootAccess => "root access".to_string(),
            Self::TunDeviceAccess => "TUN device access".to_string(),
            Self::PromiscuousMode => "promiscuous mode".to_string(),
        }
    }

    /// Get a human-readable description of this dependency
    pub fn description(&self) -> String {
        match self {
            Self::SystemLibrary(name) => {
                format!("System library lib{} must be installed", name)
            }
            Self::ToolInPath(name) => {
                format!("Tool '{}' must be available in PATH", name)
            }
            Self::ProgramAt { path, env } => format!(
                "Program {} must be installed",
                program_path(path, *env).display()
            ),
            Self::RawSocketAccess => {
                "Raw socket access (requires root or CAP_NET_RAW capability)".to_string()
            }
            Self::PrivilegedPort(port) => {
                format!(
                    "Privileged port {} (requires root or CAP_NET_BIND_SERVICE)",
                    port
                )
            }
            Self::RootAccess => "Root/Administrator access required".to_string(),
            Self::TunDeviceAccess => {
                "TUN/TAP device creation (requires root or CAP_NET_ADMIN)".to_string()
            }
            Self::PromiscuousMode => "Promiscuous mode (requires root or CAP_NET_RAW)".to_string(),
        }
    }

    /// Whether this dependency is present, for the informational consumers — the TUI's
    /// excluded-protocol footer and the model's protocol list.
    ///
    /// Only a definite [`DependencyStatus::Missing`] reads as unavailable: a probe that could
    /// not answer must not hide a protocol that may well work (the reason `DeviceAccess` derives
    /// no dependency at all).
    pub fn is_available(&self, caps: &crate::privilege::SystemCapabilities) -> bool {
        self.status(caps) != DependencyStatus::Missing
    }

    /// What the probe for this dependency established. See [`DependencyStatus`].
    pub fn status(&self, caps: &crate::privilege::SystemCapabilities) -> DependencyStatus {
        match self {
            Self::SystemLibrary(name) => system_library_status(name),
            Self::ToolInPath(name) => tool_in_path_status(name),
            Self::ProgramAt { path, env } => {
                if is_executable_file(&program_path(path, *env)) {
                    DependencyStatus::Available
                } else {
                    DependencyStatus::Missing
                }
            }
            other => {
                if other.is_met_by_capabilities(caps) {
                    DependencyStatus::Available
                } else {
                    DependencyStatus::Missing
                }
            }
        }
    }

    /// The capability-derived variants, answered from the probed [`SystemCapabilities`].
    ///
    /// [`SystemCapabilities`]: crate::privilege::SystemCapabilities
    fn is_met_by_capabilities(&self, caps: &crate::privilege::SystemCapabilities) -> bool {
        match self {
            Self::SystemLibrary(_) | Self::ToolInPath(_) | Self::ProgramAt { .. } => true,
            Self::RawSocketAccess => caps.has_raw_socket_access,
            Self::PrivilegedPort(_) => caps.can_bind_privileged_ports,
            Self::RootAccess => caps.is_root,
            Self::TunDeviceAccess => {
                // TUN device creation requires CAP_NET_ADMIN on Linux, or root on other platforms
                #[cfg(target_os = "linux")]
                {
                    caps.is_root || check_cap_net_admin()
                }
                #[cfg(not(target_os = "linux"))]
                {
                    caps.is_root
                }
            }
            // Capture access, not raw-socket access. These are genuinely separable: a macOS
            // user in the ChmodBPF group owns /dev/bpf* without being root, so they can capture
            // (ARP, DataLink, IS-IS) while `SOCK_RAW` still fails. Checking the raw-socket flag
            // here reported those protocols as unavailable to precisely the users who can run
            // them — the mistake `SystemCapabilities` was split apart to make impossible.
            Self::PromiscuousMode => caps.has_packet_capture_access,
        }
    }

    /// Get installation instructions for this dependency
    pub fn installation_hint(&self) -> String {
        match self {
            Self::SystemLibrary(name) => {
                #[cfg(target_os = "linux")]
                {
                    match *name {
                        "pcap" => "Install with: apt-get install libpcap-dev (Debian/Ubuntu) or yum install libpcap-devel (RHEL/CentOS)".to_string(),
                        "smbclient" => "Install with: apt-get install libsmbclient-dev (Debian/Ubuntu)".to_string(),
                        "git2" => "Install with: apt-get install libgit2-dev (Debian/Ubuntu)".to_string(),
                        _ => format!("Install with: apt-get install lib{}-dev (Debian/Ubuntu)", name),
                    }
                }
                #[cfg(target_os = "macos")]
                {
                    match *name {
                        "pcap" => "Install with: brew install libpcap".to_string(),
                        "smbclient" => "Install with: brew install samba".to_string(),
                        "git2" => "Install with: brew install libgit2".to_string(),
                        _ => format!("Install with: brew install lib{}", name),
                    }
                }
                #[cfg(not(any(target_os = "linux", target_os = "macos")))]
                {
                    format!("Install lib{} for your platform", name)
                }
            }
            Self::ToolInPath(name) => {
                match *name {
                    "protoc" => "Install from: https://github.com/protocolbuffers/protobuf/releases or use package manager".to_string(),
                    "fusermount3" => "Install with: apt-get install fuse3 (Debian/Ubuntu) or dnf install fuse3 (Fedora)".to_string(),
                    _ => format!("Ensure '{}' is installed and in PATH", name),
                }
            }
            Self::ProgramAt { path, .. } => match *path {
                "/usr/local/bin/go-nfsv4" => {
                    "Install FUSE-T: brew install --cask macos-fuse-t/cask/fuse-t".to_string()
                }
                _ => format!("Install {path}"),
            },
            Self::RawSocketAccess => {
                #[cfg(target_os = "linux")]
                {
                    "Grant capability with: sudo setcap cap_net_raw+ep /path/to/netget".to_string()
                }
                #[cfg(not(target_os = "linux"))]
                {
                    "Run as root/administrator".to_string()
                }
            }
            Self::PrivilegedPort(port) => {
                format!("Run as root/administrator, or use an unprivileged port (>= 1024) instead of {}", port)
            }
            Self::RootAccess => "Run as root/administrator".to_string(),
            Self::TunDeviceAccess => {
                #[cfg(target_os = "linux")]
                {
                    "Grant capability with: sudo setcap cap_net_admin+ep /path/to/netget".to_string()
                }
                #[cfg(not(target_os = "linux"))]
                {
                    "Run as root/administrator".to_string()
                }
            }
            Self::PromiscuousMode => {
                #[cfg(target_os = "linux")]
                {
                    "Grant capability with: sudo setcap cap_net_raw+ep /path/to/netget".to_string()
                }
                #[cfg(not(target_os = "linux"))]
                {
                    "Run as root/administrator".to_string()
                }
            }
        }
    }
}

/// Ask the dynamic linker whether this process can load a library.
///
/// This is the honest form of the question. A filesystem search answers "is there a
/// file with this name in one of the directories I guessed", which on modern macOS is
/// **always no** for a system library: since Big Sur the system libraries ship only
/// inside the dyld shared cache and `/usr/lib/libpcap.dylib` does not exist on disk,
/// even though `dlopen("libpcap.dylib")` succeeds and every binary on the machine links
/// against it. `dlopen` consults the cache, honours `DYLD_*`/`LD_LIBRARY_PATH`, and
/// resolves whatever the loader would resolve at link time — which is precisely the
/// property a dependency check is trying to establish.
///
/// The handle is released immediately; the point is the answer, not the library.
#[cfg(unix)]
fn dlopen_succeeds(soname: &str) -> bool {
    let Ok(cname) = std::ffi::CString::new(soname) else {
        return false;
    };

    // SAFETY: `cname` is a valid NUL-terminated C string that outlives the call, and
    // the returned handle is closed immediately. `RTLD_LOCAL` keeps the symbols out of
    // the global namespace so a probe cannot change how later symbol lookups resolve.
    unsafe {
        let handle = libc::dlopen(cname.as_ptr(), libc::RTLD_LAZY | libc::RTLD_LOCAL);
        if handle.is_null() {
            false
        } else {
            libc::dlclose(handle);
            true
        }
    }
}

/// The names to try with the dynamic linker, most conventional first.
///
/// Linux only carries the unversioned `lib<name>.so` symlink when the `-dev` package is
/// installed, so the versioned sonames are tried too — a runtime-only install is still
/// a library this process can load.
#[cfg(unix)]
fn library_candidates(name: &str) -> Vec<String> {
    #[cfg(target_os = "macos")]
    {
        vec![
            format!("lib{}.dylib", name),
            format!("{}.dylib", name),
            format!("/usr/lib/lib{}.dylib", name),
            format!("/opt/homebrew/lib/lib{}.dylib", name),
            format!("/usr/local/lib/lib{}.dylib", name),
        ]
    }

    #[cfg(not(target_os = "macos"))]
    {
        vec![
            format!("lib{}.so", name),
            format!("lib{}.so.1", name),
            format!("lib{}.so.0", name),
            format!("lib{}.so.2", name),
        ]
    }
}

/// Probe for a system library.
///
/// `dlopen` success is **Available**. When the loader and the platform's own catalogue
/// (`ldconfig -p`, `pkg-config`) both ran and neither knows the library, that is **Missing**. When
/// no catalogue could be run at all, or the platform has no probe, the answer is **Unknown**.
fn system_library_status(name: &str) -> DependencyStatus {
    // Ask the dynamic linker first on every Unix. This is the only probe that is
    // correct on macOS at all (see `dlopen_succeeds`), and on Linux it subsumes the
    // ldconfig search for the common case while also honouring LD_LIBRARY_PATH.
    #[cfg(unix)]
    {
        for candidate in library_candidates(name) {
            if dlopen_succeeds(&candidate) {
                debug!("dlopen({}) succeeded - lib{} is loadable", candidate, name);
                return DependencyStatus::Available;
            }
        }
        debug!(
            "dlopen found no loadable lib{}; falling back to platform probes",
            name
        );
    }

    // Try to use ldconfig to check if library is available
    #[cfg(target_os = "linux")]
    {
        let output = Command::new("ldconfig").arg("-p").output();

        if let Ok(output) = output {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let lib_pattern = format!("lib{}.so", name);
            let found = stdout.contains(&lib_pattern);
            debug!("Checking for lib{}: found={}", name, found);
            return if found {
                DependencyStatus::Available
            } else {
                DependencyStatus::Missing
            };
        }

        // Fallback: try pkg-config
        let pkg_config_output = Command::new("pkg-config")
            .arg("--exists")
            .arg(name)
            .status();

        if let Ok(status) = pkg_config_output {
            let found = status.success();
            debug!("Checking for {} via pkg-config: found={}", name, found);
            return if found {
                DependencyStatus::Available
            } else {
                DependencyStatus::Missing
            };
        }

        debug!(
            "Could not check for lib{} (ldconfig and pkg-config unavailable)",
            name
        );
        DependencyStatus::Unknown(format!(
            "dlopen found no lib{name} and neither ldconfig nor pkg-config could be run"
        ))
    }

    #[cfg(target_os = "macos")]
    {
        // No filesystem search here on purpose. The previous implementation ran
        // `find /usr/lib /usr/local/lib /opt/homebrew/lib -name lib<name>.dylib`, which
        // returns nothing for every library that ships in the dyld shared cache — so
        // libpcap, which is present and links fine on this platform, was reported
        // missing, and any protocol declaring SystemLibrary("pcap") would have been
        // refused at startup on exactly the OS where it works.
        //
        // dlopen above is the real test. pkg-config is kept only as a last resort for
        // a Homebrew-only library whose dylib name does not follow the convention.
        let pkg_config_output = Command::new("pkg-config")
            .arg("--exists")
            .arg(name)
            .status();

        if let Ok(status) = pkg_config_output {
            let found = status.success();
            debug!("Checking for {} via pkg-config: found={}", name, found);
            return if found {
                DependencyStatus::Available
            } else {
                DependencyStatus::Missing
            };
        }

        // dlopen is the loader's own answer; with no pkg-config to consult there is no
        // second opinion, and the loader not finding it under any conventional name is as
        // definite as this platform gets.
        debug!("dlopen and pkg-config found no lib{} on macOS", name);
        DependencyStatus::Missing
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        // No loader query or package catalogue on this platform.
        warn!(
            "Cannot check for lib{} on this platform; not treating it as missing",
            name
        );
        DependencyStatus::Unknown(format!("no library probe for lib{name} on this platform"))
    }
}

/// Probe for an executable on `PATH`, searching it the way `Command::new(tool)` will.
///
/// This walks `PATH` itself rather than running `which`: the question is whether the protocol's
/// own `Command::new(tool)` will find a program, and a `which` that cannot be spawned (no
/// `PATH`, a minimal container) used to read as "the tool is missing". An unset `PATH` is
/// **Unknown**; a `PATH` searched in full without finding an executable `tool` is **Missing**.
fn tool_in_path_status(tool: &str) -> DependencyStatus {
    let Some(path) = std::env::var_os("PATH") else {
        return DependencyStatus::Unknown("PATH is not set, so there is nothing to search".into());
    };

    #[cfg(windows)]
    let names: Vec<String> = ["", ".exe", ".cmd", ".bat", ".com"]
        .iter()
        .map(|ext| format!("{tool}{ext}"))
        .collect();
    #[cfg(not(windows))]
    let names: Vec<String> = vec![tool.to_string()];

    for dir in std::env::split_paths(&path) {
        if dir.as_os_str().is_empty() {
            continue;
        }
        for name in &names {
            let candidate = dir.join(name);
            if is_executable_file(&candidate) {
                debug!("Found tool '{}' at {}", tool, candidate.display());
                return DependencyStatus::Available;
            }
        }
    }
    debug!("Tool '{}' is not on PATH", tool);
    DependencyStatus::Missing
}

/// Where a [`ProtocolDependency::ProgramAt`] program is: what `env` names when it is set and not
/// empty, else `path`.
pub fn program_path(path: &str, env: Option<&str>) -> std::path::PathBuf {
    env.and_then(std::env::var_os)
        .filter(|v| !v.is_empty())
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from(path))
}

/// A regular file (symlinks followed) the current user may execute.
fn is_executable_file(path: &std::path::Path) -> bool {
    let Ok(metadata) = std::fs::metadata(path) else {
        return false;
    };
    if !metadata.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

/// The dependency that must stop a start, if any: the first **system library, tool or program** among
/// `deps` whose probe established it is absent.
///
/// Dependencies derived from `privilege_requirement` are skipped — startup gates privilege
/// itself, with a better message, and checking them here would report one failure twice. A
/// probe that could not answer ([`DependencyStatus::Unknown`]) is logged and let through:
/// dependencies inform, and "we could not tell" must never become a refusal.
pub fn startup_blocker(
    deps: &[ProtocolDependency],
    caps: &crate::privilege::SystemCapabilities,
) -> Option<ProtocolDependency> {
    for dep in deps {
        if !matches!(
            dep,
            ProtocolDependency::SystemLibrary(_)
                | ProtocolDependency::ToolInPath(_)
                | ProtocolDependency::ProgramAt { .. }
        ) {
            continue;
        }
        match dep.status(caps) {
            DependencyStatus::Available => {}
            DependencyStatus::Missing => return Some(dep.clone()),
            DependencyStatus::Unknown(why) => {
                tracing::warn!(
                    "Could not determine whether {} is present ({}); starting anyway",
                    dep.name(),
                    why
                );
            }
        }
    }
    None
}

/// Check for CAP_NET_ADMIN capability on Linux
#[cfg(target_os = "linux")]
fn check_cap_net_admin() -> bool {
    if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
        for line in status.lines() {
            if line.starts_with("CapEff:") {
                if let Some(cap_hex) = line.split_whitespace().nth(1) {
                    if let Ok(caps) = u64::from_str_radix(cap_hex, 16) {
                        // CAP_NET_ADMIN is bit 12 (0x1000)
                        const CAP_NET_ADMIN: u64 = 1 << 12;
                        let has_cap = (caps & CAP_NET_ADMIN) != 0;
                        debug!(
                            "Checked CAP_NET_ADMIN via /proc: caps=0x{:x}, has_cap={}",
                            caps, has_cap
                        );
                        return has_cap;
                    }
                }
            }
        }
    }

    debug!("Could not detect CAP_NET_ADMIN capability");
    false
}
