//! Script runtime environment detection

use super::types::ScriptLanguage;
use std::sync::OnceLock;
use std::time::Duration;
use tracing::warn;
#[cfg(not(target_arch = "wasm32"))]
use tracing::{debug, info};

/// How long a single `<runtime> --version` probe may take before it is treated as absent.
///
/// `Command::output()` has no timeout: it reads the child's stdout to EOF, and if the child
/// never exits, the calling thread blocks **forever**. That is not theoretical here. A
/// `--test-threads=100` run wedged completely with 98 of 100 threads parked behind one
/// initialising `AppState::new`, and the initialiser's stack was
/// `detect → detect_javascript → Command::output → read_output`. In production the same stack
/// hangs `netget --mcp` at startup, before it can report anything, if `node` or `python3` is
/// wedged on the machine.
///
/// Five seconds is far more than a version probe needs and short enough that an operator sees
/// a startup, not a hang.
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// Detected once per process. The answer is a property of the MACHINE, not of an `AppState`.
///
/// `AppState::new()` used to run all four probes, and every test and every server creation
/// calls it — so a 100-thread suite spawned four hundred subprocesses to learn the same four
/// facts, and any one of them hanging stalled everything behind it.
static DETECTED: OnceLock<ScriptingEnvironment> = OnceLock::new();

/// Information about available scripting environments
#[derive(Debug, Clone, Default)]
pub struct ScriptingEnvironment {
    /// Python availability and version
    pub python: Option<String>,

    /// JavaScript (Node.js) availability and version
    pub javascript: Option<String>,

    /// Go availability and version
    pub go: Option<String>,

    /// Perl availability and version
    pub perl: Option<String>,
}

impl ScriptingEnvironment {
    /// Detect available scripting environments
    /// The process-wide detection result, computed on first call.
    ///
    /// Prefer this over [`Self::detect_uncached`] everywhere: runtimes do not appear and
    /// disappear while NetGet runs, and probing per `AppState` costs four subprocess spawns
    /// each time for an answer that cannot have changed.
    pub fn detect() -> Self {
        DETECTED.get_or_init(Self::detect_uncached).clone()
    }

    /// Run the probes. Public for the one caller that genuinely wants to re-probe.
    pub fn detect_uncached() -> Self {
        #[cfg(target_arch = "wasm32")]
        {
            Self::default()
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            Self::detect_native()
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn detect_native() -> Self {
        debug!("Detecting scripting environments...");
        // A slow interpreter does not multiply startup latency by four.
        let (python, javascript, go, perl) = std::thread::scope(|scope| {
            let python = scope.spawn(Self::detect_python);
            let javascript = scope.spawn(Self::detect_javascript);
            let go = scope.spawn(Self::detect_go);
            let perl = scope.spawn(Self::detect_perl);
            (
                python.join().unwrap_or_default(),
                javascript.join().unwrap_or_default(),
                go.join().unwrap_or_default(),
                perl.join().unwrap_or_default(),
            )
        });

        info!("Scripting environment detection:");
        if let Some(ref ver) = python {
            info!("  Python: {} ✓", ver);
        } else {
            info!("  Python: not available");
        }
        if let Some(ref ver) = javascript {
            info!("  Node.js: {} ✓", ver);
        } else {
            info!("  Node.js: not available");
        }
        if let Some(ref ver) = go {
            info!("  Go: {} ✓", ver);
        } else {
            info!("  Go: not available");
        }
        if let Some(ref ver) = perl {
            info!("  Perl: {} ✓", ver);
        } else {
            info!("  Perl: not available");
        }

        Self {
            python,
            javascript,
            go,
            perl,
        }
    }

    /// Run `<program> --version` with a deadline, returning its trimmed output.
    ///
    /// The child is killed if it outlives [`PROBE_TIMEOUT`], because the alternative is
    /// `Command::output()`'s behaviour: block on the stdout pipe until the child exits, with
    /// no way out.
    pub fn probe(program: &str, args: &[&str]) -> Option<String> {
        Self::probe_with_timeout(program, args, PROBE_TIMEOUT)
    }

    /// Explicit budget is useful for callers probing a custom runtime.
    pub fn probe_with_timeout(program: &str, args: &[&str], timeout: Duration) -> Option<String> {
        #[cfg(target_arch = "wasm32")]
        {
            let _ = (program, args, timeout);
            None
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            let program = program.to_owned();
            let args = args.iter().map(|s| s.to_string()).collect::<Vec<_>>();
            // This sync API may be called from a Tokio worker. Own a separate
            // runtime rather than nesting block_on in the caller's runtime.
            std::thread::Builder::new()
                .name("netget-runtime-probe".into())
                .spawn(move || {
                    let runtime = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .ok()?;
                    runtime.block_on(async move {
                        use super::process_io::{read_bounded, ProcessGroup};
                        use std::process::Stdio;
                        let mut command = tokio::process::Command::new(&program);
                        command
                            .args(&args)
                            .stdin(Stdio::null())
                            .stdout(Stdio::piped())
                            .stderr(Stdio::piped())
                            .kill_on_drop(true);
                        ProcessGroup::configure(&mut command);
                        let mut child = command.spawn().ok()?;
                        let group = ProcessGroup::new(&child).ok()?;
                        let stdout = child.stdout.take()?;
                        let stderr = child.stderr.take()?;
                        let outcome = tokio::time::timeout(timeout, async {
                            tokio::try_join!(
                                read_bounded(stdout, 64 * 1024),
                                read_bounded(stderr, 64 * 1024),
                                child.wait()
                            )
                        })
                        .await;
                        group.kill();
                        let _ = child.start_kill();
                        let _ = tokio::time::timeout(Duration::from_secs(1), child.wait()).await;
                        let (stdout, stderr, status) = outcome.ok()?.ok()?;
                        if !status.success() {
                            return None;
                        }
                        let output = if stdout.is_empty() { stderr } else { stdout };
                        let text = String::from_utf8_lossy(&output).trim().to_string();
                        (!text.is_empty()).then_some(text)
                    })
                })
                .ok()?
                .join()
                .ok()
                .flatten()
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn detect_python() -> Option<String> {
        Self::probe("python3", &["--version"]).inspect(|v| debug!("python3 detected: {v}"))
    }

    /// Detect Node.js availability and version
    #[cfg(not(target_arch = "wasm32"))]
    fn detect_javascript() -> Option<String> {
        Self::probe("node", &["--version"]).inspect(|v| debug!("node detected: {v}"))
    }

    /// Detect Go availability and version
    #[cfg(not(target_arch = "wasm32"))]
    fn detect_go() -> Option<String> {
        Self::probe("go", &["version"]).inspect(|v| debug!("go detected: {v}"))
    }

    /// Detect Perl availability and version
    #[cfg(not(target_arch = "wasm32"))]
    fn detect_perl() -> Option<String> {
        // `perl --version` answers with a blank line and a nine-line copyright notice, which
        // this string carries into the startup log and into every prompt that lists the
        // scripting runtimes. `$^V` is just the version (`v5.40.0`).
        Self::probe("perl", &["-e", "print $^V"])
            .map(|v| format!("perl {v}"))
            .inspect(|v| debug!("perl detected: {v}"))
    }

    /// Check if a specific language is available
    pub fn is_available(&self, language: ScriptLanguage) -> bool {
        match language {
            ScriptLanguage::Python => self.python.is_some(),
            ScriptLanguage::JavaScript => self.javascript.is_some(),
            ScriptLanguage::Go => self.go.is_some(),
            ScriptLanguage::Perl => self.perl.is_some(),
        }
    }

    /// Get version string for a language
    pub fn get_version(&self, language: ScriptLanguage) -> Option<&str> {
        match language {
            ScriptLanguage::Python => self.python.as_deref(),
            ScriptLanguage::JavaScript => self.javascript.as_deref(),
            ScriptLanguage::Go => self.go.as_deref(),
            ScriptLanguage::Perl => self.perl.as_deref(),
        }
    }

    /// Format available environments for display to user/LLM
    pub fn format_available(&self) -> String {
        let mut parts = Vec::new();

        if let Some(ref ver) = self.python {
            parts.push(format!("Python ({})", ver));
        }
        if let Some(ref ver) = self.javascript {
            parts.push(format!("Node.js ({})", ver));
        }
        if let Some(ref ver) = self.go {
            parts.push(format!("Go ({})", ver));
        }
        if let Some(ref ver) = self.perl {
            parts.push(format!("Perl ({})", ver));
        }

        if parts.is_empty() {
            "None".to_string()
        } else {
            parts.join(", ")
        }
    }

    /// Warn if language is not available
    pub fn warn_if_unavailable(&self, language: ScriptLanguage) {
        if !self.is_available(language) {
            warn!(
                "{} is not available on this system. Scripts using {} will fail.",
                language.as_str(),
                language.as_str()
            );
        }
    }
}
