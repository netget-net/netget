//! Circuit breaker for the LLM backend transport.
//!
//! Without one, an unreachable backend costs every request the full request timeout
//! independently. With the rate limiter's `max_concurrent: 1`, N pending connections
//! serialise into N × timeout before the first peer learns anything is wrong — a 120s
//! timeout and ten queued connections is twenty minutes of a server that looks `Running`.
//!
//! The breaker turns that into "the first K requests pay the timeout, everything after fails
//! in microseconds until the backend is worth trying again".
//!
//! # States
//!
//! * **Closed** — requests pass. Consecutive transport failures are counted.
//! * **Open** — reached after `failure_threshold` consecutive transport failures. Requests
//!   fail immediately for `cooldown`.
//! * **Half-open** — after the cooldown, the next request is let through as a probe. It
//!   closes the breaker if it succeeds and re-opens it for another cooldown if it does not.
//!
//! # What counts as a failure
//!
//! Only *transport* failures: timeouts, refused connections, DNS and socket errors. A
//! backend that answers "model not found" or "401 unauthorized" is reachable — that is an
//! application error, and it resets the counter rather than advancing it. See
//! [`is_transport_failure`].

use crate::utils::clock::Instant;
use std::sync::Mutex;
use std::time::Duration;

/// Consecutive transport failures before the breaker opens.
///
/// One failure is a blip — a model load, a restart, a dropped packet — and tripping on it
/// would make the system fragile. Three is enough to be confident the backend is down while
/// costing at most 3 × timeout to discover it; every request after that is free.
pub const DEFAULT_FAILURE_THRESHOLD: u32 = 3;

/// How long the breaker stays open before letting a probe through.
///
/// Short enough that a backend which comes back up is picked up within one connection's
/// patience, long enough that a genuinely dead backend is probed twice a minute rather than
/// on every request.
pub const DEFAULT_COOLDOWN: Duration = Duration::from_secs(30);

/// Observable state of a [`CircuitBreaker`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakerState {
    /// Requests pass through.
    Closed,
    /// Requests fail immediately.
    Open,
    /// The next request is a probe.
    HalfOpen,
}

impl std::fmt::Display for BreakerState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BreakerState::Closed => write!(f, "closed"),
            BreakerState::Open => write!(f, "open"),
            BreakerState::HalfOpen => write!(f, "half-open"),
        }
    }
}

/// A snapshot of the breaker, for status displays and diagnostics.
#[derive(Debug, Clone)]
pub struct BreakerStatus {
    /// Current state.
    pub state: BreakerState,
    /// Consecutive transport failures recorded so far.
    pub consecutive_failures: u32,
    /// How long until the next probe is allowed (`None` unless open).
    pub retry_in: Option<Duration>,
    /// How many times the breaker has opened since it was created.
    pub trips: u64,
    /// The failure that opened it, for display.
    pub last_error: Option<String>,
}

impl BreakerStatus {
    /// Whether requests are currently being rejected without being attempted.
    pub fn is_open(&self) -> bool {
        self.state == BreakerState::Open
    }

    /// One-line summary suitable for a server status line or a log.
    pub fn summary(&self) -> String {
        match self.state {
            BreakerState::Closed => "LLM backend reachable".to_string(),
            BreakerState::HalfOpen => format!(
                "LLM backend circuit breaker half-open after {} trip(s): next request is a probe",
                self.trips
            ),
            BreakerState::Open => format!(
                "LLM backend circuit breaker OPEN after {} consecutive transport failure(s); \
                 failing fast for another {}s (last error: {})",
                self.consecutive_failures,
                self.retry_in.map(|d| d.as_secs()).unwrap_or(0),
                self.last_error.as_deref().unwrap_or("unknown")
            ),
        }
    }
}

#[derive(Debug)]
struct Inner {
    consecutive_failures: u32,
    opened_at: Option<Instant>,
    trips: u64,
    last_error: Option<String>,
    generation: u64,
    probe_in_flight: bool,
}

/// See the module documentation.
#[derive(Debug)]
pub struct CircuitBreaker {
    failure_threshold: u32,
    cooldown: Duration,
    inner: Mutex<Inner>,
}

impl Default for CircuitBreaker {
    fn default() -> Self {
        Self::new(DEFAULT_FAILURE_THRESHOLD, DEFAULT_COOLDOWN)
    }
}

impl CircuitBreaker {
    /// Create a breaker. A `failure_threshold` of 0 is treated as 1.
    pub fn new(failure_threshold: u32, cooldown: Duration) -> Self {
        Self {
            failure_threshold: failure_threshold.max(1),
            cooldown,
            inner: Mutex::new(Inner {
                consecutive_failures: 0,
                opened_at: None,
                trips: 0,
                last_error: None,
                generation: 0,
                probe_in_flight: false,
            }),
        }
    }

    /// Acquire an owned request lease. Keep it until the request completes and report
    /// its outcome through the lease. Only one half-open probe can be in flight;
    /// cancelling it restarts the cooldown instead of leaving the breaker wedged.
    pub fn acquire(&self) -> Result<BreakerPermit<'_>, BreakerOpen> {
        let mut inner = self.lock();
        let probe = if let Some(opened_at) = inner.opened_at {
            let elapsed = opened_at.elapsed();
            if inner.probe_in_flight || elapsed < self.cooldown {
                return Err(BreakerOpen {
                    consecutive_failures: inner.consecutive_failures,
                    retry_in: self.cooldown.saturating_sub(elapsed),
                    last_error: inner.last_error.clone(),
                });
            }
            inner.probe_in_flight = true;
            true
        } else {
            false
        };
        Ok(BreakerPermit {
            breaker: self,
            generation: inner.generation,
            probe,
            completed: false,
        })
    }

    /// Record that a request reached the backend and got an answer.
    ///
    /// Also the right call for an *application* error (unknown model, bad credentials): the
    /// backend is demonstrably reachable, which is all this breaker tracks.
    pub fn record_success(&self) {
        let mut inner = self.lock();
        inner.consecutive_failures = 0;
        inner.opened_at = None;
        inner.last_error = None;
        inner.probe_in_flight = false;
        inner.generation = inner.generation.wrapping_add(1);
    }

    /// Record a transport failure. Opens the breaker once the threshold is reached.
    ///
    /// Returns `true` if this failure opened the breaker (as opposed to it already being
    /// open or still below the threshold), so the caller can log the transition once.
    pub fn record_failure(&self, error: &str) -> bool {
        let mut inner = self.lock();
        inner.consecutive_failures = inner.consecutive_failures.saturating_add(1);
        inner.last_error = Some(crate::utils::truncate_str(error, 4096).to_owned());

        if inner.consecutive_failures >= self.failure_threshold
            && (inner.opened_at.is_none() || inner.probe_in_flight)
        {
            inner.opened_at = Some(Instant::now());
            inner.trips = inner.trips.saturating_add(1);
            inner.probe_in_flight = false;
            inner.generation = inner.generation.wrapping_add(1);
            return true;
        }
        false
    }

    /// Whether requests are currently rejected without being attempted.
    pub fn is_open(&self) -> bool {
        self.status().is_open()
    }

    /// Snapshot for status displays.
    pub fn status(&self) -> BreakerStatus {
        let inner = self.lock();
        let (state, retry_in) = match inner.opened_at {
            None if inner.consecutive_failures >= self.failure_threshold => {
                (BreakerState::HalfOpen, None)
            }
            None => (BreakerState::Closed, None),
            Some(opened_at) => {
                let elapsed = opened_at.elapsed();
                if elapsed < self.cooldown {
                    (BreakerState::Open, Some(self.cooldown - elapsed))
                } else {
                    (BreakerState::HalfOpen, None)
                }
            }
        };

        BreakerStatus {
            state,
            consecutive_failures: inner.consecutive_failures,
            retry_in,
            trips: inner.trips,
            last_error: inner.last_error.clone(),
        }
    }

    /// Force the breaker closed (used when the backend is reconfigured).
    pub fn reset(&self) {
        self.record_success();
    }

    /// Configured failure threshold.
    pub fn failure_threshold(&self) -> u32 {
        self.failure_threshold
    }

    /// Configured cooldown.
    pub fn cooldown(&self) -> Duration {
        self.cooldown
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        // A poisoned lock only means some other thread panicked while holding it; the
        // counters are plain integers, so the state is still coherent.
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// A request's circuit-breaker lease. Stale outcomes from requests started before
/// a trip/reset cannot reopen or close the current generation of the breaker.
#[must_use = "hold the lease for the request and record its outcome"]
#[derive(Debug)]
pub struct BreakerPermit<'a> {
    breaker: &'a CircuitBreaker,
    generation: u64,
    probe: bool,
    completed: bool,
}

impl BreakerPermit<'_> {
    pub fn record_success(mut self) {
        let mut inner = self.breaker.lock();
        if inner.generation == self.generation {
            inner.consecutive_failures = 0;
            inner.opened_at = None;
            inner.last_error = None;
            inner.probe_in_flight = false;
            if self.probe {
                inner.generation = inner.generation.wrapping_add(1);
            }
        }
        self.completed = true;
    }

    /// True when this failure opens (or reopens) the circuit.
    pub fn record_failure(mut self, error: &str) -> bool {
        let mut inner = self.breaker.lock();
        let mut tripped = false;
        if inner.generation == self.generation {
            inner.consecutive_failures = inner.consecutive_failures.saturating_add(1);
            inner.last_error = Some(crate::utils::truncate_str(error, 4096).to_owned());
            if inner.consecutive_failures >= self.breaker.failure_threshold {
                inner.opened_at = Some(Instant::now());
                inner.probe_in_flight = false;
                inner.trips = inner.trips.saturating_add(1);
                inner.generation = inner.generation.wrapping_add(1);
                tripped = true;
            }
        }
        self.completed = true;
        tripped
    }
}

impl Drop for BreakerPermit<'_> {
    fn drop(&mut self) {
        if self.probe && !self.completed {
            let mut inner = self.breaker.lock();
            if inner.generation == self.generation && inner.probe_in_flight {
                inner.probe_in_flight = false;
                inner.opened_at = Some(Instant::now());
                inner.generation = inner.generation.wrapping_add(1);
            }
        }
    }
}

/// Error returned by [`CircuitBreaker::acquire`] while the breaker is open.
#[derive(Debug, Clone)]
pub struct BreakerOpen {
    /// Consecutive transport failures that opened it.
    pub consecutive_failures: u32,
    /// Time remaining before the next probe is allowed.
    pub retry_in: Duration,
    /// The failure that opened it.
    pub last_error: Option<String>,
}

impl std::fmt::Display for BreakerOpen {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "✗  LLM backend is unreachable: circuit breaker open after {} consecutive \
             transport failure(s). Failing fast instead of waiting for another timeout; the \
             next probe is in {}s.{}",
            self.consecutive_failures,
            self.retry_in.as_secs().max(1),
            self.last_error
                .as_deref()
                .map(|e| format!("\n   Last error: {}", e))
                .unwrap_or_default()
        )
    }
}

impl std::error::Error for BreakerOpen {}

/// Whether an error means the backend could not be *reached*, as opposed to answering with
/// an application-level error.
///
/// A reachable backend that rejects the request (unknown model, bad key, rate limit) proves
/// the transport works, so those must not trip the breaker — otherwise a typo'd model name
/// would take the whole LLM path offline for a cooldown.
pub fn is_transport_failure(error: &anyhow::Error) -> bool {
    // The transport classifies its own failures; read the classification, not the wording.
    if let Some(backend) = crate::llm::LlmBackendError::find(error) {
        return backend.is_transport();
    }
    let text = error
        .chain()
        .map(|cause| cause.to_string())
        .collect::<Vec<_>>()
        .join(": ")
        .to_lowercase();

    // Answered-but-rejected: the backend was reached.
    const APPLICATION_ERRORS: &[&str] = &[
        "model not found",
        "authentication failed",
        "rate limited",
        "failed to parse",
        "agent-queue",
    ];
    if APPLICATION_ERRORS.iter().any(|m| text.contains(m)) {
        return false;
    }

    const TRANSPORT_ERRORS: &[&str] = &[
        "timed out",
        "timeout",
        "connection",
        "refused",
        "cannot connect",
        "failed to connect",
        "error sending request",
        "request failed",
        "dns error",
        "broken pipe",
        "network is unreachable",
        "no route to host",
        "os error 61",  // ECONNREFUSED on macOS
        "os error 111", // ECONNREFUSED on Linux
    ];
    TRANSPORT_ERRORS.iter().any(|m| text.contains(m))
}
