//! Failures of the LLM backend itself, as distinct from bad output from the model.
//!
//! A request can fail in two unrelated ways. The model can answer with something unusable —
//! unparseable JSON, an action it was not offered — which the conversation layer corrects and
//! retries. Or the backend never produces an answer at all: the model is not installed, the
//! endpoint refuses the connection, the request times out, the API key is rejected. Retrying
//! with a correction cannot fix any of the second kind, and describing one as "the LLM failed
//! to generate a valid response after retries" sends the operator looking at the model's
//! output when the model was never run.
//!
//! [`LlmBackendError`] is the typed form of the second kind. The transport
//! (`ollama_client.rs`) raises it; the conversation layer lets it through without a retry and
//! without wrapping it in retry wording; [`LlmBackendError::find`] recovers it from any
//! `anyhow` chain so the access log, `get_status` and the circuit breaker can each read it.
//! Its text names the model and the endpoint, because "model not found" without either is
//! unactionable exactly when the configured model and the endpoint disagree.
//!
//! It is still an internal error: a network peer gets a [`crate::utils::WireFailure`]
//! category, never this text.

use std::fmt;

/// What went wrong between NetGet and the LLM backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendFailureKind {
    /// The backend answered that it does not have the requested model.
    ModelNotInstalled,
    /// No connection could be made (refused, DNS, reset before a response).
    Unreachable,
    /// The backend did not answer within the request timeout.
    TimedOut,
    /// The backend rejected the credentials (HTTP 401/403).
    AuthRejected,
    /// The backend is rate limiting this client (HTTP 429).
    RateLimited,
    /// Any other non-success HTTP status.
    Refused { status: u16 },
}

/// A failure of the LLM backend, naming the model and the endpoint.
#[derive(Debug, Clone)]
pub struct LlmBackendError {
    pub kind: BackendFailureKind,
    /// `"Ollama"` or `"OpenAI-compatible endpoint"`.
    pub backend: &'static str,
    /// The base URL requests went to.
    pub endpoint: String,
    /// The model the request named.
    pub model: String,
    /// What the backend or the transport said, verbatim.
    pub detail: String,
}

pub const OLLAMA: &str = "Ollama";
pub const OPENAI: &str = "OpenAI-compatible endpoint";

impl LlmBackendError {
    pub fn new(
        kind: BackendFailureKind,
        backend: &'static str,
        endpoint: impl Into<String>,
        model: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            backend,
            endpoint: endpoint.into().trim_end_matches('/').to_string(),
            model: model.into(),
            detail: detail.into(),
        }
    }

    /// The first `LlmBackendError` anywhere in `err`'s chain.
    pub fn find(err: &anyhow::Error) -> Option<&LlmBackendError> {
        err.chain()
            .find_map(|cause| cause.downcast_ref::<LlmBackendError>())
    }

    /// Whether this says the backend itself is unhealthy, as opposed to reachable and
    /// refusing this request. Feeds the circuit breaker: a missing model or a bad key is
    /// answered instantly by a healthy backend, so it must not open the breaker.
    pub fn is_transport(&self) -> bool {
        match self.kind {
            BackendFailureKind::Unreachable | BackendFailureKind::TimedOut => true,
            BackendFailureKind::Refused { status } => status >= 500,
            BackendFailureKind::ModelNotInstalled
            | BackendFailureKind::AuthRejected
            | BackendFailureKind::RateLimited => false,
        }
    }

    /// The same failure with the backend's own words removed, for a credential-bearing
    /// request whose diagnostics must not be echoed. Kind, model and endpoint remain.
    pub fn without_detail(&self) -> Self {
        Self {
            detail: "details hidden for a credential-bearing request".to_string(),
            ..self.clone()
        }
    }
}

impl fmt::Display for LlmBackendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            backend,
            endpoint,
            model,
            detail,
            ..
        } = self;
        match self.kind {
            BackendFailureKind::ModelNotInstalled if *backend == OLLAMA => write!(
                f,
                "model '{model}' is not installed at {backend} {endpoint} (it answered: {detail}); \
                 install it with `ollama pull {model}` or choose an installed model with set_model"
            ),
            BackendFailureKind::ModelNotInstalled => write!(
                f,
                "model '{model}' is not available at {backend} {endpoint} (it answered: {detail}); \
                 choose a model it serves with set_model"
            ),
            BackendFailureKind::Unreachable => write!(
                f,
                "cannot connect to {backend} at {endpoint} (model '{model}'): {detail}"
            ),
            BackendFailureKind::TimedOut => write!(
                f,
                "{backend} at {endpoint} timed out after {detail} (model '{model}')"
            ),
            BackendFailureKind::AuthRejected => write!(
                f,
                "{backend} at {endpoint} rejected the API key (model '{model}'): {detail}"
            ),
            BackendFailureKind::RateLimited => write!(
                f,
                "{backend} at {endpoint} is rate limiting requests (model '{model}'): {detail}"
            ),
            BackendFailureKind::Refused { status } => write!(
                f,
                "{backend} at {endpoint} refused the request for model '{model}' (HTTP {status}): {detail}"
            ),
        }
    }
}

impl std::error::Error for LlmBackendError {}

/// The text an operator should see for a failed LLM request: the backend failure itself when
/// there is one (rather than whatever context was layered over it), otherwise the whole
/// chain, so the cause under a generic context is not lost.
pub fn describe_llm_failure(err: &anyhow::Error) -> String {
    match LlmBackendError::find(err) {
        Some(backend) => backend.to_string(),
        None => format!("{err:#}"),
    }
}

/// Whether `err` must pass through the conversation layer as it is: a backend failure or an
/// overload refusal. Neither came from the model, so neither is wrapped in retry wording.
pub fn is_not_a_model_output_failure(err: &anyhow::Error) -> bool {
    LlmBackendError::find(err).is_some() || crate::llm::is_overload_error(err)
}

/// `.context(…)` for the LLM call path that leaves a backend failure or an overload refusal
/// as it is. Retry wording over those is false — nothing was retried — and the context would
/// become the error's `Display`, hiding the model and the endpoint the failure names.
pub trait LlmContextExt<T> {
    fn llm_context(self, context: &'static str) -> anyhow::Result<T>;
}

impl<T> LlmContextExt<T> for anyhow::Result<T> {
    fn llm_context(self, context: &'static str) -> anyhow::Result<T> {
        self.map_err(|e| {
            if is_not_a_model_output_failure(&e) {
                e
            } else {
                e.context(context)
            }
        })
    }
}
