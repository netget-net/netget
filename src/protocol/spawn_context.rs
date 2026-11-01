//! Server spawn context
//!
//! Provides all the necessary context for spawning a protocol server.

use crate::llm::actions::ParameterDefinition;
use crate::llm::OllamaClient;
use crate::state::app_state::AppState;
use crate::state::ServerId;
use std::collections::HashSet;
use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc;

/// Error returned when startup parameters supplied by the LLM or an MCP client
/// cannot be used by the protocol.
///
/// These values are untrusted model/client input, so every failure is reported
/// rather than panicking the task that is starting the server.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StartupParamError {
    /// A key was supplied (or accessed) that the protocol never declared in
    /// `get_startup_parameters()`.
    Undeclared {
        /// Offending parameter name
        key: String,
        /// Parameter names the protocol does declare, sorted
        allowed: Vec<String>,
        /// True when the protocol code itself asked for the undeclared key
        /// (a bug in the protocol) rather than the caller supplying it.
        accessed_by_protocol: bool,
    },
    /// A required parameter was absent or held the wrong JSON type.
    Invalid {
        /// Offending parameter name
        key: String,
        /// Human readable description of what went wrong
        detail: String,
    },
}

impl fmt::Display for StartupParamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StartupParamError::Undeclared {
                key,
                allowed,
                accessed_by_protocol,
            } => {
                // The caller-supplied case is what an MCP user or the model reads, inside
                // "Invalid startup_params for <protocol>: …", so it speaks about their input.
                // The other case is a defect in the protocol itself and says so.
                let accepted = if allowed.is_empty() {
                    "none — this protocol takes no startup parameters".to_string()
                } else {
                    allowed.join(", ")
                };
                if *accessed_by_protocol {
                    write!(
                        f,
                        "internal error: the protocol read startup parameter '{}', which it \
                         does not declare (a NetGet bug — it must be added to the protocol's \
                         get_startup_parameters()). Declared parameters: {}",
                        key, accepted
                    )
                } else {
                    write!(
                        f,
                        "unknown startup parameter '{}'. Accepted parameters: {}",
                        key, accepted
                    )
                }
            }
            StartupParamError::Invalid { key, detail } => {
                write!(f, "Invalid startup parameter '{}': {}", key, detail)
            }
        }
    }
}

impl std::error::Error for StartupParamError {}

/// Convenience alias for fallible startup-parameter access.
pub type StartupParamResult<T> = std::result::Result<T, StartupParamError>;

/// Type-safe wrapper for startup parameters
///
/// Validates that parameters can only be accessed if they were declared
/// in the protocol's `get_startup_parameters()` implementation.
///
/// Every accessor returns a [`StartupParamResult`]: the JSON originates from the
/// LLM (`open_server`) or an MCP client (`start_server`), so malformed values
/// must surface as errors to the caller instead of aborting the task.
#[derive(Clone)]
pub struct StartupParams {
    /// The actual JSON parameter values provided by the LLM
    params: serde_json::Value,
    /// Set of allowed parameter names (from ParameterDefinition)
    allowed_params: HashSet<String>,
}

/// Maximum retained startup JSON content, including keys and node overhead.
pub const MAX_STARTUP_PARAM_BYTES: usize = 8 * 1024 * 1024;
/// Maximum nodes in a constructed startup parameter object.
pub const MAX_STARTUP_PARAM_NODES: usize = 65_536;
/// Maximum nesting depth in a constructed startup parameter object.
pub const MAX_STARTUP_PARAM_DEPTH: usize = 64;

impl fmt::Debug for StartupParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StartupParams")
            .field(
                "params",
                &crate::utils::redact::redact_sensitive(&self.params),
            )
            .field("allowed_params", &self.allowed_params)
            .finish()
    }
}

impl StartupParams {
    /// Check borrowed JSON before cloning or formatting untrusted startup data.
    pub fn preflight(params: &serde_json::Value) -> StartupParamResult<()> {
        if crate::utils::json_budget::within_budget(
            params,
            MAX_STARTUP_PARAM_BYTES,
            MAX_STARTUP_PARAM_NODES,
            MAX_STARTUP_PARAM_DEPTH,
        ) {
            Ok(())
        } else {
            Err(StartupParamError::Invalid {
                key: "startup_params".into(),
                detail: "startup_params exceeds the JSON size, node or depth budget".into(),
            })
        }
    }

    /// Refuse an excessive owned value without recursively dropping its children.
    /// Call this before an earlier error path can dispose of a constructed value.
    pub fn preflight_owned(params: &mut Option<serde_json::Value>) -> StartupParamResult<()> {
        if let Some(value) = params.as_ref() {
            if let Err(error) = Self::preflight(value) {
                crate::utils::json_budget::drop_iteratively(params.take().expect("present above"));
                return Err(error);
            }
        }
        Ok(())
    }

    /// Create new StartupParams with validation
    ///
    /// # Arguments
    /// * `params` - JSON object containing parameter values
    /// * `schema` - Parameter definitions from protocol's `get_startup_parameters()`
    ///
    /// # Errors
    /// Returns [`StartupParamError::Undeclared`] if any key in `params` is not
    /// defined in `schema`, or [`StartupParamError::Invalid`] if `params` is not
    /// an object. An absent parameter set should be represented by `None` at the caller.
    pub fn new(
        params: serde_json::Value,
        schema: Vec<ParameterDefinition>,
    ) -> StartupParamResult<Self> {
        if let Err(error) = Self::preflight(&params) {
            crate::utils::json_budget::drop_iteratively(params);
            return Err(error);
        }
        let allowed_params: HashSet<String> = schema.iter().map(|p| p.name.clone()).collect();

        let obj = params
            .as_object()
            .ok_or_else(|| StartupParamError::Invalid {
                key: "startup_params".to_string(),
                detail: "startup_params must be a JSON object".to_string(),
            })?;
        // Validate that all provided parameters are in the schema.
        for key in obj.keys() {
            if !allowed_params.contains(key) {
                return Err(StartupParamError::Undeclared {
                    key: key.clone(),
                    allowed: sorted(&allowed_params),
                    accessed_by_protocol: false,
                });
            }
        }

        Ok(Self {
            params,
            allowed_params,
        })
    }

    /// Validate declared JSON shapes and required fields before any resource is
    /// stopped or registered. Protocol-specific I/O checks still occur at spawn.
    pub fn new_validated(
        params: serde_json::Value,
        schema: Vec<ParameterDefinition>,
    ) -> StartupParamResult<Self> {
        let result = Self::new(params, schema.clone())?;
        for parameter in &schema {
            let value = result.params.get(&parameter.name);
            if value.is_none_or(serde_json::Value::is_null) {
                if parameter.required {
                    return Err(result.invalid(
                        &parameter.name,
                        "required parameter is missing or null".into(),
                    ));
                }
                continue;
            }
            let value = value.expect("present above");
            let hint = parameter.type_hint.replace(" or ", "|");
            if !hint
                .split('|')
                .any(|kind| parameter_type_matches(value, kind.trim()))
            {
                return Err(result.invalid(
                    &parameter.name,
                    format!(
                        "expected {}, got {}",
                        parameter.type_hint,
                        diagnostic_value(&parameter.name, value)
                    ),
                ));
            }
        }
        Ok(result)
    }

    /// Names of the parameters this protocol declares, sorted.
    pub fn allowed_parameters(&self) -> Vec<String> {
        sorted(&self.allowed_params)
    }

    /// Get a required string parameter
    ///
    /// # Errors
    /// - If the parameter was not declared in `get_startup_parameters()`
    /// - If the parameter is missing
    /// - If the parameter is not a string
    pub fn get_string(&self, key: &str) -> StartupParamResult<String> {
        self.validate_key(key)?;
        match self.params.get(key).and_then(|v| v.as_str()) {
            Some(s) => Ok(s.to_string()),
            None => Err(self.invalid(
                key,
                format!(
                    "Required string parameter '{}' is missing or not a string. Params: {}",
                    key,
                    crate::utils::redact::redact_sensitive(&self.params)
                ),
            )),
        }
    }

    /// Get an optional string parameter
    ///
    /// # Errors
    /// - If the parameter was not declared in `get_startup_parameters()`
    /// - If the parameter exists but is not a string
    pub fn get_optional_string(&self, key: &str) -> StartupParamResult<Option<String>> {
        self.validate_key(key)?;
        match self.params.get(key) {
            None | Some(serde_json::Value::Null) => Ok(None),
            Some(v) => match v.as_str() {
                Some(s) => Ok(Some(s.to_string())),
                None => Err(self.invalid(
                    key,
                    format!(
                        "Optional string parameter '{}' exists but is not a string. Value: {}",
                        key,
                        diagnostic_value(key, v)
                    ),
                )),
            },
        }
    }

    /// Get a required boolean parameter
    ///
    /// # Errors
    /// - If the parameter was not declared in `get_startup_parameters()`
    /// - If the parameter is missing
    /// - If the parameter is not a boolean
    pub fn get_bool(&self, key: &str) -> StartupParamResult<bool> {
        self.validate_key(key)?;
        match self.params.get(key).and_then(|v| v.as_bool()) {
            Some(b) => Ok(b),
            None => Err(self.invalid(
                key,
                format!(
                    "Required boolean parameter '{}' is missing or not a boolean. Params: {}",
                    key,
                    crate::utils::redact::redact_sensitive(&self.params)
                ),
            )),
        }
    }

    /// Get an optional boolean parameter
    ///
    /// # Errors
    /// - If the parameter was not declared in `get_startup_parameters()`
    /// - If the parameter exists but is not a boolean
    pub fn get_optional_bool(&self, key: &str) -> StartupParamResult<Option<bool>> {
        self.validate_key(key)?;
        match self.params.get(key) {
            None | Some(serde_json::Value::Null) => Ok(None),
            Some(v) => match v.as_bool() {
                Some(b) => Ok(Some(b)),
                None => Err(self.invalid(
                    key,
                    format!(
                        "Optional boolean parameter '{}' exists but is not a boolean. Value: {}",
                        key,
                        diagnostic_value(key, v)
                    ),
                )),
            },
        }
    }

    /// Get a required integer parameter
    ///
    /// # Errors
    /// - If the parameter was not declared in `get_startup_parameters()`
    /// - If the parameter is missing
    /// - If the parameter is not an integer
    pub fn get_i64(&self, key: &str) -> StartupParamResult<i64> {
        self.validate_key(key)?;
        match self.params.get(key).and_then(|v| v.as_i64()) {
            Some(n) => Ok(n),
            None => Err(self.invalid(
                key,
                format!(
                    "Required integer parameter '{}' is missing or not an integer. Params: {}",
                    key,
                    crate::utils::redact::redact_sensitive(&self.params)
                ),
            )),
        }
    }

    /// Get an optional integer parameter
    ///
    /// # Errors
    /// - If the parameter was not declared in `get_startup_parameters()`
    /// - If the parameter exists but is not an integer
    pub fn get_optional_i64(&self, key: &str) -> StartupParamResult<Option<i64>> {
        self.validate_key(key)?;
        match self.params.get(key) {
            None | Some(serde_json::Value::Null) => Ok(None),
            Some(v) => match v.as_i64() {
                Some(n) => Ok(Some(n)),
                None => Err(self.invalid(
                    key,
                    format!(
                        "Optional integer parameter '{}' exists but is not an integer. Value: {}",
                        key,
                        diagnostic_value(key, v)
                    ),
                )),
            },
        }
    }

    /// Get an optional number parameter (integer or fraction)
    ///
    /// # Errors
    /// - If the parameter was not declared in `get_startup_parameters()`
    /// - If the parameter exists but is not a number
    pub fn get_optional_f64(&self, key: &str) -> StartupParamResult<Option<f64>> {
        self.validate_key(key)?;
        match self.params.get(key) {
            None | Some(serde_json::Value::Null) => Ok(None),
            Some(v) => match v.as_f64() {
                Some(n) => Ok(Some(n)),
                None => Err(self.invalid(
                    key,
                    format!(
                        "Optional number parameter '{}' exists but is not a number. Value: {}",
                        key,
                        diagnostic_value(key, v)
                    ),
                )),
            },
        }
    }

    /// Get a required unsigned integer parameter
    ///
    /// # Errors
    /// - If the parameter was not declared in `get_startup_parameters()`
    /// - If the parameter is missing
    /// - If the parameter is not an unsigned integer
    pub fn get_u64(&self, key: &str) -> StartupParamResult<u64> {
        self.validate_key(key)?;
        match self.params.get(key).and_then(|v| v.as_u64()) {
            Some(n) => Ok(n),
            None => Err(self.invalid(
                key,
                format!(
                    "Required unsigned integer parameter '{}' is missing or not an unsigned integer. Params: {}",
                    key, crate::utils::redact::redact_sensitive(&self.params)
                ),
            )),
        }
    }

    /// Get an optional unsigned integer parameter
    ///
    /// # Errors
    /// - If the parameter was not declared in `get_startup_parameters()`
    /// - If the parameter exists but is not an unsigned integer
    pub fn get_optional_u64(&self, key: &str) -> StartupParamResult<Option<u64>> {
        self.validate_key(key)?;
        match self.params.get(key) {
            None | Some(serde_json::Value::Null) => Ok(None),
            Some(v) => match v.as_u64() {
                Some(n) => Ok(Some(n)),
                None => Err(self.invalid(
                    key,
                    format!(
                        "Optional unsigned integer parameter '{}' exists but is not an unsigned integer. Value: {}",
                        key, diagnostic_value(key, v)
                    ),
                )),
            },
        }
    }

    /// Get an optional u32 parameter
    ///
    /// # Errors
    /// - If the parameter was not declared in `get_startup_parameters()`
    /// - If the parameter exists but is not an unsigned integer or exceeds u32::MAX
    pub fn get_optional_u32(&self, key: &str) -> StartupParamResult<Option<u32>> {
        self.validate_key(key)?;
        match self.params.get(key) {
            None | Some(serde_json::Value::Null) => Ok(None),
            Some(v) => {
                let val = match v.as_u64() {
                    Some(n) => n,
                    None => {
                        return Err(self.invalid(
                            key,
                            format!(
                                "Optional u32 parameter '{}' exists but is not an unsigned integer. Value: {}",
                                key, diagnostic_value(key, v)
                            ),
                        ))
                    }
                };
                if val > u32::MAX as u64 {
                    return Err(self.invalid(
                        key,
                        format!(
                            "Optional u32 parameter '{}' exceeds u32::MAX ({}). Value: {}",
                            key,
                            u32::MAX,
                            diagnostic_value(key, v)
                        ),
                    ));
                }
                Ok(Some(val as u32))
            }
        }
    }

    /// Get a required object/map parameter
    ///
    /// # Errors
    /// - If the parameter was not declared in `get_startup_parameters()`
    /// - If the parameter is missing
    /// - If the parameter is not an object
    pub fn get_object(
        &self,
        key: &str,
    ) -> StartupParamResult<&serde_json::Map<String, serde_json::Value>> {
        self.validate_key(key)?;
        match self.params.get(key).and_then(|v| v.as_object()) {
            Some(o) => Ok(o),
            None => Err(self.invalid(
                key,
                format!(
                    "Required object parameter '{}' is missing or not an object. Params: {}",
                    key,
                    crate::utils::redact::redact_sensitive(&self.params)
                ),
            )),
        }
    }

    /// Get an optional object/map parameter
    ///
    /// # Errors
    /// - If the parameter was not declared in `get_startup_parameters()`
    /// - If the parameter exists but is not an object
    pub fn get_optional_object(
        &self,
        key: &str,
    ) -> StartupParamResult<Option<&serde_json::Map<String, serde_json::Value>>> {
        self.validate_key(key)?;
        match self.params.get(key) {
            None | Some(serde_json::Value::Null) => Ok(None),
            Some(v) => match v.as_object() {
                Some(o) => Ok(Some(o)),
                None => Err(self.invalid(
                    key,
                    format!(
                        "Optional object parameter '{}' exists but is not an object. Value: {}",
                        key,
                        diagnostic_value(key, v)
                    ),
                )),
            },
        }
    }

    /// Get a required array parameter
    ///
    /// # Errors
    /// - If the parameter was not declared in `get_startup_parameters()`
    /// - If the parameter is missing
    /// - If the parameter is not an array
    pub fn get_array(&self, key: &str) -> StartupParamResult<&Vec<serde_json::Value>> {
        self.validate_key(key)?;
        match self.params.get(key).and_then(|v| v.as_array()) {
            Some(a) => Ok(a),
            None => Err(self.invalid(
                key,
                format!(
                    "Required array parameter '{}' is missing or not an array. Params: {}",
                    key,
                    crate::utils::redact::redact_sensitive(&self.params)
                ),
            )),
        }
    }

    /// Get an optional array parameter
    ///
    /// # Errors
    /// - If the parameter was not declared in `get_startup_parameters()`
    /// - If the parameter exists but is not an array
    pub fn get_optional_array(
        &self,
        key: &str,
    ) -> StartupParamResult<Option<&Vec<serde_json::Value>>> {
        self.validate_key(key)?;
        match self.params.get(key) {
            None | Some(serde_json::Value::Null) => Ok(None),
            Some(v) => match v.as_array() {
                Some(a) => Ok(Some(a)),
                None => Err(self.invalid(
                    key,
                    format!(
                        "Optional array parameter '{}' exists but is not an array. Value: {}",
                        key,
                        diagnostic_value(key, v)
                    ),
                )),
            },
        }
    }

    /// Build an `Invalid` error for `key`.
    fn invalid(&self, key: &str, detail: String) -> StartupParamError {
        StartupParamError::Invalid {
            key: key.to_string(),
            detail,
        }
    }

    /// Validate that a key was declared in get_startup_parameters()
    ///
    /// # Errors
    /// If the key is not in the allowed parameters set
    fn validate_key(&self, key: &str) -> StartupParamResult<()> {
        if !self.allowed_params.contains(key) {
            return Err(StartupParamError::Undeclared {
                key: key.to_string(),
                allowed: sorted(&self.allowed_params),
                accessed_by_protocol: true,
            });
        }
        Ok(())
    }
}

/// A parameter's value as an error message may show it: masked by the same rule the
/// redactor applies to a key/value pair (`is_shown_redacted`, which also hides a string
/// `auth`), and otherwise with any credential nested inside it masked.
fn diagnostic_value(key: &str, value: &serde_json::Value) -> serde_json::Value {
    if crate::utils::redact::is_shown_redacted(key, value) {
        serde_json::Value::String(crate::utils::redact::REDACTED.into())
    } else {
        crate::utils::redact::redact_sensitive(value)
    }
}

/// Sorted copy of a name set, so error messages are deterministic.
fn sorted(set: &HashSet<String>) -> Vec<String> {
    let mut v: Vec<String> = set.iter().cloned().collect();
    v.sort();
    v
}

/// Context passed to protocol servers during spawning
///
/// Contains all the dependencies and configuration needed to start a server.
#[derive(Clone)]
pub struct SpawnContext {
    /// Address to listen on (DEPRECATED - use host/port fields instead)
    ///
    /// This field is maintained for backwards compatibility with unmigrated protocols.
    /// New protocols should use the flexible binding system (mac_address, interface, host, port).
    #[deprecated(since = "1.0.0", note = "Use host/port fields instead")]
    pub listen_addr: SocketAddr,

    // === NEW FLEXIBLE BINDING FIELDS ===
    /// MAC address for Layer 2 protocols (e.g., ARP spoofing with specific MAC)
    ///
    /// Protocol defaults are already applied. Use this value directly.
    pub mac_address: Option<String>,

    /// Network interface for raw protocols (e.g., "lo", "eth0", "en0")
    ///
    /// Protocol defaults are already applied. Use this value directly.
    pub interface: Option<String>,

    /// Host address (IPv4, IPv6, or hostname) for socket-based protocols
    ///
    /// Protocol defaults are already applied. Use this value directly.
    /// Examples: "127.0.0.1", "0.0.0.0", "::", "localhost"
    pub host: Option<String>,

    /// Port number for socket-based protocols
    ///
    /// Protocol defaults are already applied. Use this value directly.
    /// Some(0) means automatic port assignment.
    pub port: Option<u16>,

    /// LLM client for generating responses
    pub llm_client: OllamaClient,

    /// Application state
    pub state: Arc<AppState>,

    /// Channel for sending status updates to UI
    pub status_tx: mpsc::UnboundedSender<String>,

    /// Unique identifier for this server instance
    pub server_id: ServerId,

    /// Optional type-safe startup parameters specific to the protocol
    ///
    /// Parameters can only be accessed if they were declared in the protocol's
    /// `get_startup_parameters()` implementation. Accessing an undeclared
    /// parameter, or one holding the wrong JSON type, returns a
    /// [`StartupParamError`] rather than panicking.
    ///
    /// For example:
    /// - HTTP Proxy: certificate_mode, request_filter_mode, response_filter_mode
    /// - gRPC: proto_schema, enable_reflection
    /// - DataLink: interface, filter
    pub startup_params: Option<StartupParams>,
}

impl SpawnContext {
    /// Helper method to get socket address from host and port
    ///
    /// Port-based protocols can use this to construct a SocketAddr from
    /// the flexible binding fields.
    ///
    /// # Returns
    /// * `Some(SocketAddr)` - If both host and port are available
    /// * `None` - If host or port is missing
    ///
    /// # Example
    /// ```ignore
    /// let addr = ctx.socket_addr().context("TCP requires host and port")?;
    /// ```
    pub fn socket_addr(&self) -> Option<SocketAddr> {
        match (&self.host, self.port) {
            (Some(host), Some(port)) => host
                .parse::<std::net::IpAddr>()
                .ok()
                .map(|ip| SocketAddr::new(ip, port)),
            _ => None,
        }
    }

    /// Helper method to get interface name
    ///
    /// Interface-based protocols can use this to get the interface name
    /// with proper error context.
    ///
    /// # Returns
    /// * `Some(&str)` - If interface is available
    /// * `None` - If interface is not set
    ///
    /// # Example
    /// ```ignore
    /// let interface = ctx.interface()
    ///     .context("ICMP requires network interface")?;
    /// ```
    pub fn interface(&self) -> Option<&str> {
        self.interface.as_deref()
    }

    /// Helper method to get MAC address
    ///
    /// Layer 2 protocols can use this to get the MAC address
    /// with proper error context.
    ///
    /// # Returns
    /// * `Some(&str)` - If MAC address is available
    /// * `None` - If MAC address is not set
    ///
    /// # Example
    /// ```ignore
    /// let mac = ctx.mac_address()
    ///     .context("ARP spoofing requires MAC address")?;
    /// ```
    pub fn mac_address(&self) -> Option<&str> {
        self.mac_address.as_deref()
    }

    /// Get the legacy listen address (for unmigrated protocols)
    ///
    /// This method provides access to the deprecated `listen_addr` field without
    /// triggering deprecation warnings. Use this during migration or for protocols
    /// that haven't been migrated to the flexible binding system yet.
    ///
    /// Once a protocol is migrated to use `socket_addr()`, `interface()`, or
    /// `mac_address()`, it should no longer use this method.
    ///
    /// # Example
    /// ```ignore
    /// // Unmigrated protocol:
    /// let addr = ctx.legacy_listen_addr();
    /// TcpListener::bind(addr).await?;
    ///
    /// // After migration:
    /// let addr = ctx.socket_addr().context("requires host and port")?;
    /// TcpListener::bind(addr).await?;
    /// ```
    #[allow(deprecated)]
    pub fn legacy_listen_addr(&self) -> SocketAddr {
        self.listen_addr
    }
}

/// Type hints intentionally admit unions and typed arrays. Unknown descriptive
/// hints retain protocol validation rather than inventing an interpretation.
fn parameter_type_matches(value: &serde_json::Value, kind: &str) -> bool {
    match kind {
        "string" => value.is_string(),
        "number" => value.is_number(),
        "integer" => value.is_i64() || value.is_u64(),
        "boolean" => value.is_boolean(),
        "object" => value.is_object(),
        "array" => value.is_array(),
        "null" => value.is_null(),
        "array of strings" => value
            .as_array()
            .is_some_and(|items| items.iter().all(|item| item.is_string())),
        "array of objects" => value
            .as_array()
            .is_some_and(|items| items.iter().all(|item| item.is_object())),
        "array of integers" => value
            .as_array()
            .is_some_and(|items| items.iter().all(|item| item.is_i64() || item.is_u64())),
        "array of booleans" => value
            .as_array()
            .is_some_and(|items| items.iter().all(|item| item.is_boolean())),
        _ => true,
    }
}
