//! Shared log pattern constants
//!
//! These constants are used both for logging and for test assertions.
//! When a log pattern changes, the tests that wait for it automatically update.
//!
//! ## Usage in Code
//! ```ignore
//! info!("{} {} connected to {}", patterns::TCP_CLIENT, client_id, remote_addr);
//! ```
//!
//! ## Usage in Tests
//! ```ignore
//! client.wait_for_pattern(patterns::TCP_CLIENT_CONNECTED, Duration::from_secs(5)).await?;
//! ```

// Client patterns - TCP
pub const TCP_CLIENT: &str = "TCP client";
pub const TCP_CLIENT_CONNECTED: &str = "connected to";
pub const TCP_CLIENT_SENT: &str = "bytes after connect";
pub const TCP_CLIENT_RECEIVED: &str = "bytes from server";
pub const TCP_CLIENT_DISCONNECTED: &str = "disconnected";

// Client patterns - TLS
pub const TLS_CLIENT: &str = "TLS client";
pub const TLS_CLIENT_CONNECTED: &str = "connected to";
pub const TLS_CLIENT_SENT: &str = "bytes after connect";
pub const TLS_CLIENT_RECEIVED: &str = "bytes from server";
pub const TLS_CLIENT_DISCONNECTED: &str = "disconnected";

// Client patterns - Telnet
pub const TELNET_CLIENT: &str = "Telnet client";
pub const TELNET_CLIENT_CONNECTED: &str = "connected to";
pub const TELNET_CLIENT_RECEIVED: &str = "received";
pub const TELNET_CLIENT_DISCONNECTED: &str = "disconnected";

// Client patterns - Redis
pub const REDIS_CLIENT: &str = "Redis client";
pub const REDIS_CLIENT_CONNECTED: &str = "connected to";
pub const REDIS_CLIENT_SENT_COMMAND: &str = "Sent Redis command after connect:";
pub const REDIS_CLIENT_RECEIVED: &str = "received:";
pub const REDIS_CLIENT_DISCONNECTED: &str = "disconnected";

// Client patterns - HTTP
pub const HTTP_CLIENT_CONNECTED: &str = "HTTP client";

// Client patterns - AMQP
pub const AMQP_CLIENT_CONNECTED: &str = "AMQP client";

// Server patterns - TCP
//
// The "(action-based)" qualifier was dropped from these startup lines long ago
// and the constants were never updated, so every test waiting on one sat out its
// full timeout and then failed somewhere else entirely. `tests/log_patterns_test.rs`
// now fails the build on a constant that matches no log line.
pub const TCP_SERVER_LISTENING: &str = "TCP server listening on";
pub const TCP_SERVER_RECEIVED: &str = "TCP received";
pub const TCP_SERVER_CONNECTION_CLOSED: &str = "Connection";

// Server patterns - Telnet
pub const TELNET_SERVER_LISTENING: &str = "Telnet server listening on";

// Server patterns - Redis
pub const REDIS_SERVER_LISTENING: &str = "Redis server listening on";

// Server patterns - HTTP
//
// The HTTP server names itself from its TLS mode ("HTTP"/"HTTPS server listening
// on ..."), so the shared suffix is the whole matchable part.
pub const HTTP_SERVER_LISTENING: &str = "server listening on";

// TELNET_SERVER_RECEIVED, REDIS_SERVER_RECEIVED and HTTP_SERVER_REQUEST used to
// live here. They described per-request lines that no longer exist in any form:
// that detail moved to the protocols' event log templates, and the per-read
// summaries are DEBUG/Sink::FileOnly so they never reach the status stream a test
// observes. Nothing referenced them. A pattern that cannot match is worse than an
// absent one — it turns "this never happened" into a timeout somewhere unrelated.

// General patterns
pub const SERVER_STARTUP: &str = "Starting server";
pub const CLIENT_STARTUP: &str = "Starting client";
pub const CONVERSATION_STATE_UPDATED: &str = "Updated conversation state";
