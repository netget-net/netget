//! WebSocket (RFC 6455) server tests

mod answer_with_test;
mod connection_bounds_test;
#[cfg(all(test, feature = "websocket"))]
mod deflate_real_client_test;
pub mod e2e_test;
