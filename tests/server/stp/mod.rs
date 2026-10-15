//! STP / RSTP server tests.
//!
//! Two files with different jobs:
//!
//! * `codec_test` — the BPDU codec against literal specification bytes, in both directions.
//!   No sockets, no LLM, no privilege. This is the part of the protocol that is actually
//!   proved.
//! * `e2e_test` — the full frame → event → model → action → frame path over the UDP test
//!   transport, plus the silence-on-failure guarantee and the raw transport's refusal to
//!   report success without a capture handle.

#[cfg(all(unix, feature = "libpcap"))]
mod codec_test;

#[cfg(all(unix, feature = "libpcap"))]
mod e2e_test;
