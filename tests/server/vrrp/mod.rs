//! VRRP (v2/v3) and CARP server tests.
//!
//! Two files with different jobs:
//!
//! * `codec_test` — the packet codec against literal specification bytes, in both directions,
//!   plus the FIPS 180 / RFC 2202 vectors proving this code drives the `sha1` crate correctly
//!   (the hash itself is the crate's; only the RFC 2104 HMAC construction is local). No
//!   sockets, no LLM, no privilege. This is the part of the protocol that is actually proved.
//! * `e2e_test` — the full advertisement → event → model → action → packet path over the UDP
//!   test transport, the silence-on-LLM-failure guarantee, startup-parameter handling, and
//!   the raw transport's refusal to report success without a raw socket.

#[cfg(unix)]
mod codec_test;

#[cfg(unix)]
mod e2e_test;
