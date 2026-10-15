//! EAPOL / 802.1X authenticator tests.
//!
//! Two layers, deliberately, and the split mirrors the source:
//!
//! 1. **`codec_test`** — the pure wire format against literal specification bytes, with no
//!    socket, no privilege and no LLM. This is the layer that is actually *proven*, and it is
//!    what `metadata().e2e_testing` claims.
//! 2. **`e2e_test`** — the whole authenticator through the real binary over the declared
//!    `transport: "udp"` test transport, with the model mocked. Its centre of gravity is the
//!    fail-closed regressions, not the happy path: an `EAP-Success` opens a switch port, so
//!    the interesting question is never "can it admit" but "can anything make it admit".
//!
//! There is no third layer. No third-party supplicant has spoken to this server, and the
//! raw-Ethernet transport has never been executed — see `src/server/eapol/CLAUDE.md` for
//! exactly what it would take.

#[cfg(all(unix, feature = "libpcap"))]
pub mod codec_test;

#[cfg(all(unix, feature = "libpcap"))]
pub mod e2e_test;
