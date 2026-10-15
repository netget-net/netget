//! Per-protocol live-LLM suites.
//!
//! Two shapes, both hand-authored per protocol from that protocol's own event
//! and action vocabulary:
//!
//! - **Wire suites** (protocols whose transport runs here): a
//!   `*_setup_via_llm` test proving the model starts the server from a
//!   plain-language prompt, plus one test per request type driving a real
//!   client and asserting the bytes that come back.
//! - **Event-level suites** (protocols needing hardware, root or a peer —
//!   Bluetooth, USB, raw sockets, VPNs, NFC): the exact event a real exchange
//!   produces is fed to the model, and the assertion names the one correct
//!   action *and checks its parameters* (echoed transaction IDs, correctly
//!   encoded GATT values, ISO 7816 status words…).
//!
//! NOTE: this mod.rs is the only place these modules are declared. A file on
//! disk that is not listed here is silently never compiled (same footgun as
//! tests/server/mod.rs) — add every new protocol module here.

// ---------------------------------------------------------------------------
// Wire suites — gated on the protocol being compiled in.
// ---------------------------------------------------------------------------
pub mod couchdb;
pub mod dns;
pub mod elasticsearch;
pub mod ftp;
pub mod http;
pub mod imap;
pub mod irc;
pub mod jsonrpc;
pub mod memcached;
pub mod nntp;
pub mod ntp;
pub mod openai;
pub mod pop3;
pub mod redis;
pub mod rss;
pub mod rtsp;
pub mod sip;
pub mod smtp;
pub mod socks5;
#[cfg(unix)]
pub mod stun;
pub mod tcp;
pub mod telnet;
pub mod udp;
pub mod whois;
pub mod xmlrpc;

// ---------------------------------------------------------------------------
// Event-level suites — no feature gate needed: each case resolves its protocol
// in the registry at runtime and skips cleanly when it is not compiled in.
// ---------------------------------------------------------------------------
pub mod bigdata;
pub mod ble_profiles;
pub mod bluetooth_ble;
pub mod datastores;
pub mod dns_secure;
pub mod federation;
pub mod http_apis;
pub mod netservices;
pub mod nfc;
pub mod p2p;
pub mod rawnet;
pub mod realtime;
pub mod remote_access;
pub mod routing;
pub mod streams;
pub mod usb;
pub mod vpn;
