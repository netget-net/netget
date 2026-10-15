//! H.323: a gatekeeper (`H323-Gatekeeper`, H.225.0 RAS over UDP 1719) and a called endpoint
//! (`H323`, H.225.0 call signalling — Q.931 over TPKT — on TCP 1720), plus the codecs the H.323
//! client (`src/client/h323`) shares.
//!
//! - [`per`] — ALIGNED PER, interpreted over [`schema`], the tables
//!   `scripts/h323_asn1_schema.py` generates from the ITU's H.225.0, H.235.0 and H.245 modules.
//! - [`q931`] — TPKT framing and the Q.931 envelope.
//! - [`h225`] — addresses, aliases, endpoint types and the RAS / UUIE envelopes as JSON.
//! - [`h245`] — fastStart and the tunnelled H.245 a call needs to count as connected.
//! - [`call`] — one call-signalling leg, shared by the endpoint and the client.
//! - [`gatekeeper`] and [`endpoint`] — the two servers; [`actions`] — what the model decides.
pub mod actions;
pub mod call;
pub mod endpoint;
pub mod gatekeeper;
pub mod h225;
pub mod h245;
pub mod per;
pub mod q931;
pub mod schema;
