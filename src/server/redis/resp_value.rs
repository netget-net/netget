//! Replies the server composes itself — pub/sub confirmations and messages, `PUBSUB`, and the
//! `CLUSTER` introspection family — as a small typed tree, encoded for the connection's RESP
//! version.
//!
//! The model-facing verbs encode JSON (`resp3.rs`), where a nested array in RESP2 has to fall
//! back to JSON text. These shapes are fixed by Redis — `CLUSTER SLOTS` is an array of arrays,
//! `CLUSTER SHARDS` an array of maps — so they need real nesting on both versions. Every tree
//! built here is a literal shape a few levels deep; nothing a peer or the model sends decides
//! its depth.

/// One RESP value.
#[derive(Debug, Clone, PartialEq)]
pub enum Resp {
    /// A bulk string (`$`).
    Bulk(Vec<u8>),
    /// A simple string (`+`).
    Simple(String),
    /// An integer (`:`).
    Int(i64),
    /// A null: `$-1` on RESP2, `_` on RESP3.
    Null,
    /// An array (`*`).
    Array(Vec<Resp>),
    /// A map (`%`); a flat key/value array on RESP2.
    Map(Vec<(Resp, Resp)>),
    /// An out-of-band push (`>`); on RESP2, where there is no push frame, an array — which is
    /// exactly how Redis frames pub/sub messages there.
    Push(Vec<Resp>),
    /// Text a client shows as is: a RESP3 verbatim string (`=`, format `txt`), a bulk string on
    /// RESP2. Redis answers `CLUSTER NODES` and `CLUSTER INFO` this way.
    Verbatim(String),
}

impl Resp {
    pub fn bulk(s: impl AsRef<[u8]>) -> Resp {
        Resp::Bulk(s.as_ref().to_vec())
    }

    /// Encode for a connection speaking RESP `proto` (2 or 3).
    pub fn encode(&self, proto: u8) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode_into(proto, &mut out);
        out
    }

    fn encode_into(&self, proto: u8, out: &mut Vec<u8>) {
        use super::actions::{encode_bulk_string, encode_integer, encode_simple_string};
        match self {
            Resp::Bulk(b) => out.extend_from_slice(&encode_bulk_string(b)),
            Resp::Simple(s) => out.extend_from_slice(&encode_simple_string(s)),
            Resp::Int(i) => out.extend_from_slice(&encode_integer(*i)),
            Resp::Null => out.extend_from_slice(&super::resp3::null(proto)),
            Resp::Array(items) => {
                out.extend_from_slice(format!("*{}\r\n", items.len()).as_bytes());
                for item in items {
                    item.encode_into(proto, out);
                }
            }
            Resp::Push(items) => {
                let marker = if proto == 3 { '>' } else { '*' };
                out.extend_from_slice(format!("{marker}{}\r\n", items.len()).as_bytes());
                for item in items {
                    item.encode_into(proto, out);
                }
            }
            Resp::Map(entries) => {
                if proto == 3 {
                    out.extend_from_slice(format!("%{}\r\n", entries.len()).as_bytes());
                } else {
                    out.extend_from_slice(format!("*{}\r\n", entries.len() * 2).as_bytes());
                }
                for (k, v) in entries {
                    k.encode_into(proto, out);
                    v.encode_into(proto, out);
                }
            }
            Resp::Verbatim(text) => {
                if proto == 3 {
                    let body = format!("txt:{text}");
                    out.extend_from_slice(format!("={}\r\n", body.len()).as_bytes());
                    out.extend_from_slice(body.as_bytes());
                    out.extend_from_slice(b"\r\n");
                } else {
                    out.extend_from_slice(&encode_bulk_string(text.as_bytes()));
                }
            }
        }
    }
}
