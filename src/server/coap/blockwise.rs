//! Block-wise transfer (RFC 7959) for the CoAP server: the two tables it needs and nothing
//! else. Pure and synchronous — `mod.rs` holds each behind a `std::sync::Mutex` that is never
//! held across an `.await`, and passes `now` in so the expiry rules can be tested without a
//! clock.
//!
//! * [`Transfers`] — **Block2**, the response direction. The model answers a request once; a
//!   representation over one block is cached and every later block is served from the cache,
//!   so a 64-block transfer costs one model call rather than sixty-four, and every block comes
//!   from the same answer (the ETag says so). A miss is not an error: the request goes to the
//!   model again, as RFC 7959 §2.4's stateless server would do, and its answer is sliced.
//!   The source address a cached entry is keyed by is spoofable, so a hit is a reply the
//!   server sends to whoever that address is, without the model: each entry therefore lives
//!   [`TRANSFER_TTL`] from when it was cached (a hit does not renew it) and serves at most
//!   [`TRANSFER_SERVE_FACTOR`] times its own length before it is evicted, which bounds what
//!   one model answer can be made to reflect.
//! * [`Uploads`] — **Block1**, the request direction. Blocks are appended in order and
//!   answered 2.31 Continue without the model; the body reaches the model once, whole, with
//!   the last block. Out of order is 4.08, over [`codec::MAX_REPRESENTATION_LEN`] is 4.13 with
//!   Size1, and a full table is 5.03. One source IP holds at most [`MAX_UPLOADS_PER_IP`]
//!   uploads; a new one past that evicts that IP's least recently advanced upload.
//!
//! Both are keyed by the peer's address and the target resource (RFC 7959 §2.4: block-wise
//! transfers are matched by endpoint and request URI, not by token — a client may use a new
//! token for every block, and libcoap does).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use crate::utils::clock::Instant;

use super::codec::{self, BlockValue};

/// Cached Block2 representations a server holds at once. Inserting past this evicts the
/// oldest one — a cache, so eviction costs a model call, never a refusal.
pub const MAX_TRANSFERS: usize = 32;

/// Bytes one cached representation may serve, as a multiple of its payload length, counting
/// the block that was sent when it was cached. A whole transfer is 1×; 2× leaves room for a
/// client that retransmits every block once. A block that would pass it evicts the entry and
/// goes to the model instead.
pub const TRANSFER_SERVE_FACTOR: usize = 2;

/// Block1 uploads in progress at once. A new upload past this is refused 5.03: an upload
/// cannot be evicted to make room for a different peer without losing what was already
/// acknowledged with 2.31.
pub const MAX_UPLOADS: usize = 16;

/// Block1 uploads one source IP holds at once. A new upload from an IP already holding this
/// many evicts that IP's least recently advanced one, so one address cannot hold the table.
pub const MAX_UPLOADS_PER_IP: usize = 2;

/// How long a cached representation is kept after it was cached, and a half-finished upload
/// after its last block. RFC 7252's EXCHANGE_LIFETIME is 247 s; a client that needs longer
/// than a minute for one transfer is not doing block-wise transfer, and a miss only costs a
/// model call.
pub const TRANSFER_TTL: Duration = Duration::from_secs(60);

/// Which resource, at which endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ResourceKey {
    pub peer: SocketAddr,
    pub path: String,
    pub query: Option<String>,
}

/// One answer the model gave, kept so every block of it is served from the same bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Representation {
    pub code: u8,
    pub payload: Vec<u8>,
    pub content_format: Option<u16>,
    /// Identifies this representation across its blocks (RFC 7252 §5.10.6): a client that sees
    /// it change mid-transfer knows it is stitching two answers together.
    pub etag: Vec<u8>,
}

impl Representation {
    pub fn new(code: u8, payload: Vec<u8>, content_format: Option<u16>) -> Representation {
        let etag = etag_for(&payload, content_format);
        Representation {
            code,
            payload,
            content_format,
            etag,
        }
    }

    /// Block `block.num` at `block.size()`, and whether more follow. `None` when the block
    /// starts past the end — except block 0 of an empty representation, which is itself.
    pub fn block(&self, block: BlockValue) -> Option<(&[u8], bool)> {
        let offset = block.offset();
        if offset >= self.payload.len() && !(offset == 0 && self.payload.is_empty()) {
            return None;
        }
        let end = (offset + block.size()).min(self.payload.len());
        Some((&self.payload[offset..end], end < self.payload.len()))
    }
}

/// An 8-byte ETag: FNV-1a over the content format and the payload. Not a security property,
/// only an identity — two different answers to the same request must not share one.
pub fn etag_for(payload: &[u8], content_format: Option<u16>) -> Vec<u8> {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    let cf = content_format.map_or([0xFF, 0xFF, 0xFF], |c| {
        let b = c.to_be_bytes();
        [1, b[0], b[1]]
    });
    for byte in cf.iter().chain(payload.iter()) {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash.to_be_bytes().to_vec()
}

#[derive(Debug)]
struct Cached {
    /// When the representation was cached. Never renewed by a hit.
    cached: Instant,
    rep: Arc<Representation>,
    /// Payload bytes served from this entry, including the block sent when it was cached.
    served: usize,
}

/// The Block2 cache.
#[derive(Debug)]
pub struct Transfers {
    entries: HashMap<ResourceKey, Cached>,
    cap: usize,
    ttl: Duration,
}

impl Default for Transfers {
    fn default() -> Self {
        Transfers::new(MAX_TRANSFERS, TRANSFER_TTL)
    }
}

impl Transfers {
    pub fn new(cap: usize, ttl: Duration) -> Transfers {
        Transfers {
            entries: HashMap::new(),
            cap: cap.max(1),
            ttl,
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn expire(&mut self, now: Instant) {
        let ttl = self.ttl;
        self.entries
            .retain(|_, c| now.saturating_duration_since(c.cached) < ttl);
    }

    /// The cached representation for `key`, to serve `block` of it. The block's bytes are
    /// charged to the entry; a block that would take it past [`TRANSFER_SERVE_FACTOR`] times
    /// the payload length evicts the entry and is a miss. A hit does not renew the entry's
    /// age. A block past the end is charged nothing and still returns the representation, so
    /// the caller can answer 4.02.
    pub fn get(
        &mut self,
        key: &ResourceKey,
        block: BlockValue,
        now: Instant,
    ) -> Option<Arc<Representation>> {
        self.expire(now);
        let entry = self.entries.get_mut(key)?;
        let len = entry.rep.block(block).map_or(0, |(slice, _)| slice.len());
        let budget = entry
            .rep
            .payload
            .len()
            .saturating_mul(TRANSFER_SERVE_FACTOR);
        if entry.served.saturating_add(len) > budget {
            self.entries.remove(key);
            return None;
        }
        entry.served += len;
        Some(entry.rep.clone())
    }

    /// Cache `rep` under `key`, charged `served` bytes for the block just sent from it. If
    /// `key` already holds this same representation (a block served from the cache), the
    /// entry is left as it is: its age and its charge stand. Returns the key evicted to make
    /// room, if any.
    pub fn insert(
        &mut self,
        key: ResourceKey,
        rep: Arc<Representation>,
        served: usize,
        now: Instant,
    ) -> Option<ResourceKey> {
        self.expire(now);
        if self
            .entries
            .get(&key)
            .is_some_and(|c| Arc::ptr_eq(&c.rep, &rep))
        {
            return None;
        }
        let mut evicted = None;
        if !self.entries.contains_key(&key) && self.entries.len() >= self.cap {
            evicted = self
                .entries
                .iter()
                .min_by_key(|(_, c)| c.cached)
                .map(|(k, _)| k.clone());
            if let Some(old) = &evicted {
                self.entries.remove(old);
            }
        }
        self.entries.insert(
            key,
            Cached {
                cached: now,
                rep,
                served,
            },
        );
        evicted
    }

    /// Forget `key` — the last block was served.
    pub fn remove(&mut self, key: &ResourceKey) {
        self.entries.remove(key);
    }
}

/// An upload is also keyed by method: a PUT and a POST to the same resource are two bodies.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UploadKey {
    pub resource: ResourceKey,
    pub method: u8,
}

#[derive(Debug)]
struct Upload {
    body: Vec<u8>,
    touched: Instant,
}

/// What to do with one Block1 block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UploadStep {
    /// Acknowledge with 2.31 Continue, echoing this Block1 value. The model is not asked.
    Continue(BlockValue),
    /// The last block arrived: this is the whole body, in `blocks` blocks.
    Complete {
        body: Vec<u8>,
        blocks: u32,
        last: BlockValue,
    },
    /// Refuse with `code`. `size1` is the largest body this server takes, for a 4.13.
    Refuse {
        code: u8,
        size1: Option<usize>,
        /// `decision=` token for the log.
        decision: &'static str,
        reason: String,
    },
}

/// The Block1 reassembly table.
#[derive(Debug)]
pub struct Uploads {
    entries: HashMap<UploadKey, Upload>,
    cap: usize,
    per_ip: usize,
    ttl: Duration,
    max_body: usize,
}

impl Default for Uploads {
    fn default() -> Self {
        Uploads::new(
            MAX_UPLOADS,
            MAX_UPLOADS_PER_IP,
            TRANSFER_TTL,
            codec::MAX_REPRESENTATION_LEN,
        )
    }
}

impl Uploads {
    pub fn new(cap: usize, per_ip: usize, ttl: Duration, max_body: usize) -> Uploads {
        Uploads {
            entries: HashMap::new(),
            cap: cap.max(1),
            per_ip: per_ip.max(1),
            ttl,
            max_body,
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn too_large(&self, what: String) -> UploadStep {
        UploadStep::Refuse {
            code: codec::CODE_REQUEST_ENTITY_TOO_LARGE,
            size1: Some(self.max_body),
            decision: "refused_upload_too_large",
            reason: format!("{what}; this server takes at most {} bytes", self.max_body),
        }
    }

    /// Take one block. `size1` is the request's Size1 option, the size the client announced.
    pub fn accept(
        &mut self,
        key: UploadKey,
        block: BlockValue,
        payload: &[u8],
        size1: Option<u32>,
        now: Instant,
    ) -> UploadStep {
        let ttl = self.ttl;
        self.entries
            .retain(|_, u| now.saturating_duration_since(u.touched) < ttl);

        // Refused on the announcement, before a byte of it is held (RFC 7959 §4).
        if let Some(announced) = size1 {
            if announced as usize > self.max_body {
                self.entries.remove(&key);
                return self.too_large(format!("the client announced {announced} bytes"));
            }
        }
        if block.more && payload.len() != block.size() {
            self.entries.remove(&key);
            return UploadStep::Refuse {
                code: codec::CODE_BAD_REQUEST,
                size1: None,
                decision: "refused_upload_bad_block",
                reason: format!(
                    "block {} says more follow but carries {} bytes, not its size {}",
                    block.num,
                    payload.len(),
                    block.size()
                ),
            };
        }
        if payload.len() > block.size() {
            self.entries.remove(&key);
            return UploadStep::Refuse {
                code: codec::CODE_BAD_REQUEST,
                size1: None,
                decision: "refused_upload_bad_block",
                reason: format!(
                    "block {} carries {} bytes, over its size {}",
                    block.num,
                    payload.len(),
                    block.size()
                ),
            };
        }

        if block.num == 0 {
            self.entries.remove(&key);
            if !block.more {
                return UploadStep::Complete {
                    body: payload.to_vec(),
                    blocks: 1,
                    last: block,
                };
            }
            // One IP at its own cap gives up its least recently advanced upload; only then is
            // the shared cap checked, so one address cannot be the reason another is refused.
            let ip = key.resource.peer.ip();
            loop {
                let held = self
                    .entries
                    .iter()
                    .filter(|(k, _)| k.resource.peer.ip() == ip);
                if held.clone().count() < self.per_ip {
                    break;
                }
                let Some(oldest) = held.min_by_key(|(_, u)| u.touched).map(|(k, _)| k.clone())
                else {
                    break;
                };
                self.entries.remove(&oldest);
                tracing::info!(
                    "CoAP Block1 upload {} {}{} from {} evicted: {} uploads from that IP are \
                     in progress decision=upload_evicted_per_ip",
                    codec::method_name(oldest.method).unwrap_or("?"),
                    oldest.resource.path,
                    oldest
                        .resource
                        .query
                        .as_ref()
                        .map(|q| format!("?{q}"))
                        .unwrap_or_default(),
                    oldest.resource.peer,
                    self.per_ip
                );
            }
            if self.entries.len() >= self.cap {
                return UploadStep::Refuse {
                    code: codec::CODE_SERVICE_UNAVAILABLE,
                    size1: None,
                    decision: "refused_upload_table_full",
                    reason: format!("{} uploads are already in progress", self.cap),
                };
            }
            self.entries.insert(
                key,
                Upload {
                    body: payload.to_vec(),
                    touched: now,
                },
            );
            return UploadStep::Continue(block);
        }

        // A later block must continue exactly where the body ends. Comparing offsets rather
        // than numbers is what lets a client lower the block size mid-transfer (§2.3).
        let expected = self.entries.get(&key).map(|u| u.body.len());
        if expected != Some(block.offset()) {
            self.entries.remove(&key);
            return UploadStep::Refuse {
                code: codec::CODE_REQUEST_ENTITY_INCOMPLETE,
                size1: None,
                decision: "refused_upload_out_of_order",
                reason: match expected {
                    Some(have) => format!(
                        "block {} starts at byte {}, but {have} bytes have arrived",
                        block.num,
                        block.offset()
                    ),
                    None => format!("block {} arrived with no upload in progress", block.num),
                },
            };
        }
        let upload = self.entries.get_mut(&key).expect("checked above");
        if upload.body.len() + payload.len() > self.max_body {
            let have = upload.body.len() + payload.len();
            self.entries.remove(&key);
            return self.too_large(format!("the upload reached {have} bytes"));
        }
        upload.body.extend_from_slice(payload);
        upload.touched = now;
        if block.more {
            return UploadStep::Continue(block);
        }
        let upload = self.entries.remove(&key).expect("present above");
        UploadStep::Complete {
            body: upload.body,
            blocks: block.num + 1,
            last: block,
        }
    }
}
