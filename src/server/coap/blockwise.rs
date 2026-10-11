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
//! * [`Uploads`] — **Block1**, the request direction. Blocks are appended in order and
//!   answered 2.31 Continue without the model; the body reaches the model once, whole, with
//!   the last block. Out of order is 4.08, over [`codec::MAX_REPRESENTATION_LEN`] is 4.13 with
//!   Size1, and a full table is 5.03.
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
/// least recently used one — a cache, so eviction costs a model call, never a refusal.
pub const MAX_TRANSFERS: usize = 32;

/// Block1 uploads in progress at once. A new upload past this is refused 5.03: an upload
/// cannot be evicted without losing what was already acknowledged with 2.31.
pub const MAX_UPLOADS: usize = 16;

/// How long a cached representation or a half-finished upload is kept after it was last
/// touched. RFC 7252's EXCHANGE_LIFETIME is 247 s; a client that pauses longer than a minute
/// between two blocks of one transfer is not doing block-wise transfer.
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

/// The Block2 cache.
#[derive(Debug)]
pub struct Transfers {
    entries: HashMap<ResourceKey, (Instant, Arc<Representation>)>,
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
            .retain(|_, (touched, _)| now.saturating_duration_since(*touched) < ttl);
    }

    /// The cached representation for `key`, refreshing its age.
    pub fn get(&mut self, key: &ResourceKey, now: Instant) -> Option<Arc<Representation>> {
        self.expire(now);
        let (touched, rep) = self.entries.get_mut(key)?;
        *touched = now;
        Some(rep.clone())
    }

    /// Cache `rep` under `key`. Returns the key evicted to make room, if any.
    pub fn insert(
        &mut self,
        key: ResourceKey,
        rep: Arc<Representation>,
        now: Instant,
    ) -> Option<ResourceKey> {
        self.expire(now);
        let mut evicted = None;
        if !self.entries.contains_key(&key) && self.entries.len() >= self.cap {
            evicted = self
                .entries
                .iter()
                .min_by_key(|(_, (touched, _))| *touched)
                .map(|(k, _)| k.clone());
            if let Some(old) = &evicted {
                self.entries.remove(old);
            }
        }
        self.entries.insert(key, (now, rep));
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
    ttl: Duration,
    max_body: usize,
}

impl Default for Uploads {
    fn default() -> Self {
        Uploads::new(MAX_UPLOADS, TRANSFER_TTL, codec::MAX_REPRESENTATION_LEN)
    }
}

impl Uploads {
    pub fn new(cap: usize, ttl: Duration, max_body: usize) -> Uploads {
        Uploads {
            entries: HashMap::new(),
            cap: cap.max(1),
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
