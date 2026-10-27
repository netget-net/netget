//! AppleDouble sidecars (`._name`) on macOS: accepted, and their bytes discarded.
//!
//! A FUSE-T mount has no named attributes (`--namedattr` is never passed; see `macos.rs`), so
//! macOS keeps a file's extended attributes — Finder tags, quarantine, provenance, which copyfile
//! (`cp`, Finder) copies with every file — in an AppleDouble file beside it. Refusing those
//! creates made every `cp` of a file carrying macOS's provenance attribute fail (FUSE-T relays the
//! refusal as EPERM, which copyfile treats as an error). So each `._` file is accepted without
//! asking the model and kept here, outside the described tree: a synthetic regular file whose
//! writes succeed and are thrown away. Only its length is kept, and reads return zeroes up to it.
//! macOS metadata written to this volume is therefore accepted and discarded.
//!
//! **Attributes are stable**, which is the point of the design as much as the discarding: an NFS
//! client that sees attributes change invalidates its caches, and attribute churn is what makes
//! Apple's NFS client panic (FUSE-T issue #109, FB23527406). A sidecar's inode is allocated once
//! and never reused; its mode is 0644 and its owner the creator; its times are fixed at creation
//! and only moved forward (`advance`) by a write or a size change; its length grows to the
//! highest byte written and shrinks only on an explicit truncate. A setattr of anything but the
//! size changes nothing.
//!
//! Bounds: [`MAX_SIDECARS`] per mount (ENOSPC past it) and [`MAX_SIDECAR_LEN`] each (EFBIG past
//! it). Memory is O(count): no byte is kept. Sidecars are not counted against the overlay.
//! Compiled with the FUSE server on every platform it builds on, and used only on macOS.
use crate::server::described_tree::{advance, Attr, Kind};
use crate::utils::clock::SystemTime;
use std::collections::HashMap;

/// Sidecars one mount may hold.
pub const MAX_SIDECARS: usize = 4096;
/// The largest length a sidecar may reach.
pub const MAX_SIDECAR_LEN: u64 = 16 * 1024 * 1024;
/// Sidecar inode numbers start here, far above anything the described tree allocates (it counts
/// up from 2), so the two never meet.
pub const FIRST_INO: u64 = 1 << 62;
const PERM: u16 = 0o644;
const BLOCK: u64 = 512;

/// Whether a name is an AppleDouble sidecar's.
pub fn is_appledouble(name: &[u8]) -> bool {
    name.starts_with(b"._")
}

struct Sidecar {
    uid: u32,
    gid: u32,
    len: u64,
    atime: SystemTime,
    mtime: SystemTime,
    ctime: SystemTime,
}

/// The sidecars of one mount.
pub struct Sidecars {
    by_ino: HashMap<u64, Sidecar>,
    by_name: HashMap<(u64, String), u64>,
    next_ino: u64,
}

impl Default for Sidecars {
    fn default() -> Self {
        Self::new()
    }
}

impl Sidecars {
    pub fn new() -> Self {
        Sidecars {
            by_ino: HashMap::new(),
            by_name: HashMap::new(),
            next_ino: FIRST_INO,
        }
    }

    pub fn count(&self) -> usize {
        self.by_ino.len()
    }

    /// Whether `ino` is a sidecar's (live or not): sidecar inodes have a range of their own.
    pub fn owns(ino: u64) -> bool {
        ino >= FIRST_INO
    }

    fn attr_of(ino: u64, s: &Sidecar) -> Attr {
        Attr {
            ino,
            kind: Kind::File,
            size: s.len,
            blocks: s.len.div_ceil(BLOCK),
            perm: PERM,
            nlink: 1,
            rdev: 0,
            uid: s.uid,
            gid: s.gid,
            atime: s.atime,
            mtime: s.mtime,
            ctime: s.ctime,
        }
    }

    pub fn attr(&self, ino: u64) -> Option<Attr> {
        self.by_ino.get(&ino).map(|s| Self::attr_of(ino, s))
    }

    pub fn lookup(&self, parent: u64, name: &str) -> Option<Attr> {
        let ino = *self.by_name.get(&(parent, name.to_string()))?;
        self.attr(ino)
    }

    /// Create `name` in `parent`, or return the one already there (unchanged). ENOSPC past
    /// [`MAX_SIDECARS`].
    pub fn create(
        &mut self,
        parent: u64,
        name: &str,
        uid: u32,
        gid: u32,
        now: SystemTime,
    ) -> Result<Attr, i32> {
        if let Some(a) = self.lookup(parent, name) {
            return Ok(a);
        }
        if self.by_ino.len() >= MAX_SIDECARS {
            return Err(libc::ENOSPC);
        }
        let ino = self.next_ino;
        self.next_ino += 1;
        let s = Sidecar {
            uid,
            gid,
            len: 0,
            atime: now,
            mtime: now,
            ctime: now,
        };
        let attr = Self::attr_of(ino, &s);
        self.by_ino.insert(ino, s);
        self.by_name.insert((parent, name.to_string()), ino);
        Ok(attr)
    }

    /// Accept a write and discard its bytes: the length becomes the highest byte written, never
    /// less. EFBIG past [`MAX_SIDECAR_LEN`], ENOENT for a sidecar that is gone.
    pub fn write(&mut self, ino: u64, offset: u64, len: u32, now: SystemTime) -> Result<u32, i32> {
        let s = self.by_ino.get_mut(&ino).ok_or(libc::ENOENT)?;
        let end = offset.checked_add(u64::from(len)).ok_or(libc::EFBIG)?;
        if end > MAX_SIDECAR_LEN {
            return Err(libc::EFBIG);
        }
        if len > 0 {
            s.len = s.len.max(end);
            advance(&mut s.mtime, now);
            advance(&mut s.ctime, now);
        }
        Ok(len)
    }

    /// Zeroes, up to the length.
    pub fn read(&self, ino: u64, offset: u64, size: u32) -> Result<Vec<u8>, i32> {
        let s = self.by_ino.get(&ino).ok_or(libc::ENOENT)?;
        let end = s.len.min(offset.saturating_add(u64::from(size)));
        Ok(vec![0; end.saturating_sub(offset) as usize])
    }

    /// A setattr: only a size changes anything (EFBIG past the bound); mode, owner and times are
    /// left as they are, so the attributes stay what they were.
    pub fn setattr(&mut self, ino: u64, size: Option<u64>, now: SystemTime) -> Result<Attr, i32> {
        let s = self.by_ino.get_mut(&ino).ok_or(libc::ENOENT)?;
        if let Some(size) = size {
            if size > MAX_SIDECAR_LEN {
                return Err(libc::EFBIG);
            }
            if size != s.len {
                s.len = size;
                advance(&mut s.mtime, now);
                advance(&mut s.ctime, now);
            }
        }
        Ok(Self::attr_of(ino, s))
    }

    pub fn unlink(&mut self, parent: u64, name: &str) -> Result<(), i32> {
        let ino = self
            .by_name
            .remove(&(parent, name.to_string()))
            .ok_or(libc::ENOENT)?;
        self.by_ino.remove(&ino);
        Ok(())
    }

    /// Move a sidecar to another `._` name, replacing a sidecar there. The inode moves with it.
    pub fn rename(
        &mut self,
        parent: u64,
        name: &str,
        new_parent: u64,
        new_name: &str,
        now: SystemTime,
    ) -> Result<(), i32> {
        let ino = *self
            .by_name
            .get(&(parent, name.to_string()))
            .ok_or(libc::ENOENT)?;
        if parent == new_parent && name == new_name {
            return Ok(());
        }
        if let Some(old) = self.by_name.remove(&(new_parent, new_name.to_string())) {
            self.by_ino.remove(&old);
        }
        self.by_name.remove(&(parent, name.to_string()));
        self.by_name.insert((new_parent, new_name.to_string()), ino);
        if let Some(s) = self.by_ino.get_mut(&ino) {
            advance(&mut s.ctime, now);
        }
        Ok(())
    }
}
