//! A disk the model describes rather than stores: a size, extents of text, hex or a fill byte,
//! and regions whose I/O fails. Everything an extent does not cover reads as zeroes. Shared by
//! the block servers that serve reads from a description — NBD's exports and iSCSI's LUNs —
//! so Rust answers every read at no model cost and nothing is written anywhere.
//!
//! Each protocol keeps its own vocabulary for a failing region (NBD names errnos, iSCSI names
//! SCSI sense conditions); [`parse_errors`] takes the mapping from name to the protocol's code.
use anyhow::{bail, ensure, Context, Result};
use serde_json::Value as Json;

/// Bytes of explicit content one description may carry, and its extents.
pub const MAX_CONTENT: usize = 16 * 1024 * 1024;
pub const MAX_EXTENTS: usize = 4096;

#[derive(Clone, Debug, PartialEq)]
pub enum Content {
    Bytes(Vec<u8>),
    Fill(u8),
}

#[derive(Clone, Debug, PartialEq)]
pub struct Extent {
    pub offset: u64,
    pub length: u64,
    pub content: Content,
}

/// A failing region: offset, length and the protocol's code for the failure.
pub type ErrorRegion = (u64, u64, u32);

pub fn u64_of(v: &Json, key: &str) -> Result<u64> {
    v.get(key)
        .and_then(Json::as_u64)
        .with_context(|| format!("{key} is a non-negative number"))
}

/// The entries of an optional array field, at most [`MAX_EXTENTS`] of them.
fn list(v: &Json, key: &str) -> Result<Vec<Json>> {
    match v.get(key) {
        None | Some(Json::Null) => Ok(vec![]),
        Some(Json::Array(a)) => {
            ensure!(
                a.len() <= MAX_EXTENTS,
                "{key} has more than {MAX_EXTENTS} entries"
            );
            Ok(a.clone())
        }
        _ => bail!("{key} is an array"),
    }
}

/// The `extents` of a description of `size` bytes: `{offset, text}`, `{offset, hex}` or
/// `{offset, length, fill}`, each inside the disk, at most [`MAX_CONTENT`] explicit bytes.
pub fn parse_extents(v: &Json, size: u64) -> Result<Vec<Extent>> {
    let mut extents = Vec::new();
    let mut content = 0usize;
    for e in list(v, "extents")? {
        let offset = u64_of(&e, "offset")?;
        let content_of = if let Some(t) = e.get("text").and_then(Json::as_str) {
            Content::Bytes(t.as_bytes().to_vec())
        } else if let Some(h) = e.get("hex").and_then(Json::as_str) {
            Content::Bytes(hex::decode(h).context("hex is not hex")?)
        } else if let Some(f) = e.get("fill") {
            Content::Fill(
                f.as_u64()
                    .and_then(|f| u8::try_from(f).ok())
                    .context("fill is a byte value 0-255")?,
            )
        } else {
            bail!("each extent has text, hex or fill");
        };
        let length = match &content_of {
            Content::Bytes(b) => {
                content += b.len();
                b.len() as u64
            }
            Content::Fill(_) => u64_of(&e, "length")?,
        };
        ensure!(
            content <= MAX_CONTENT,
            "extents carry more than {MAX_CONTENT} bytes"
        );
        ensure!(
            offset.checked_add(length).is_some_and(|end| end <= size),
            "an extent at {offset} runs past the size {size}"
        );
        if length > 0 {
            extents.push(Extent {
                offset,
                length,
                content: content_of,
            });
        }
    }
    Ok(extents)
}

/// The `errors` of a description: `{offset, length, error}` regions inside the disk. `code_of`
/// maps an error name to the protocol's code; `default` is the name used when none is given,
/// and `names` lists the accepted ones for the refusal message.
pub fn parse_errors(
    v: &Json,
    size: u64,
    code_of: impl Fn(&str) -> Option<u32>,
    default: &str,
    names: &str,
) -> Result<Vec<ErrorRegion>> {
    let mut errors = Vec::new();
    for e in list(v, "errors")? {
        let (offset, length) = (u64_of(&e, "offset")?, u64_of(&e, "length")?);
        ensure!(
            offset.checked_add(length).is_some_and(|end| end <= size),
            "an error region runs past the size"
        );
        let name = e.get("error").and_then(Json::as_str).unwrap_or(default);
        errors.push((
            offset,
            length,
            code_of(name).with_context(|| format!("error is {names}"))?,
        ));
    }
    Ok(errors)
}

/// The first failing byte in a range, with its code.
pub fn error_in(errors: &[ErrorRegion], offset: u64, length: u64) -> Option<(u64, u32)> {
    errors
        .iter()
        .filter(|(o, l, _)| *o < offset + length && offset < o + l)
        .map(|(o, _, e)| ((*o).max(offset), *e))
        .min_by_key(|(o, _)| *o)
}

/// The bytes of a range, zeroes where no extent covers it.
pub fn read(extents: &[Extent], offset: u64, length: usize) -> Vec<u8> {
    let mut out = vec![0u8; length];
    let end = offset + length as u64;
    for e in extents {
        let (s, t) = (e.offset.max(offset), (e.offset + e.length).min(end));
        if s >= t {
            continue;
        }
        let dst = &mut out[(s - offset) as usize..(t - offset) as usize];
        match &e.content {
            Content::Bytes(b) => {
                dst.copy_from_slice(&b[(s - e.offset) as usize..(t - e.offset) as usize])
            }
            Content::Fill(f) => dst.fill(*f),
        }
    }
    out
}

/// Covered (data) and uncovered (zero) runs of a range, in order.
pub fn runs(extents: &[Extent], offset: u64, length: u64) -> Vec<(u64, u64, bool)> {
    let end = offset + length;
    let mut cuts = vec![offset, end];
    for e in extents {
        for p in [e.offset, e.offset + e.length] {
            if p > offset && p < end {
                cuts.push(p);
            }
        }
    }
    cuts.sort_unstable();
    cuts.dedup();
    let mut runs: Vec<(u64, u64, bool)> = Vec::new();
    for w in cuts.windows(2) {
        let data = extents
            .iter()
            .any(|e| e.offset < w[1] && w[0] < e.offset + e.length);
        match runs.last_mut() {
            Some(last) if last.2 == data => last.1 += w[1] - w[0],
            _ => runs.push((w[0], w[1] - w[0], data)),
        }
    }
    runs
}
