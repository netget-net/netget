//! Formatting a value whose `Display` may fail.
//!
//! `ToString::to_string` panics when a `Display` implementation returns `Err` ("a Display
//! implementation returned an error unexpectedly"). Some third-party types do: hickory-proto's
//! record data, on a record a peer crafted, was found by the `dns_message` fuzz target in
//! October 2026. Where the value came off the wire, format it through this instead.

use std::fmt::{Display, Write};

/// The value's `Display` output, or `None` if its `Display` failed.
pub fn try_display<T: Display + ?Sized>(value: &T) -> Option<String> {
    let mut out = String::new();
    write!(out, "{value}").ok()?;
    Some(out)
}
