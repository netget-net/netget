//! CQL frame header — `cassandra_protocol::frame::Envelope::from_buffer`, behind NetGet's checks.
//!
//! NetGet's Cassandra server hands every complete frame to `cassandra-protocol` 5.0's
//! `Envelope::from_buffer` on the first packet of a connection, before STARTUP. The read loop
//! bounds the declared length at `MAX_FRAME_BODY_BYTES`, and `parse_request_frame` refuses a
//! response-direction frame and the warning flag on a request. The decoder reads a tracing id, a
//! warning `[string list]` and a custom-payload `[bytes map]` out of the body on the header's
//! say-so; 3.3.0 panicked on three malformed shapes of those and on a negative body length.
//!
//! The target runs exactly that pair, in that order: **anything the read loop and the screen
//! accept, the decoder must survive.**

#![no_main]

use libfuzzer_sys::fuzz_target;
use netget::server::cassandra::{parse_request_frame, MAX_FRAME_BODY_BYTES};

fuzz_target!(|data: &[u8]| {
    // The read loop's framing: a 9-byte header, the declared length bounded, the frame whole.
    if data.len() < 9 {
        return;
    }
    let length = u32::from_be_bytes([data[5], data[6], data[7], data[8]]) as usize;
    if length > MAX_FRAME_BODY_BYTES || data.len() < 9 + length {
        return;
    }
    let _ = parse_request_frame(&data[..9 + length]);
});
