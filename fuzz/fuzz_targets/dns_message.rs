//! DNS wire format — `hickory_proto::op::Message::from_vec`.
//!
//! **NetGet has no DNS parser of its own** (DNS over TCP adds only a two-byte length prefix,
//! read with `read_u16` and bounded by its own width). `src/server/dns/mod.rs`, `dot/mod.rs` and
//! `doh/mod.rs` each call `DnsMessage::from_vec(&data)` inline in their receive loop and
//! hand the result to the model; there is no hand-written framing or name decompression
//! anywhere around it. That makes this the one target here that fuzzes a third-party crate
//! rather than NetGet code — and it earns its place anyway, because the exposure is NetGet's:
//! three registered protocols reach this decoder from an unauthenticated datagram on the
//! first packet, and a crash inside it kills the whole process exactly as one inside our own
//! code would.
//!
//! Name compression is the reason to fuzz it: a compression pointer may point backwards into
//! the message, and a decoder that follows pointers without bounding the chain either loops
//! or recurses. That is the same class as the six overflows this harness exists for, sitting
//! in a dependency rather than in `src/`.
//!
//! If this target crashes, the finding belongs upstream — and the NetGet-side fix is a
//! structural screen in front of `from_vec`, the shape `utils::bencode` already establishes.

#![no_main]

use hickory_proto::op::Message as DnsMessage;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(msg) = DnsMessage::from_vec(data) else {
        return;
    };

    // The accessors the servers read before building an event for the model. Each re-walks
    // the decoded records.
    for q in msg.queries() {
        let _ = q.name().to_string();
        let _ = q.query_type();
    }
    for r in msg.answers() {
        let _ = r.name().to_string();
        let _ = r.data();
    }
    // Since October 2026 the DNS server also reads the OPT record (the client's UDP size and
    // DO bit decide truncation and signing) and, for IXFR, the serial of the SOA in the
    // authority section — both from the first message of an unauthenticated peer. With the
    // `dns` feature hickory now decodes DNSSEC rdata too (RRSIG, NSEC, DNSKEY), which a
    // query's sections can carry.
    if let Some(edns) = msg.extensions() {
        let _ = edns.max_payload();
        let _ = edns.dnssec_ok();
    }
    for r in msg.name_servers().iter().chain(msg.additionals()) {
        if let Some(hickory_proto::rr::RData::SOA(soa)) = r.data() {
            let _ = soa.serial();
        }
        // Through NetGet's helper, as the DoH and DoQ clients do: hickory's own Display
        // returns Err for some crafted record data, which `to_string()` turns into a panic.
        let _ = r.data().and_then(netget::utils::display::try_display);
    }

    // A message that decodes must re-encode; `to_vec` is what the servers call on the reply
    // path, and a record that survives decode but not encode is a desync.
    let _ = msg.to_vec();
});
