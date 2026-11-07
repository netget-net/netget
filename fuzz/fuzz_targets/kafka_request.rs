//! The Kafka broker's request decode path: `kafka-protocol`'s code-generated request header
//! and body decoders at the version the request names, and, for Produce, NetGet's
//! `decode_record_batches`, which decodes each partition's record batches through
//! `kafka-protocol` with an inflation bound of NetGet's own.
//!
//! The input is one request message — what follows the 4-byte size prefix, which the
//! connection loop has already checked against `MIN_REQUEST_BYTES` and `MAX_REQUEST_BYTES`.
//! From there it is the loop's own sequence: api key, version and correlation id at fixed
//! offsets, `supported_versions` decides whether the request is answered, the header is
//! decoded at `ApiKey::request_header_version`, and the body is decoded from where the header
//! ended. All of it is before any authentication — Kafka has none here — and before the model.
//!
//! Asserted:
//!
//! 1. Nothing panics or allocates past libFuzzer's `-rss_limit_mb`, whatever the bytes. Every
//!    array, string and byte-field length in a Kafka request is a peer-chosen `i32` or varint;
//!    a decoder that reserves what it is told is the size-lie class this target exists for.
//! 2. A request body that decodes re-encodes, and the re-encoding decodes to the same value.
//! 3. Produce record batches never inflate past `MAX_INFLATED_PRODUCE_BYTES` per request —
//!    `kafka-protocol`'s own gzip/zstd/lz4 decompressors have no output bound at all — and
//!    never decode to more than `MAX_PRODUCE_RECORDS` records.
//!
//! A record batch carries a CRC-32C over everything after it, which a mutating fuzzer
//! essentially never gets right, so every batch also goes through a second time with its CRC
//! recomputed. That is what lets the search reach the decompressors and the record walker
//! behind the checksum, which is where the inflation bound lives.
//!
//! Kafka requests do not nest, so there is no depth bomb; the corpus carries a decompression
//! bomb (a gzip batch of 64 MiB of zeros) and size lies instead.

#![no_main]

use libfuzzer_sys::fuzz_target;
use netget::server::kafka::kafka_protocol::messages::{
    ApiKey, ApiVersionsRequest, FetchRequest, MetadataRequest, OffsetCommitRequest, ProduceRequest,
    RequestHeader,
};
use netget::server::kafka::kafka_protocol::protocol::{Decodable, Encodable};
use netget::server::kafka::{
    decode_record_batches, supported_versions, ProduceBudget, MAX_INFLATED_PRODUCE_BYTES,
    MAX_PRODUCE_RECORDS,
};

/// CRC-32C (Castagnoli), bitwise — what a v2 record batch carries.
fn crc32c(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0x82F6_3B78
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

/// The same bytes with the first v2 batch's CRC made correct, if there is one to fix.
fn with_fixed_crc(raw: &[u8]) -> Option<Vec<u8>> {
    if raw.len() < 21 || raw[16] != 2 {
        return None;
    }
    let batch_len = i32::from_be_bytes([raw[8], raw[9], raw[10], raw[11]]);
    let end = 12usize.checked_add(usize::try_from(batch_len).ok()?)?;
    if end > raw.len() || end < 21 {
        return None;
    }
    let mut fixed = raw.to_vec();
    let crc = crc32c(&fixed[21..end]);
    fixed[17..21].copy_from_slice(&crc.to_be_bytes());
    Some(fixed)
}

fn batches(raw: &[u8]) {
    let mut budget = ProduceBudget::per_request();
    if let Ok(records) = decode_record_batches(raw, &mut budget) {
        assert!(
            budget.inflated_bytes <= MAX_INFLATED_PRODUCE_BYTES,
            "the inflation budget grew"
        );
        assert!(
            records.len() <= MAX_PRODUCE_RECORDS,
            "past the record bound"
        );
        assert_eq!(
            budget.records,
            MAX_PRODUCE_RECORDS - records.len(),
            "the record budget must be charged exactly what was decoded"
        );
    }
}

/// Decode `T` from where the header ended; if it decodes, re-encode and decode again.
fn body<T: Decodable + Encodable + PartialEq + std::fmt::Debug>(
    rest: &[u8],
    version: i16,
) -> Option<T> {
    let mut cursor = std::io::Cursor::new(rest);
    let decoded = T::decode(&mut cursor, version).ok()?;
    let mut out = Vec::new();
    if decoded.encode(&mut out, version).is_ok() {
        let mut again = std::io::Cursor::new(&out[..]);
        let redecoded = T::decode(&mut again, version)
            .expect("a request body this decoder produced did not decode back");
        assert_eq!(
            decoded, redecoded,
            "encode/decode round trip changed the request"
        );
    }
    Some(decoded)
}

fuzz_target!(|data: &[u8]| {
    // MIN_REQUEST_BYTES: the connection loop refuses anything shorter before decoding.
    if data.len() < 8 {
        return;
    }
    let api_key_raw = i16::from_be_bytes([data[0], data[1]]);
    let api_version = i16::from_be_bytes([data[2], data[3]]);
    let Ok(api_key) = ApiKey::try_from(api_key_raw) else {
        return;
    };
    let supported = supported_versions(api_key_raw);
    if !matches!(supported, Some((min, max)) if api_version >= min && api_version <= max) {
        return;
    }

    let mut cursor = std::io::Cursor::new(data);
    let header_version = api_key.request_header_version(api_version);
    let Ok(_header) = RequestHeader::decode(&mut cursor, header_version) else {
        return;
    };
    let rest = &data[cursor.position() as usize..];

    match api_key {
        ApiKey::ApiVersions => {
            body::<ApiVersionsRequest>(rest, api_version);
        }
        ApiKey::Metadata => {
            body::<MetadataRequest>(rest, api_version);
        }
        ApiKey::Fetch => {
            body::<FetchRequest>(rest, api_version);
        }
        ApiKey::OffsetCommit => {
            body::<OffsetCommitRequest>(rest, api_version);
        }
        ApiKey::Produce => {
            if let Some(produce) = body::<ProduceRequest>(rest, api_version) {
                for topic in &produce.topic_data {
                    for partition in &topic.partition_data {
                        if let Some(raw) = &partition.records {
                            batches(raw);
                            if let Some(fixed) = with_fixed_crc(raw) {
                                batches(&fixed);
                            }
                        }
                    }
                }
            }
        }
        _ => {}
    }
});
