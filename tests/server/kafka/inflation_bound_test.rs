//! A Produce request's record batches inflate only as far as `MAX_INFLATED_PRODUCE_BYTES`, and
//! decode only as far as `MAX_PRODUCE_RECORDS` records, not as far as the batches say.
//!
//! `kafka-protocol`'s gzip, zstd and lz4 decompressors copy the whole inflated stream into a
//! buffer before a single record is decoded, so a gzip batch of 64 MiB of zeros — about 64 KiB
//! on the wire — cost 64 MiB in the broker, and one request at the 100 MiB request cap could
//! ask for ~100 GiB. And every record decodes into a 176-byte `Record` from as little as 7
//! bytes, compressed or not. The broker decodes through `decode_record_batches`, which inflates
//! through a reader bounded by the request's remaining budget and reads each batch's record
//! count before decoding it. These drive that function directly with batches `kafka-protocol`'s
//! own encoder produced; `fuzz/fuzz_targets/kafka_request.rs` carries the same bomb in its
//! corpus.

use bytes::Bytes;
use netget::server::kafka::kafka_protocol::records::{
    Compression, Record, RecordBatchEncoder, RecordEncodeOptions, TimestampType,
};
use netget::server::kafka::{
    decode_record_batches, BatchError, ProduceBudget, MAX_INFLATED_PRODUCE_BYTES,
    MAX_PRODUCE_RECORDS,
};

type Compressor = fn(&mut bytes::BytesMut, &mut Vec<u8>, Compression) -> anyhow::Result<()>;

const CODECS: [Compression; 4] = [
    Compression::Gzip,
    Compression::Zstd,
    Compression::Lz4,
    Compression::Snappy,
];

fn record(offset: i64, value: Option<Bytes>) -> Record {
    Record {
        transactional: false,
        control: false,
        partition_leader_epoch: 0,
        producer_id: -1,
        producer_epoch: -1,
        timestamp_type: TimestampType::Creation,
        offset,
        // The encoder starts a new batch whenever `offset - sequence` changes.
        sequence: offset as i32,
        timestamp: 1_700_000_000_000,
        key: None,
        value,
        headers: Default::default(),
    }
}

fn encode(records: &[Record], compression: Compression) -> Vec<u8> {
    let mut buf = Vec::new();
    RecordBatchEncoder::encode_with_custom_compression::<_, _, Compressor>(
        &mut buf,
        records,
        &RecordEncodeOptions {
            version: 2,
            compression,
        },
        None,
    )
    .expect("test record batch must encode");
    buf
}

/// One batch holding one record of `value_len` zero bytes.
fn batch(value_len: usize, compression: Compression) -> Vec<u8> {
    encode(
        &[record(0, Some(Bytes::from(vec![0u8; value_len])))],
        compression,
    )
}

/// One batch holding `count` empty records — the 7-byte minimum each.
fn many(count: usize, compression: Compression) -> Vec<u8> {
    let records: Vec<Record> = (0..count as i64).map(|i| record(i, None)).collect();
    encode(&records, compression)
}

#[test]
fn a_compressed_batch_inflating_past_the_budget_is_refused_for_every_codec() {
    for compression in CODECS {
        let bomb = batch(MAX_INFLATED_PRODUCE_BYTES * 4, compression);
        assert!(
            bomb.len() < MAX_INFLATED_PRODUCE_BYTES / 4,
            "{compression:?}: the fixture is meant to be small on the wire, got {} bytes",
            bomb.len()
        );
        let mut budget = ProduceBudget::per_request();
        match decode_record_batches(&bomb, &mut budget) {
            Err(BatchError::TooLarge) => {}
            Err(other) => {
                panic!("{compression:?}: refused, but not as too large: {other:?}")
            }
            Ok(records) => panic!(
                "{compression:?}: a {}-byte batch inflated to {} records ({} value bytes) past \
                 the {MAX_INFLATED_PRODUCE_BYTES}-byte budget",
                bomb.len(),
                records.len(),
                records
                    .iter()
                    .map(|r| r.value.as_ref().map_or(0, |v| v.len()))
                    .sum::<usize>()
            ),
        }
    }
}

#[test]
fn the_budget_is_shared_by_every_batch_of_one_request() {
    let third = MAX_INFLATED_PRODUCE_BYTES * 2 / 5;
    let one = batch(third, Compression::Gzip);
    let mut budget = ProduceBudget::per_request();

    let first = decode_record_batches(&one, &mut budget).expect("the first batch fits");
    assert_eq!(first[0].value.as_ref().map(|v| v.len()), Some(third));
    assert!(budget.inflated_bytes < MAX_INFLATED_PRODUCE_BYTES - third);
    decode_record_batches(&one, &mut budget).expect("the second batch still fits");
    assert!(
        matches!(
            decode_record_batches(&one, &mut budget),
            Err(BatchError::TooLarge)
        ),
        "a third batch takes the request past its budget and must be refused"
    );
}

#[test]
fn an_uncompressed_batch_costs_no_inflation_budget() {
    let plain = batch(1024, Compression::None);
    let mut budget = ProduceBudget::per_request();
    let records = decode_record_batches(&plain, &mut budget).expect("plain batch decodes");
    assert_eq!(records.len(), 1);
    assert_eq!(budget.inflated_bytes, MAX_INFLATED_PRODUCE_BYTES);
    assert_eq!(budget.records, MAX_PRODUCE_RECORDS - 1);
}

/// What one single-record batch of `value_len` bytes inflates to: the budget it consumes.
fn inflated_len(value_len: usize, compression: Compression) -> usize {
    let roomy = 1usize << 40;
    let mut budget = ProduceBudget {
        inflated_bytes: roomy,
        records: MAX_PRODUCE_RECORDS,
    };
    decode_record_batches(&batch(value_len, compression), &mut budget)
        .expect("a probe batch decodes with a budget far above its size");
    roomy - budget.inflated_bytes
}

#[test]
fn a_batch_inflating_to_exactly_the_budget_is_taken_and_one_byte_more_is_refused() {
    for compression in CODECS {
        // A record's framing is a few varints; between 2^21 and 2^28 bytes of value their
        // widths do not change, so the overhead measured at 4 MiB holds at the budget too.
        let probe = 4 * 1024 * 1024;
        let overhead = inflated_len(probe, compression) - probe;
        let exact = MAX_INFLATED_PRODUCE_BYTES - overhead;

        let mut budget = ProduceBudget::per_request();
        let records = match decode_record_batches(&batch(exact, compression), &mut budget) {
            Ok(records) => records,
            Err(other) => panic!(
                "{compression:?}: a batch inflating to exactly {MAX_INFLATED_PRODUCE_BYTES} \
                 bytes must be taken, got {other:?}"
            ),
        };
        assert_eq!(records[0].value.as_ref().map(|v| v.len()), Some(exact));
        assert_eq!(
            budget.inflated_bytes, 0,
            "{compression:?}: the exact fit uses the whole budget"
        );

        let mut budget = ProduceBudget::per_request();
        match decode_record_batches(&batch(exact + 1, compression), &mut budget) {
            Err(BatchError::TooLarge) => {}
            Err(other) => panic!("{compression:?}: one byte over refused as {other:?}"),
            Ok(_) => panic!(
                "{compression:?}: one byte past the {MAX_INFLATED_PRODUCE_BYTES}-byte budget \
                 must be MESSAGE_TOO_LARGE"
            ),
        }
    }
}

#[test]
fn exactly_the_record_bound_is_taken_and_one_record_more_is_refused() {
    for compression in [Compression::None, Compression::Gzip] {
        let mut budget = ProduceBudget::per_request();
        let records =
            match decode_record_batches(&many(MAX_PRODUCE_RECORDS, compression), &mut budget) {
                Ok(records) => records,
                Err(other) => panic!(
                    "{compression:?}: a batch of exactly {MAX_PRODUCE_RECORDS} records must be \
                 taken, got {other:?}"
                ),
            };
        assert_eq!(records.len(), MAX_PRODUCE_RECORDS);
        assert_eq!(
            budget.records, 0,
            "{compression:?}: the exact fit uses the whole bound"
        );

        let mut budget = ProduceBudget::per_request();
        match decode_record_batches(&many(MAX_PRODUCE_RECORDS + 1, compression), &mut budget) {
            Err(BatchError::TooManyRecords) => {}
            Err(other) => panic!("{compression:?}: one record over refused as {other:?}"),
            Ok(records) => panic!(
                "{compression:?}: {} records past the {MAX_PRODUCE_RECORDS}-record bound must \
                 be MESSAGE_TOO_LARGE",
                records.len()
            ),
        }
        assert_eq!(
            budget,
            ProduceBudget::per_request(),
            "{compression:?}: a batch refused on its declared count costs nothing"
        );
    }
}

#[test]
fn the_record_bound_is_shared_by_every_batch_of_one_request() {
    let most = many(MAX_PRODUCE_RECORDS * 3 / 5, Compression::None);
    let mut budget = ProduceBudget::per_request();
    decode_record_batches(&most, &mut budget).expect("the first batch fits");
    assert!(
        matches!(
            decode_record_batches(&most, &mut budget),
            Err(BatchError::TooManyRecords)
        ),
        "a second batch takes the request past its record bound and must be refused"
    );
}

#[test]
fn a_header_declaring_billions_of_records_is_refused_before_it_is_decoded() {
    // A 61-byte-header batch whose recordsCount says i32::MAX. The CRC is left wrong on
    // purpose: the count is read before anything is decoded, so this must be refused as too
    // many records, never reach the decoder's CRC check, and never reserve for the count.
    let mut hostile = many(1, Compression::None);
    hostile[57..61].copy_from_slice(&i32::MAX.to_be_bytes());
    let mut budget = ProduceBudget::per_request();
    match decode_record_batches(&hostile, &mut budget) {
        Err(BatchError::TooManyRecords) => {}
        other => panic!("a batch declaring i32::MAX records must be TooManyRecords: {other:?}"),
    }
}
