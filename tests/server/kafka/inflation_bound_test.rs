//! A Produce request's compressed record batches inflate only as far as
//! `MAX_INFLATED_PRODUCE_BYTES`, not as far as the compressed stream says.
//!
//! `kafka-protocol`'s gzip, zstd and lz4 decompressors copy the whole inflated stream into a
//! buffer before a single record is decoded, so a gzip batch of 64 MiB of zeros — about 64 KiB
//! on the wire — cost 64 MiB in the broker, and one request at the 100 MiB request cap could
//! ask for ~100 GiB. The broker decodes through `decode_record_batches`, which inflates through
//! a reader bounded by the request's remaining budget. These drive that function directly with
//! batches `kafka-protocol`'s own encoder produced; `fuzz/fuzz_targets/kafka_request.rs` carries
//! the same bomb in its corpus.

use bytes::Bytes;
use netget::server::kafka::kafka_protocol::records::{
    Compression, Record, RecordBatchEncoder, RecordEncodeOptions, TimestampType,
};
use netget::server::kafka::{decode_record_batches, BatchError, MAX_INFLATED_PRODUCE_BYTES};

type Compressor = fn(&mut bytes::BytesMut, &mut Vec<u8>, Compression) -> anyhow::Result<()>;

fn batch(value_len: usize, compression: Compression) -> Vec<u8> {
    let records = vec![Record {
        transactional: false,
        control: false,
        partition_leader_epoch: 0,
        producer_id: -1,
        producer_epoch: -1,
        timestamp_type: TimestampType::Creation,
        offset: 0,
        sequence: 0,
        timestamp: 1_700_000_000_000,
        key: None,
        value: Some(Bytes::from(vec![0u8; value_len])),
        headers: Default::default(),
    }];
    let mut buf = Vec::new();
    RecordBatchEncoder::encode_with_custom_compression::<_, _, Compressor>(
        &mut buf,
        &records,
        &RecordEncodeOptions {
            version: 2,
            compression,
        },
        None,
    )
    .expect("test record batch must encode");
    buf
}

#[test]
fn a_compressed_batch_inflating_past_the_budget_is_refused_for_every_codec() {
    for compression in [
        Compression::Gzip,
        Compression::Zstd,
        Compression::Lz4,
        Compression::Snappy,
    ] {
        let bomb = batch(MAX_INFLATED_PRODUCE_BYTES * 4, compression);
        assert!(
            bomb.len() < MAX_INFLATED_PRODUCE_BYTES / 4,
            "{compression:?}: the fixture is meant to be small on the wire, got {} bytes",
            bomb.len()
        );
        let mut budget = MAX_INFLATED_PRODUCE_BYTES;
        match decode_record_batches(&bomb, &mut budget) {
            Err(BatchError::TooLarge) => {}
            Err(BatchError::Corrupt(e)) => {
                panic!("{compression:?}: refused, but as corrupt rather than too large: {e:#}")
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
    let mut budget = MAX_INFLATED_PRODUCE_BYTES;

    let first = decode_record_batches(&one, &mut budget).expect("the first batch fits");
    assert_eq!(first[0].value.as_ref().map(|v| v.len()), Some(third));
    assert!(budget < MAX_INFLATED_PRODUCE_BYTES - third);
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
    let mut budget = MAX_INFLATED_PRODUCE_BYTES;
    let records = decode_record_batches(&plain, &mut budget).expect("plain batch decodes");
    assert_eq!(records.len(), 1);
    assert_eq!(budget, MAX_INFLATED_PRODUCE_BYTES);
}
