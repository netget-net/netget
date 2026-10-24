//! `netget::server::libp2p::{kad, ipns}` — the Kademlia DHT message as it arrives on
//! `/ipfs/kad/1.0.0`, and the IPNS record a PUT_VALUE carries, which the host verifies before
//! it keeps it.
//!
//! The input is a DHT message. What decodes must encode and decode again to the same message;
//! a record in it is verified under the message's key (at time zero, so a seed never expires),
//! and what verifies must say what its signed data says and stay inside `MAX_RECORD`. The same
//! bytes are also read as a record's CBOR `data` directly, because a signature over mutated
//! data never verifies and the reader behind it would otherwise go unexercised.
//!
//! The corpus carries records signed in `seed_corpus.py` (RFC 8032 Ed25519, so they verify),
//! with and without the V1 fields Kubo still writes, and a depth bomb: `data` nesting a
//! thousand CBOR maps, signed, so it gets past the signature and the reader must refuse the
//! nesting rather than follow it.

#![no_main]

use libfuzzer_sys::fuzz_target;
use netget::server::libp2p::{ipns, kad};

fuzz_target!(|data: &[u8]| {
    let _ = ipns::cbor_map(data);
    let Ok(m) = kad::decode(data) else {
        return;
    };
    let again = kad::decode(&kad::encode(&m)).expect("an encoded DHT message decodes");
    assert_eq!(again.kind, m.kind);
    assert_eq!(again.key, m.key);
    assert_eq!(again.record, m.record);
    assert_eq!(again.closer.len(), m.closer.len());
    assert_eq!(again.providers.len(), m.providers.len());
    if let Some((key, value)) = &m.record {
        if let Ok(rec) = ipns::verify(key, value, 0) {
            assert!(rec.bytes.len() <= ipns::MAX_RECORD);
            assert_eq!(&rec.bytes, value);
            assert_eq!(ipns::name_of_key(key).unwrap(), rec.name.as_slice());
            // The same record again is never refused by a store that holds it.
            let dht = ipns::Dht::default();
            if dht.put(key, value).is_ok() {
                assert!(dht.put(key, value).is_ok());
            }
        }
    }
});
