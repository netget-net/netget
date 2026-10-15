//! The wire code against vectors NetGet did not produce: RLP from the Ethereum wiki's examples,
//! the RLPx handshake from EIP-8, fork hashes from EIP-2124, block hashes from go-ethereum's
//! block tests. Then the bounds: nesting, item counts, frame and decompressed sizes, each
//! refused before the work it would cost.
use super::vectors::*;
use netget::server::devp2p::crypto::{self, NodeKey};
use netget::server::devp2p::eth::{self, HeaderRequest, Origin, Status};
use netget::server::devp2p::rlp::{self, Rlp, MAX_RLP_DEPTH, MAX_RLP_ITEMS};
use netget::server::devp2p::rlpx::{self, FrameError};
use netget::server::devp2p::session::{self, StatusDefaults, StatusSpec};
use serde_json::{json, Value};
use sha3::Digest;
use std::time::Duration;
use tokio::io::AsyncWriteExt;

fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap()
}

#[test]
fn rlp_matches_the_specification_examples() {
    let cases: Vec<(Rlp, &str)> = vec![
        (Rlp::string("dog"), "83646f67"),
        (
            Rlp::List(vec![Rlp::string("cat"), Rlp::string("dog")]),
            "c88363617483646f67",
        ),
        (Rlp::string(""), "80"),
        (Rlp::empty_list(), "c0"),
        (Rlp::uint(0), "80"),
        (Rlp::bytes(&[0]), "00"),
        (Rlp::uint(15), "0f"),
        (Rlp::uint(1024), "820400"),
        // The set-theoretic representation of three.
        (
            Rlp::List(vec![
                Rlp::empty_list(),
                Rlp::List(vec![Rlp::empty_list()]),
                Rlp::List(vec![Rlp::empty_list(), Rlp::List(vec![Rlp::empty_list()])]),
            ]),
            "c7c0c1c0c3c0c1c0",
        ),
        (
            Rlp::string("Lorem ipsum dolor sit amet, consectetur adipisicing elit"),
            "b8384c6f72656d20697073756d20646f6c6f722073697420616d65742c20636f6e7365637465747572206164697069736963696e6720656c6974",
        ),
    ];
    for (item, want) in cases {
        assert_eq!(hex::encode(item.encode()), want, "{item:?}");
        assert_eq!(rlp::decode(&unhex(want)).unwrap(), item, "{want}");
    }
    assert_eq!(
        rlp::decode(&unhex("820400")).unwrap().as_u64().unwrap(),
        1024
    );
}

#[test]
fn rlp_refuses_what_is_not_canonical_or_not_there() {
    for (bad, why) in [
        ("8105", "a single byte below 0x80 with a length prefix"),
        ("b80141", "the long form for one byte"),
        ("b9000141", "a length with a leading zero"),
        ("83646f", "a string longer than the input"),
        ("c3c0c0", "a list longer than the input"),
        ("83646f6700", "a trailing byte"),
        ("", "nothing"),
        ("bf0fffffffffffffff", "a length past the input by 2^60"),
    ] {
        assert!(rlp::decode(&unhex(bad)).is_err(), "accepted {why}: {bad}");
    }
    // An integer with a leading zero byte decodes as bytes but is refused as a number.
    assert!(rlp::decode(&unhex("820004")).unwrap().as_u64().is_err());
}

/// `depth` lists, each holding the next, around an empty list.
fn nested(depth: usize) -> Vec<u8> {
    let mut v = vec![0xc0];
    for _ in 0..depth {
        // Wrap the already-encoded inner bytes in a list header of the right length.
        let mut outer = Vec::new();
        let len = v.len();
        if len <= 55 {
            outer.push(0xc0 + len as u8);
        } else {
            let be = (len as u64).to_be_bytes();
            let start = be.iter().position(|b| *b != 0).unwrap();
            outer.push(0xf7 + (8 - start) as u8);
            outer.extend_from_slice(&be[start..]);
        }
        outer.extend_from_slice(&v);
        v = outer;
    }
    v
}

#[test]
fn rlp_nesting_is_bounded_before_it_can_exhaust_the_stack() {
    // MAX_RLP_DEPTH levels of lists is the deepest accepted…
    assert!(rlp::decode(&nested(MAX_RLP_DEPTH - 1)).is_ok());
    // …one more is refused…
    let e = rlp::decode(&nested(MAX_RLP_DEPTH + 1))
        .unwrap_err()
        .to_string();
    assert!(e.contains("deeper"), "{e}");
    // …and a hundred thousand levels (about 400 KB, which an unbounded recursive decoder
    // would turn into a stack overflow that kills the process) is refused the same way.
    let bomb = nested(100_000);
    assert!(bomb.len() < 1_000_000);
    assert!(rlp::decode(&bomb).is_err());
}

#[test]
fn rlp_item_count_is_bounded() {
    let many = Rlp::List(vec![Rlp::bytes(&[1]); MAX_RLP_ITEMS + 1]).encode();
    let e = rlp::decode(&many).unwrap_err().to_string();
    assert!(e.contains("items"), "{e}");
    let fine = Rlp::List(vec![Rlp::bytes(&[1]); 1000]).encode();
    assert!(rlp::decode(&fine).is_ok());
}

fn key(hex_key: &str) -> NodeKey {
    NodeKey::from_hex(hex_key).unwrap()
}

const KEY_A: &str = "49a7b37aa6f6645917e7b807e9d1c00d4fa71f18343b0d4122a4d2df64dd6fee";
const KEY_B: &str = "b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291";
const EPH_A: &str = "869d6ecf5211f1cc60418a13b9d870b22959d0c16f02bec714c960dd2298a32d";
const EPH_B: &str = "e238eb8e04fee6511ab04c6dd3c89ce097b11f25d584863ac2b6d5b35b1847e4";
const NONCE_A: &str = "7e968bba13b6c50e2c4cd7f241cc0d64d1ac25c7f5952df231ac6a2bda8ee5d6";
const NONCE_B: &str = "559aead08264d5795d3909718cdd05abd49572e84fe55590eef31a88a08fdffd";
const AUTH_SIGNATURE: &str = "299ca6acfd35e3d72d8ba3d1e2b60b5561d5af5218eb5bc182045769eb4226910a301acae3b369fffc4a4899d6b02531e89fd4fe36a2cf0d93607ba470b50f7800";

#[test]
fn eip8_auth_and_ack_messages_decode() {
    let b = key(KEY_B);
    let auth2 = rlpx::parse_auth(&rlpx::open_packet(&b, &unhex(AUTH2)).unwrap()).unwrap();
    assert_eq!(auth2.version, 4);
    assert_eq!(auth2.initiator_id, key(KEY_A).id());
    assert_eq!(hex::encode(auth2.nonce), NONCE_A);
    assert_eq!(hex::encode(auth2.signature), AUTH_SIGNATURE);
    // Auth₃: a newer version with extra list elements still decodes (EIP-8's point).
    let auth3 = rlpx::parse_auth(&rlpx::open_packet(&b, &unhex(AUTH3)).unwrap()).unwrap();
    assert_eq!(auth3.version, 56);
    assert_eq!(auth3.initiator_id, key(KEY_A).id());

    let ack2 = rlpx::parse_ack(&rlpx::open_packet(&key(KEY_A), &unhex(ACK2)).unwrap()).unwrap();
    assert_eq!(ack2.version, 4);
    assert_eq!(ack2.ephemeral_id, key(EPH_B).id());
    assert_eq!(hex::encode(ack2.nonce), NONCE_B);

    // The signature recovers the initiator's ephemeral key.
    let accepted = rlpx::accept_auth(&b, auth2).unwrap();
    assert_eq!(crypto::node_id(&accepted.remote_ephemeral), key(EPH_A).id());

    // A packet addressed to someone else does not open, and one flipped bit fails the tag.
    assert!(rlpx::open_packet(&key(KEY_A), &unhex(AUTH2)).is_err());
    let mut tampered = unhex(AUTH2);
    tampered[100] ^= 1;
    assert!(rlpx::open_packet(&b, &tampered).is_err());
    // The size prefix is authenticated data: changing it fails the tag too.
    let mut prefix = unhex(AUTH2);
    prefix[1] ^= 1;
    assert!(rlpx::open_packet(&b, &prefix).is_err());
}

#[test]
fn eip8_secrets_derive_to_the_listed_values() {
    let b = key(KEY_B);
    let auth = rlpx::parse_auth(&rlpx::open_packet(&b, &unhex(AUTH2)).unwrap()).unwrap();
    let accepted = rlpx::accept_auth(&b, auth).unwrap();
    let nonce_a: [u8; 32] = unhex(NONCE_A).try_into().unwrap();
    let nonce_b: [u8; 32] = unhex(NONCE_B).try_into().unwrap();
    let secrets = rlpx::derive_secrets(
        false,
        &key(EPH_B),
        &accepted.remote_ephemeral,
        &nonce_a,
        &nonce_b,
        &unhex(AUTH2),
        &unhex(ACK2),
        accepted.initiator,
    );
    assert_eq!(
        hex::encode(secrets.aes),
        "80e8632c05fed6fc2a13b0f8d31a3cf645366239170ea067065aba8e28bac487"
    );
    assert_eq!(
        hex::encode(secrets.mac),
        "2ea74ec5dae199227dff1af715362700e989d889d7a493cb0639691efb8e5f98"
    );
    let mut ingress = secrets.ingress_mac.clone();
    ingress.update(b"foo");
    assert_eq!(
        hex::encode(ingress.finalize()),
        "0c7ec6340062cc46f5e9f1e3cf86f8c8c403c5a0964f5df0ebd34a75ddc86db5"
    );
}

#[test]
fn ecies_round_trips_and_authenticates_its_shared_data() {
    let k = NodeKey::random();
    let c = crypto::ecies_encrypt(k.public(), b"hello devp2p", b"ab");
    assert_eq!(c.len(), b"hello devp2p".len() + crypto::ECIES_OVERHEAD);
    assert_eq!(
        crypto::ecies_decrypt(k.secret(), &c, b"ab").unwrap(),
        b"hello devp2p"
    );
    assert!(crypto::ecies_decrypt(k.secret(), &c, b"ac").is_err());
    let mut t = c.clone();
    let last = t.len() - 1;
    t[last] ^= 0x80;
    assert!(crypto::ecies_decrypt(k.secret(), &t, b"ab").is_err());
    assert!(crypto::ecies_decrypt(NodeKey::random().secret(), &c, b"ab").is_err());
}

#[test]
fn fork_hashes_match_eip_2124_mainnet() {
    let genesis: [u8; 32] =
        unhex("d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3")
            .try_into()
            .unwrap();
    let forks = [
        1150000u64, 1920000, 2463000, 2675000, 4370000, 7280000, 7280000, 9069000, 9200000,
        12244000, 12965000, 13773000, 15050000,
    ];
    let want = [
        (0usize, "fc64ec04"),
        (1, "97c2c34c"),
        (2, "91d1f948"),
        (3, "7a64da13"),
        (4, "3edd5b10"),
        (5, "a00bc324"),
        (7, "668db0af"),
        (8, "879d6e30"),
        (9, "e029e991"),
        (10, "0eb440f6"),
        (11, "b715077d"),
        (12, "20c327fc"),
        (13, "f0afd0e3"),
    ];
    for (passed, hash) in want {
        assert_eq!(
            hex::encode(eth::fork_hash(&genesis, &forks[..passed])),
            hash,
            "after {passed} forks"
        );
    }
}

fn block_header(block_hex: &str) -> Rlp {
    let block = rlp::decode(&unhex(block_hex)).unwrap();
    block.as_list().unwrap()[0].clone()
}

#[test]
fn block_hashes_match_go_ethereum_vectors() {
    for (block, want, number) in [
        (
            BLOCK_FRONTIER,
            "0x0a5843ac1cb04865017cb35a57b50b07084e5fcee39b5acadade33149f4fff9e",
            1,
        ),
        (
            BLOCK_1559,
            "0xc7252048cd273fe0dac09650027d07f0e3da4ee0675ebbb26627cea92729c372",
            1,
        ),
    ] {
        let header = block_header(block);
        assert_eq!(eth::hex0x(&eth::header_hash(&header)), want);
        assert_eq!(eth::header_number(&header).unwrap(), number);
        // Decoded to the model's JSON and back gives the same bytes and the same hash.
        let j = eth::header_to_json(&header).unwrap();
        assert_eq!(j["hash"], want);
        let again = eth::header_from_json(&j).unwrap();
        assert_eq!(again, header);
        // One field changed is a different block, and a stale `hash` claim is refused.
        let mut changed = j.clone();
        changed["gasUsed"] = json!(1);
        let e = eth::header_from_json(&changed).unwrap_err().to_string();
        assert!(e.contains("not the"), "{e}");
        changed.as_object_mut().unwrap().remove("hash");
        assert_ne!(
            eth::hex0x(&eth::header_hash(&eth::header_from_json(&changed).unwrap())),
            want
        );
    }
    // The Frontier block's one legacy transaction: its hash is keccak of its RLP list.
    let block = rlp::decode(&unhex(BLOCK_FRONTIER)).unwrap();
    let txs = block.as_list().unwrap()[1].as_list().unwrap().to_vec();
    let body = Rlp::List(vec![Rlp::List(txs.clone()), Rlp::empty_list()]);
    let j = eth::body_json(&body).unwrap();
    assert_eq!(
        j["transactions"][0]["hash"],
        eth::hex0x(&crypto::keccak256(&[&txs[0].encode()]))
    );
    let raw = eth::hex0x(&txs[0].encode());
    let (embedded, hash) = eth::transaction_from_hex(&json!(raw)).unwrap();
    assert_eq!(embedded, txs[0]);
    assert_eq!(
        eth::hex0x(&hash),
        j["transactions"][0]["hash"].as_str().unwrap()
    );
}

#[test]
fn header_json_is_strict() {
    let mut h = netget::server::devp2p::actions::example_header();
    assert!(eth::header_from_json(&h).is_ok());
    // A field the header does not have is refused rather than ignored: ignoring it would hash
    // a header that is not the one meant.
    h["prevRandao"] = json!("0x00");
    assert!(eth::header_from_json(&h).is_err());
    h.as_object_mut().unwrap().remove("prevRandao");
    // Optional fields are contiguous: excessBlobGas without blobGasUsed and withdrawalsRoot is
    // refused.
    h["excessBlobGas"] = json!(0);
    assert!(eth::header_from_json(&h).is_err());
    h["withdrawalsRoot"] = json!(format!("0x{}", "00".repeat(32)));
    h["blobGasUsed"] = json!(0);
    assert!(eth::header_from_json(&h).is_ok());
    // Required fields are required.
    h.as_object_mut().unwrap().remove("nonce");
    assert!(eth::header_from_json(&h).is_err());
}

/// A linked chain of `n` headers from block 0, as the model would write them.
pub fn chain(n: u64) -> Vec<Value> {
    let mut out: Vec<Value> = Vec::new();
    let mut parent = [0u8; 32];
    for i in 0..n {
        let mut h = netget::server::devp2p::actions::example_header();
        h["number"] = json!(i);
        h["parentHash"] = json!(eth::hex0x(&parent));
        parent = eth::header_hash(&eth::header_from_json(&h).unwrap());
        h["hash"] = json!(eth::hex0x(&parent));
        out.push(h);
    }
    out
}

#[test]
fn answers_must_be_the_headers_asked_for() {
    let c = chain(5);
    let rlp_of = |v: &[Value]| -> Vec<Rlp> {
        v.iter()
            .map(|h| eth::header_from_json(h).unwrap())
            .collect()
    };
    let req = |origin, amount, skip, reverse| HeaderRequest {
        origin,
        amount,
        skip,
        reverse,
    };
    // In order, from the origin.
    session::validate_answer(&req(Origin::Number(1), 3, 0, false), &rlp_of(&c[1..4])).unwrap();
    // Fewer than asked is an allowed answer, and so is none.
    session::validate_answer(&req(Origin::Number(1), 3, 0, false), &rlp_of(&c[1..2])).unwrap();
    session::validate_answer(&req(Origin::Number(1), 3, 0, false), &[]).unwrap();
    // Reverse, by hash.
    let h3: [u8; 32] = eth::parse_fixed(&c[3]["hash"], "hash").unwrap();
    let rev: Vec<Value> = c[1..4].iter().rev().cloned().collect();
    session::validate_answer(&req(Origin::Hash(h3), 3, 0, true), &rlp_of(&rev)).unwrap();
    // With a skip, the numbers step.
    let skipped = vec![c[0].clone(), c[2].clone(), c[4].clone()];
    session::validate_answer(&req(Origin::Number(0), 3, 1, false), &rlp_of(&skipped)).unwrap();

    // Refused: the wrong first block, more than asked, a gap, a first hash that is not the
    // requested one, and a header whose parent is not the previous header.
    for (r, headers, why) in [
        (
            req(Origin::Number(0), 3, 0, false),
            rlp_of(&c[1..4]),
            "the wrong first block",
        ),
        (
            req(Origin::Number(1), 2, 0, false),
            rlp_of(&c[1..4]),
            "too many",
        ),
        (
            req(Origin::Number(0), 3, 0, false),
            rlp_of(&[c[0].clone(), c[2].clone()]),
            "a gap",
        ),
        (
            req(Origin::Hash([7; 32]), 1, 0, false),
            rlp_of(&c[0..1]),
            "the wrong first hash",
        ),
    ] {
        assert!(
            session::validate_answer(&r, &headers).is_err(),
            "accepted {why}"
        );
    }
    let mut forged = c[2].clone();
    forged["parentHash"] = json!(format!("0x{}", "99".repeat(32)));
    forged.as_object_mut().unwrap().remove("hash");
    let headers = rlp_of(&[c[1].clone(), forged]);
    let e = session::validate_answer(&req(Origin::Number(1), 2, 0, false), &headers)
        .unwrap_err()
        .to_string();
    assert!(e.contains("chain"), "{e}");
}

fn status(version: u64) -> Status {
    Status {
        version,
        network_id: 1337,
        genesis: [1; 32],
        fork_hash: [2, 3, 4, 5],
        fork_next: 0,
        total_difficulty: if version >= 69 { vec![] } else { vec![1, 0] },
        head: if version >= 69 { [0; 32] } else { [6; 32] },
        earliest_block: 0,
        latest_block: if version >= 69 { 9 } else { 0 },
        latest_block_hash: if version >= 69 { [7; 32] } else { [0; 32] },
    }
}

#[test]
fn status_round_trips_at_both_versions() {
    for v in [68, 69] {
        let s = status(v);
        assert_eq!(Status::decode(&s.encode(), v).unwrap(), s);
        // A Status naming another version than the session negotiated is refused.
        assert!(Status::decode(&s.encode(), if v == 68 { 69 } else { 68 }).is_err());
    }
}

#[test]
fn a_status_is_built_from_the_action_the_peer_and_the_configuration() {
    let peer = status(69);
    let mirror = StatusSpec {
        mirror_peer: true,
        ..Default::default()
    };
    let s = session::build_status(&mirror, 69, Some(&peer), &StatusDefaults::default()).unwrap();
    assert_eq!(s, peer);
    // Nothing to go on is a refusal naming the field.
    let e = session::build_status(&StatusSpec::default(), 69, None, &StatusDefaults::default())
        .unwrap_err()
        .to_string();
    assert!(e.contains("network_id"), "{e}");
    // From configuration: the fork hash is computed, the latest hash defaults to genesis.
    let defaults = StatusDefaults {
        network_id: Some(5),
        genesis: Some([9; 32]),
        forks: vec![10, 20],
        ..Default::default()
    };
    let s = session::build_status(&StatusSpec::default(), 69, None, &defaults).unwrap();
    assert_eq!(s.network_id, 5);
    assert_eq!(s.fork_hash, eth::fork_hash(&[9; 32], &[10, 20]));
    assert_eq!(s.latest_block_hash, [9; 32]);
    // An explicit field beats the mirror.
    let mut fields = serde_json::Map::new();
    fields.insert("network_id".into(), json!(42));
    let spec = StatusSpec {
        fields,
        mirror_peer: true,
    };
    let s = session::build_status(&spec, 69, Some(&peer), &defaults).unwrap();
    assert_eq!((s.network_id, s.genesis), (42, peer.genesis));
}

#[test]
fn hello_round_trips_and_is_bounded() {
    let id = NodeKey::random().id();
    let h = eth::Hello::ours("NetGet/test", 30303, id);
    let back = eth::Hello::decode(&h.encode()).unwrap();
    assert_eq!(back, h);
    assert_eq!(back.shared_eth(), Some(69));
    // A client id is reduced to a printable token.
    let mut odd = h.clone();
    odd.client_id = "Geth/\u{1b}[31mred\nline".into();
    let back = eth::Hello::decode(&odd.encode()).unwrap();
    assert!(
        !back.client_id.chars().any(char::is_control),
        "{:?}",
        back.client_id
    );
    // Too many capabilities is refused.
    let mut many = h.clone();
    many.caps = (0..(eth::MAX_CAPS as u64 + 1))
        .map(|v| ("x".to_string(), v))
        .collect();
    assert!(eth::Hello::decode(&many.encode()).is_err());
    // No eth in common is no session.
    let mut snap_only = h;
    snap_only.caps = vec![("snap".into(), 1), ("eth".into(), 66)];
    assert_eq!(snap_only.shared_eth(), None);
}

#[test]
fn enode_urls_parse() {
    let k = NodeKey::random();
    let url = eth::format_enode(&k.id(), "127.0.0.1:30303".parse().unwrap());
    let (id, addr) = eth::parse_enode(&format!("{url}?discport=0")).unwrap();
    assert_eq!((id, addr.as_str()), (k.id(), "127.0.0.1:30303"));
    assert!(eth::parse_enode("127.0.0.1:30303").is_err());
    assert!(eth::parse_enode(&format!("enode://{}@127.0.0.1:1", "00".repeat(64))).is_err());
}

/// Two ends of an in-memory RLPx session.
async fn pair() -> (
    (rlpx::FrameReader, rlpx::FrameWriter),
    (rlpx::FrameReader, rlpx::FrameWriter),
    tokio::io::DuplexStream,
    tokio::io::DuplexStream,
) {
    let (a, b) = tokio::io::duplex(1 << 20);
    let (ka, kb) = (NodeKey::random(), NodeKey::random());
    let kb_pub = *kb.public();
    let (mut ar, mut aw) = tokio::io::split(a);
    let (mut br, mut bw) = tokio::io::split(b);
    let (sa, sb) = tokio::join!(
        rlpx::initiate(&mut ar, &mut aw, &ka, &kb_pub),
        rlpx::respond(&mut br, &mut bw, &kb)
    );
    let (sa, sb) = (sa.unwrap(), sb.unwrap());
    assert_eq!(crypto::node_id(&sb.remote), ka.id());
    let a = ar.unsplit(aw);
    let b = br.unsplit(bw);
    (
        rlpx::codec(sa, session::MAX_MESSAGE_BYTES),
        rlpx::codec(sb, 64 * 1024),
        a,
        b,
    )
}

#[tokio::test]
async fn frames_round_trip_and_every_mac_is_checked() {
    let ((_ra, mut wa), (mut rb, _wb), mut a, mut b) = pair().await;
    for (code, payload, snappy) in [
        (0x00u64, b"hello".to_vec(), false),
        (0x13, vec![7u8; 5000], true),
        (0x10, Vec::new(), true),
    ] {
        wa.set_snappy(snappy);
        rb.set_snappy(snappy);
        let frame = wa.encode(code, &payload).unwrap();
        a.write_all(&frame).await.unwrap();
        assert_eq!(rb.read(&mut b).await.unwrap(), (code, payload));
    }
    // One flipped bit in the body fails the frame MAC.
    let mut frame = wa.encode(0x14, b"tamper me").unwrap();
    frame[40] ^= 1;
    a.write_all(&frame).await.unwrap();
    match rb.read(&mut b).await {
        Err(FrameError::Protocol(m)) => assert!(m.contains("MAC"), "{m}"),
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn a_frame_header_mac_is_checked_first() {
    let ((_ra, mut wa), (mut rb, _wb), mut a, mut b) = pair().await;
    let mut frame = wa.encode(0x14, b"x").unwrap();
    frame[2] ^= 1;
    a.write_all(&frame).await.unwrap();
    match rb.read(&mut b).await {
        Err(FrameError::Protocol(m)) => assert!(m.contains("header MAC"), "{m}"),
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn an_oversized_frame_is_refused_before_its_body_is_read() {
    // The reader's bound is 64 KiB; a 200 KiB message's header alone is sent, and the refusal
    // must come without waiting for a body that never arrives.
    let ((_ra, mut wa), (mut rb, _wb), mut a, mut b) = pair().await;
    let frame = wa.encode(0x14, &vec![1u8; 200 * 1024]).unwrap();
    a.write_all(&frame[..32]).await.unwrap();
    let r = tokio::time::timeout(Duration::from_secs(5), rb.read(&mut b))
        .await
        .expect("the reader waited for the body of a frame it should have refused");
    assert!(matches!(r, Err(FrameError::TooLarge { .. })), "{r:?}");
}

#[tokio::test]
async fn a_snappy_bomb_is_refused_before_it_is_decompressed() {
    // A Snappy block declaring 100 MB after decompression, in a frame of a few bytes.
    let ((_ra, mut wa), (mut rb, _wb), mut a, mut b) = pair().await;
    let mut declared = Vec::new();
    let mut n: u64 = 100 * 1024 * 1024;
    while n >= 0x80 {
        declared.push((n as u8) | 0x80);
        n >>= 7;
    }
    declared.push(n as u8);
    declared.extend_from_slice(&[0u8; 8]);
    // Written uncompressed so the bytes arrive exactly as crafted; read as Snappy.
    wa.set_snappy(false);
    rb.set_snappy(true);
    a.write_all(&wa.encode(0x10, &declared).unwrap())
        .await
        .unwrap();
    let r = rb.read(&mut b).await;
    assert!(
        matches!(r, Err(FrameError::TooLarge { declared, .. }) if declared == 100 * 1024 * 1024),
        "{r:?}"
    );
}
