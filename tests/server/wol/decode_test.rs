//! The magic packet decoder, against literal bytes.
//!
//! Wake-on-LAN's payload is small enough to validate exhaustively, and the decoder is the only
//! thing this protocol really does — there is no response to check, so the decode direction is
//! the whole of the protocol's correctness. These cases are built from the Magic Packet
//! specification (6 bytes of `0xFF`, then the target MAC repeated exactly 16 times, optionally
//! followed by a 4- or 6-byte SecureON password), **not** from a third-party sender: no
//! `wakeonlan` or `etherwake` binary is installed here and no WoL crate is a dependency, so
//! every packet below is this repository reading the specification for itself. That is why the
//! protocol is rated `Experimental` and not `Beta` — see `src/server/wol/CLAUDE.md`.
//!
//! These are pure function calls: no socket, no process, no LLM. The e2e suite next door
//! covers what the *server* does with the result.

use netget::server::wol::{
    decode_magic_packet, MagicPacket, Transport, MAC_LEN, MAC_REPETITIONS, MAGIC_PACKET_LEN,
    SYNC_STREAM_LEN,
};

const LAB_NAS: [u8; MAC_LEN] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];

/// A well-formed magic packet: 6x0xFF then `mac` sixteen times.
fn magic_packet(mac: [u8; MAC_LEN]) -> Vec<u8> {
    let mut out = vec![0xFFu8; SYNC_STREAM_LEN];
    for _ in 0..MAC_REPETITIONS {
        out.extend_from_slice(&mac);
    }
    out
}

/// The same thing with a caller-chosen sync stream and repetition count, for the near-misses.
fn packet_with(sync: [u8; SYNC_STREAM_LEN], mac: [u8; MAC_LEN], repetitions: usize) -> Vec<u8> {
    let mut out = sync.to_vec();
    for _ in 0..repetitions {
        out.extend_from_slice(&mac);
    }
    out
}

fn decoded(data: &[u8]) -> MagicPacket {
    decode_magic_packet(data).expect("expected this datagram to decode as a magic packet")
}

#[test]
fn a_bare_magic_packet_decodes_to_the_right_mac() {
    let data = magic_packet(LAB_NAS);
    assert_eq!(data.len(), MAGIC_PACKET_LEN, "the payload is 102 bytes");

    let packet = decoded(&data);
    assert_eq!(packet.target_mac, LAB_NAS);
    assert_eq!(packet.mac_string(), "00:11:22:33:44:55");
    assert_eq!(packet.sync_offset, 0);
    assert_eq!(packet.password_len, 0);
    assert!(!packet.has_password());
    assert_eq!(packet.transport, Transport::Udp);
}

#[test]
fn the_payload_is_found_at_a_non_zero_offset() {
    // This is the decoding subtlety: senders wrap the payload, so a decoder that assumes
    // offset 0 silently drops real wake requests.
    for prefix_len in [1usize, 7, 20, 137] {
        let mut data = vec![0x5Au8; prefix_len];
        data.extend_from_slice(&magic_packet(LAB_NAS));

        let packet = decoded(&data);
        assert_eq!(
            packet.sync_offset, prefix_len,
            "the sync stream sits at offset {prefix_len}"
        );
        assert_eq!(packet.target_mac, LAB_NAS);
        assert_eq!(packet.transport, Transport::Udp);
    }
}

#[test]
fn a_false_sync_stream_before_the_real_packet_does_not_stop_the_scan() {
    // Six 0xFF bytes that are not followed by sixteen repetitions. A decoder that gives up on
    // the first candidate would miss the packet that follows.
    let mut data = vec![0xFFu8; SYNC_STREAM_LEN];
    data.extend_from_slice(&[0x01, 0x02, 0x03]);
    let false_sync_len = data.len();
    data.extend_from_slice(&magic_packet(LAB_NAS));

    let packet = decoded(&data);
    assert_eq!(packet.sync_offset, false_sync_len);
    assert_eq!(packet.target_mac, LAB_NAS);
}

#[test]
fn a_four_byte_secure_on_password_is_reported() {
    let mut data = magic_packet(LAB_NAS);
    data.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);

    let packet = decoded(&data);
    assert!(packet.has_password());
    assert_eq!(packet.password_len, 4);
    assert_eq!(packet.target_mac, LAB_NAS);
}

#[test]
fn a_six_byte_secure_on_password_is_reported() {
    let mut data = magic_packet(LAB_NAS);
    data.extend_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);

    let packet = decoded(&data);
    assert!(packet.has_password());
    assert_eq!(packet.password_len, 6);
}

#[test]
fn a_trailer_that_is_neither_four_nor_six_bytes_is_not_a_password() {
    // SecureON defines exactly two lengths. Anything else is padding or wrapping, and
    // claiming a password we are not sure about would be worse than reporting none.
    for trailer_len in [1usize, 2, 3, 5, 7, 8, 32] {
        let mut data = magic_packet(LAB_NAS);
        data.resize(data.len() + trailer_len, 0xAA);

        let packet = decoded(&data);
        assert!(
            !packet.has_password(),
            "a {trailer_len}-byte trailer is not a SecureON password"
        );
        assert_eq!(packet.password_len, 0);
    }
}

#[test]
fn fifteen_repetitions_is_not_a_magic_packet() {
    // The classic off-by-one, and the one near-miss a length check alone would accept: it is
    // 96 bytes of a plausible-looking pattern. A NIC's pattern matcher requires all sixteen.
    let data = packet_with([0xFF; SYNC_STREAM_LEN], LAB_NAS, 15);
    assert!(data.len() < MAGIC_PACKET_LEN);
    assert!(decode_magic_packet(&data).is_none());

    // Even padded out to the full length, so the size is right and only the repetition count
    // is wrong.
    let mut padded = data.clone();
    padded.extend_from_slice(&[0x00; MAC_LEN]);
    assert_eq!(padded.len(), MAGIC_PACKET_LEN);
    assert!(
        decode_magic_packet(&padded).is_none(),
        "15 repetitions plus padding must not be accepted"
    );
}

#[test]
fn a_wrong_sync_stream_is_not_a_magic_packet() {
    for sync in [
        [0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE],
        [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE],
        [0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
        [0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    ] {
        let data = packet_with(sync, LAB_NAS, MAC_REPETITIONS);
        assert_eq!(data.len(), MAGIC_PACKET_LEN);
        assert!(
            decode_magic_packet(&data).is_none(),
            "sync stream {sync:02X?} is not six 0xFF bytes"
        );
    }
}

#[test]
fn one_wrong_byte_in_one_repetition_rejects_the_packet() {
    for repetition in [1usize, 8, 15] {
        let mut data = magic_packet(LAB_NAS);
        let corrupt_at = SYNC_STREAM_LEN + repetition * MAC_LEN + 3;
        data[corrupt_at] ^= 0xFF;
        assert!(
            decode_magic_packet(&data).is_none(),
            "repetition {repetition} differs from the target MAC"
        );
    }
}

#[test]
fn a_datagram_shorter_than_the_payload_is_rejected() {
    for len in [0usize, 1, 6, 101] {
        let data = vec![0xFFu8; len];
        assert!(decode_magic_packet(&data).is_none());
    }
}

#[test]
fn an_encapsulated_ethernet_frame_is_reported_as_ethernet_transport() {
    // A complete Ethernet header — broadcast destination, some source, EtherType 0x0842 —
    // followed by the magic packet as the frame's payload.
    let mut data = vec![0xFFu8; 6]; // destination: broadcast
    data.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]); // source
    data.extend_from_slice(&[0x08, 0x42]); // EtherType: Wake-on-LAN
    data.extend_from_slice(&magic_packet(LAB_NAS));

    let packet = decoded(&data);
    assert_eq!(
        packet.sync_offset, 14,
        "the payload begins after the 14-byte Ethernet header"
    );
    assert_eq!(packet.transport, Transport::EncapsulatedEthernet);
    assert_eq!(packet.transport.as_str(), "ethernet");
    assert_eq!(packet.target_mac, LAB_NAS);
    assert_eq!(packet.password_len, 0);
}

#[test]
fn an_0842_that_is_not_preceded_by_a_full_header_stays_udp() {
    // The EtherType check is structural, not a two-byte guess: without 12 bytes of addresses
    // in front of it, `08 42` is just data.
    let mut data = vec![0x08, 0x42];
    data.extend_from_slice(&magic_packet(LAB_NAS));

    let packet = decoded(&data);
    assert_eq!(packet.sync_offset, 2);
    assert_eq!(
        packet.transport,
        Transport::Udp,
        "two bytes of 0x0842 with no Ethernet header in front is not an encapsulated frame"
    );
}

#[test]
fn the_broadcast_mac_decodes_rather_than_confusing_the_scan() {
    // Degenerate but legal: every byte is 0xFF, so the sync stream and the MAC are
    // indistinguishable. The scan must still terminate with the right answer.
    let broadcast = [0xFFu8; MAC_LEN];
    let data = magic_packet(broadcast);

    let packet = decoded(&data);
    assert_eq!(packet.target_mac, broadcast);
    assert_eq!(packet.mac_string(), "FF:FF:FF:FF:FF:FF");
    assert_eq!(packet.sync_offset, 0);
}

#[test]
fn the_mac_reaches_the_model_as_a_formatted_string_never_as_bytes() {
    // The action & event design rules forbid raw bytes in event data; this is the one field
    // that could have carried them.
    let packet = decoded(&magic_packet([0x0A, 0xB1, 0xC2, 0xD3, 0xE4, 0xF5]));
    assert_eq!(packet.mac_string(), "0A:B1:C2:D3:E4:F5");
    assert_eq!(packet.mac_string().len(), 17);
}
