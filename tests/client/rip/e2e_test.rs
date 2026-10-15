//! RIP wire-format tests for the client's own codec.
//!
//! These are codec round-trips, not end-to-end evidence: `RipMessage` encodes and `RipMessage`
//! decodes, so they assert only that one implementation agrees with itself. They are still
//! worth having — they pin the byte layout of RFC 2453 §4 against hand-written literals — but
//! the protocol path is exercised by `llm_path_test.rs`, which drives the real client against
//! a stub router and a mocked model.

mod rip_client_codec_tests {
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn test_rip_packet_encoding() {
        // Test RIP request packet construction
        use netget::client::rip::{RipCommand, RipMessage, RipVersion};

        let request = RipMessage::request(RipVersion::V2);
        assert_eq!(request.command, RipCommand::Request);
        assert_eq!(request.version, RipVersion::V2);
        assert_eq!(request.routes.len(), 1);

        // Encode and verify structure
        let bytes = request.encode();
        assert_eq!(bytes[0], 1); // Command = Request
        assert_eq!(bytes[1], 2); // Version = 2
        assert_eq!(bytes[2], 0); // Must be zero
        assert_eq!(bytes[3], 0); // Must be zero
        assert_eq!(bytes.len(), 24); // 4 byte header + 20 byte route entry
    }

    #[tokio::test]
    async fn test_rip_packet_decoding() {
        // Test RIP response parsing
        use netget::client::rip::RipMessage;

        // Build mock RIP response (header + 1 route)
        let mut response = Vec::new();
        response.push(2); // Command = Response
        response.push(2); // Version = 2
        response.extend_from_slice(&[0, 0]); // Must be zero

        // Route: 10.0.0.0/8 via 192.168.1.254 metric 3
        response.extend_from_slice(&[0, 2]); // Address family
        response.extend_from_slice(&[0, 0]); // Route tag
        response.extend_from_slice(&Ipv4Addr::new(10, 0, 0, 0).octets());
        response.extend_from_slice(&Ipv4Addr::new(255, 0, 0, 0).octets());
        response.extend_from_slice(&Ipv4Addr::new(192, 168, 1, 254).octets());
        response.extend_from_slice(&3u32.to_be_bytes());

        // Decode
        let msg = RipMessage::decode(&response).expect("Failed to decode RIP message");

        assert_eq!(msg.routes.len(), 1);
        assert_eq!(msg.routes[0].ip_address, Ipv4Addr::new(10, 0, 0, 0));
        assert_eq!(msg.routes[0].subnet_mask, Ipv4Addr::new(255, 0, 0, 0));
        assert_eq!(msg.routes[0].next_hop, Ipv4Addr::new(192, 168, 1, 254));
        assert_eq!(msg.routes[0].metric, 3);
    }
}
