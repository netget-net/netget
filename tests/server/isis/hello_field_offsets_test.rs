//! The LAN Hello field layout, against ISO/IEC 10589 rather than against itself.
//!
//! `build_isis_hello` wrote the PDU-length field at offset **15**, which is the *holding
//! time*. Counting the fields the function actually pushes gives the spec layout:
//!
//! ```text
//!   0..8   common header
//!   8      circuit type
//!   9..15  source ID (6)
//!   15..17 holding time (2)
//!   17..19 PDU length (2)
//!   19     priority        (LAN only)
//!   20..27 LAN ID (7)      (LAN only)
//! ```
//!
//! So every Hello this server emitted carried the PDU length *in place of* the holding time,
//! and left the real length field as zeros. A receiver reads holding time as the adjacency
//! hold timer, so it got whatever the packet happened to be long — and read the length as 0.
//!
//! Nothing caught it because no test asserted a field offset: the e2e suite drives the server
//! and checks it emits *something*, and the codec that would disagree is the same code.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features isis --test server -- isis::hello_field

#![cfg(all(unix, feature = "libpcap"))]

use netget::server::isis::actions::IsisProtocol;

const LAN_LEVEL2_HELLO: u8 = 16;
const HOLDING_TIME: u16 = 27;

#[test]
fn lan_hello_puts_holding_time_and_pdu_length_where_the_spec_says() {
    let packet =
        IsisProtocol::build_isis_hello(LAN_LEVEL2_HELLO, "1921.6800.1001", "49.0001", HOLDING_TIME)
            .expect("build a LAN Level-2 Hello");

    assert_eq!(
        packet[0], 0x83,
        "intradomain routing protocol discriminator"
    );
    assert_eq!(packet[4], LAN_LEVEL2_HELLO, "PDU type");

    // 15..17 is the holding time, and it must still be the value asked for — this is the
    // byte pair the PDU length used to overwrite.
    assert_eq!(
        u16::from_be_bytes([packet[15], packet[16]]),
        HOLDING_TIME,
        "holding time was clobbered; the PDU length is being written over it"
    );

    // 17..19 is the PDU length, and it must be the real length rather than the zeros the
    // builder pushes as a placeholder.
    assert_eq!(
        u16::from_be_bytes([packet[17], packet[18]]) as usize,
        packet.len(),
        "PDU length field must carry the packet's actual length"
    );
    assert_ne!(
        u16::from_be_bytes([packet[17], packet[18]]),
        0,
        "PDU length is still the placeholder, so it was written somewhere else"
    );
}
