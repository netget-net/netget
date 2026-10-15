//! NetGet's wtransport and wtransport-proto forks (`netget-wtransport`, `netget-wtransport-proto`,
//! github.com/netget-net/wtransport) are what Cargo builds, and they still carry NetGet's
//! patches (the fork's NETGET.md).
#[path = "helpers/fork_source.rs"]
mod fork_source;

use fork_source::{assert_fork_is_built, read_fork};

fn read(rel: &str) -> String {
    let (crate_dir, path) = rel.split_once('/').expect("crate/path");
    read_fork(&format!("netget-{crate_dir}"), path)
}

#[test]
fn cargo_builds_the_forks_at_the_patched_version() {
    for name in ["wtransport", "wtransport-proto"] {
        assert_fork_is_built(name, "0.7.2");
    }
}

#[test]
fn the_patches_are_still_in_the_source() {
    let driver = read("wtransport/src/driver/mod.rs");
    for marker in [
        "impl Drop for Driver",
        "worker: tokio::task::JoinHandle<()>",
        "readers: tokio::task::JoinSet<Result<(), DriverError>>",
        "if self.readers.len() < 16",
        "value(SettingId::H3Datagram) != 1",
    ] {
        assert!(driver.contains(marker), "driver patch lost: {marker}");
    }
    assert!(
        !driver.contains("TODO(biagio): validate settings"),
        "the driver's settings check is gone"
    );
    let endpoint = read("wtransport/src/endpoint.rs");
    assert!(
        endpoint.contains("SettingId::EnableConnectProtocol"),
        "clients must wait for the server's ENABLE_CONNECT_PROTOCOL"
    );
    let qpack = read("wtransport-proto/src/qpack.rs");
    for marker in [
        "MAX_FIELDS: usize = 64",
        "MAX_FIELD_SECTION: usize = 16 * 1024",
        "DuplicateField",
    ] {
        assert!(qpack.contains(marker), "QPACK patch lost: {marker}");
    }
    assert!(read("wtransport-proto/src/settings.rs").contains("seen_ids"));
}

mod decoding {
    use wtransport_proto::error::ErrorCode;
    use wtransport_proto::frame::Frame;
    use wtransport_proto::qpack::{Decoder, DecodingError, Encoder};
    use wtransport_proto::settings::Settings;

    fn decode(fields: &[(&str, &str)]) -> String {
        match Decoder::decode(Encoder::encode(fields.iter().copied())) {
            Ok(h) => format!("{} fields", h.len()),
            Err(e) => format!("{e:?}"),
        }
    }
    fn err(e: DecodingError) -> String {
        format!("{e:?}")
    }

    #[test]
    fn field_sections_are_bounded_and_well_formed() {
        assert_eq!(
            decode(&[(":method", "CONNECT"), ("origin", "https://a.example")]),
            "2 fields"
        );
        let names: Vec<String> = (0..65).map(|i| format!("x-{i}")).collect();
        let many: Vec<(&str, &str)> = names.iter().map(|n| (n.as_str(), "v")).collect();
        assert_eq!(decode(&many), err(DecodingError::FieldSectionTooLarge));
        assert_eq!(decode(&many[..64]), "64 fields");
        let big = "v".repeat(16 * 1024);
        assert_eq!(
            decode(&[("x-big", &big)]),
            err(DecodingError::FieldSectionTooLarge)
        );
        assert_eq!(
            decode(&[("x-a", "1"), ("x-a", "2")]),
            err(DecodingError::DuplicateField)
        );
        assert_eq!(
            decode(&[("X-Upper", "1")]),
            err(DecodingError::InvalidField)
        );
        assert_eq!(
            decode(&[("x-a", "line\nbreak")]),
            err(DecodingError::InvalidField)
        );
        assert_eq!(
            decode(&[("x-a", "1"), (":path", "/")]),
            err(DecodingError::InvalidField)
        );
        // Required Insert Count 1: a reference into a dynamic table nobody advertised.
        assert!(matches!(
            Decoder::decode([0x01u8, 0x00]),
            Err(DecodingError::DynamicNotSupported)
        ));
    }

    #[test]
    fn a_repeated_setting_is_a_settings_error() {
        let ok = Settings::builder()
            .enable_webtransport()
            .enable_h3_datagrams()
            .build();
        let frame = ok.generate_frame();
        assert!(Settings::with_frame(&frame).is_ok());
        // SETTINGS_ENABLE_CONNECT_PROTOCOL (0x08) = 1, twice.
        let twice = Frame::new_settings(vec![0x08, 0x01, 0x08, 0x01].into());
        assert!(Settings::with_frame(&twice).err() == Some(ErrorCode::Settings));
    }
}
