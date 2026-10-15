//! The BLE Proximity / Find Me profile's GATT layout, against the SIG specifications.
//!
//! Pure unit tests: no adapter, no radio, no `#[ignore]`.
//!
//! Unlike its four HID siblings this profile carries no report descriptor — Immediate Alert,
//! Link Loss and Tx Power are three services of one characteristic each. What can still go
//! wrong is the layout itself: the wrong characteristic under a service, a readable Immediate
//! Alert (the spec forbids it), or an Alert Level outside the three values defined for it.
//! Nothing inside NetGet checks any of that, because the base stack builds whatever service
//! the model describes.

#![cfg(all(unix, feature = "bluetooth"))]

use netget::llm::actions::protocol_trait::Protocol;
use netget::server::bluetooth_ble_proximity::actions::BluetoothBleProximityProtocol;
use serde_json::Value;

fn sig_uuid(alias: &str) -> String {
    format!("0000{}-0000-1000-8000-00805f9b34fb", alias)
}

/// Every `add_service` action in the `static_mode` example, keyed by its service UUID.
fn services(static_mode: &Value) -> Vec<&Value> {
    static_mode["event_handlers"]
        .as_array()
        .expect("static_mode has no event_handlers")
        .iter()
        .filter_map(|h| h["handler"]["actions"].as_array())
        .flatten()
        .filter(|a| a["type"] == "add_service")
        .collect()
}

fn service<'a>(static_mode: &'a Value, alias: &str) -> &'a Value {
    let want = sig_uuid(alias);
    services(static_mode)
        .into_iter()
        .find(|s| s["uuid"].as_str() == Some(want.as_str()))
        .unwrap_or_else(|| panic!("no add_service for {want} in the static_mode example"))
}

fn sole_characteristic<'a>(svc: &'a Value, alias: &str) -> &'a Value {
    let want = sig_uuid(alias);
    let chars = svc["characteristics"]
        .as_array()
        .expect("service has no characteristics array");
    assert_eq!(
        chars.len(),
        1,
        "service {} should declare exactly one characteristic",
        svc["uuid"]
    );
    assert_eq!(
        chars[0]["uuid"].as_str(),
        Some(want.as_str()),
        "service {} should declare {want}",
        svc["uuid"]
    );
    &chars[0]
}

fn properties(ch: &Value) -> Vec<String> {
    ch["properties"]
        .as_array()
        .expect("characteristic has no properties array")
        .iter()
        .map(|p| p.as_str().expect("property must be a string").to_string())
        .collect()
}

/// The three services of the Proximity and Find Me profiles, each with the characteristic the
/// specification assigns to it.
#[test]
fn declares_the_three_proximity_services() {
    let examples = BluetoothBleProximityProtocol::new().get_startup_examples();
    let sm = &examples.static_mode;

    assert_eq!(
        services(sm).len(),
        3,
        "expected Immediate Alert (0x1802), Link Loss (0x1803) and Tx Power (0x1804)"
    );

    // Immediate Alert carries Alert Level (0x2A06).
    sole_characteristic(service(sm, "1802"), "2a06");
    // Link Loss carries Alert Level (0x2A06) as well — the same characteristic, different
    // service, which is the part of this profile most often got wrong.
    sole_characteristic(service(sm, "1803"), "2a06");
    // Tx Power carries Tx Power Level (0x2A07), a different characteristic.
    sole_characteristic(service(sm, "1804"), "2a07");
}

/// Immediate Alert's Alert Level is write-without-response and **not** readable.
///
/// The specification makes this characteristic write-only: it is a command ("start alerting"),
/// not a state. A readable one invites a central to poll it as though it meant something.
#[test]
fn immediate_alert_is_write_only() {
    let examples = BluetoothBleProximityProtocol::new().get_startup_examples();
    let ch = sole_characteristic(service(&examples.static_mode, "1802"), "2a06");
    let props = properties(ch);

    assert!(
        props.iter().any(|p| p == "write_without_response"),
        "Immediate Alert's Alert Level must be write-without-response, got {props:?}"
    );
    assert!(
        !props.iter().any(|p| p == "read"),
        "Immediate Alert's Alert Level must not be readable — it is a command, not a state; \
         got {props:?}"
    );
}

/// Link Loss's Alert Level is readable and writable: it *is* state, unlike Immediate Alert's.
#[test]
fn link_loss_alert_level_is_readable_and_writable() {
    let examples = BluetoothBleProximityProtocol::new().get_startup_examples();
    let ch = sole_characteristic(service(&examples.static_mode, "1803"), "2a06");
    let props = properties(ch);

    assert!(
        props.iter().any(|p| p == "read"),
        "Link Loss's Alert Level is the configured alert and must be readable, got {props:?}"
    );
    assert!(
        props.iter().any(|p| p == "write"),
        "Link Loss's Alert Level must be writable, got {props:?}"
    );
}

/// Tx Power Level is read-only. It is a property of the radio; a central cannot set it.
#[test]
fn tx_power_level_is_read_only() {
    let examples = BluetoothBleProximityProtocol::new().get_startup_examples();
    let ch = sole_characteristic(service(&examples.static_mode, "1804"), "2a07");
    let props = properties(ch);

    assert_eq!(
        props,
        vec!["read".to_string()],
        "Tx Power Level is read-only — a central cannot set the radio's output power"
    );
}

/// Every published characteristic value is one octet, and the Alert Levels are a value the
/// specification actually defines.
///
/// Alert Level is an enumerated uint8: 0 No Alert, 1 Mild Alert, 2 High Alert. Anything else
/// is reserved, and a central is entitled to ignore the whole characteristic.
#[test]
fn published_values_are_one_octet_and_in_range() {
    let examples = BluetoothBleProximityProtocol::new().get_startup_examples();
    let sm = &examples.static_mode;

    for (service_alias, char_alias, name) in [
        ("1802", "2a06", "Immediate Alert / Alert Level"),
        ("1803", "2a06", "Link Loss / Alert Level"),
        ("1804", "2a07", "Tx Power / Tx Power Level"),
    ] {
        let ch = sole_characteristic(service(sm, service_alias), char_alias);
        let value = ch["initial_value"]
            .as_str()
            .unwrap_or_else(|| panic!("{name} has no string initial_value"));
        let bytes = hex::decode(value).unwrap_or_else(|e| panic!("{name} is not valid hex: {e}"));
        assert_eq!(bytes.len(), 1, "{name} is a single octet, got {bytes:?}");

        if char_alias == "2a06" {
            assert!(
                bytes[0] <= 2,
                "{name} is 0x{:02x}; Alert Level defines only 0 (No Alert), 1 (Mild) and \
                 2 (High)",
                bytes[0]
            );
        } else {
            // Tx Power Level is a signed dBm value; the spec's valid range is -100..=20.
            let dbm = bytes[0] as i8;
            assert!(
                (-100..=20).contains(&dbm),
                "{name} is {dbm} dBm, outside the specified -100..=20"
            );
        }
    }
}

/// The advertisement names all three services, so a central scanning for Find Me sees it.
#[test]
fn advertises_all_three_services() {
    let examples = BluetoothBleProximityProtocol::new().get_startup_examples();
    let advertised: Vec<String> = examples.static_mode["event_handlers"]
        .as_array()
        .expect("static_mode has no event_handlers")
        .iter()
        .filter_map(|h| h["handler"]["actions"].as_array())
        .flatten()
        .find(|a| a["type"] == "start_advertising")
        .expect("static_mode example must start advertising")["service_uuids"]
        .as_array()
        .expect("start_advertising must name service_uuids")
        .iter()
        .map(|u| u.as_str().expect("uuid must be a string").to_string())
        .collect();

    for alias in ["1802", "1803", "1804"] {
        assert!(
            advertised.contains(&sig_uuid(alias)),
            "service 0x{alias} is declared but not advertised; a central scanning for it \
             will not find this peripheral"
        );
    }
}
