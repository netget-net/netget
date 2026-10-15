//! A SUBSCRIBE is told to publish the retained message after its SUBACK, and a connection
//! gets exactly one CONNACK.
//!
//! The real-model eval (`./run-eval.sh mqtt`, `mqtt/retained-message` 0/5) found llama3.1:8b,
//! told a topic "holds the retained reading 19.5", answering `mosquitto_sub`'s SUBSCRIBE with a
//! SUBACK and nothing else - the subscriber waited out its timeout - and in one run answering
//! the CONNECT with two CONNACKs, which libmosquitto drops as a protocol error. This file pins
//! both fixes from the wire:
//!
//! * the subscribe event carries `answer_with` naming the SUBACK and the retained publish - the
//!   rule below matches only on it;
//! * a second CONNACK on one connection is not sent, logged
//!   `decision=duplicate_response_dropped`, so the next packet the client reads is its SUBACK.

use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

fn build_connect(client_id: &str) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&[0x00, 0x04, b'M', b'Q', b'T', b'T', 0x04, 0x02, 0x00, 0x3C]);
    body.extend_from_slice(&(client_id.len() as u16).to_be_bytes());
    body.extend_from_slice(client_id.as_bytes());
    let mut packet = vec![0x10, body.len() as u8];
    packet.extend_from_slice(&body);
    packet
}

fn build_subscribe(packet_id: u16, filter: &str) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&packet_id.to_be_bytes());
    body.extend_from_slice(&(filter.len() as u16).to_be_bytes());
    body.extend_from_slice(filter.as_bytes());
    body.push(0);
    let mut packet = vec![0x82, body.len() as u8];
    packet.extend_from_slice(&body);
    packet
}

async fn read_packet(stream: &mut TcpStream) -> E2EResult<Vec<u8>> {
    let mut header = [0u8; 2];
    tokio::time::timeout(Duration::from_secs(20), stream.read_exact(&mut header))
        .await
        .map_err(|_| "no MQTT packet within 20s")??;
    // Every packet in this test is under 128 bytes, so one length byte.
    let mut body = vec![0u8; header[1] as usize];
    stream.read_exact(&mut body).await?;
    let mut packet = header.to_vec();
    packet.extend_from_slice(&body);
    Ok(packet)
}

#[tokio::test]
async fn subscribe_is_told_to_publish_the_retained_message_and_connack_is_sent_once(
) -> E2EResult<()> {
    let prompt = "listen on port {AVAILABLE_PORT} via mqtt. sensors/greenhouse/temp holds 19.5.";

    let config = NetGetConfig::new_no_scripts(prompt).with_mock(|mock| {
        mock.on_instruction_containing("via mqtt")
            .respond_with_actions(serde_json::json!([{
                "type": "open_server",
                "port": 0,
                "base_stack": "MQTT",
                "instruction": "sensors/greenhouse/temp holds the retained reading 19.5."
            }]))
            .expect_calls(1)
            .and()
            .on_event("mqtt_connect")
            .respond_with_actions(serde_json::json!([
                {"type": "mqtt_connack", "return_code": 0},
                {"type": "mqtt_connack", "return_code": 0}
            ]))
            .expect_calls(1)
            .and()
            .on_event("mqtt_subscribe")
            .and_event_data_contains("answer_with", "mqtt_suback with packet_id 7")
            .and_event_data_contains("answer_with", "retain true")
            .respond_with_actions(serde_json::json!([
                {"type": "mqtt_suback", "packet_id": 7, "granted_qos": [0]},
                {"type": "mqtt_publish", "topic": "sensors/greenhouse/temp",
                 "payload": "19.5", "retain": true}
            ]))
            .expect_calls(1)
            .and()
    });

    let server = start_netget_server(config).await?;
    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", server.port)).await?;

    stream.write_all(&build_connect("eval-subscriber")).await?;
    assert_eq!(
        read_packet(&mut stream).await?,
        vec![0x20, 0x02, 0x00, 0x00]
    );

    stream
        .write_all(&build_subscribe(7, "sensors/greenhouse/temp"))
        .await?;
    assert_eq!(
        read_packet(&mut stream).await?,
        vec![0x90, 0x03, 0x00, 0x07, 0x00],
        "the packet after the CONNACK must be the SUBACK, not a second CONNACK"
    );

    let publish = read_packet(&mut stream).await?;
    assert_eq!(
        publish[0], 0x31,
        "PUBLISH, QoS 0, RETAIN set: {publish:02x?}"
    );
    let topic_len = u16::from_be_bytes([publish[2], publish[3]]) as usize;
    assert_eq!(&publish[4..4 + topic_len], b"sensors/greenhouse/temp");
    assert_eq!(&publish[4 + topic_len..], b"19.5");

    server
        .wait_for_log("decision=duplicate_response_dropped", 30)
        .await?;

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}
