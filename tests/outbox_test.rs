//! A connection's outbound queue is bounded, and a peer that fills it is cut off.
//!
//! `utils::outbox` replaces the unbounded per-connection writer channels of the stream servers
//! whose queues a peer could grow without limit: MQTT and Nostr (a publish fanned out to a
//! subscriber that has stopped reading), WebSocket (a broadcast, or its own answers), AMQP
//! (deliveries and replies) and BGP (answers and keepalives). The policy is Redis's for a slow
//! pub/sub client: past the bound the connection is cut off, never left to grow and never
//! carried on with frames missing from the middle of its stream.

use netget::utils::outbox::{bytes_channel, OutboxLimits};

const SMALL: OutboxLimits = OutboxLimits {
    max_items: 4,
    max_bytes: 1024,
};

#[tokio::test]
async fn a_peer_that_keeps_up_gets_every_frame_in_order() {
    let (tx, mut rx) = bytes_channel("test", SMALL);
    for round in 0..10u8 {
        for n in 0..4u8 {
            tx.send(vec![round, n]).unwrap();
        }
        for n in 0..4u8 {
            assert_eq!(rx.recv().await, Some(vec![round, n]));
        }
    }
    assert!(!tx.overflowed());
}

#[tokio::test]
async fn a_peer_that_stops_reading_is_cut_off_at_the_frame_bound() {
    let (tx, mut rx) = bytes_channel("test", SMALL);
    for n in 0..4u8 {
        tx.send(vec![n]).unwrap();
    }
    assert!(tx.send(vec![4]).is_err(), "the fifth frame does not fit");
    assert!(tx.overflowed());
    assert!(tx.send(vec![5]).is_err(), "every later send fails at once");
    assert_eq!(tx.dropped(), 2);
    assert_eq!(
        rx.recv().await,
        None,
        "the writer stops, abandoning what is queued"
    );
}

#[tokio::test]
async fn a_peer_that_stops_reading_is_cut_off_at_the_byte_bound() {
    let (tx, mut rx) = bytes_channel("test", SMALL);
    tx.send(vec![0; 600]).unwrap();
    assert!(
        tx.send(vec![0; 600]).is_err(),
        "1 200 queued bytes pass 1 024"
    );
    assert!(tx.overflowed());
    assert_eq!(rx.recv().await, None);
}

#[tokio::test]
async fn one_large_frame_is_accepted_when_nothing_is_queued() {
    let (tx, mut rx) = bytes_channel("test", SMALL);
    tx.send(vec![0; 4096]).unwrap();
    assert_eq!(rx.recv().await.map(|f| f.len()), Some(4096));
    tx.send(vec![0; 4096]).unwrap();
    assert!(!tx.overflowed());
}

#[tokio::test]
async fn sends_fail_without_cutting_off_once_the_writer_is_gone() {
    let (tx, rx) = bytes_channel("test", SMALL);
    drop(rx);
    assert!(tx.send(vec![1]).is_err());
    assert!(!tx.overflowed(), "a closed writer is not a slow peer");
}

#[tokio::test]
async fn cutting_a_peer_off_shuts_its_socket_down() {
    use netget::utils::outbox::ConnectionCloser;
    use tokio::io::AsyncReadExt;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut peer = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (server_side, _) = listener.accept().await.unwrap();

    let (tx, _rx) = bytes_channel("test", SMALL);
    tx.close_on_cut_off(ConnectionCloser::for_stream(&server_side));
    for n in 0..5u8 {
        let _ = tx.send(vec![n]);
    }
    assert!(tx.overflowed());

    // The server still holds its stream; only the cut-off can have ended the connection.
    let mut buf = [0u8; 16];
    let n = tokio::time::timeout(std::time::Duration::from_secs(5), peer.read(&mut buf))
        .await
        .expect("the peer was not disconnected when it was cut off")
        .unwrap_or(0);
    assert_eq!(n, 0, "the peer reads EOF");
    drop(server_side);
}
