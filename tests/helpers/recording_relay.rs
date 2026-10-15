//! Relays that sit between a third-party peer and NetGet and record both directions, so the
//! pcap oracle can dissect real traffic rather than traffic a test fabricated.
//!
//! The recording is the bytes as they crossed, in order: one entry per datagram for UDP, one
//! entry per read for a TCP stream (the oracle coalesces adjacent chunks).
#![allow(dead_code)]

use std::sync::{Arc, Mutex};
use std::time::Duration;

/// `(to_server, bytes)` in the order they crossed.
pub type Recording = Arc<Mutex<Vec<(bool, Vec<u8>)>>>;

/// A UDP relay in front of `upstream`: each client datagram is forwarded from a socket of its
/// own, and each answer returned to the client.
pub async fn udp_relay(upstream: std::net::SocketAddr) -> (std::net::SocketAddr, Recording) {
    let front = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr = front.local_addr().unwrap();
    let rec: Recording = Arc::new(Mutex::new(Vec::new()));
    let r = rec.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 70_000];
        loop {
            let Ok((n, client)) = front.recv_from(&mut buf).await else {
                return;
            };
            let msg = buf[..n].to_vec();
            r.lock().unwrap().push((true, msg.clone()));
            let back = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let front = front.clone();
            let r = r.clone();
            tokio::spawn(async move {
                let _ = back.send_to(&msg, upstream).await;
                let mut buf = vec![0u8; 70_000];
                if let Ok(Ok((n, _))) =
                    tokio::time::timeout(Duration::from_secs(30), back.recv_from(&mut buf)).await
                {
                    r.lock().unwrap().push((false, buf[..n].to_vec()));
                    let _ = front.send_to(&buf[..n], client).await;
                }
            });
        }
    });
    (addr, rec)
}

/// A TCP relay in front of `upstream`, recording one stream per connection.
pub async fn tcp_relay(
    upstream: std::net::SocketAddr,
) -> (std::net::SocketAddr, Arc<Mutex<Vec<Recording>>>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let streams: Arc<Mutex<Vec<Recording>>> = Arc::new(Mutex::new(Vec::new()));
    let s = streams.clone();
    tokio::spawn(async move {
        loop {
            let Ok((client, _)) = listener.accept().await else {
                return;
            };
            let rec: Recording = Arc::new(Mutex::new(Vec::new()));
            s.lock().unwrap().push(rec.clone());
            tokio::spawn(async move {
                let Ok(server) = tokio::net::TcpStream::connect(upstream).await else {
                    return;
                };
                let (mut cr, mut cw) = client.into_split();
                let (mut sr, mut sw) = server.into_split();
                let up = rec.clone();
                let a = tokio::spawn(async move {
                    let mut buf = vec![0u8; 16384];
                    while let Ok(n) = cr.read(&mut buf).await {
                        if n == 0 {
                            break;
                        }
                        up.lock().unwrap().push((true, buf[..n].to_vec()));
                        if sw.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                    let _ = sw.shutdown().await;
                });
                let mut buf = vec![0u8; 16384];
                while let Ok(n) = sr.read(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                    rec.lock().unwrap().push((false, buf[..n].to_vec()));
                    if cw.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
                let _ = cw.shutdown().await;
                let _ = a.await;
            });
        }
    });
    (addr, streams)
}
