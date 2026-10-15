//! BitTorrent DHT E2E tests with mocks


use crate::helpers::*;
use serde_json::json;
use std::collections::HashMap;
use std::time::Duration;
use tokio::net::UdpSocket;

/// Test DHT ping, find_node, and get_peers queries with mocks
///
/// LLM calls: 4 total
/// - 1 server startup
/// - 1 ping query
/// - 1 find_node query
/// - 1 get_peers query
#[tokio::test]
async fn test_dht_queries() -> E2EResult<()> {
    // Start DHT server with mocks
    let server_config = NetGetConfig::new(
        "Listen on port {AVAILABLE_PORT} via torrent-dht. Respond to DHT queries with node ID 0000000000000000000000000000000000000000."
    )
    .with_mock(|mock| {
        mock
            // Mock 1: Server startup
            .on_instruction_containing("Listen on port")
            .and_instruction_containing("torrent-dht")
            .respond_with_actions(json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "Torrent-DHT",
                    "instruction": "DHT node for peer discovery"
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 2: Ping query
            .on_event("dht_ping_query")
            .respond_with_actions(json!([
                {
                    "type": "send_ping_response",
                    "transaction_id": "6161",
                    "node_id": "0000000000000000000000000000000000000000"
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 3: Find node query
            .on_event("dht_find_node_query")
            .respond_with_actions(json!([
                {
                    "type": "send_find_node_response",
                    "transaction_id": "6262",
                    "node_id": "0000000000000000000000000000000000000000",
                    "nodes": [
                        {
                            "id": "1111111111111111111111111111111111111111",
                            "ip": "192.168.1.10",
                            "port": 6881
                        },
                        {
                            "id": "2222222222222222222222222222222222222222",
                            "ip": "192.168.1.20",
                            "port": 6881
                        }
                    ]
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 4: Get peers query
            .on_event("dht_get_peers_query")
            .respond_with_actions(json!([
                {
                    "type": "send_get_peers_response",
                    "transaction_id": "6363",
                    "node_id": "0000000000000000000000000000000000000000",
                    "token": "aoeusnth",
                    "peers": [
                        {
                            "ip": "192.168.1.100",
                            "port": 51413
                        },
                        {
                            "ip": "192.168.1.101",
                            "port": 6881
                        }
                    ]
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let mut server = start_netget_server(server_config).await?;

    tokio::time::sleep(Duration::from_millis(500)).await;

    // Create UDP socket for DHT queries
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let dht_addr = format!("127.0.0.1:{}", server.port);

    println!("Connecting to DHT node at {}", dht_addr);

    // Test 1: Ping query
    {
        let mut query = HashMap::new();
        query.insert(
            b"t".to_vec(),
            serde_bencode::value::Value::Bytes(b"aa".to_vec()),
        );
        query.insert(
            b"y".to_vec(),
            serde_bencode::value::Value::Bytes(b"q".to_vec()),
        );
        query.insert(
            b"q".to_vec(),
            serde_bencode::value::Value::Bytes(b"ping".to_vec()),
        );

        let mut args = HashMap::new();
        args.insert(
            b"id".to_vec(),
            serde_bencode::value::Value::Bytes(b"abcdefghij0123456789".to_vec()),
        );
        query.insert(b"a".to_vec(), serde_bencode::value::Value::Dict(args));

        let query_bytes = serde_bencode::to_bytes(&serde_bencode::value::Value::Dict(query))?;

        println!("[Ping] Sending query ({} bytes)", query_bytes.len());
        socket.send_to(&query_bytes, &dht_addr).await?;

        let mut buf = vec![0u8; 65535];
        let (n, _) = tokio::time::timeout(Duration::from_secs(10), socket.recv_from(&mut buf))
            .await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "DHT timeout"))??;

        println!("[Ping] Received response ({} bytes)", n);

        let response: serde_bencode::value::Value = serde_bencode::from_bytes(&buf[..n])?;
        let dict = match response {
            serde_bencode::value::Value::Dict(d) => d,
            _ => panic!("Response should be dictionary"),
        };

        // Verify response type
        assert_eq!(
            dict.get(b"y" as &[u8])
                .and_then(|v| match v {
                    serde_bencode::value::Value::Bytes(b) => Some(b),
                    _ => None,
                })
                .map(|b| b.as_slice()),
            Some(b"r".as_ref()),
            "Response type should be 'r'"
        );

        println!("✅ Ping query successful");
    }

    // Test 2: Find node query
    {
        let mut query = HashMap::new();
        query.insert(
            b"t".to_vec(),
            serde_bencode::value::Value::Bytes(b"bb".to_vec()),
        );
        query.insert(
            b"y".to_vec(),
            serde_bencode::value::Value::Bytes(b"q".to_vec()),
        );
        query.insert(
            b"q".to_vec(),
            serde_bencode::value::Value::Bytes(b"find_node".to_vec()),
        );

        let mut args = HashMap::new();
        args.insert(
            b"id".to_vec(),
            serde_bencode::value::Value::Bytes(b"abcdefghij0123456789".to_vec()),
        );
        args.insert(
            b"target".to_vec(),
            serde_bencode::value::Value::Bytes(b"0123456789abcdefghij".to_vec()),
        );
        query.insert(b"a".to_vec(), serde_bencode::value::Value::Dict(args));

        let query_bytes = serde_bencode::to_bytes(&serde_bencode::value::Value::Dict(query))?;

        println!("[FindNode] Sending query ({} bytes)", query_bytes.len());
        socket.send_to(&query_bytes, &dht_addr).await?;

        let mut buf = vec![0u8; 65535];
        let (n, _) = tokio::time::timeout(Duration::from_secs(10), socket.recv_from(&mut buf))
            .await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "DHT timeout"))??;

        println!("[FindNode] Received response ({} bytes)", n);

        let response: serde_bencode::value::Value = serde_bencode::from_bytes(&buf[..n])?;
        let dict = match response {
            serde_bencode::value::Value::Dict(d) => d,
            _ => panic!("Response should be dictionary"),
        };

        // Verify response type
        assert_eq!(
            dict.get(b"y" as &[u8])
                .and_then(|v| match v {
                    serde_bencode::value::Value::Bytes(b) => Some(b),
                    _ => None,
                })
                .map(|b| b.as_slice()),
            Some(b"r".as_ref()),
            "Response type should be 'r'"
        );

        // Verify nodes field exists (compact format)
        let r_dict = dict
            .get(b"r" as &[u8])
            .and_then(|v| match v {
                serde_bencode::value::Value::Dict(d) => Some(d),
                _ => None,
            })
            .expect("Response should have 'r' dict");

        assert!(
            r_dict.contains_key::<[u8]>(b"nodes".as_ref()),
            "Response should contain nodes"
        );

        println!("✅ Find node query successful");
    }

    // Test 3: Get peers query
    {
        let mut query = HashMap::new();
        query.insert(
            b"t".to_vec(),
            serde_bencode::value::Value::Bytes(b"cc".to_vec()),
        );
        query.insert(
            b"y".to_vec(),
            serde_bencode::value::Value::Bytes(b"q".to_vec()),
        );
        query.insert(
            b"q".to_vec(),
            serde_bencode::value::Value::Bytes(b"get_peers".to_vec()),
        );

        let mut args = HashMap::new();
        args.insert(
            b"id".to_vec(),
            serde_bencode::value::Value::Bytes(b"abcdefghij0123456789".to_vec()),
        );
        args.insert(
            b"info_hash".to_vec(),
            serde_bencode::value::Value::Bytes(b"fedcba9876543210fedc".to_vec()),
        );
        query.insert(b"a".to_vec(), serde_bencode::value::Value::Dict(args));

        let query_bytes = serde_bencode::to_bytes(&serde_bencode::value::Value::Dict(query))?;

        println!("[GetPeers] Sending query ({} bytes)", query_bytes.len());
        socket.send_to(&query_bytes, &dht_addr).await?;

        let mut buf = vec![0u8; 65535];
        let (n, _) = tokio::time::timeout(Duration::from_secs(10), socket.recv_from(&mut buf))
            .await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "DHT timeout"))??;

        println!("[GetPeers] Received response ({} bytes)", n);

        let response: serde_bencode::value::Value = serde_bencode::from_bytes(&buf[..n])?;
        let dict = match response {
            serde_bencode::value::Value::Dict(d) => d,
            _ => panic!("Response should be dictionary"),
        };

        // Verify response type
        assert_eq!(
            dict.get(b"y" as &[u8])
                .and_then(|v| match v {
                    serde_bencode::value::Value::Bytes(b) => Some(b),
                    _ => None,
                })
                .map(|b| b.as_slice()),
            Some(b"r".as_ref()),
            "Response type should be 'r'"
        );

        // Verify token exists
        let r_dict = dict
            .get(b"r" as &[u8])
            .and_then(|v| match v {
                serde_bencode::value::Value::Dict(d) => Some(d),
                _ => None,
            })
            .expect("Response should have 'r' dict");

        assert!(
            r_dict.contains_key::<[u8]>(b"token".as_ref()),
            "Response should contain token"
        );

        println!("✅ Get peers query successful");
    }

    // Verify all mocks were called
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;

    // Cleanup
    server.stop().await?;

    Ok(())
}
