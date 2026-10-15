//! A Tor client for the NetGet relay, written from tor-spec.
//!
//! Shared by `e2e_test.rs` and `llm_failure_test.rs`. It deliberately does **not** call into
//! the server's own `circuit.rs`: it recomputes the server's ntor AUTH value and derives Kf/Kb
//! itself, so any divergence in the handshake, the 92-byte KDF layout (tor-spec 5.2.2), the
//! forward/backward key assignment or the cell layout fails the test rather than being
//! reproduced identically on both sides.
//!
//! Everything here talks to 127.0.0.1 only. The real Tor network is never contacted.

#![cfg(unix)]

use super::super::super::helpers::server::NetGetServer;
use super::super::super::helpers::E2EResult;
use aes::Aes128;
use ctr::cipher::{KeyIvInit, StreamCipher};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::ClientConfig;
use tokio_rustls::TlsConnector;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

type HmacSha256 = Hmac<Sha256>;
pub type Aes128Ctr = ctr::Ctr128BE<Aes128>;

// tor-spec 5.1.4 ntor constants
pub const PROTOID: &[u8] = b"ntor-curve25519-sha256-1";
pub const T_MAC: &[u8] = b"ntor-curve25519-sha256-1:mac";
pub const T_KEY: &[u8] = b"ntor-curve25519-sha256-1:key_extract";
pub const T_VERIFY: &[u8] = b"ntor-curve25519-sha256-1:verify";
pub const M_EXPAND: &[u8] = b"ntor-curve25519-sha256-1:key_expand";

// tor-spec 3 cell commands
pub const CELL_VERSIONS: u8 = 7;
pub const CELL_RELAY: u8 = 3;
pub const CELL_DESTROY: u8 = 4;
pub const CELL_CREATE2: u8 = 10;
pub const CELL_CREATED2: u8 = 11;
pub const CELL_LEN: usize = 514;

// tor-spec 6.1 relay commands
pub const RELAY_BEGIN: u8 = 1;
pub const RELAY_DATA: u8 = 2;
pub const RELAY_CONNECTED: u8 = 4;
/// A relay command this relay does not implement, so it is the model's to answer.
pub const RELAY_EXTEND: u8 = 6;

// tor-spec 5.4 DESTROY reasons
pub const DESTROY_REASON_PROTOCOL: u8 = 1;
pub const DESTROY_REASON_INTERNAL: u8 = 2;

/// A Tor client for this relay: TLS, VERSIONS, ntor, and RELAY cell crypto.
pub struct RelayPeer {
    tls: tokio_rustls::client::TlsStream<TcpStream>,
    pub circuit_id: u32,
    /// Kf — client to relay.
    encrypt: Option<Aes128Ctr>,
    /// Kb — relay to client.
    decrypt: Option<Aes128Ctr>,
}

impl RelayPeer {
    pub async fn connect(port: u16) -> E2EResult<Self> {
        let provider =
            std::sync::Arc::new(tokio_rustls::rustls::crypto::aws_lc_rs::default_provider());
        let tls_config = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()?
            .dangerous()
            .with_custom_certificate_verifier(std::sync::Arc::new(NoCertVerifier))
            .with_no_client_auth();

        let connector = TlsConnector::from(std::sync::Arc::new(tls_config));
        let tcp = TcpStream::connect(format!("127.0.0.1:{}", port)).await?;
        let tls = connector
            .connect(ServerName::try_from("tor-relay.local")?, tcp)
            .await?;

        Ok(Self {
            tls,
            circuit_id: 0x8000_0001, // MSB set: the initiator picks the id (tor-spec 5.1)
            encrypt: None,
            decrypt: None,
        })
    }

    pub async fn read_exact_bytes(&mut self, n: usize, what: &str) -> Vec<u8> {
        let mut buf = vec![0u8; n];
        tokio::time::timeout(Duration::from_secs(15), self.tls.read_exact(&mut buf))
            .await
            .unwrap_or_else(|_| panic!("timed out reading {} ({} bytes)", what, n))
            .unwrap_or_else(|e| panic!("read error while reading {}: {}", what, e));
        buf
    }

    /// tor-spec 4.1: the first cell on a connection, 2-byte circuit id, variable length.
    pub async fn versions_handshake(&mut self) -> E2EResult<Vec<u16>> {
        let offered: [u16; 3] = [3, 4, 5];
        let mut cell = Vec::with_capacity(11);
        cell.extend_from_slice(&0u16.to_be_bytes());
        cell.push(CELL_VERSIONS);
        cell.extend_from_slice(&((offered.len() * 2) as u16).to_be_bytes());
        for v in offered {
            cell.extend_from_slice(&v.to_be_bytes());
        }
        assert_eq!(cell.len(), 11, "a 3-version VERSIONS cell is 11 bytes");
        self.tls.write_all(&cell).await?;
        self.tls.flush().await?;

        let header = self.read_exact_bytes(5, "the VERSIONS reply header").await;
        assert_eq!(
            header[2], CELL_VERSIONS,
            "the relay must answer VERSIONS with VERSIONS, got command {}",
            header[2]
        );
        let length = u16::from_be_bytes([header[3], header[4]]) as usize;
        let payload = self
            .read_exact_bytes(length, "the VERSIONS reply body")
            .await;
        Ok(payload
            .chunks_exact(2)
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect())
    }

    /// Send a well-formed ntor CREATE2 and return whatever fixed cell comes back, unparsed.
    ///
    /// For tests about what the relay answers *instead of* CREATED2; `create_circuit` asserts
    /// that the answer is a CREATED2 and so cannot observe the alternative.
    pub async fn send_create2_expecting_any(
        &mut self,
        fingerprint: &[u8; 20],
        onion_key: &[u8; 32],
        what: &str,
    ) -> E2EResult<Vec<u8>> {
        let x = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let big_x = X25519PublicKey::from(&x);
        let mut cell = Vec::with_capacity(CELL_LEN);
        cell.extend_from_slice(&self.circuit_id.to_be_bytes());
        cell.push(CELL_CREATE2);
        cell.extend_from_slice(&2u16.to_be_bytes());
        cell.extend_from_slice(&84u16.to_be_bytes());
        cell.extend_from_slice(fingerprint);
        cell.extend_from_slice(onion_key);
        cell.extend_from_slice(big_x.as_bytes());
        cell.resize(CELL_LEN, 0);
        self.tls.write_all(&cell).await?;
        self.tls.flush().await?;
        Ok(self.recv_cell(what).await)
    }

    /// Run the client half of the ntor handshake and install the circuit ciphers.
    pub async fn create_circuit(
        &mut self,
        fingerprint: &[u8; 20],
        onion_key: &[u8; 32],
    ) -> E2EResult<()> {
        let x = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let big_x = X25519PublicKey::from(&x);
        let big_b = X25519PublicKey::from(*onion_key);

        // CircID(4) | Command(1) | HTYPE(2)=2 ntor | HLEN(2)=84 | ID(20) B(32) X(32)
        let mut cell = Vec::with_capacity(CELL_LEN);
        cell.extend_from_slice(&self.circuit_id.to_be_bytes());
        cell.push(CELL_CREATE2);
        cell.extend_from_slice(&2u16.to_be_bytes());
        cell.extend_from_slice(&84u16.to_be_bytes());
        cell.extend_from_slice(fingerprint);
        cell.extend_from_slice(onion_key);
        cell.extend_from_slice(big_x.as_bytes());
        cell.resize(CELL_LEN, 0);
        self.tls.write_all(&cell).await?;
        self.tls.flush().await?;

        let reply = self.read_exact_bytes(CELL_LEN, "the CREATED2 cell").await;
        assert_eq!(
            u32::from_be_bytes([reply[0], reply[1], reply[2], reply[3]]),
            self.circuit_id,
            "CREATED2 must carry the circuit id from the CREATE2"
        );
        assert_eq!(
            reply[4], CELL_CREATED2,
            "expected a CREATED2 (11) cell, got command {}",
            reply[4]
        );
        let hlen = u16::from_be_bytes([reply[5], reply[6]]) as usize;
        assert_eq!(
            hlen, 64,
            "an ntor CREATED2 carries Y(32) + AUTH(32) = 64 bytes, got {}",
            hlen
        );

        let big_y: [u8; 32] = reply[7..39].try_into().unwrap();
        let server_auth: [u8; 32] = reply[39..71].try_into().unwrap();
        assert_ne!(big_y, [0u8; 32], "CREATED2 carried a zero server key");

        // secret_input = EXP(Y,x) | EXP(B,x) | ID | B | X | Y | PROTOID
        let xy = x.diffie_hellman(&X25519PublicKey::from(big_y));
        let xb = x.diffie_hellman(&big_b);
        let mut secret_input = Vec::new();
        secret_input.extend_from_slice(xy.as_bytes());
        secret_input.extend_from_slice(xb.as_bytes());
        secret_input.extend_from_slice(fingerprint);
        secret_input.extend_from_slice(big_b.as_bytes());
        secret_input.extend_from_slice(big_x.as_bytes());
        secret_input.extend_from_slice(&big_y);
        secret_input.extend_from_slice(PROTOID);

        let key_seed = hmac_sha256(T_KEY, &secret_input);
        let verify = hmac_sha256(T_VERIFY, &secret_input);

        // auth_input = verify | ID | B | Y | X | PROTOID | "Server"
        let mut auth_input = Vec::new();
        auth_input.extend_from_slice(&verify);
        auth_input.extend_from_slice(fingerprint);
        auth_input.extend_from_slice(big_b.as_bytes());
        auth_input.extend_from_slice(&big_y);
        auth_input.extend_from_slice(big_x.as_bytes());
        auth_input.extend_from_slice(PROTOID);
        auth_input.extend_from_slice(b"Server");
        let expected_auth = hmac_sha256(T_MAC, &auth_input);

        assert_eq!(
            server_auth, expected_auth,
            "the AUTH value in CREATED2 does not match the one this client derives from the \
             handshake, so the relay and the client did not agree on a shared secret"
        );

        // tor-spec 5.2.2: HKDF-SHA256 output is Df(20) | Db(20) | Kf(16) | Kb(16) | KH(20)
        let hkdf = Hkdf::<Sha256>::new(Some(T_KEY), &key_seed);
        let mut okm = [0u8; 92];
        hkdf.expand(M_EXPAND, &mut okm)
            .map_err(|_| "HKDF expand failed")?;
        let kf: [u8; 16] = okm[40..56].try_into().unwrap();
        let kb: [u8; 16] = okm[56..72].try_into().unwrap();

        self.encrypt = Some(Aes128Ctr::new(&kf.into(), &[0u8; 16].into()));
        self.decrypt = Some(Aes128Ctr::new(&kb.into(), &[0u8; 16].into()));
        Ok(())
    }

    /// tor-spec 6.1 relay cell: Command | Recognized | StreamID | Digest | Length | Data.
    pub async fn send_relay(
        &mut self,
        relay_cmd: u8,
        stream_id: u16,
        data: &[u8],
    ) -> E2EResult<()> {
        let mut payload = Vec::with_capacity(509);
        payload.push(relay_cmd);
        payload.extend_from_slice(&0u16.to_be_bytes()); // recognized
        payload.extend_from_slice(&stream_id.to_be_bytes());
        payload.extend_from_slice(&[0u8; 4]); // digest: this relay neither sets nor checks it
        payload.extend_from_slice(&(data.len() as u16).to_be_bytes());
        payload.extend_from_slice(data);
        payload.resize(509, 0);

        self.encrypt
            .as_mut()
            .expect("no circuit")
            .apply_keystream(&mut payload);

        let mut cell = Vec::with_capacity(CELL_LEN);
        cell.extend_from_slice(&self.circuit_id.to_be_bytes());
        cell.push(CELL_RELAY);
        cell.extend_from_slice(&payload);

        self.tls.write_all(&cell).await?;
        self.tls.flush().await?;
        Ok(())
    }

    /// Read one fixed-length cell of any command, without decrypting it.
    ///
    /// Needed for cells that are not RELAY — DESTROY carries its reason in the clear.
    pub async fn recv_cell(&mut self, what: &str) -> Vec<u8> {
        let cell = self.read_exact_bytes(CELL_LEN, what).await;
        assert_eq!(
            u32::from_be_bytes([cell[0], cell[1], cell[2], cell[3]]),
            self.circuit_id,
            "cell for {} arrived on the wrong circuit",
            what
        );
        cell
    }

    /// Read one RELAY cell and decrypt it with the backward key.
    pub async fn recv_relay(&mut self, what: &str) -> (u8, u16, Vec<u8>) {
        let cell = self.recv_cell(what).await;
        assert_eq!(
            cell[4], CELL_RELAY,
            "expected a RELAY (3) cell for {}, got command {}",
            what, cell[4]
        );

        let mut payload = cell[5..CELL_LEN].to_vec();
        self.decrypt
            .as_mut()
            .expect("no circuit")
            .apply_keystream(&mut payload);

        let relay_cmd = payload[0];
        let recognized = u16::from_be_bytes([payload[1], payload[2]]);
        let stream_id = u16::from_be_bytes([payload[3], payload[4]]);
        let length = u16::from_be_bytes([payload[9], payload[10]]) as usize;

        assert_eq!(
            recognized, 0,
            "the 'recognized' field of {} decrypted to {:#06x}, which means the backward key or \
             the keystream position is wrong",
            what, recognized
        );
        assert!(
            11 + length <= payload.len(),
            "{} declares {} bytes of data, more than the 498 a relay cell can hold — the payload \
             did not decrypt to anything sensible",
            what,
            length
        );

        (relay_cmd, stream_id, payload[11..11 + length].to_vec())
    }
}

pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(message);
    mac.finalize().into_bytes().into()
}

/// A peer cannot run ntor without the relay's identity fingerprint (ID) and onion public key
/// (B): both are mixed into `secret_input`. A real relay publishes them in its descriptor;
/// this one logs them at startup.
pub async fn read_relay_identity(server: &NetGetServer) -> E2EResult<([u8; 20], [u8; 32])> {
    let fingerprint_line = server
        .wait_for_pattern("Relay fingerprint: ", Duration::from_secs(20))
        .await?;
    let onion_line = server
        .wait_for_pattern("Relay onion key: ", Duration::from_secs(20))
        .await?;

    let fingerprint: [u8; 20] = hex_after(&fingerprint_line, "Relay fingerprint: ", 40)
        .try_into()
        .map_err(|_| "relay fingerprint is not 20 bytes")?;
    let onion_key: [u8; 32] = hex_after(&onion_line, "Relay onion key: ", 64)
        .try_into()
        .map_err(|_| "relay onion key is not 32 bytes")?;
    Ok((fingerprint, onion_key))
}

/// Pull `hex_chars` hex digits following `marker` out of a log line.
pub fn hex_after(line: &str, marker: &str, hex_chars: usize) -> Vec<u8> {
    let start = line
        .find(marker)
        .unwrap_or_else(|| panic!("marker {:?} not in log line {:?}", marker, line))
        + marker.len();
    let digits: String = line[start..]
        .chars()
        .take_while(|c| c.is_ascii_hexdigit())
        .collect();
    assert_eq!(
        digits.len(),
        hex_chars,
        "expected {} hex digits after {:?} in {:?}",
        hex_chars,
        marker,
        line
    );
    hex_decode(&digits)
}

pub fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
        .collect()
}

/// Certificate verifier that accepts all certificates (for testing only)
#[derive(Debug)]
pub struct NoCertVerifier;

impl tokio_rustls::rustls::client::danger::ServerCertVerifier for NoCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[tokio_rustls::rustls::pki_types::CertificateDer<'_>],
        _server_name: &tokio_rustls::rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: tokio_rustls::rustls::pki_types::UnixTime,
    ) -> Result<tokio_rustls::rustls::client::danger::ServerCertVerified, tokio_rustls::rustls::Error>
    {
        Ok(tokio_rustls::rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
        _dss: &tokio_rustls::rustls::DigitallySignedStruct,
    ) -> Result<
        tokio_rustls::rustls::client::danger::HandshakeSignatureValid,
        tokio_rustls::rustls::Error,
    > {
        Ok(tokio_rustls::rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
        _dss: &tokio_rustls::rustls::DigitallySignedStruct,
    ) -> Result<
        tokio_rustls::rustls::client::danger::HandshakeSignatureValid,
        tokio_rustls::rustls::Error,
    > {
        Ok(tokio_rustls::rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<tokio_rustls::rustls::SignatureScheme> {
        vec![
            tokio_rustls::rustls::SignatureScheme::RSA_PKCS1_SHA256,
            tokio_rustls::rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            tokio_rustls::rustls::SignatureScheme::ED25519,
        ]
    }
}
