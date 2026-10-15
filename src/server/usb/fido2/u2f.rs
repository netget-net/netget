//! U2F (Universal 2nd Factor) / CTAP1 protocol implementation
//!
//! This module implements the U2F protocol (CTAP1) commands:
//! - U2F_REGISTER: Register a new credential
//! - U2F_AUTHENTICATE: Authenticate with an existing credential
//! - U2F_VERSION: Get protocol version
//!
//! ## U2F Command Format (APDU-like)
//!
//! ```text
//! | CLA (1) | INS (1) | P1 (1) | P2 (1) | Lc (3) | Data (Lc) |
//! ```
//!
//! ## U2F Response Format
//!
//! ```text
//! | Data | SW1 (1) | SW2 (1) |
//! ```

#[cfg(all(unix, feature = "libusb"))]
use anyhow::{bail, Context, Result};
#[cfg(all(unix, feature = "libusb"))]
use ring::rand::SecureRandom;
#[cfg(all(unix, feature = "libusb"))]
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
#[cfg(all(unix, feature = "libusb"))]
use tracing::{debug, warn};

#[cfg(all(unix, feature = "libusb"))]
use crate::server::usb::fido2::approval::{ApprovalDetails, OperationType, UserPresence};

/// What processing one U2F command produced. Mirrors `Ctap2Outcome`.
#[cfg(all(unix, feature = "libusb"))]
pub enum U2fOutcome {
    /// Encoded U2F response (data + status word), ready for CTAPHID framing.
    Response(Vec<u8>),
    /// This command cannot proceed until a user-presence decision is made.
    NeedsApproval(ApprovalDetails),
}

/// U2F command codes (INS byte)
#[cfg(all(unix, feature = "libusb"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum U2fCommand {
    Register = 0x01,
    Authenticate = 0x02,
    Version = 0x03,
}

#[cfg(all(unix, feature = "libusb"))]
impl U2fCommand {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x01 => Some(Self::Register),
            0x02 => Some(Self::Authenticate),
            0x03 => Some(Self::Version),
            _ => None,
        }
    }
}

/// U2F authentication control byte (P1)
#[cfg(all(unix, feature = "libusb"))]
pub const U2F_AUTH_ENFORCE: u8 = 0x03; // Enforce user presence
#[cfg(all(unix, feature = "libusb"))]
pub const U2F_AUTH_CHECK_ONLY: u8 = 0x07; // Check only (don't sign)

/// U2F status words
#[cfg(all(unix, feature = "libusb"))]
pub const SW_NO_ERROR: u16 = 0x9000;
#[cfg(all(unix, feature = "libusb"))]
pub const SW_CONDITIONS_NOT_SATISFIED: u16 = 0x6985;
#[cfg(all(unix, feature = "libusb"))]
pub const SW_WRONG_DATA: u16 = 0x6a80;
#[cfg(all(unix, feature = "libusb"))]
pub const SW_WRONG_LENGTH: u16 = 0x6700;
#[cfg(all(unix, feature = "libusb"))]
pub const SW_INS_NOT_SUPPORTED: u16 = 0x6d00;

/// U2F APDU request
#[cfg(all(unix, feature = "libusb"))]
#[derive(Debug)]
pub struct U2fRequest {
    pub cla: u8,
    pub ins: u8,
    pub p1: u8,
    pub p2: u8,
    pub data: Vec<u8>,
}

#[cfg(all(unix, feature = "libusb"))]
impl U2fRequest {
    /// Parse U2F APDU request
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 7 {
            bail!("U2F request too short: {} bytes", data.len());
        }

        let cla = data[0];
        let ins = data[1];
        let p1 = data[2];
        let p2 = data[3];

        // Lc is 3 bytes (extended length encoding)
        let lc = if data.len() >= 7 {
            let lc_bytes = [data[4], data[5], data[6]];
            u32::from_be_bytes([0, lc_bytes[0], lc_bytes[1], lc_bytes[2]]) as usize
        } else {
            0
        };

        let request_data = if lc > 0 && data.len() >= 7 + lc {
            data[7..7 + lc].to_vec()
        } else {
            Vec::new()
        };

        Ok(Self {
            cla,
            ins,
            p1,
            p2,
            data: request_data,
        })
    }

    /// Get command type
    pub fn command(&self) -> Option<U2fCommand> {
        U2fCommand::from_u8(self.ins)
    }
}

/// U2F response builder
#[cfg(all(unix, feature = "libusb"))]
pub struct U2fResponse {
    data: Vec<u8>,
    sw: u16,
}

#[cfg(all(unix, feature = "libusb"))]
impl U2fResponse {
    pub fn success(data: Vec<u8>) -> Self {
        Self {
            data,
            sw: SW_NO_ERROR,
        }
    }

    pub fn error(sw: u16) -> Self {
        Self {
            data: Vec::new(),
            sw,
        }
    }

    /// Build complete response with status word
    pub fn to_bytes(self) -> Vec<u8> {
        let mut response = self.data;
        response.extend_from_slice(&self.sw.to_be_bytes());
        response
    }
}

/// U2F credential storage (simplified in-memory version)
#[cfg(all(unix, feature = "libusb"))]
pub struct U2fCredentialStore {
    /// Stored credentials (keyed by application parameter)
    credentials: std::collections::HashMap<Vec<u8>, Credential>,
    /// RNG for generating key handles
    rng: ring::rand::SystemRandom,
}

#[cfg(all(unix, feature = "libusb"))]
#[derive(Clone)]
struct Credential {
    /// PKCS#8 private key document
    private_key: Vec<u8>,
    /// Public key (x9.62 uncompressed point format)
    #[allow(dead_code)]
    public_key: Vec<u8>,
    /// Key handle (opaque to client)
    key_handle: Vec<u8>,
    /// Signature counter
    counter: u32,
}

#[cfg(all(unix, feature = "libusb"))]
impl U2fCredentialStore {
    pub fn new() -> Self {
        Self {
            credentials: std::collections::HashMap::new(),
            rng: ring::rand::SystemRandom::new(),
        }
    }

    /// How many credentials exist for an application parameter (0 or 1 — U2F keeps one).
    pub fn credential_count(&self, app_param: &[u8]) -> usize {
        usize::from(self.credentials.contains_key(app_param))
    }

    /// Every stored credential as `(application label, counter)`, for `list_credentials`.
    ///
    /// No key handles and no key material: this reaches the model and the log.
    pub fn describe_credentials(&self) -> Vec<(String, u32)> {
        let mut out: Vec<(String, u32)> = self
            .credentials
            .iter()
            .map(|(app, cred)| {
                let hex: String = app.iter().take(4).map(|b| format!("{:02x}", b)).collect();
                (format!("u2f-app:{}", hex), cred.counter)
            })
            .collect();
        out.sort();
        out
    }

    /// Forget every credential whose application label matches. Returns how many were removed.
    pub fn delete_credentials(&mut self, label: &str) -> usize {
        let before = self.credentials.len();
        self.credentials.retain(|app, _| {
            let hex: String = app.iter().take(4).map(|b| format!("{:02x}", b)).collect();
            format!("u2f-app:{}", hex) != label
        });
        before - self.credentials.len()
    }

    /// Generate a new ECDSA P-256 key pair
    fn generate_keypair(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &self.rng)?;
        let key_pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &self.rng)?;

        let public_key = key_pair.public_key().as_ref().to_vec();

        Ok((pkcs8.as_ref().to_vec(), public_key))
    }

    /// Register a new credential
    pub fn register(&mut self, app_param: &[u8], _challenge_param: &[u8]) -> Result<Vec<u8>> {
        debug!("U2F REGISTER: app_param={} bytes", app_param.len());

        // Generate new key pair
        let (private_key, public_key) = self.generate_keypair()?;

        // Generate random key handle (32 bytes)
        let mut key_handle = vec![0u8; 32];
        self.rng.fill(&mut key_handle)?;

        // Build registration response
        let mut response = Vec::new();

        // Reserved byte
        response.push(0x05);

        // Public key (65 bytes: 0x04 || X || Y)
        response.extend_from_slice(&public_key);

        // Key handle length (1 byte)
        response.push(key_handle.len() as u8);

        // Key handle
        response.extend_from_slice(&key_handle);

        // For a real implementation, we would:
        // 1. Generate an attestation certificate
        // 2. Sign over (0x00 || app_param || challenge_param || key_handle || public_key)
        // 3. Append certificate and signature
        //
        // For now, we'll use a dummy certificate and signature

        // Dummy X.509 certificate (self-signed)
        let dummy_cert = vec![
            0x30, 0x82, 0x01,
            0x00, // SEQUENCE (256 bytes - placeholder)
                 // ... (simplified for demo)
        ];

        // Dummy signature (71-73 bytes typical for ECDSA P-256)
        let dummy_signature = vec![0u8; 71];

        response.extend_from_slice(&dummy_cert);
        response.extend_from_slice(&dummy_signature);

        // Store credential
        let credential = Credential {
            private_key,
            public_key,
            key_handle: key_handle.clone(),
            counter: 0,
        };

        self.credentials.insert(app_param.to_vec(), credential);

        Ok(response)
    }

    /// Authenticate with an existing credential
    pub fn authenticate(
        &mut self,
        app_param: &[u8],
        challenge_param: &[u8],
        key_handle: &[u8],
        control: u8,
    ) -> Result<Vec<u8>> {
        debug!(
            "U2F AUTHENTICATE: app_param={} bytes, key_handle={} bytes, control={:#04x}",
            app_param.len(),
            key_handle.len(),
            control
        );

        // Find credential
        let credential = self
            .credentials
            .get_mut(app_param)
            .context("Credential not found")?;

        // Verify key handle matches
        if credential.key_handle != key_handle {
            bail!("Key handle mismatch");
        }

        // If check-only, just return success
        if control == U2F_AUTH_CHECK_ONLY {
            return Ok(Vec::new());
        }

        // Increment counter
        credential.counter += 1;

        // Build authentication response
        let mut response = Vec::new();

        // User presence byte (0x01 = present)
        response.push(0x01);

        // Counter (4 bytes, big-endian)
        response.extend_from_slice(&credential.counter.to_be_bytes());

        // Sign over (app_param || user_presence || counter || challenge_param)
        let mut sig_data = Vec::new();
        sig_data.extend_from_slice(app_param);
        sig_data.push(0x01);
        sig_data.extend_from_slice(&credential.counter.to_be_bytes());
        sig_data.extend_from_slice(challenge_param);

        // Generate signature
        let key_pair = EcdsaKeyPair::from_pkcs8(
            &ECDSA_P256_SHA256_FIXED_SIGNING,
            &credential.private_key,
            &self.rng,
        )?;

        let signature = key_pair.sign(&self.rng, &sig_data)?;

        // Append signature
        response.extend_from_slice(signature.as_ref());

        Ok(response)
    }
}

#[cfg(all(unix, feature = "libusb"))]
impl Default for U2fCredentialStore {
    fn default() -> Self {
        Self::new()
    }
}

/// U2F protocol handler
#[cfg(all(unix, feature = "libusb"))]
pub struct U2fHandler {
    store: U2fCredentialStore,
}

#[cfg(all(unix, feature = "libusb"))]
impl U2fHandler {
    pub fn new() -> Self {
        Self {
            store: U2fCredentialStore::new(),
        }
    }

    /// Read-only view of the credential store, for the `list_credentials` action.
    pub fn store(&self) -> &U2fCredentialStore {
        &self.store
    }

    /// Mutable view of the credential store, for the `delete_credential` action.
    pub fn store_mut(&mut self) -> &mut U2fCredentialStore {
        &mut self.store
    }

    /// Process U2F command.
    ///
    /// `presence` gates the two commands that a real key requires a button press for:
    /// REGISTER, and AUTHENTICATE with `P1 = 0x03` (enforce-user-presence). `U2F_VERSION` and
    /// AUTHENTICATE with `P1 = 0x07` (check-only) answer immediately — check-only exists
    /// precisely so a host can ask "do you know this key handle?" *without* a user gesture, and
    /// gating it would break every browser that probes before prompting.
    pub fn process_command(&mut self, data: &[u8], presence: UserPresence) -> U2fOutcome {
        let request = match U2fRequest::parse(data) {
            Ok(req) => req,
            Err(e) => {
                warn!("Failed to parse U2F request: {}", e);
                return U2fOutcome::Response(U2fResponse::error(SW_WRONG_DATA).to_bytes());
            }
        };

        let response = match request.command() {
            Some(U2fCommand::Register) => match self.handle_register(&request, presence) {
                Ok(r) => r,
                Err(details) => return U2fOutcome::NeedsApproval(details),
            },
            Some(U2fCommand::Authenticate) => match self.handle_authenticate(&request, presence) {
                Ok(r) => r,
                Err(details) => return U2fOutcome::NeedsApproval(details),
            },
            Some(U2fCommand::Version) => self.handle_version(&request),
            None => {
                warn!("Unsupported U2F command: {:#04x}", request.ins);
                U2fResponse::error(SW_INS_NOT_SUPPORTED)
            }
        };

        U2fOutcome::Response(response.to_bytes())
    }

    /// U2F identifies the relying party only by the SHA-256 of its origin, which is not
    /// reversible, so the event names it as an explicitly-labelled digest prefix rather than
    /// pretending to know the domain.
    fn app_label(app_param: &[u8]) -> String {
        let hex: String = app_param
            .iter()
            .take(4)
            .map(|b| format!("{:02x}", b))
            .collect();
        format!("u2f-app:{}", hex)
    }

    fn handle_register(
        &mut self,
        req: &U2fRequest,
        presence: UserPresence,
    ) -> std::result::Result<U2fResponse, ApprovalDetails> {
        debug!("U2F_REGISTER command");

        // Register request data: challenge_param (32) || app_param (32)
        if req.data.len() != 64 {
            warn!("Invalid REGISTER data length: {}", req.data.len());
            return Ok(U2fResponse::error(SW_WRONG_LENGTH));
        }

        let challenge_param = &req.data[0..32];
        let app_param = &req.data[32..64];

        match presence {
            UserPresence::Ask => {
                return Err(ApprovalDetails {
                    operation: OperationType::Register,
                    rp_id: Self::app_label(app_param),
                    user_name: None,
                    credential_count: self.store.credential_count(app_param),
                })
            }
            UserPresence::Denied => {
                warn!("U2F_REGISTER denied for {}", Self::app_label(app_param));
                // 0x6985 is what a key returns while the button has not been pressed; it is
                // also the honest answer to a refusal, and is what a host retries on.
                return Ok(U2fResponse::error(SW_CONDITIONS_NOT_SATISFIED));
            }
            UserPresence::Approved => {}
        }

        match self.store.register(app_param, challenge_param) {
            Ok(response_data) => Ok(U2fResponse::success(response_data)),
            Err(e) => {
                warn!("REGISTER failed: {}", e);
                Ok(U2fResponse::error(SW_WRONG_DATA))
            }
        }
    }

    fn handle_authenticate(
        &mut self,
        req: &U2fRequest,
        presence: UserPresence,
    ) -> std::result::Result<U2fResponse, ApprovalDetails> {
        debug!("U2F_AUTHENTICATE command (control={:#04x})", req.p1);

        // Authenticate request: challenge_param (32) || app_param (32) || key_handle_len (1) || key_handle
        if req.data.len() < 65 {
            warn!("Invalid AUTHENTICATE data length: {}", req.data.len());
            return Ok(U2fResponse::error(SW_WRONG_LENGTH));
        }

        let challenge_param = &req.data[0..32];
        let app_param = &req.data[32..64];
        let kh_len = req.data[64] as usize;

        if req.data.len() < 65 + kh_len {
            warn!("Key handle length mismatch");
            return Ok(U2fResponse::error(SW_WRONG_LENGTH));
        }

        let key_handle = &req.data[65..65 + kh_len];

        // A key handle this device did not issue is answered before user presence is
        // collected, exactly as a real key does: there is nothing to sign, so there is nothing
        // to ask about.
        if self.store.credential_count(app_param) == 0 {
            warn!(
                "U2F_AUTHENTICATE for unknown application {}",
                Self::app_label(app_param)
            );
            return Ok(U2fResponse::error(SW_WRONG_DATA));
        }

        // Check-only never signs anything, so it needs no user gesture and must not ask for one.
        if req.p1 != U2F_AUTH_CHECK_ONLY {
            match presence {
                UserPresence::Ask => {
                    return Err(ApprovalDetails {
                        operation: OperationType::Authenticate,
                        rp_id: Self::app_label(app_param),
                        user_name: None,
                        credential_count: self.store.credential_count(app_param),
                    })
                }
                UserPresence::Denied => {
                    warn!("U2F_AUTHENTICATE denied for {}", Self::app_label(app_param));
                    return Ok(U2fResponse::error(SW_CONDITIONS_NOT_SATISFIED));
                }
                UserPresence::Approved => {}
            }
        }

        match self
            .store
            .authenticate(app_param, challenge_param, key_handle, req.p1)
        {
            Ok(response_data) => Ok(U2fResponse::success(response_data)),
            Err(e) => {
                warn!("AUTHENTICATE failed: {}", e);
                Ok(U2fResponse::error(SW_CONDITIONS_NOT_SATISFIED))
            }
        }
    }

    fn handle_version(&self, _req: &U2fRequest) -> U2fResponse {
        debug!("U2F_VERSION command");

        // Return "U2F_V2"
        U2fResponse::success(b"U2F_V2".to_vec())
    }
}

#[cfg(all(unix, feature = "libusb"))]
impl Default for U2fHandler {
    fn default() -> Self {
        Self::new()
    }
}
