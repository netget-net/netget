//! NVMe/TCP secure channels: TLS 1.3 with an external PSK, through OpenSSL.
//!
//! The TLS session starts with the TCP connection, before the first NVMe/TCP PDU, and carries
//! every PDU after it (NVMe TCP Transport 1.1). Both ends hold the configured PSK; the host
//! names the key it uses in its PSK identity (`super::tls_psk`), and nothing else authenticates
//! either end — there are no certificates.
//!
//! rustls has no external PSKs, so this is OpenSSL, and rust-openssl wraps only the legacy PSK
//! callbacks, which TLS 1.3 accepts for SHA-256 keys alone. The callbacks TLS 1.3 actually uses
//! — `SSL_CTX_set_psk_find_session_callback` on the target, `..._use_session_callback` on the
//! host — are declared here, and each builds the TLS 1.3 session OpenSSL resumes from: the TLS
//! PSK as its master key, the cipher suite whose hash is the key's (SHA-256 →
//! TLS_AES_128_GCM_SHA256, SHA-384 → TLS_AES_256_GCM_SHA384), which is also the only suite
//! either end offers.
//!
//! A target that cannot find the key a host names hands OpenSSL no session; with no
//! certificate to fall back on, the handshake fails. That is the fail-closed path, and the
//! callback records why, so the log says which of the reasons in `tls_psk::Refusal` it was.
use std::ffi::{c_int, c_uchar, c_void};
use std::pin::Pin;
use std::sync::{Arc, Mutex, OnceLock};

use foreign_types::ForeignTypeRef;
use openssl::ex_data::Index;
use openssl::ssl::{
    Ssl, SslContext, SslContextBuilder, SslMethod, SslOptions, SslRef, SslVerifyMode, SslVersion,
};
use tokio::net::TcpStream;
use tokio_openssl::SslStream;

use super::auth::Hash;
use super::tls_psk::{self, ConfiguredKey, Identity, Refusal};

/// An NVMe/TCP connection inside its TLS session.
pub type TlsStream = SslStream<TcpStream>;

/// The cipher suite NVMe/TCP names for a PSK's hash. Each end offers only its key's: OpenSSL's
/// target picks the suite before it looks at the PSK, and a SHA-384 key cannot be used under a
/// SHA-256 suite, so offering both made it pick TLS_AES_128_GCM_SHA256 and refuse the key.
fn ciphersuite(hash: Hash) -> &'static str {
    match hash {
        Hash::Sha384 => "TLS_AES_256_GCM_SHA384",
        _ => "TLS_AES_128_GCM_SHA256",
    }
}
const TLS1_3_VERSION: c_int = 0x0304;

type FindSession = unsafe extern "C" fn(
    ssl: *mut c_void,
    identity: *const c_uchar,
    identity_len: usize,
    sess: *mut *mut c_void,
) -> c_int;
type UseSession = unsafe extern "C" fn(
    ssl: *mut c_void,
    md: *const c_void,
    id: *mut *const c_uchar,
    idlen: *mut usize,
    sess: *mut *mut c_void,
) -> c_int;

// libssl, which rust-openssl links; these are the TLS 1.3 PSK entry points it does not wrap.
extern "C" {
    fn SSL_CTX_set_psk_find_session_callback(ctx: *mut c_void, cb: Option<FindSession>);
    fn SSL_CTX_set_psk_use_session_callback(ctx: *mut c_void, cb: Option<UseSession>);
    fn SSL_SESSION_new() -> *mut c_void;
    fn SSL_SESSION_free(s: *mut c_void);
    fn SSL_SESSION_set1_master_key(s: *mut c_void, key: *const c_uchar, len: usize) -> c_int;
    fn SSL_SESSION_set_cipher(s: *mut c_void, cipher: *const c_void) -> c_int;
    fn SSL_SESSION_set_protocol_version(s: *mut c_void, version: c_int) -> c_int;
    fn SSL_CIPHER_find(ssl: *mut c_void, ptr: *const c_uchar) -> *const c_void;
    fn EVP_MD_get_size(md: *const c_void) -> c_int;
}

/// A TLS 1.3 session resuming from `psk` with the cipher suite of `hash`, or null. OpenSSL
/// takes ownership of a session a callback returns.
fn session(ssl: *mut c_void, hash: Hash, psk: &[u8]) -> *mut c_void {
    let suite: [u8; 2] = match hash {
        Hash::Sha384 => [0x13, 0x02],
        _ => [0x13, 0x01],
    };
    // SAFETY: `ssl` is the live SSL the callback was handed; every pointer passed is valid for
    // the call, and a session that is not fully built is freed before null is returned.
    unsafe {
        let cipher = SSL_CIPHER_find(ssl, suite.as_ptr());
        if cipher.is_null() {
            return std::ptr::null_mut();
        }
        let s = SSL_SESSION_new();
        if s.is_null() {
            return s;
        }
        if SSL_SESSION_set1_master_key(s, psk.as_ptr(), psk.len()) != 1
            || SSL_SESSION_set_cipher(s, cipher) != 1
            || SSL_SESSION_set_protocol_version(s, TLS1_3_VERSION) != 1
        {
            SSL_SESSION_free(s);
            return std::ptr::null_mut();
        }
        s
    }
}

/// A context both roles share: TLS 1.3 only, the key's cipher suite, no tickets.
fn builder(method: SslMethod, hash: Hash) -> Result<SslContextBuilder, openssl::error::ErrorStack> {
    let mut b = SslContextBuilder::new(method)?;
    b.set_min_proto_version(Some(SslVersion::TLS1_3))?;
    b.set_max_proto_version(Some(SslVersion::TLS1_3))?;
    b.set_ciphersuites(ciphersuite(hash))?;
    b.set_options(SslOptions::NO_TICKET);
    b.set_num_tickets(0)?;
    Ok(b)
}

// ------------------------------------------------------------------------------- target

/// What the target's callback decided about the identity a host sent.
type Outcome = Mutex<Option<Result<Identity, Refusal>>>;

struct TargetSide {
    key: Arc<ConfiguredKey>,
    outcome: Outcome,
}

fn target_index() -> Index<Ssl, Arc<TargetSide>> {
    static INDEX: OnceLock<Index<Ssl, Arc<TargetSide>>> = OnceLock::new();
    *INDEX.get_or_init(|| Ssl::new_ex_index().expect("an SSL ex_data index"))
}

unsafe extern "C" fn find_session(
    ssl: *mut c_void,
    identity: *const c_uchar,
    identity_len: usize,
    sess: *mut *mut c_void,
) -> c_int {
    // SAFETY: OpenSSL passes the SSL this context created and an identity of `identity_len`
    // bytes; both outlive the call.
    let ssl_ref = SslRef::from_ptr_mut(ssl.cast());
    *sess = std::ptr::null_mut();
    let Some(side) = ssl_ref.ex_data(target_index()).cloned() else {
        return 0;
    };
    let text = if identity.is_null() || identity_len > tls_psk::MAX_IDENTITY_LEN {
        Err(Refusal::Malformed("the PSK identity is too long".into()))
    } else {
        let bytes = std::slice::from_raw_parts(identity, identity_len);
        std::str::from_utf8(bytes)
            .map_err(|_| Refusal::Malformed("the PSK identity is not UTF-8".into()))
    };
    let found = text.and_then(|t| tls_psk::target_psk(&side.key, t));
    let decided = match found {
        Ok((id, psk)) => {
            *sess = session(ssl, id.hash, &psk);
            Ok(id)
        }
        Err(refusal) => Err(refusal),
    };
    if let Ok(mut o) = side.outcome.lock() {
        *o = Some(decided);
    }
    // 1 with no session: no PSK, and so (with no certificate) no handshake.
    1
}

/// Why a host's TLS handshake did not complete.
#[derive(Debug)]
pub enum TargetFailure {
    /// The host named a key this target does not hold.
    Refused(Refusal),
    /// The host offered no PSK at all, or the handshake failed after the key was found.
    Handshake(String),
}

impl std::fmt::Display for TargetFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Refused(r) => write!(f, "{r}"),
            Self::Handshake(e) => write!(f, "TLS handshake failed: {e}"),
        }
    }
}

/// The target's TLS: one context, a session per connection.
#[derive(Clone)]
pub struct Acceptor {
    ctx: SslContext,
    key: Arc<ConfiguredKey>,
}

impl std::fmt::Debug for Acceptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Acceptor({:?})", self.key)
    }
}

impl Acceptor {
    pub fn new(key: ConfiguredKey) -> Result<Self, openssl::error::ErrorStack> {
        let mut b = builder(SslMethod::tls_server(), key.hash())?;
        // SAFETY: the context outlives every SSL made from it, and the callback is a plain fn.
        unsafe { SSL_CTX_set_psk_find_session_callback(b.as_ptr().cast(), Some(find_session)) };
        Ok(Self {
            ctx: b.build(),
            key: Arc::new(key),
        })
    }

    /// Run the server side of the handshake on a new connection: the stream and the identity the
    /// host proved, or why there is none.
    pub async fn accept(&self, tcp: TcpStream) -> Result<(TlsStream, Identity), TargetFailure> {
        let side = Arc::new(TargetSide {
            key: self.key.clone(),
            outcome: Mutex::new(None),
        });
        let mut ssl = Ssl::new(&self.ctx).map_err(|e| TargetFailure::Handshake(e.to_string()))?;
        ssl.set_ex_data(target_index(), side.clone());
        let mut stream =
            SslStream::new(ssl, tcp).map_err(|e| TargetFailure::Handshake(e.to_string()))?;
        let result = Pin::new(&mut stream).accept().await;
        let decided = side.outcome.lock().ok().and_then(|mut o| o.take());
        match (result, decided) {
            (_, Some(Err(refusal))) => Err(TargetFailure::Refused(refusal)),
            (Ok(()), Some(Ok(identity))) => Ok((stream, identity)),
            (Ok(()), None) => Err(TargetFailure::Handshake("completed without a PSK".into())),
            (Err(e), Some(Ok(_))) => Err(TargetFailure::Handshake(e.to_string())),
            (Err(e), None) => Err(TargetFailure::Handshake(format!(
                "the host offered no PSK ({e})"
            ))),
        }
    }
}

// --------------------------------------------------------------------------------- host

struct HostSide {
    identity: Vec<u8>,
    hash: Hash,
    psk: Vec<u8>,
}

impl Drop for HostSide {
    fn drop(&mut self) {
        self.psk.iter_mut().for_each(|b| *b = 0);
    }
}

fn host_index() -> Index<Ssl, Arc<HostSide>> {
    static INDEX: OnceLock<Index<Ssl, Arc<HostSide>>> = OnceLock::new();
    *INDEX.get_or_init(|| Ssl::new_ex_index().expect("an SSL ex_data index"))
}

unsafe extern "C" fn use_session(
    ssl: *mut c_void,
    md: *const c_void,
    id: *mut *const c_uchar,
    idlen: *mut usize,
    sess: *mut *mut c_void,
) -> c_int {
    // SAFETY: OpenSSL passes the SSL this context created; the identity handed back lives in
    // its ex_data, which outlives the handshake.
    let ssl_ref = SslRef::from_ptr_mut(ssl.cast());
    *sess = std::ptr::null_mut();
    let Some(side) = ssl_ref.ex_data(host_index()).cloned() else {
        return 0;
    };
    // After a HelloRetryRequest OpenSSL names the negotiated suite's hash; a key of another
    // length cannot be used with it.
    if !md.is_null() && EVP_MD_get_size(md) as usize != side.psk.len() {
        return 1;
    }
    *id = side.identity.as_ptr();
    *idlen = side.identity.len();
    *sess = session(ssl, side.hash, &side.psk);
    1
}

/// Run the host side of the handshake: offer `key` under a version `version` identity for
/// this host and subsystem. Returns the identity offered with the stream.
pub async fn connect(
    tcp: TcpStream,
    key: &ConfiguredKey,
    hostnqn: &str,
    subnqn: &str,
    version: u8,
) -> anyhow::Result<(TlsStream, Identity)> {
    let (identity, psk) = tls_psk::host_offer(key, hostnqn, subnqn, version);
    let mut b = builder(SslMethod::tls_client(), identity.hash)?;
    // Nothing to verify: the PSK is the only credential, and the target that knows it is the
    // one the handshake proves.
    b.set_verify(SslVerifyMode::NONE);
    // SAFETY: as for the target's callback.
    unsafe { SSL_CTX_set_psk_use_session_callback(b.as_ptr().cast(), Some(use_session)) };
    let ctx = b.build();
    let mut ssl = Ssl::new(&ctx)?;
    ssl.set_ex_data(
        host_index(),
        Arc::new(HostSide {
            identity: identity.text().into_bytes(),
            hash: identity.hash,
            psk,
        }),
    );
    let mut stream = SslStream::new(ssl, tcp)?;
    Pin::new(&mut stream)
        .connect()
        .await
        .map_err(|e| anyhow::anyhow!("TLS handshake with the target failed: {e}"))?;
    Ok((stream, identity))
}
