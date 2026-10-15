//! An MIT `FILE:` credential cache, version 4 (0x0504), written only when the operator names a
//! `ccache_path`. MIT's and Heimdal's `klist` read it, and MIT's `kvno` can use the TGT in it
//! to ask its own KDC for more tickets — which is what makes it evidence that the tickets
//! NetGet's client obtained are real.
//!
//! The file holds session keys, as every credential cache does. It is written with mode 0600
//! through a temporary file and a rename, and nothing else in NetGet ever reads it back.
//!
//! Format (MIT `doc/formats/ccache_file_format.rst`): big-endian throughout; a header with one
//! zero time-offset tag; the default principal; then each credential as client, server,
//! keyblock, four times, is-skey, flags, addresses, authdata, ticket and second ticket.

use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result};

use super::wire::Credential;
use crate::server::kerberos::codec::{encode, Principal};

fn data(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn principal(out: &mut Vec<u8>, p: &Principal, realm: &str) {
    out.extend_from_slice(&(p.name_type as u32).to_be_bytes());
    out.extend_from_slice(&(p.components.len() as u32).to_be_bytes());
    data(out, realm.as_bytes());
    for c in &p.components {
        data(out, c.as_bytes());
    }
}

fn time(t: i64) -> [u8; 4] {
    (t.clamp(0, u32::MAX as i64) as u32).to_be_bytes()
}

/// The bytes of a v4 ccache for `default` holding `creds`.
pub fn encode_ccache(default: (&Principal, &str), creds: &[Credential]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    out.extend_from_slice(&0x0504u16.to_be_bytes());
    // Header: one tag, DeltaTime (1), eight bytes of zero offset.
    out.extend_from_slice(&12u16.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&8u16.to_be_bytes());
    out.extend_from_slice(&[0u8; 8]);
    principal(&mut out, default.0, default.1);
    for c in creds {
        principal(&mut out, &c.client, &c.client_realm);
        principal(&mut out, &c.service, &c.service_realm);
        out.extend_from_slice(&(c.session_key.etype() as u16).to_be_bytes());
        data(&mut out, c.session_key.bytes_for_ccache());
        out.extend_from_slice(&time(c.authtime));
        out.extend_from_slice(&time(c.starttime));
        out.extend_from_slice(&time(c.endtime));
        out.extend_from_slice(&time(c.renew_till.unwrap_or(0)));
        out.push(0); // is_skey
        out.extend_from_slice(&c.flags.to_be_bytes());
        out.extend_from_slice(&0u32.to_be_bytes()); // addresses
        out.extend_from_slice(&0u32.to_be_bytes()); // authdata
        data(&mut out, &encode(&c.ticket)?);
        data(&mut out, &[]); // second ticket
    }
    Ok(out)
}

/// Write the cache to `path`, replacing it atomically, readable by its owner only.
pub fn write_ccache(path: &Path, default: (&Principal, &str), creds: &[Credential]) -> Result<()> {
    let bytes = encode_ccache(default, creds)?;
    let mut name = path.as_os_str().to_owned();
    name.push(format!(".netget-tmp-{:08x}", rand::random::<u32>()));
    let tmp = std::path::PathBuf::from(name);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let written = (|| -> std::io::Result<()> {
        let mut file = options.open(&tmp)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        std::fs::rename(&tmp, path)
    })();
    if written.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    written.with_context(|| format!("cannot write the credential cache {}", path.display()))
}
