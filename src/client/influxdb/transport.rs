use crate::server::influxdb::codec::{self, WriteBatch};
use anyhow::{ensure, Context, Result};
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::{
    client::conn::http1,
    header::{
        AUTHORIZATION, CONNECTION, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, HOST,
        RETRY_AFTER, TRANSFER_ENCODING,
    },
    Request, Uri,
};
use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};
use std::time::Duration;
pub const IO_TIMEOUT: Duration = Duration::from_secs(10);
pub const MAX_RESPONSE_BYTES: usize = 64 * 1024;
#[derive(Clone)]
pub struct Origin {
    pub authority: String,
    pub connect_addr: String,
}
impl Origin {
    pub fn parse(value: &str) -> Result<Self> {
        ensure!(
            !value.contains(['#', '@']),
            "HTTP origin cannot contain credentials/fragment"
        );
        let value = if value.starts_with("http://") {
            value.to_string()
        } else {
            format!("http://{value}")
        };
        let uri: Uri = value.parse().context("invalid HTTP origin")?;
        ensure!(
            uri.scheme_str() == Some("http")
                && uri.query().is_none()
                && matches!(uri.path(), "" | "/"),
            "cleartext HTTP origin only, without path/query"
        );
        let authority = uri.authority().context("HTTP host required")?;
        ensure!(authority.as_str().len() <= 1024, "HTTP origin byte limit");
        let host = authority.host();
        let connect_addr = format!("{}:{}", host, authority.port_u16().unwrap_or(8086));
        Ok(Self {
            authority: authority.as_str().to_string(),
            connect_addr,
        })
    }
}
pub(crate) fn query(value: &str) -> String {
    let mut out = String::new();
    for b in value.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            out.push(b as char);
        } else {
            use std::fmt::Write;
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WriteError {
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accepted_points: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rejected_points: Option<usize>,
}
#[derive(Clone, Debug, Serialize)]
pub struct WriteResponse {
    pub org: String,
    pub bucket: String,
    pub point_count: usize,
    pub status: u16,
    pub error: Option<WriteError>,
    pub retry_after_seconds: Option<u16>,
}
pub async fn write(
    origin: Origin,
    token: Option<String>,
    batch: WriteBatch,
    body: Vec<u8>,
) -> Result<WriteResponse> {
    tokio::time::timeout(IO_TIMEOUT, async move {
        let socket = tokio::net::TcpStream::connect(&origin.connect_addr).await?;
        let (mut sender, connection) = http1::Builder::new()
            .max_headers(64)
            .max_buf_size(32 * 1024)
            .handshake(TokioIo::new(socket))
            .await?;
        let mut request = Request::builder()
            .method("POST")
            .uri(format!(
                "/api/v2/write?org={}&bucket={}&precision={}",
                query(&batch.org),
                query(&batch.bucket),
                batch.precision.as_str()
            ))
            .header(HOST, &origin.authority)
            .header(CONNECTION, "close")
            .header(CONTENT_TYPE, "text/plain; charset=utf-8")
            .header(
                CONTENT_ENCODING,
                if batch.gzip { "gzip" } else { "identity" },
            );
        if let Some(token) = token {
            request = request.header(AUTHORIZATION, format!("Token {token}"));
        }
        let request = request.body(Full::new(Bytes::from(body)))?;
        let exchange = async {
            let response = sender.send_request(request).await?;
            let (parts, body) = response.into_parts();
            ensure!(
                parts.headers.get_all(RETRY_AFTER).iter().count() <= 1,
                "duplicate Retry-After"
            );
            let retry = parts
                .headers
                .get(RETRY_AFTER)
                .map(|h| {
                    h.to_str()
                        .context("invalid Retry-After")?
                        .parse::<u16>()
                        .context("only numeric Retry-After supported")
                })
                .transpose()?;
            if let Some(n) = retry {
                ensure!(
                    (1..=3600).contains(&n) && matches!(parts.status.as_u16(), 429 | 503),
                    "invalid Retry-After range/status"
                );
            }
            ensure!(
                parts.headers.get_all(CONTENT_ENCODING).iter().count() <= 1,
                "duplicate response encoding"
            );
            ensure!(
                parts
                    .headers
                    .get(CONTENT_ENCODING)
                    .map(|v| v.as_bytes() == b"identity")
                    .unwrap_or(true),
                "compressed HTTP responses unsupported"
            );
            let bytes = Limited::new(body, MAX_RESPONSE_BYTES)
                .collect()
                .await
                .map_err(|_| anyhow::anyhow!("invalid/oversized response body"))?
                .to_bytes();
            let status = parts.status.as_u16();
            let error = if status == 204 {
                ensure!(
                    bytes.is_empty()
                        && retry.is_none()
                        && parts
                            .headers
                            .get_all(CONTENT_LENGTH)
                            .iter()
                            .all(|h| h.as_bytes() == b"0")
                        && !parts.headers.contains_key(TRANSFER_ENCODING),
                    "204 response must be empty"
                );
                None
            } else {
                ensure!(
                    [400, 401, 403, 404, 405, 408, 413, 415, 422, 429, 500, 503].contains(&status),
                    "unsupported InfluxDB write status"
                );
                let ct = parts
                    .headers
                    .get(CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok())
                    .context("JSON error content type required")?;
                ensure!(
                    ct.split(';')
                        .next()
                        .is_some_and(|v| v.trim().eq_ignore_ascii_case("application/json")),
                    "JSON error content type required"
                );
                let error: WriteError =
                    serde_json::from_slice(&bytes).context("invalid InfluxDB JSON error")?;
                ensure!(
                    !error.code.is_empty()
                        && error.code.len() <= 128
                        && !crate::utils::sanitize::has_controls(&error.code)
                        && error.message.len() <= 1024
                        && !crate::utils::sanitize::has_controls(&error.message),
                    "error text limit"
                );
                if let Some(line) = error.line {
                    ensure!((1..=codec::MAX_LINES).contains(&line), "invalid error line");
                }
                for n in [error.accepted_points, error.rejected_points]
                    .into_iter()
                    .flatten()
                {
                    ensure!(n <= batch.points.len(), "invalid partial-write count");
                }
                if let (Some(a), Some(r)) = (error.accepted_points, error.rejected_points) {
                    ensure!(
                        a + r == batch.points.len(),
                        "inconsistent partial-write counts"
                    );
                }
                Some(error)
            };
            Ok::<_, anyhow::Error>(WriteResponse {
                org: batch.org,
                bucket: batch.bucket,
                point_count: batch.points.len(),
                status,
                error,
                retry_after_seconds: retry,
            })
        };
        tokio::pin!(connection);
        tokio::pin!(exchange);
        // Both futures own the single TCP exchange; dropping either path cancels IO.
        tokio::select! {
            result = &mut exchange => result,
            result = &mut connection => {
                result.context("HTTP driver failed")?;
                exchange.await
            }
        }
    })
    .await
    .context("InfluxDB exchange deadline exceeded")?
}
