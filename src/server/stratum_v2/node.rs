//! A Bitcoin Core node over JSON-RPC, for the server roles that have one configured
//! (`bitcoin_rpc_url`, `bitcoin_rpc_user`, `bitcoin_rpc_password`).
//!
//! Two calls, nothing else: the tip a block may build on next (`getmininginfo`'s `next`, which
//! names the height and the nbits the next block must carry, and the hash of the block below
//! it), and `submitblock`. The job declarator checks a declaration against the first, the pool
//! checks a custom job against what the job declarator recorded, and every role hands the
//! blocks it verified to the second. Responses are read up to `MAX_RESPONSE` bytes and every
//! call has a deadline; the password is never logged.
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value};
use std::time::Duration;

/// How long one RPC call may take.
pub const RPC_TIMEOUT: Duration = Duration::from_secs(15);
/// The largest response body read. The two calls answer in well under a kilobyte.
pub const MAX_RESPONSE: usize = 64 * 1024;

/// What the next block must build on: the tip's hash (internal byte order, as a header and
/// U256 carry it), the next block's height and its nbits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tip {
    pub prev_hash: [u8; 32],
    pub height: u32,
    pub nbits: u32,
}

/// A configured node.
pub struct Node {
    url: String,
    user: Option<String>,
    password: Option<String>,
    client: reqwest::Client,
}

impl std::fmt::Debug for Node {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Node").field("url", &self.url).finish()
    }
}

impl Node {
    pub fn new(url: &str, user: Option<String>, password: Option<String>) -> Result<Self> {
        let parsed = reqwest::Url::parse(url)
            .with_context(|| format!("bitcoin_rpc_url {url:?} is not a URL"))?;
        ensure!(
            matches!(parsed.scheme(), "http" | "https") && parsed.host_str().is_some(),
            "bitcoin_rpc_url must be an http:// or https:// URL with a host"
        );
        ensure!(
            parsed.username().is_empty() && parsed.password().is_none(),
            "put the RPC credentials in bitcoin_rpc_user and bitcoin_rpc_password, not in the URL"
        );
        ensure!(
            user.is_some() == password.is_some(),
            "bitcoin_rpc_user and bitcoin_rpc_password go together"
        );
        Ok(Self {
            url: url.to_string(),
            user,
            password,
            client: crate::llm::ollama_client::client_for_endpoint_with_timeout(url, RPC_TIMEOUT),
        })
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    /// One JSON-RPC call; the `result`, or the node's error message.
    pub async fn call(&self, method: &str, params: Value) -> Result<Value> {
        let mut request = self
            .client
            .post(&self.url)
            .json(&json!({"jsonrpc": "1.0", "id": "netget", "method": method, "params": params}));
        if let (Some(u), Some(p)) = (&self.user, &self.password) {
            request = request.basic_auth(u, Some(p));
        }
        let mut response = tokio::time::timeout(RPC_TIMEOUT, request.send())
            .await
            .context("the Bitcoin Core RPC call timed out")?
            .with_context(|| format!("Bitcoin Core RPC {method}"))?;
        let status = response.status();
        let mut body = Vec::new();
        while let Some(chunk) = tokio::time::timeout(RPC_TIMEOUT, response.chunk())
            .await
            .context("the Bitcoin Core RPC response timed out")??
        {
            ensure!(
                body.len() + chunk.len() <= MAX_RESPONSE,
                "the Bitcoin Core RPC response to {method} is over {MAX_RESPONSE} bytes"
            );
            body.extend_from_slice(&chunk);
        }
        let v: Value = serde_json::from_slice(&body).with_context(|| {
            format!("Bitcoin Core answered {method} with HTTP {status} and no JSON")
        })?;
        if let Some(e) = v.get("error").filter(|e| !e.is_null()) {
            bail!(
                "Bitcoin Core refused {method}: {}",
                crate::utils::sanitize::strip_controls(
                    e["message"]
                        .as_str()
                        .unwrap_or("an error without a message")
                )
            );
        }
        ensure!(
            status.is_success(),
            "Bitcoin Core answered {method} with HTTP {status}"
        );
        Ok(v["result"].clone())
    }

    /// The tip the next block builds on. `getmininginfo.next` (Bitcoin Core 29 and later) names
    /// the next block's height and nbits, which at a retarget boundary or on testnet differ
    /// from the tip's own; the hash is the block one below that height.
    pub async fn tip(&self) -> Result<Tip> {
        let info = self.call("getmininginfo", json!([])).await?;
        let next = &info["next"];
        let height = next["height"]
            .as_u64()
            .context("getmininginfo has no next.height (Bitcoin Core 29 or later is needed)")?;
        let height = u32::try_from(height).context("next.height is out of range")?;
        ensure!(
            height >= 1,
            "getmininginfo named height 0 as the next block"
        );
        let nbits = u32::from_str_radix(next["bits"].as_str().context("next.bits is missing")?, 16)
            .context("next.bits is not 8 hex digits")?;
        let hash = self
            .call("getblockhash", json!([height - 1]))
            .await?
            .as_str()
            .context("getblockhash returned no hash")?
            .to_string();
        let prev_hash = super::wire::parse_display_hash(Some(&hash))?;
        Ok(Tip {
            prev_hash,
            height,
            nbits,
        })
    }

    /// Hand a block to the node. None when it was accepted; otherwise the node's reason
    /// (`duplicate`, `inconclusive`, `high-hash`, …).
    pub async fn submit_block(&self, block: &[u8]) -> Result<Option<String>> {
        let result = self
            .call("submitblock", json!([hex::encode(block)]))
            .await?;
        Ok(result.as_str().map(crate::utils::sanitize::strip_controls))
    }
}
