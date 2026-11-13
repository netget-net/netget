//! Reading the FTP control connection one command line at a time.
//!
//! The reader keeps what it has read and not yet returned in a buffer of its own, and only ever
//! waits in [`AsyncReadExt::read`], which reads nothing when it is cancelled. That makes
//! [`ControlReader::read_line`] cancel-safe, which is what lets a transfer race the control
//! connection for an `ABOR` (`mod.rs`, `watch`) without losing a byte of whatever else the
//! client sent meanwhile; a line that is not `ABOR` is put back with [`ControlReader::unread`].

use std::time::Duration;

use tokio::io::{AsyncReadExt, ReadHalf};

use super::tls::MaybeTls;

/// The result of trying to read one control line.
pub enum CommandLine {
    /// A complete line. The trailing CRLF is still attached; the caller trims it.
    Line(String),
    /// The peer closed the control connection.
    Eof,
    /// The peer sent more than the line limit with no newline in it.
    TooLong,
}

/// Telnet's "interpret as command" byte (RFC 854). RFC 959 runs the control connection as a
/// Telnet session, and a client may put `IAC IP IAC DM` in front of `ABOR`.
const IAC: u8 = 0xFF;

/// The command line with any Telnet command sequence removed, decoded lossily: a stray
/// non-UTF-8 byte in a command is the peer's problem, answered by the handler, not a reason to
/// drop the connection without a reply.
fn decode(raw: &[u8]) -> String {
    let mut out = Vec::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        if raw[i] != IAC {
            out.push(raw[i]);
            i += 1;
            continue;
        }
        match raw.get(i + 1) {
            // IAC IAC is a data byte 0xFF.
            Some(&IAC) => {
                out.push(IAC);
                i += 2;
            }
            // WILL, WONT, DO, DONT carry an option byte.
            Some(251..=254) => i += 3,
            Some(_) => i += 2,
            None => i += 1,
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The control connection's read side.
pub struct ControlReader {
    /// Taken out for the length of an `AUTH TLS` handshake.
    half: Option<ReadHalf<MaybeTls>>,
    /// Read from the socket and not yet returned as a line.
    pending: Vec<u8>,
    eof: bool,
    /// An `ABOR\r` was taken without its `\n`; drop the `\n` when it comes.
    swallow_lf: bool,
}

impl ControlReader {
    pub fn new(half: ReadHalf<MaybeTls>) -> Self {
        Self {
            half: Some(half),
            pending: Vec::new(),
            eof: false,
            swallow_lf: false,
        }
    }

    /// Whether bytes the client sent are waiting that no line has returned yet.
    pub fn has_pending(&self) -> bool {
        !self.pending.is_empty()
    }

    pub fn take_half(&mut self) -> Option<ReadHalf<MaybeTls>> {
        self.half.take()
    }

    pub fn put_half(&mut self, half: ReadHalf<MaybeTls>) {
        self.half = Some(half);
    }

    /// Read once from the socket into the buffer. Cancel-safe.
    async fn fill(&mut self) -> std::io::Result<usize> {
        let half = self.half.as_mut().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "the FTP control connection is being upgraded to TLS",
            )
        })?;
        let mut chunk = [0u8; 4096];
        let n = half.read(&mut chunk).await?;
        if n == 0 {
            self.eof = true;
        } else {
            self.pending.extend_from_slice(&chunk[..n]);
        }
        Ok(n)
    }

    /// Drop the `\n` of an `ABOR\r` already taken, once it has arrived.
    fn drop_swallowed_lf(&mut self) {
        if self.swallow_lf && !self.pending.is_empty() {
            if self.pending[0] == b'\n' {
                self.pending.remove(0);
            }
            self.swallow_lf = false;
        }
    }

    /// A line already in the buffer, or the outcome that ends reading, without waiting.
    fn take_line(&mut self, max_len: usize) -> Option<(CommandLine, usize)> {
        self.drop_swallowed_lf();
        if let Some(idx) = self.pending.iter().position(|&b| b == b'\n') {
            let len = idx + 1;
            if len > max_len {
                self.pending.drain(..len);
                return Some((CommandLine::TooLong, len));
            }
            let raw: Vec<u8> = self.pending.drain(..len).collect();
            return Some((CommandLine::Line(decode(&raw)), len));
        }
        if self.pending.len() > max_len {
            let n = self.pending.len();
            self.pending.clear();
            return Some((CommandLine::TooLong, n));
        }
        if self.pending.last() == Some(&b'\r')
            && decode(&self.pending).trim().eq_ignore_ascii_case("ABOR")
        {
            // `ABOR\r` with its `\n` still to come: the `\n` was sent as TCP urgent data (python's
            // `ftplib.abort()` sends the whole line `MSG_OOB`, and the urgent byte is the last
            // one). With `SO_OOBINLINE` it is delivered in line, but a read stops at the urgent
            // mark, and tokio takes a short read to mean the socket is drained: the `\n` stays in
            // the kernel until the client sends something else. An `ABOR` cannot wait for that,
            // so the line is taken here and its `\n` dropped when it arrives.
            let n = self.pending.len();
            let line = decode(&self.pending);
            self.pending.clear();
            self.swallow_lf = true;
            return Some((CommandLine::Line(line), n));
        }
        if self.eof {
            // A trailing fragment with no newline is not a command; the peer hung up mid-line,
            // which is the same as hanging up.
            let n = self.pending.len();
            self.pending.clear();
            return Some((CommandLine::Eof, n));
        }
        None
    }

    /// Read one CRLF-terminated command, refusing to buffer more than `max_len` bytes of it.
    ///
    /// Returns the line and the number of bytes it took from the socket. Cancel-safe.
    pub async fn read_line(&mut self, max_len: usize) -> std::io::Result<(CommandLine, usize)> {
        loop {
            if let Some(outcome) = self.take_line(max_len) {
                return Ok(outcome);
            }
            self.fill().await?;
        }
    }

    /// Put a line [`read_line`](Self::read_line) returned back in front of everything else.
    pub fn unread(&mut self, line: &str) {
        let mut restored = line.as_bytes().to_vec();
        restored.append(&mut self.pending);
        self.pending = restored;
    }

    /// Complete command lines already here — buffered, or readable without waiting — up to
    /// `max`, each with the bytes it took, stopping before the first one `batchable` refuses.
    ///
    /// What a batch collects after the first command: everything a pipelining client sent
    /// while the model was answering. A zero deadline on a cancel-safe read never waits and
    /// never loses a byte. It stops at a partial line or one over `max_len`, leaving either for
    /// [`read_line`](Self::read_line) to read and report.
    pub async fn lines_already_here(
        &mut self,
        max: usize,
        max_len: usize,
        batchable: impl Fn(&str) -> bool,
    ) -> Vec<(String, usize)> {
        let mut lines = Vec::new();
        while lines.len() < max {
            self.drop_swallowed_lf();
            let Some(idx) = self.pending.iter().position(|&b| b == b'\n') else {
                if self.pending.len() > max_len {
                    break;
                }
                match tokio::time::timeout(Duration::ZERO, self.fill()).await {
                    Ok(Ok(n)) if n > 0 => continue,
                    _ => break,
                }
            };
            if idx >= max_len {
                break;
            }
            let line = decode(&self.pending[..=idx]);
            if !batchable(&line) {
                break;
            }
            self.pending.drain(..=idx);
            lines.push((line, idx + 1));
        }
        lines
    }
}
