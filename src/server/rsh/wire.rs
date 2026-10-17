//! The BSD r-services' wire, shared by the rsh, rexec and rlogin servers and clients.
//!
//! All three open with the same handshake, `rcmd(3)`'s: NUL-terminated ASCII fields, the first
//! of which names the port of an optional second (stderr) connection.
//!
//! | service | port | fields after the stderr port |
//! |---|---|---|
//! | rexec | 512 | user, password, command |
//! | rlogin | 513 | client user, server user, `terminal/speed` (stderr port always empty) |
//! | rsh | 514 | client user, server user, command |
//!
//! The server answers with one status byte: `\0` (go ahead) or `\1` followed by a line of
//! text ending in a newline (refused). rsh and rexec then stream the command's standard output
//! on the main connection and its standard error on the second one (or the main one when the
//! client asked for none), and close; neither protocol carries an exit status. rlogin becomes a
//! terminal session: the client sends keystrokes, a window size as the in-band sequence
//! `FF FF 's' 's'` + rows, cols, x pixels, y pixels (four big-endian `u16`s), and the server
//! sends output plus single urgent (TCP out-of-band) control bytes.
//!
//! Everything a peer declares is bounded here: each field has a cap, the port field must be
//! decimal and at most five digits, the window message is matched exactly and a partial one is
//! held for at most eleven bytes, and the line editor never holds more than [`MAX_LINE_BYTES`].
//! None of the parsers recurses.
use std::time::Duration;

/// rexec's well-known port (`exec` in `/etc/services`).
pub const REXEC_PORT: u16 = 512;
/// rlogin's well-known port (`login`).
pub const RLOGIN_PORT: u16 = 513;
/// rsh's well-known port (`shell`).
pub const RSH_PORT: u16 = 514;

/// Status byte: the server accepted the request.
pub const STATUS_OK: u8 = 0;
/// Status byte: the server refused, and a line of text follows.
pub const STATUS_ERROR: u8 = 1;

/// Digits in the stderr-port field: "65535" is the longest legitimate value.
pub const MAX_PORT_FIELD: usize = 5;
/// A user name, either side. BSD's `rshd` held sixteen bytes; Linux allows 32 and NIS-era
/// systems longer, so 256 refuses nothing real and bounds what a stranger can make us hold.
pub const MAX_USER: usize = 256;
/// rexec's password field.
pub const MAX_PASSWORD: usize = 256;
/// A command line. `rshd`'s historical bound was `NCARGS`; 64 KiB covers any command a person
/// types and is what a peer can make the server buffer before anything is decided.
pub const MAX_COMMAND: usize = 64 * 1024;
/// rlogin's `terminal/speed` field (`xterm-256color/38400` is 20 bytes).
pub const MAX_TERMINAL: usize = 64;
/// The whole handshake at its largest: every field at its cap plus its NUL.
pub const MAX_HANDSHAKE: usize = MAX_PORT_FIELD + 2 * MAX_USER + MAX_COMMAND + 4;
/// The longest refusal line either side sends or accepts.
pub const MAX_ERROR_LINE: usize = 1024;
/// One rlogin line, in either role.
pub const MAX_LINE_BYTES: usize = 8192;

/// How long a peer has to complete the handshake. `rshd` and `rexecd` set `alarm(60)` around
/// the same reads.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(60);
/// How long opening the stderr connection may take, from either end.
pub const STDERR_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// The lowest port `rresvport(3)` hands out, and the floor of the "reserved" range the
/// r-services trust.
pub const RESERVED_LOW: u16 = 512;
/// The highest reserved port (`IPPORT_RESERVED - 1`).
pub const RESERVED_HIGH: u16 = 1023;

/// Whether a source port is one only root could have bound — the r-services' whole idea of
/// proving which user on the client host is asking (`rshd` and `rlogind` refuse anything else).
pub fn is_reserved(port: u16) -> bool {
    (RESERVED_LOW..=RESERVED_HIGH).contains(&port)
}

/// Where a NUL-terminated field stands in a buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldScan {
    /// The field is `buf[..len]`; its NUL is at `buf[len]`.
    Complete(usize),
    /// No NUL yet, and fewer than `max` bytes: read more.
    NeedMore,
    /// More than `max` bytes with no NUL among them.
    TooLong,
}

/// Find the field at the start of `buf`, at most `max` bytes before its NUL.
pub fn split_field(buf: &[u8], max: usize) -> FieldScan {
    match buf.iter().take(max + 1).position(|b| *b == 0) {
        Some(len) => FieldScan::Complete(len),
        None if buf.len() > max => FieldScan::TooLong,
        None => FieldScan::NeedMore,
    }
}

/// The stderr-port field: empty or `0` for none, otherwise a decimal port.
///
/// `rshd` folds any byte into the number (`port * 10 + c - '0'`); a non-digit here is refused
/// instead, so the field cannot smuggle anything into the connect-back.
pub fn parse_port(field: &[u8]) -> Result<Option<u16>, &'static str> {
    if field.is_empty() {
        return Ok(None);
    }
    if field.len() > MAX_PORT_FIELD || !field.iter().all(u8::is_ascii_digit) {
        return Err("netget: the stderr port is not a decimal port number");
    }
    let n: u32 = std::str::from_utf8(field)
        .ok()
        .and_then(|s| s.parse().ok())
        .ok_or("netget: the stderr port is not a decimal port number")?;
    match n {
        0 => Ok(None),
        1..=65535 => Ok(Some(n as u16)),
        _ => Err("netget: the stderr port is above 65535"),
    }
}

/// rlogin's third field, `terminal/speed` (`xterm/38400`). The speed is absent when the field
/// has no `/` or what follows is not a number.
pub fn parse_terminal(field: &str) -> (String, Option<u32>) {
    match field.rsplit_once('/') {
        Some((term, speed)) => match speed.parse::<u32>() {
            Ok(n) => (term.to_string(), Some(n)),
            Err(_) => (field.to_string(), None),
        },
        None => (field.to_string(), None),
    }
}

/// The NUL-terminated encoding of a handshake: each field followed by its NUL.
pub fn encode_fields(fields: &[&str]) -> Vec<u8> {
    let mut out = Vec::new();
    for f in fields {
        out.extend_from_slice(f.as_bytes());
        out.push(0);
    }
    out
}

/// A field a peer must not send: an embedded NUL would end it early and shift every field
/// after it.
pub fn check_field(value: &str, max: usize, what: &str) -> anyhow::Result<()> {
    anyhow::ensure!(!value.contains('\0'), "{what} may not contain a NUL byte");
    anyhow::ensure!(
        value.len() <= max,
        "{what} is longer than {max} bytes ({})",
        value.len()
    );
    Ok(())
}

/// A refusal: `\1`, the text, a newline. The text is one line, with controls replaced, cut to
/// [`MAX_ERROR_LINE`] characters. rlogin's ends `\r\n` because the client's terminal is raw.
pub fn refusal(text: &str, crlf: bool) -> Vec<u8> {
    let line = crate::utils::sanitize::token(text, MAX_ERROR_LINE);
    let mut out = vec![STATUS_ERROR];
    out.extend_from_slice(line.as_bytes());
    out.extend_from_slice(if crlf { b"\r\n" } else { b"\n" });
    out
}

/// The refusal line for a handshake field that ran past its cap. Fixed text per field, so
/// nothing a peer sent or an error produced can reach the line.
pub fn field_too_long(field: &str) -> &'static str {
    match field {
        "stderr port" => "netget: stderr port too long",
        "leading NUL" => "netget: rlogin takes no stderr port",
        "client user" => "netget: client user too long",
        "server user" => "netget: server user too long",
        "user" => "netget: user too long",
        "password" => "netget: password too long",
        "command" => "netget: command too long",
        "terminal" => "netget: terminal too long",
        _ => "netget: handshake field too long",
    }
}

/// What the status byte and anything after it say, as a client reads them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status {
    /// `\0`: accepted.
    Accepted,
    /// `\1` and the line that followed it (sanitised, without its newline).
    Refused(String),
    /// Anything else in the status position: not an r-service answer.
    Garbled(u8),
}

/// Read a refusal line from what followed a `\1`: up to the first `\n`, at most
/// [`MAX_ERROR_LINE`] bytes. `None` while no newline has arrived and the line is short.
pub fn refusal_line(after: &[u8], at_eof: bool) -> Option<String> {
    let end = after.iter().position(|b| *b == b'\n');
    let raw = match end {
        Some(i) => &after[..i],
        None if at_eof || after.len() >= MAX_ERROR_LINE => {
            &after[..after.len().min(MAX_ERROR_LINE)]
        }
        None => return None,
    };
    let text = String::from_utf8_lossy(raw);
    Some(crate::utils::sanitize::token(&text, MAX_ERROR_LINE))
}

// ---------------------------------------------------------------------------------------------
// rlogin
// ---------------------------------------------------------------------------------------------

/// The urgent byte a server sends to ask for the window size (`TIOCPKT_WINDOW`).
pub const TIOCPKT_WINDOW: u8 = 0x80;
/// Urgent: discard output up to the mark (`TIOCPKT_FLUSHWRITE`), sent on an interrupt.
pub const TIOCPKT_FLUSHWRITE: u8 = 0x02;
/// Urgent: the terminal is in raw mode, ^S/^Q are data (`TIOCPKT_NOSTOP`).
pub const TIOCPKT_NOSTOP: u8 = 0x10;
/// Urgent: the terminal is cooked, the client may handle ^S/^Q (`TIOCPKT_DOSTOP`).
pub const TIOCPKT_DOSTOP: u8 = 0x20;

/// The window-size message's first four bytes.
pub const WINDOW_MAGIC: [u8; 4] = [0xFF, 0xFF, b's', b's'];
/// The whole message: magic plus four `u16`s.
pub const WINDOW_MESSAGE_LEN: usize = 12;

/// A terminal's size as rlogin carries it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct WindowSize {
    pub rows: u16,
    pub cols: u16,
    pub xpixel: u16,
    pub ypixel: u16,
}

impl WindowSize {
    pub fn encode(&self) -> [u8; WINDOW_MESSAGE_LEN] {
        let mut out = [0u8; WINDOW_MESSAGE_LEN];
        out[..4].copy_from_slice(&WINDOW_MAGIC);
        out[4..6].copy_from_slice(&self.rows.to_be_bytes());
        out[6..8].copy_from_slice(&self.cols.to_be_bytes());
        out[8..10].copy_from_slice(&self.xpixel.to_be_bytes());
        out[10..12].copy_from_slice(&self.ypixel.to_be_bytes());
        out
    }

    /// The message at the start of `buf`, which must hold all twelve bytes.
    pub fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() < WINDOW_MESSAGE_LEN || buf[..4] != WINDOW_MAGIC {
            return None;
        }
        let u = |i: usize| u16::from_be_bytes([buf[i], buf[i + 1]]);
        Some(Self {
            rows: u(4),
            cols: u(6),
            xpixel: u(8),
            ypixel: u(10),
        })
    }
}

/// Separates a client's window-size messages from its keystrokes.
///
/// `rlogind` scans each read for `FF FF` and, when `'s' 's'` and eight more bytes follow,
/// takes the twelve bytes as a window size. This does the same across reads: a message split
/// over two reads is held (never more than eleven bytes) until it is whole, and `FF FF`
/// followed by anything but `'s' 's'` is ordinary data.
#[derive(Debug, Default)]
pub struct RloginInput {
    held: Vec<u8>,
}

impl RloginInput {
    /// Feed what arrived; returns the keystroke bytes and every window size found, in order.
    pub fn feed(&mut self, bytes: &[u8]) -> (Vec<u8>, Vec<WindowSize>) {
        let mut buf = std::mem::take(&mut self.held);
        buf.extend_from_slice(bytes);
        let mut data = Vec::with_capacity(buf.len());
        let mut sizes = Vec::new();
        let mut i = 0;
        while i < buf.len() {
            if buf[i] != 0xFF {
                data.push(buf[i]);
                i += 1;
                continue;
            }
            let rest = &buf[i..];
            // Could this be the start of a message that has not fully arrived yet?
            let prefix = rest.len().min(4);
            if rest.len() < WINDOW_MESSAGE_LEN && rest[..prefix] == WINDOW_MAGIC[..prefix] {
                self.held = rest.to_vec();
                break;
            }
            if let Some(size) = WindowSize::decode(rest) {
                sizes.push(size);
                i += WINDOW_MESSAGE_LEN;
            } else {
                data.push(0xFF);
                i += 1;
            }
        }
        (data, sizes)
    }

    /// Bytes held as a possible partial message.
    pub fn held(&self) -> usize {
        self.held.len()
    }
}

/// What the server-side line editor makes of a keystroke run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LineEvent {
    /// Bytes to echo to the terminal.
    Echo(Vec<u8>),
    /// A complete line, without its terminator.
    Line(String),
    /// ^C: the line was discarded.
    Interrupt,
    /// ^D on an empty line.
    Eof,
    /// [`MAX_LINE_BYTES`] arrived with no end of line.
    TooLong,
}

/// The line discipline a pty's cooked mode would apply, done in Rust because there is no pty:
/// an rlogin client sends every keystroke raw and expects the server to echo it.
///
/// Enter is CR, which a client may follow with LF or NUL (both swallowed); LF alone also ends a
/// line. DEL and BS erase a character (a whole UTF-8 character), ^U the line, ^C interrupts,
/// ^D on an empty line is end of input. Other control characters are dropped; tab is kept.
/// With echo off (a password prompt) nothing is echoed but the line's end.
#[derive(Debug)]
pub struct LineEditor {
    line: Vec<u8>,
    pub echo: bool,
    after_cr: bool,
}

impl Default for LineEditor {
    fn default() -> Self {
        Self {
            line: Vec::new(),
            echo: true,
            after_cr: false,
        }
    }
}

impl LineEditor {
    pub fn feed(&mut self, data: &[u8]) -> Vec<LineEvent> {
        let mut out = Vec::new();
        let mut echo = Vec::new();
        let flush = |echo: &mut Vec<u8>, out: &mut Vec<LineEvent>| {
            if !echo.is_empty() {
                out.push(LineEvent::Echo(std::mem::take(echo)));
            }
        };
        for &b in data {
            let after_cr = std::mem::replace(&mut self.after_cr, false);
            match b {
                b'\n' | 0 if after_cr => {}
                b'\r' | b'\n' => {
                    self.after_cr = b == b'\r';
                    echo.extend_from_slice(b"\r\n");
                    flush(&mut echo, &mut out);
                    let line =
                        String::from_utf8_lossy(&std::mem::take(&mut self.line)).into_owned();
                    out.push(LineEvent::Line(line));
                }
                0x7F | 0x08 => {
                    if self.line.is_empty() {
                        continue;
                    }
                    // Remove one character, continuation bytes and all.
                    while let Some(last) = self.line.pop() {
                        if last & 0xC0 != 0x80 {
                            break;
                        }
                    }
                    if self.echo {
                        echo.extend_from_slice(b"\x08 \x08");
                    }
                }
                0x15 => {
                    if self.echo && !self.line.is_empty() {
                        echo.extend_from_slice(b"\r\n");
                    }
                    self.line.clear();
                }
                0x03 => {
                    self.line.clear();
                    echo.extend_from_slice(b"^C\r\n");
                    flush(&mut echo, &mut out);
                    out.push(LineEvent::Interrupt);
                }
                0x04 => {
                    if self.line.is_empty() {
                        flush(&mut echo, &mut out);
                        out.push(LineEvent::Eof);
                    }
                }
                b'\t' | 0x20..=0x7E | 0x80..=0xFF => {
                    if self.line.len() >= MAX_LINE_BYTES {
                        flush(&mut echo, &mut out);
                        out.push(LineEvent::TooLong);
                        self.line.clear();
                        return out;
                    }
                    self.line.push(b);
                    if self.echo {
                        echo.push(b);
                    }
                }
                _ => {}
            }
        }
        flush(&mut echo, &mut out);
        out
    }

    /// Bytes typed on the line so far.
    pub fn pending(&self) -> usize {
        self.line.len()
    }
}

/// Text written to a raw terminal: every `\n` not already preceded by `\r` becomes `\r\n`, as
/// a pty's `ONLCR` would make it.
pub fn crlf(text: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(text.len() + 8);
    let mut prev = 0u8;
    for &b in text.as_bytes() {
        if b == b'\n' && prev != b'\r' {
            out.push(b'\r');
        }
        out.push(b);
        prev = b;
    }
    out
}

// ---------------------------------------------------------------------------------------------
// Sockets
// ---------------------------------------------------------------------------------------------

/// Connect to `target`, from a reserved source port when this process may bind one.
///
/// Returns the stream and whether its source port is reserved. Ports are tried from 1023
/// down, as `rresvport(3)` does; a port in use (or whose four-tuple with `target` is still in
/// TIME_WAIT) moves to the next. Permission denied on the first attempt means this process
/// cannot bind any of them, and the connection is made from an ordinary port instead — which a
/// stock `rshd`/`rlogind` will refuse, and the caller says so.
pub async fn connect_maybe_reserved(
    target: std::net::SocketAddr,
    want_reserved: bool,
) -> std::io::Result<(tokio::net::TcpStream, bool)> {
    use tokio::net::TcpSocket;
    let fresh = || {
        if target.is_ipv4() {
            TcpSocket::new_v4()
        } else {
            TcpSocket::new_v6()
        }
    };
    if want_reserved {
        let unspecified: std::net::IpAddr = if target.is_ipv4() {
            std::net::Ipv4Addr::UNSPECIFIED.into()
        } else {
            std::net::Ipv6Addr::UNSPECIFIED.into()
        };
        for port in (RESERVED_LOW..=RESERVED_HIGH).rev() {
            let socket = fresh()?;
            match socket.bind(std::net::SocketAddr::new(unspecified, port)) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => break,
                Err(_) => continue,
            }
            match socket.connect(target).await {
                Ok(stream) => return Ok((stream, true)),
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::AddrInUse | std::io::ErrorKind::AddrNotAvailable
                    ) =>
                {
                    continue
                }
                Err(e) => return Err(e),
            }
        }
    }
    let stream = fresh()?.connect(target).await?;
    let reserved = stream.local_addr().map(|a| is_reserved(a.port()))?;
    Ok((stream, reserved))
}

/// Pending connections the stderr listener holds. `rcmd(3)` listens with 1, which lets a
/// stranger who connects first fill the queue (macOS then resets the server's own connection):
/// the client skips connections from anywhere but the server, so it needs room to reach it.
pub const STDERR_BACKLOG: u32 = 8;

/// A listener on `ip` for the stderr connection a client asks its server to open: on a
/// reserved port when this process may bind one (`rshd` requires it), otherwise on any.
pub async fn listen_maybe_reserved(
    ip: std::net::IpAddr,
    want_reserved: bool,
) -> std::io::Result<tokio::net::TcpListener> {
    use tokio::net::TcpSocket;
    let fresh = || {
        if ip.is_ipv4() {
            TcpSocket::new_v4()
        } else {
            TcpSocket::new_v6()
        }
    };
    if want_reserved {
        for port in (RESERVED_LOW..=RESERVED_HIGH).rev() {
            let socket = fresh()?;
            match socket.bind(std::net::SocketAddr::new(ip, port)) {
                Ok(()) => return socket.listen(STDERR_BACKLOG),
                Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => break,
                Err(_) => continue,
            }
        }
    }
    let socket = fresh()?;
    socket.bind(std::net::SocketAddr::new(ip, 0))?;
    socket.listen(STDERR_BACKLOG)
}
