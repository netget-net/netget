//! FTP data connections (RFC 959 §3.2-3.3, RFC 2428): the passive and active setup commands,
//! the representation type, and moving bytes over the second socket.
//!
//! Everything here is mechanics, not content. The setup verbs — `PASV`, `EPSV`, `PORT`,
//! `EPRT`, `TYPE`, `MODE`, `STRU`, `REST`, `PBSZ`, `PROT` — are answered by the server itself,
//! because their replies name a socket only the server can open or change how the server frames
//! bytes; a model inventing a `227` would point the client at a port nothing listens on. What
//! crosses the data connection (a listing, a file, an upload) is the handler's, through
//! `send_ftp_list` and `send_ftp_data`, and the protocol stores none of it.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use super::tls::MaybeTls;

/// How long the server waits for a data connection to open once a transfer starts: the client
/// connecting to the passive port, or the server's connect to the client's `PORT`/`EPRT`.
///
/// vsftpd's `accept_timeout` and `connect_timeout` are both 60 seconds. A client opens the data
/// connection as part of the transfer it asked for, with no human in between, so a minute is
/// generous. Past it the transfer is answered `425 Can't open data connection`. Overridable per
/// server with `data_connect_timeout_secs`.
pub const DATA_CONNECT_TIMEOUT: Duration = Duration::from_secs(60);

/// How long one read or write on an open data connection may make no progress.
///
/// vsftpd's `data_connection_timeout` default, 300 seconds. It bounds a peer that opens the data
/// connection and then neither sends (upload) nor reads (download); past it the transfer is
/// answered `426 Connection closed; transfer aborted`. Overridable per server with
/// `data_idle_timeout_secs`.
pub const DATA_IDLE_TIMEOUT: Duration = Duration::from_secs(300);

/// The largest upload (`STOR`/`APPE`) the server reads, counted in bytes as they cross the wire.
///
/// An upload is handed to the handler whole, in the `ftp_command` event, so the bound is on what
/// one event may carry into a prompt rather than on disk — there is no disk. 1 MiB is far past
/// what a model can read in one prompt and still small enough that 256 connections at the cap
/// stay in the hundreds of megabytes. A larger upload is answered
/// `552 Requested file action aborted: exceeded storage allocation` without consulting the
/// handler. Overridable per server with `max_upload_bytes`.
pub const MAX_UPLOAD_BYTES: usize = 1024 * 1024;

/// The largest binary upload whose bytes reach the handler, as `upload_hex`.
///
/// A file that is not UTF-8 text can only reach a model as hex, two characters per byte, so
/// this bounds what one event carries into a prompt at 128 KiB of hex. A larger binary upload
/// is still read (up to [`MAX_UPLOAD_BYTES`]) and still reaches the handler, described by its
/// size alone. Overridable per server with `max_hex_upload_bytes`.
pub const MAX_HEX_UPLOAD_BYTES: usize = 64 * 1024;

/// Write granularity on the data connection, so [`DATA_IDLE_TIMEOUT`] bounds a stall rather
/// than the length of a whole transfer.
const DATA_CHUNK: usize = 64 * 1024;

/// The data-connection bounds for one server, resolved from its startup parameters.
#[derive(Clone, Copy, Debug)]
pub struct DataLimits {
    pub connect: Duration,
    pub idle: Duration,
    pub max_upload: usize,
    pub max_hex_upload: usize,
}

impl DataLimits {
    pub fn resolve(
        connect_secs: Option<u64>,
        idle_secs: Option<u64>,
        max_upload: Option<u64>,
        max_hex_upload: Option<u64>,
    ) -> Self {
        Self {
            connect: connect_secs
                .map(Duration::from_secs)
                .unwrap_or(DATA_CONNECT_TIMEOUT),
            idle: idle_secs
                .map(Duration::from_secs)
                .unwrap_or(DATA_IDLE_TIMEOUT),
            max_upload: max_upload
                .map(|n| usize::try_from(n).unwrap_or(usize::MAX))
                .unwrap_or(MAX_UPLOAD_BYTES),
            max_hex_upload: max_hex_upload
                .map(|n| usize::try_from(n).unwrap_or(usize::MAX))
                .unwrap_or(MAX_HEX_UPLOAD_BYTES),
        }
    }
}

/// The representation type set by `TYPE` (RFC 959 §3.1.1). Stream mode and file structure are
/// the only mode and structure, so this is all the per-session transfer state there is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransferType {
    /// `TYPE A` (`A N`): NVT-ASCII, every line ending CRLF on the wire.
    Ascii,
    /// `TYPE I` (`L 8`): bytes unchanged.
    Image,
}

impl TransferType {
    /// The value of the event's `transfer_type` field.
    pub fn event_name(self) -> &'static str {
        match self {
            TransferType::Ascii => "ascii",
            TransferType::Image => "binary",
        }
    }

    fn reply_name(self) -> &'static str {
        match self {
            TransferType::Ascii => "ASCII",
            TransferType::Image => "BINARY",
        }
    }
}

/// A data connection the client has asked for and no transfer has used yet.
pub enum DataChannel {
    /// `PASV`/`EPSV`: a listener on the server's host, waiting for the client.
    Passive(TcpListener),
    /// `PORT`/`EPRT`: the client's address, which the server connects to when a transfer starts.
    Active(SocketAddr),
}

/// Per-session data-connection state.
pub struct DataState {
    pub transfer_type: TransferType,
    /// Consumed by the next transfer command, whatever its outcome: one channel, one transfer.
    pub channel: Option<DataChannel>,
    /// After `EPSV ALL` (RFC 2428 §4) every other setup command is refused.
    pub epsv_all: bool,
    /// The `REST` marker (RFC 3659 §5): a byte offset, consumed by the next transfer command.
    pub restart: Option<u64>,
    /// The control connection is TLS (`AUTH TLS` succeeded).
    pub control_tls: bool,
    /// `PBSZ` has been answered, which RFC 4217 §9 requires before `PROT`.
    pub pbsz: bool,
    /// `PROT P`: every data connection is TLS.
    pub protect: bool,
}

impl Default for DataState {
    fn default() -> Self {
        // RFC 959 §3.1.1.1: ASCII is the default type.
        Self {
            transfer_type: TransferType::Ascii,
            channel: None,
            epsv_all: false,
            restart: None,
            control_tls: false,
            pbsz: false,
            protect: false,
        }
    }
}

/// The addresses a session needs to set up a data connection.
#[derive(Clone, Copy, Debug)]
pub struct ControlEnds {
    /// The host the server was configured to bind. A passive listener binds here and nowhere
    /// wider: `0.0.0.0` only when that is the configured host.
    pub bind_ip: IpAddr,
    /// The control connection's local address: what a `227` reply advertises, since a
    /// wildcard bind host is not an address a client can connect to.
    pub local: SocketAddr,
    /// The control connection's peer. A data connection must come from, or go to, this host.
    pub peer: SocketAddr,
}

/// The commands the data-connection machinery owns, by verb.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verb {
    Pasv,
    Epsv,
    Port,
    Eprt,
    Type,
    Mode,
    Stru,
    List,
    Nlst,
    Mlsd,
    Retr,
    Stor,
    Appe,
    Stou,
    Rest,
    Abor,
    Auth,
    Pbsz,
    Prot,
    /// Everything else: answered by the handler on the control connection.
    Other,
}

impl Verb {
    pub fn of(command: &str) -> Self {
        let verb = command
            .split_whitespace()
            .next()
            .unwrap_or("")
            .to_ascii_uppercase();
        match verb.as_str() {
            "PASV" => Verb::Pasv,
            "EPSV" => Verb::Epsv,
            "PORT" => Verb::Port,
            "EPRT" => Verb::Eprt,
            "TYPE" => Verb::Type,
            "MODE" => Verb::Mode,
            "STRU" => Verb::Stru,
            "LIST" => Verb::List,
            "NLST" => Verb::Nlst,
            "MLSD" => Verb::Mlsd,
            "RETR" => Verb::Retr,
            "STOR" => Verb::Stor,
            "APPE" => Verb::Appe,
            "STOU" => Verb::Stou,
            "REST" => Verb::Rest,
            "ABOR" => Verb::Abor,
            "AUTH" => Verb::Auth,
            "PBSZ" => Verb::Pbsz,
            "PROT" => Verb::Prot,
            _ => Verb::Other,
        }
    }

    /// Answered by the server with no handler involved.
    pub fn is_setup(self) -> bool {
        matches!(
            self,
            Verb::Pasv
                | Verb::Epsv
                | Verb::Port
                | Verb::Eprt
                | Verb::Type
                | Verb::Mode
                | Verb::Stru
                | Verb::Rest
                | Verb::Pbsz
                | Verb::Prot
        )
    }

    /// Moves bytes over a data connection.
    pub fn is_transfer(self) -> bool {
        matches!(
            self,
            Verb::List
                | Verb::Nlst
                | Verb::Mlsd
                | Verb::Retr
                | Verb::Stor
                | Verb::Appe
                | Verb::Stou
        )
    }

    pub fn is_upload(self) -> bool {
        matches!(self, Verb::Stor | Verb::Appe | Verb::Stou)
    }

    /// Takes the `REST` marker (RFC 3659 §5.3: a restarted `RETR` or `STOR`).
    pub fn restarts(self) -> bool {
        matches!(self, Verb::Retr | Verb::Stor)
    }

    pub fn is_listing(self) -> bool {
        matches!(self, Verb::List | Verb::Nlst | Verb::Mlsd)
    }
}

/// The argument after the verb, trimmed.
fn argument(command: &str) -> &str {
    let command = command.trim();
    match command.find(char::is_whitespace) {
        Some(i) => command[i..].trim(),
        None => "",
    }
}

/// The reply to one setup command, and the `decision=` token the log line carries.
pub struct SetupReply {
    pub reply: String,
    pub decision: &'static str,
}

fn setup_reply(decision: &'static str, reply: String) -> SetupReply {
    SetupReply {
        reply: format!("{reply}\r\n"),
        decision,
    }
}

/// Answer a setup command, updating the session's data state.
pub async fn answer_setup(
    verb: Verb,
    command: &str,
    state: &mut DataState,
    ends: &ControlEnds,
) -> SetupReply {
    let arg = argument(command);
    match verb {
        Verb::Type => answer_type(arg, state),
        Verb::Mode => match arg.to_ascii_uppercase().as_str() {
            "S" => setup_reply("server_answer", "200 Mode set to S".into()),
            "" => setup_reply("refused_syntax", "501 MODE needs an argument".into()),
            _ => setup_reply(
                "refused_unsupported",
                "504 Only stream mode (S) is implemented".into(),
            ),
        },
        Verb::Stru => match arg.to_ascii_uppercase().as_str() {
            "F" => setup_reply("server_answer", "200 Structure set to F".into()),
            "" => setup_reply("refused_syntax", "501 STRU needs an argument".into()),
            _ => setup_reply(
                "refused_unsupported",
                "504 Only file structure (F) is implemented".into(),
            ),
        },
        Verb::Rest => answer_rest(arg, state),
        Verb::Pbsz => answer_pbsz(arg, state),
        Verb::Prot => answer_prot(arg, state),
        Verb::Pasv | Verb::Epsv | Verb::Port | Verb::Eprt => {
            // Any setup command replaces a channel no transfer has used yet.
            state.channel = None;
            match verb {
                Verb::Pasv => answer_pasv(state, ends).await,
                Verb::Epsv => answer_epsv(arg, state, ends).await,
                Verb::Port => answer_port(arg, state, ends),
                _ => answer_eprt(arg, state, ends),
            }
        }
        _ => setup_reply("refused_syntax", "500 Not a data-connection command".into()),
    }
}

fn answer_type(arg: &str, state: &mut DataState) -> SetupReply {
    let words: Vec<String> = arg
        .split_whitespace()
        .map(|w| w.to_ascii_uppercase())
        .collect();
    let words: Vec<&str> = words.iter().map(String::as_str).collect();
    let chosen = match words.as_slice() {
        ["A"] | ["A", "N"] => TransferType::Ascii,
        ["I"] | ["L", "8"] => TransferType::Image,
        [] => return setup_reply("refused_syntax", "501 TYPE needs an argument".into()),
        _ => {
            return setup_reply(
                "refused_unsupported",
                format!("504 TYPE {arg} is not implemented; use A or I"),
            )
        }
    };
    state.transfer_type = chosen;
    let letter = match chosen {
        TransferType::Ascii => "A",
        TransferType::Image => "I",
    };
    setup_reply("server_answer", format!("200 Type set to {letter}"))
}

/// `REST <offset>` in stream mode (RFC 3659 §5): the next `RETR` starts at that byte of the
/// file, or the next `STOR` carries the file from that byte on. `REST 0` clears the marker.
fn answer_rest(arg: &str, state: &mut DataState) -> SetupReply {
    let Ok(offset) = arg.parse::<u64>() else {
        return setup_reply(
            "refused_syntax",
            "501 REST needs a byte offset (stream mode)".into(),
        );
    };
    state.restart = (offset > 0).then_some(offset);
    setup_reply(
        "server_answer",
        format!("350 Restarting at {offset}. Send STOR or RETR to start the transfer"),
    )
}

/// `PBSZ` (RFC 4217 §8-9): meaningful only once the control connection is TLS, and always 0
/// for TLS, which is a stream.
fn answer_pbsz(arg: &str, state: &mut DataState) -> SetupReply {
    if !state.control_tls {
        return setup_reply("refused_sequence", "503 PBSZ needs AUTH TLS first".into());
    }
    if arg.is_empty() {
        return setup_reply("refused_syntax", "501 PBSZ needs an argument".into());
    }
    state.pbsz = true;
    setup_reply("server_answer", "200 PBSZ=0".into())
}

/// `PROT C` / `PROT P` (RFC 4217 §9): clear or TLS-protected data connections.
fn answer_prot(arg: &str, state: &mut DataState) -> SetupReply {
    if !state.control_tls {
        return setup_reply("refused_sequence", "503 PROT needs AUTH TLS first".into());
    }
    if !state.pbsz {
        return setup_reply("refused_sequence", "503 PROT needs PBSZ first".into());
    }
    match arg.to_ascii_uppercase().as_str() {
        "C" => {
            state.protect = false;
            setup_reply("server_answer", "200 Protection level set to C".into())
        }
        "P" => {
            state.protect = true;
            setup_reply("server_answer", "200 Protection level set to P".into())
        }
        "S" | "E" => setup_reply(
            "refused_unsupported",
            "536 Only PROT C and PROT P are supported with TLS".into(),
        ),
        "" => setup_reply("refused_syntax", "501 PROT needs an argument".into()),
        _ => setup_reply("refused_unsupported", "504 Unknown protection level".into()),
    }
}

/// Bind a passive listener on the configured host, on a port the OS picks.
async fn bind_passive(ends: &ControlEnds) -> std::io::Result<TcpListener> {
    TcpListener::bind(SocketAddr::new(ends.bind_ip, 0)).await
}

async fn answer_pasv(state: &mut DataState, ends: &ControlEnds) -> SetupReply {
    if state.epsv_all {
        return setup_reply(
            "refused_after_epsv_all",
            "501 PASV is not allowed after EPSV ALL".into(),
        );
    }
    // PASV can only name an IPv4 address (RFC 2428 §3 is EPSV's reason to exist).
    let IpAddr::V4(local) = ends.local.ip().to_canonical() else {
        return setup_reply(
            "refused_unsupported",
            "425 PASV cannot describe an IPv6 address; use EPSV".into(),
        );
    };
    let listener = match bind_passive(ends).await {
        Ok(l) => l,
        Err(_) => {
            return setup_reply(
                "refused_passive_bind",
                "425 Cannot open passive connection".into(),
            )
        }
    };
    let port = match listener.local_addr() {
        Ok(a) => a.port(),
        Err(_) => {
            return setup_reply(
                "refused_passive_bind",
                "425 Cannot open passive connection".into(),
            )
        }
    };
    state.channel = Some(DataChannel::Passive(listener));
    let o = local.octets();
    setup_reply(
        "server_answer",
        format!(
            "227 Entering Passive Mode ({},{},{},{},{},{})",
            o[0],
            o[1],
            o[2],
            o[3],
            port >> 8,
            port & 0xff
        ),
    )
}

/// The RFC 2428 network protocol number of an address: 1 for IPv4, 2 for IPv6.
fn family_number(ip: IpAddr) -> &'static str {
    match ip.to_canonical() {
        IpAddr::V4(_) => "1",
        IpAddr::V6(_) => "2",
    }
}

async fn answer_epsv(arg: &str, state: &mut DataState, ends: &ControlEnds) -> SetupReply {
    let family = family_number(ends.local.ip());
    match arg.to_ascii_uppercase().as_str() {
        "" => {}
        "ALL" => {
            state.epsv_all = true;
            return setup_reply("server_answer", "200 EPSV ALL ok".into());
        }
        a if a == family => {}
        "1" | "2" => {
            return setup_reply(
                "refused_unsupported",
                format!("522 Network protocol not supported, use ({family})"),
            )
        }
        _ => return setup_reply("refused_syntax", "501 Syntax error in EPSV".into()),
    }
    let listener = match bind_passive(ends).await {
        Ok(l) => l,
        Err(_) => {
            return setup_reply(
                "refused_passive_bind",
                "425 Cannot open passive connection".into(),
            )
        }
    };
    let port = match listener.local_addr() {
        Ok(a) => a.port(),
        Err(_) => {
            return setup_reply(
                "refused_passive_bind",
                "425 Cannot open passive connection".into(),
            )
        }
    };
    state.channel = Some(DataChannel::Passive(listener));
    setup_reply(
        "server_answer",
        format!("229 Entering Extended Passive Mode (|||{port}|)"),
    )
}

/// Accept an active-mode target only if it is the control connection's own peer, on an
/// unprivileged port.
///
/// Without the address check `PORT` is the FTP bounce attack (RFC 2577 §3): a client names a
/// third host and the server connects to it on the client's behalf. vsftpd's
/// `port_promiscuous=NO` is the same rule.
fn check_active_target(target: SocketAddr, ends: &ControlEnds) -> Result<(), &'static str> {
    if target.ip().to_canonical() != ends.peer.ip().to_canonical() {
        return Err("the address is not the client's own");
    }
    if target.port() < 1024 {
        return Err("the port is privileged");
    }
    Ok(())
}

fn answer_port(arg: &str, state: &mut DataState, ends: &ControlEnds) -> SetupReply {
    if state.epsv_all {
        return setup_reply(
            "refused_after_epsv_all",
            "501 PORT is not allowed after EPSV ALL".into(),
        );
    }
    let numbers: Option<Vec<u8>> = arg.split(',').map(|n| n.trim().parse().ok()).collect();
    let Some(n) = numbers.filter(|n| n.len() == 6) else {
        return setup_reply("refused_syntax", "501 Syntax error in PORT".into());
    };
    let target = SocketAddr::new(
        IpAddr::from([n[0], n[1], n[2], n[3]]),
        u16::from(n[4]) << 8 | u16::from(n[5]),
    );
    if check_active_target(target, ends).is_err() {
        return setup_reply("refused_port_bounce", "500 Illegal PORT command".into());
    }
    state.channel = Some(DataChannel::Active(target));
    setup_reply("server_answer", "200 PORT command successful".into())
}

fn answer_eprt(arg: &str, state: &mut DataState, ends: &ControlEnds) -> SetupReply {
    if state.epsv_all {
        return setup_reply(
            "refused_after_epsv_all",
            "501 EPRT is not allowed after EPSV ALL".into(),
        );
    }
    // `<d><proto><d><addr><d><port><d>`, the delimiter being the first character.
    let Some(delim) = arg.chars().next() else {
        return setup_reply("refused_syntax", "501 Syntax error in EPRT".into());
    };
    let parts: Vec<&str> = arg.split(delim).collect();
    let [_, proto, addr, port, _] = parts.as_slice() else {
        return setup_reply("refused_syntax", "501 Syntax error in EPRT".into());
    };
    let ip: Option<IpAddr> = match *proto {
        "1" => addr.parse::<std::net::Ipv4Addr>().ok().map(IpAddr::V4),
        "2" => addr.parse::<std::net::Ipv6Addr>().ok().map(IpAddr::V6),
        _ => {
            return setup_reply(
                "refused_unsupported",
                "522 Network protocol not supported, use (1,2)".into(),
            )
        }
    };
    let (Some(ip), Ok(port)) = (ip, port.parse::<u16>()) else {
        return setup_reply("refused_syntax", "501 Syntax error in EPRT".into());
    };
    let target = SocketAddr::new(ip, port);
    if check_active_target(target, ends).is_err() {
        return setup_reply("refused_port_bounce", "500 Illegal EPRT command".into());
    }
    state.channel = Some(DataChannel::Active(target));
    setup_reply("server_answer", "200 EPRT command successful".into())
}

/// The `150` that opens a transfer.
pub fn opening_reply(transfer_type: TransferType, what: &str) -> String {
    format!(
        "150 Opening {} mode data connection for {what}\r\n",
        transfer_type.reply_name()
    )
}

/// Open the data connection a transfer will use, within `limits.connect`, and with `tls`
/// (`PROT P`) complete its TLS handshake within the same deadline: a data connection is not
/// open until it can carry the file.
///
/// A passive connection from any host but the control connection's peer is dropped and the
/// wait goes on: otherwise another host that guessed the port could take the transfer
/// (vsftpd's `pasv_promiscuous=NO`).
pub async fn open(
    channel: DataChannel,
    ends: &ControlEnds,
    limits: &DataLimits,
    tls: Option<&tokio_rustls::TlsAcceptor>,
) -> Result<MaybeTls, String> {
    let deadline = tokio::time::Instant::now() + limits.connect;
    let tcp = connect(channel, ends, limits, deadline).await?;
    let Some(acceptor) = tls else {
        return Ok(MaybeTls::Plain(tcp));
    };
    match tokio::time::timeout_at(deadline, acceptor.accept(tcp)).await {
        Err(_) => Err(format!(
            "the data connection's TLS handshake did not complete within {}s",
            limits.connect.as_secs()
        )),
        Ok(Err(e)) => Err(format!("the data connection's TLS handshake failed: {e}")),
        Ok(Ok(stream)) => Ok(MaybeTls::Tls(Box::new(stream))),
    }
}

async fn connect(
    channel: DataChannel,
    ends: &ControlEnds,
    limits: &DataLimits,
    deadline: tokio::time::Instant,
) -> Result<TcpStream, String> {
    match channel {
        DataChannel::Passive(listener) => loop {
            match tokio::time::timeout_at(deadline, listener.accept()).await {
                Err(_) => {
                    return Err(format!(
                        "no data connection arrived within {}s",
                        limits.connect.as_secs()
                    ))
                }
                Ok(Err(e)) => return Err(format!("accept failed: {e}")),
                Ok(Ok((stream, from))) => {
                    if from.ip().to_canonical() == ends.peer.ip().to_canonical() {
                        return Ok(stream);
                    }
                    tracing::warn!(
                        "FTP data connection from {from} dropped: the control connection's peer \
                         is {}",
                        ends.peer
                    );
                }
            }
        },
        DataChannel::Active(target) => {
            match tokio::time::timeout_at(deadline, TcpStream::connect(target)).await {
                Err(_) => Err(format!(
                    "connecting to {target} took longer than {}s",
                    limits.connect.as_secs()
                )),
                Ok(Err(e)) => Err(format!("connecting to {target} failed: {e}")),
                Ok(Ok(stream)) => Ok(stream),
            }
        }
    }
}

/// Write `bytes` and close the data connection, each chunk within `idle`.
pub async fn send_all<S>(stream: &mut S, bytes: &[u8], idle: Duration) -> Result<(), String>
where
    S: AsyncWrite + Unpin,
{
    for chunk in bytes.chunks(DATA_CHUNK) {
        match tokio::time::timeout(idle, stream.write_all(chunk)).await {
            Err(_) => return Err(format!("the peer read nothing for {}s", idle.as_secs())),
            Ok(Err(e)) => return Err(format!("write failed: {e}")),
            Ok(Ok(())) => {}
        }
    }
    match tokio::time::timeout(idle, stream.shutdown()).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(format!("closing the data connection failed: {e}")),
        Err(_) => Err(format!(
            "closing the data connection took over {}s",
            idle.as_secs()
        )),
    }
}

/// How reading an upload ended.
pub enum Upload {
    /// The peer closed the data connection: this is the whole file, as it crossed the wire.
    Complete(Vec<u8>),
    /// More than `max_upload` bytes arrived; reading stopped there.
    TooLarge,
    /// The peer sent nothing for `idle`.
    Idle,
    Failed(String),
}

/// Read an upload to EOF, refusing more than `limits.max_upload` bytes.
///
/// On a TLS data connection EOF is the client's `close_notify`; rustls reports a TCP close
/// without one as an error, which is what a truncated upload looks like, so it is a failure
/// (`426`) rather than a complete file.
pub async fn receive_all<S>(stream: &mut S, limits: &DataLimits) -> Upload
where
    S: AsyncRead + Unpin,
{
    let mut data = Vec::new();
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        match tokio::time::timeout(limits.idle, stream.read(&mut buf)).await {
            Err(_) => return Upload::Idle,
            Ok(Err(e)) => return Upload::Failed(e.to_string()),
            Ok(Ok(0)) => return Upload::Complete(data),
            Ok(Ok(n)) => {
                if data.len() + n > limits.max_upload {
                    return Upload::TooLarge;
                }
                data.extend_from_slice(&buf[..n]);
            }
        }
    }
}

/// Local text to NVT-ASCII for a `TYPE A` download: every LF not already preceded by CR
/// becomes CRLF.
pub fn to_network_ascii(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len() + bytes.len() / 16);
    let mut previous = 0u8;
    for &b in bytes {
        if b == b'\n' && previous != b'\r' {
            out.push(b'\r');
        }
        out.push(b);
        previous = b;
    }
    out
}

/// NVT-ASCII to local text for a `TYPE A` upload: CRLF becomes LF. A CR not followed by LF is
/// data and is kept.
pub fn from_network_ascii(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\r' && bytes.get(i + 1) == Some(&b'\n') {
            i += 1;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    out
}
