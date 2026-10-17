//! rsh, rexec and rlogin servers from raw sockets: handshakes written byte by byte, every
//! refusal and bound, the stderr connection, the password check, the fail-closed paths, rlogin's
//! line editing, window size and urgent bytes, and tshark's dissectors over the bytes. No LLM:
//! the python policies in `support.rs` play the model.
use super::support::*;
use serde_json::json;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const FAIL_CLOSED: &[u8] = b"\x01netget: request could not be processed\n";

#[tokio::test]
async fn rsh_runs_a_trusted_command_with_stderr_on_a_connection_back_to_the_client() {
    let srv = start("rsh", policy(RSH_POLICY), None).await;
    let stderr_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let stderr_port = stderr_listener.local_addr().unwrap().port().to_string();
    let mut main = TcpStream::connect(("127.0.0.1", srv.port)).await.unwrap();
    // rcmd(3)'s order: the port, then wait for the server to connect, then the rest.
    main.write_all(&nul_fields(&[stderr_port.as_bytes()]))
        .await
        .unwrap();
    let (mut err, from) = tokio::time::timeout(Duration::from_secs(10), stderr_listener.accept())
        .await
        .expect("the server connects back before reading the user fields")
        .unwrap();
    assert_eq!(from.ip(), main.local_addr().unwrap().ip());
    main.write_all(&nul_fields(&[b"alice", b"alice", b"uname -a"]))
        .await
        .unwrap();
    let out = read_to_end(&mut main).await;
    assert_eq!(out, b"\0ran uname -a\n", "status byte, then stdout only");
    let mut stderr = Vec::new();
    err.read_to_end(&mut stderr).await.unwrap();
    assert_eq!(stderr, b"warn uname -a\n");

    let seen = events(&srv.state, srv.id, "rsh_command").await;
    assert_eq!(seen.len(), 1);
    let e = &seen[0];
    assert_eq!(e["client_user"], "alice");
    assert_eq!(e["server_user"], "alice");
    assert_eq!(e["command"], "uname -a");
    assert_eq!(e["client_address"], "127.0.0.1");
    assert_eq!(e["client_port"], main.local_addr().unwrap().port());
    assert_eq!(e["stderr_channel"], true);
    assert_eq!(
        e["reserved_source_port"],
        (512..=1023).contains(&main.local_addr().unwrap().port())
    );
}

#[tokio::test]
async fn rsh_without_a_stderr_port_sends_stderr_after_stdout_and_untrusted_pairs_are_refused() {
    let srv = start("rsh", policy(RSH_POLICY), None).await;
    let out = exchange(srv.port, &nul_fields(&[b"", b"alice", b"alice", b"id"])).await;
    assert_eq!(out, b"\0ran id\nwarn id\n");
    // "0" is no stderr connection too.
    let out = exchange(srv.port, &nul_fields(&[b"0", b"alice", b"alice", b"id"])).await;
    assert_eq!(out, b"\0ran id\nwarn id\n");
    let out = exchange(srv.port, &nul_fields(&[b"", b"mallory", b"alice", b"id"])).await;
    assert_eq!(
        out, b"\x01Permission denied.\n",
        "the model's refusal, nothing run"
    );
    let out = exchange(srv.port, &nul_fields(&[b"", b"alice", b"root", b"id"])).await;
    assert_eq!(out, b"\x01Permission denied.\n");
}

#[tokio::test]
async fn rsh_fails_closed_and_never_runs_as_trusted() {
    // No handler and an unreachable model: the backend fails.
    let srv = start("rsh", None, None).await;
    let out = exchange(srv.port, &nul_fields(&[b"", b"alice", b"alice", b"id"])).await;
    assert_eq!(out, FAIL_CLOSED);

    let srv = start("rsh", policy(RSH_POLICY), None).await;
    // The model answers nothing.
    let out = exchange(srv.port, &nul_fields(&[b"", b"alice", b"alice", b"silent"])).await;
    assert_eq!(out, FAIL_CLOSED);
    // The model answers something the executor refuses.
    let out = exchange(srv.port, &nul_fields(&[b"", b"alice", b"alice", b"bad"])).await;
    assert_eq!(out, FAIL_CLOSED);
    // Output past the 1 MiB cap is refused whole rather than cut.
    let out = exchange(srv.port, &nul_fields(&[b"", b"alice", b"alice", b"big"])).await;
    assert_eq!(out, FAIL_CLOSED);
}

#[tokio::test]
async fn handshake_fields_are_bounded_before_the_model_is_asked() {
    let srv = start("rsh", policy(RSH_POLICY), None).await;
    // Six digits: the port field holds at most five.
    let out = exchange(srv.port, b"123456\0alice\0alice\0id\0").await;
    assert_eq!(out, b"\x01netget: stderr port too long\n");
    let out = exchange(srv.port, b"12a\0alice\0alice\0id\0").await;
    assert_eq!(
        out,
        b"\x01netget: the stderr port is not a decimal port number\n"
    );
    let out = exchange(srv.port, b"70000\0alice\0alice\0id\0").await;
    assert_eq!(out, b"\x01netget: the stderr port is above 65535\n");
    // A user name of 256 bytes is accepted, 257 is not.
    let at = vec![b'a'; 256];
    let over = vec![b'a'; 257];
    let out = exchange(srv.port, &nul_fields(&[b"", &at, b"alice", b"id"])).await;
    assert_eq!(out, b"\x01Permission denied.\n");
    let out = exchange(srv.port, &nul_fields(&[b"", &over, b"alice", b"id"])).await;
    assert_eq!(out, b"\x01netget: client user too long\n");
    let out = exchange(srv.port, &nul_fields(&[b"", b"alice", &over, b"id"])).await;
    assert_eq!(out, b"\x01netget: server user too long\n");
    // A command of exactly 64 KiB is answered; one byte more is refused unread.
    let mut command = b"size ".to_vec();
    command.resize(64 * 1024, b'x');
    let out = exchange(srv.port, &nul_fields(&[b"", b"alice", b"alice", &command])).await;
    assert_eq!(out, b"\x0065536\n");
    command.push(b'x');
    let out = exchange(srv.port, &nul_fields(&[b"", b"alice", b"alice", &command])).await;
    assert_eq!(out, b"\x01netget: command too long\n");
    // Only the two in-bound requests reached the model.
    assert_eq!(events(&srv.state, srv.id, "rsh_command").await.len(), 2);
}

#[tokio::test]
async fn an_unreachable_stderr_port_refuses_the_request() {
    let srv = start("rsh", policy(RSH_POLICY), None).await;
    // A port nothing listens on.
    let free = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = free.local_addr().unwrap().port().to_string();
    drop(free);
    let out = exchange(
        srv.port,
        &nul_fields(&[port.as_bytes(), b"alice", b"alice", b"id"]),
    )
    .await;
    assert_eq!(out, b"\x01netget: cannot connect to the stderr port\n");
    assert!(events(&srv.state, srv.id, "rsh_command").await.is_empty());
}

/// The stderr connection goes to the address the request came from, never the server's own
/// or anyone else's: the client connects to the server on 127.0.0.1 *from* this host's
/// non-loopback address, listens for stderr there, and a decoy on 127.0.0.1 at the same port
/// — where the server itself is — must stay untouched.
#[tokio::test]
async fn the_stderr_connection_goes_only_to_the_clients_own_address() {
    let srv = start("rsh", policy(RSH_POLICY), None).await;
    let client_ip = non_loopback_address();
    let real = TcpListener::bind((client_ip, 0)).await.unwrap();
    let port = real.local_addr().unwrap().port();
    let decoy = TcpListener::bind(("127.0.0.1", port)).await.unwrap();
    let socket = tokio::net::TcpSocket::new_v4().unwrap();
    socket
        .bind(std::net::SocketAddr::new(client_ip, 0))
        .unwrap();
    let mut main = socket
        .connect(format!("127.0.0.1:{}", srv.port).parse().unwrap())
        .await
        .unwrap();
    let port_field = port.to_string();
    main.write_all(&nul_fields(&[
        port_field.as_bytes(),
        b"alice",
        b"alice",
        b"pwd",
    ]))
    .await
    .unwrap();
    let (mut err, _) = tokio::time::timeout(Duration::from_secs(10), real.accept())
        .await
        .expect("the client's own address is connected")
        .unwrap();
    let out = read_to_end(&mut main).await;
    assert_eq!(out, b"\0ran pwd\n");
    let mut stderr = Vec::new();
    err.read_to_end(&mut stderr).await.unwrap();
    assert_eq!(stderr, b"warn pwd\n");
    assert!(
        tokio::time::timeout(Duration::from_millis(500), decoy.accept())
            .await
            .is_err(),
        "nothing may connect to the decoy"
    );
    assert_eq!(
        events(&srv.state, srv.id, "rsh_command").await[0]["client_address"],
        client_ip.to_string()
    );
}

#[tokio::test]
async fn rexec_checks_the_password_itself_and_the_model_never_sees_it() {
    let accounts = json!({"accounts": [{"user": "alice", "password": "s3cret-wonderland"}]});
    let srv = start("rexec", policy(REXEC_POLICY), Some(accounts)).await;
    let out = exchange(
        srv.port,
        &nul_fields(&[b"", b"alice", b"s3cret-wonderland", b"ls /"]),
    )
    .await;
    assert_eq!(out, b"\0alice ran ls /\nnote\n");
    for (user, pass) in [
        (&b"alice"[..], &b"wrong"[..]),
        (b"alice", b"s3cret-wonderlan"),
        (b"alice", b"s3cret-wonderlandX"),
        (b"bob", b"s3cret-wonderland"),
        (b"", b""),
    ] {
        let out = exchange(srv.port, &nul_fields(&[b"", user, pass, b"ls /"])).await;
        assert_eq!(out, b"\x01Login incorrect.\n", "{user:?}/{pass:?}");
    }
    let out = exchange(
        srv.port,
        &nul_fields(&[b"", b"alice", b"s3cret-wonderland", b"rm -rf /"]),
    )
    .await;
    assert_eq!(out, b"\x01rm: Permission denied\n");
    let seen = events(&srv.state, srv.id, "rexec_command").await;
    assert_eq!(seen.len(), 2, "only the two logged-in commands were asked");
    assert_eq!(seen[0]["user"], "alice");
    assert_eq!(seen[0]["command"], "ls /");
    assert!(seen[0].get("password").is_none());
    let everything = access_log_text(&srv.state, srv.id).await;
    assert!(
        !everything.contains("s3cret-wonderland"),
        "the password reached the access log: {everything}"
    );

    // A password field past its cap is refused like any other.
    let long = vec![b'p'; 257];
    let out = exchange(srv.port, &nul_fields(&[b"", b"alice", &long, b"id"])).await;
    assert_eq!(out, b"\x01netget: password too long\n");
}

#[tokio::test]
async fn rexec_with_no_accounts_refuses_everyone_and_fails_closed_without_a_model() {
    let srv = start("rexec", policy(REXEC_POLICY), None).await;
    let out = exchange(srv.port, &nul_fields(&[b"", b"alice", b"", b"id"])).await;
    assert_eq!(out, b"\x01Login incorrect.\n");
    assert!(events(&srv.state, srv.id, "rexec_command").await.is_empty());

    let accounts = json!({"accounts": [{"user": "alice", "password": "pw"}]});
    let srv = start("rexec", None, Some(accounts)).await;
    let out = exchange(srv.port, &nul_fields(&[b"", b"alice", b"pw", b"id"])).await;
    assert_eq!(out, FAIL_CLOSED);
}

#[tokio::test]
async fn rexec_stderr_goes_on_its_own_connection() {
    let accounts = json!({"accounts": [{"user": "alice", "password": "pw"}]});
    let srv = start("rexec", policy(REXEC_POLICY), Some(accounts)).await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port().to_string();
    // inetutils rexec's order: everything at once after the port is accepted is fine too.
    let mut main = TcpStream::connect(("127.0.0.1", srv.port)).await.unwrap();
    main.write_all(&nul_fields(&[port.as_bytes(), b"alice", b"pw", b"date"]))
        .await
        .unwrap();
    let (mut err, _) = listener.accept().await.unwrap();
    let out = read_to_end(&mut main).await;
    assert_eq!(out, b"\0alice ran date\n");
    let mut stderr = Vec::new();
    err.read_to_end(&mut stderr).await.unwrap();
    assert_eq!(stderr, b"note\n");
}

// rlogin's peer is a blocking socket on a blocking thread, as a real rlogin(1) is: a tokio
// stream on macOS can miss the wake-up for data that follows an urgent byte (kqueue), which
// would read as the server going silent. The server under test runs on the test's runtime.

/// Connect and send rlogin's handshake from literal bytes.
fn rlogin(port: u16, client_user: &[u8], server_user: &[u8]) -> std::net::TcpStream {
    use std::io::Write;
    let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.write_all(&nul_fields(&[
        b"",
        client_user,
        server_user,
        b"xterm/38400",
    ]))
    .unwrap();
    s
}

fn send(s: &mut std::net::TcpStream, bytes: &[u8]) {
    use std::io::Write;
    s.write_all(bytes).unwrap();
}

/// Run `body` on a blocking thread while the server keeps running on this runtime.
async fn blocking<F: FnOnce() + Send + 'static>(body: F) {
    tokio::task::spawn_blocking(body).await.unwrap();
}

#[tokio::test]
async fn rlogin_trusted_session_echoes_edits_lines_and_reads_window_sizes() {
    let srv = start("rlogin", policy(RLOGIN_POLICY), None).await;
    let port = srv.port;
    blocking(move || {
        let mut s = rlogin(port, b"alice", b"alice");
        // Urgent data is read before the stream passes its mark, as rlogin's SIGURG handler
        // does: BSD stacks refuse MSG_OOB once a normal read has gone past it.
        assert_eq!(
            b_urgent(&s),
            Some(0x80),
            "TIOCPKT_WINDOW is sent out of band once the login is accepted"
        );
        let mut out = Vec::new();
        assert!(b_read_until(&mut s, &mut out, b"$ "), "{out:?}");
        assert_eq!(
            out, b"\0Welcome alice\r\n$ ",
            "ack, banner with CRLF, prompt"
        );

        // A window-size message split across two writes, then a line asking for it.
        send(&mut s, &[0xFF, 0xFF, b's']);
        std::thread::sleep(Duration::from_millis(100));
        send(&mut s, &[b's', 0, 30, 0, 100, 0, 0, 0, 0]);
        send(&mut s, b"size\r");
        out.clear();
        assert!(b_read_until(&mut s, &mut out, b"cols=100\r\n$ "), "{out:?}");
        assert_eq!(out, b"size\r\nrows=30 cols=100\r\n$ ");

        // DEL erases a character (echoed as BS SP BS); CR NUL is one line end.
        send(&mut s, b"lx\x7fs -l\r\0");
        out.clear();
        assert!(b_read_until(&mut s, &mut out, b"ls -l\r\n$ "), "{out:?}");
        assert_eq!(out, b"lx\x08 \x08s -l\r\nyou typed ls -l\r\n$ ");

        // ^C discards the line and flushes output out of band; the model re-prompts.
        send(&mut s, b"half\x03");
        out.clear();
        assert!(b_read_until(&mut s, &mut out, b"^C\r\n"), "{out:?}");
        assert_eq!(b_urgent(&s), Some(0x02), "TIOCPKT_FLUSHWRITE");
        assert!(b_read_until(&mut s, &mut out, b"^C\r\n$ "), "{out:?}");
        assert_eq!(out, b"half^C\r\n$ ");

        // Echo off while the model asks for a secret, then on again.
        send(&mut s, b"secret\r");
        out.clear();
        assert!(b_read_until(&mut s, &mut out, b"Secret: "));
        send(&mut s, b"hunter2\r");
        out.clear();
        assert!(b_read_until(&mut s, &mut out, b"you typed hunter2\r\n$ "));
        assert_eq!(
            out, b"\r\nyou typed hunter2\r\n$ ",
            "nothing typed was echoed"
        );
        send(&mut s, b"echo-on\r");
        out.clear();
        assert!(b_read_until(&mut s, &mut out, b"$ "));
        assert_eq!(
            out, b"\r\n$ ",
            "echo still off for the line that turns it on"
        );
        send(&mut s, b"ok\r");
        out.clear();
        assert!(b_read_until(&mut s, &mut out, b"you typed ok\r\n$ "));
        assert_eq!(out, b"ok\r\nyou typed ok\r\n$ ");

        send(&mut s, b"exit\r");
        assert_eq!(
            b_read_to_end(&mut s),
            b"exit\r\nlogout\r\n",
            "the session ends after logout"
        );
    })
    .await;

    let lines = events(&srv.state, srv.id, "rlogin_line").await;
    let typed: Vec<&str> = lines.iter().map(|e| e["line"].as_str().unwrap()).collect();
    assert_eq!(
        typed,
        ["size", "ls -l", "", "secret", "hunter2", "echo-on", "ok", "exit"]
    );
    assert_eq!(lines[0]["window"], json!({"rows": 30, "cols": 100}));
    assert_eq!(lines[2]["interrupt"], true);
    let login = &events(&srv.state, srv.id, "rlogin_login").await[0];
    assert_eq!(login["terminal"], "xterm");
    assert_eq!(login["speed"], 38400);
    assert_eq!(login["client_user"], "alice");
}

#[tokio::test]
async fn rlogin_password_is_checked_by_netget_with_three_tries() {
    let accounts = json!({"accounts": [{"user": "bob", "password": "builder"}]});
    let srv = start("rlogin", policy(RLOGIN_POLICY), Some(accounts)).await;
    let port = srv.port;
    blocking(move || {
        let mut s = rlogin(port, b"bob", b"bob");
        let mut out = Vec::new();
        assert!(b_read_until(&mut s, &mut out, b"Password: "), "{out:?}");
        assert_eq!(out, b"\0Password: ");
        send(&mut s, b"wrong\r");
        out.clear();
        assert!(b_read_until(&mut s, &mut out, b"Password: "), "{out:?}");
        assert_eq!(
            out, b"\r\nLogin incorrect\r\nPassword: ",
            "no echo of the password"
        );
        send(&mut s, b"builder\r");
        out.clear();
        assert!(b_read_until(&mut s, &mut out, b"$ "));
        assert_eq!(out, b"\r\nWelcome bob\r\n$ ");
        drop(s);

        // Three wrong passwords end the session.
        let mut s = rlogin(port, b"bob", b"bob");
        send(&mut s, b"a\rb\rc\r");
        let out = b_read_to_end(&mut s);
        assert_eq!(
            out.windows(15).filter(|w| w == b"Login incorrect").count(),
            3,
            "{}",
            String::from_utf8_lossy(&out)
        );
    })
    .await;
    // The password never reaches the model or the access log.
    let everything = access_log_text(&srv.state, srv.id).await;
    assert!(!everything.contains("builder"));
    assert!(events(&srv.state, srv.id, "rlogin_line").await.is_empty());
}

#[tokio::test]
async fn rlogin_refusals_and_failures_close_with_the_error_byte() {
    let srv = start("rlogin", policy(RLOGIN_POLICY), None).await;
    let port = srv.port;
    blocking(move || {
        let mut s = rlogin(port, b"carol", b"carol");
        assert_eq!(
            b_read_to_end(&mut s),
            b"\x01rlogind: Permission denied.\r\n"
        );
        let mut s = rlogin(port, b"silent", b"silent");
        assert_eq!(
            b_read_to_end(&mut s),
            b"\x01netget: request could not be processed\r\n"
        );
    })
    .await;
    // An rsh handshake on the rlogin port: a stderr port where rlogin sends an empty field.
    let out = exchange(srv.port, b"1023\0alice\0alice\0xterm/9600\0").await;
    assert_eq!(out, b"\x01netget: rlogin takes no stderr port\r\n");
    let long = vec![b't'; 65];
    let out = exchange(srv.port, &nul_fields(&[b"", b"alice", b"alice", &long])).await;
    assert_eq!(out, b"\x01netget: terminal too long\r\n");

    let srv = start("rlogin", None, None).await;
    let out = exchange(
        srv.port,
        &nul_fields(&[b"", b"alice", b"alice", b"xterm/38400"]),
    )
    .await;
    assert_eq!(out, b"\x01netget: request could not be processed\r\n");
}

#[tokio::test]
async fn rlogin_lines_are_bounded_and_a_dead_model_mid_session_prints_a_notice() {
    // A model that trusts and then stops answering: the line handler is missing.
    let handlers = Some(vec![
        json!({"event_pattern":"rlogin_login","handler":{"type":"static",
        "actions":[{"type":"rlogin_trust","prompt":"$ "}]}}),
    ]);
    let srv = start("rlogin", handlers, None).await;
    let port = srv.port;
    blocking(move || {
        let mut s = rlogin(port, b"alice", b"alice");
        let mut out = Vec::new();
        assert!(b_read_until(&mut s, &mut out, b"$ "));
        send(&mut s, b"ls\r");
        out.clear();
        assert!(b_read_until(
            &mut s,
            &mut out,
            b"request could not be processed\r\n"
        ));
        assert_eq!(
            out,
            b"ls\r\n\r\n[netget] request could not be processed\r\n"
        );
        // 8 KiB is a line; one byte more with no Enter ends the session.
        send(&mut s, &vec![b'y'; 8193]);
        let rest = b_read_to_end(&mut s);
        assert!(
            rest.ends_with(b"\r\n[netget] line too long\r\n"),
            "{:?}",
            &rest[rest.len().saturating_sub(40)..]
        );
    })
    .await;
}

#[tokio::test]
async fn the_dissectors_read_every_service_cleanly() {
    use crate::helpers::pcap_oracle::PcapOracle;
    // rsh: the handshake and an answer, as this server writes them.
    let srv = start("rsh", policy(RSH_POLICY), None).await;
    let rsh_in = nul_fields(&[b"", b"alice", b"alice", b"uname -a"]);
    let rsh_out = exchange(srv.port, &rsh_in).await;
    let oracle = || {
        PcapOracle::tcp("rsh")
            .to_server(&rsh_in)
            .from_server(&rsh_out)
    };
    oracle().assert_clean();
    let fields = oracle()
        .fields(&["rsh.client_username", "rsh.server_username", "rsh.command"])
        .unwrap();
    assert!(
        fields
            .iter()
            .any(|r| r == &["alice".to_string(), "alice".into(), "uname -a".into()]),
        "{fields:?}"
    );

    // rexec.
    let accounts = json!({"accounts": [{"user": "alice", "password": "pw"}]});
    let srv = start("rexec", policy(REXEC_POLICY), Some(accounts)).await;
    let exec_in = nul_fields(&[b"", b"alice", b"pw", b"date"]);
    let exec_out = exchange(srv.port, &exec_in).await;
    let oracle = || {
        PcapOracle::tcp("rexec")
            .to_server(&exec_in)
            .from_server(&exec_out)
    };
    oracle().assert_clean();
    let fields = oracle().fields(&["exec.username", "exec.command"]).unwrap();
    assert!(
        fields
            .iter()
            .any(|r| r == &["alice".to_string(), "date".into()]),
        "{fields:?}"
    );

    // rlogin: the handshake, a window size, a line; the server's ack and output.
    let srv = start("rlogin", policy(RLOGIN_POLICY), None).await;
    let handshake = nul_fields(&[b"", b"alice", b"alice", b"xterm/38400"]);
    let window = [0xFF, 0xFF, b's', b's', 0, 30, 0, 100, 0, 0, 0, 0];
    let port = srv.port;
    let (first, rest) = tokio::task::spawn_blocking(move || {
        let mut s = rlogin(port, b"alice", b"alice");
        let mut first = Vec::new();
        assert!(b_read_until(&mut s, &mut first, b"$ "));
        send(&mut s, &window);
        send(&mut s, b"exit\r");
        (first, b_read_to_end(&mut s))
    })
    .await
    .unwrap();
    let oracle = || {
        PcapOracle::tcp("rlogin")
            .to_server(&handshake)
            .from_server(&first)
            .to_server(&window)
            .to_server(b"exit\r")
            .from_server(&rest)
    };
    oracle().assert_clean();
    let fields = oracle()
        .fields(&[
            "rlogin.client_user_name",
            "rlogin.terminal_type",
            "rlogin.window_size.rows",
            "rlogin.window_size.cols",
        ])
        .unwrap();
    let flat = fields.concat();
    for want in ["alice", "xterm", "30", "100"] {
        assert!(
            flat.iter().any(|f| f == want),
            "{want} not read: {fields:?}"
        );
    }
}
