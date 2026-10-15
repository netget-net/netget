//! The canonical operator instructions, per protocol.
//!
//! # The one rule these must obey
//!
//! **An instruction may never name an action, a parameter or an event.** It is
//! written the way an operator types it into the dashboard — "serve a page that
//! says hello", "answer example.com with 1.2.3.4" — and the model has to find
//! the vocabulary for itself, out of the protocol's own action descriptions and
//! parameter docs. The moment an instruction says `send_http_response`, the
//! thing under test stops being the descriptions and becomes the model's
//! copy-paste.
//!
//! The corollary is that these instructions are *allowed* to be under-specified
//! in exactly the way a real one is. Where the model guesses wrong, that is the
//! finding.
//!
//! Each case is feature-gated, so a build compiles only the cases whose protocol
//! it contains and `run-eval.sh` chooses the feature set.

#![allow(dead_code)]

use super::case::{EvalCase, Expect, Probe};

/// Every case this build knows about, in protocol order.
pub fn all_cases() -> Vec<EvalCase> {
    let mut cases = Vec::new();
    cases.extend(http());
    cases.extend(dns());
    cases.extend(whois());
    cases.extend(gopher());
    cases.extend(dict());
    cases.extend(gemini());
    cases.extend(beanstalkd());
    cases.extend(zabbix());
    cases.extend(gearman());
    cases.extend(nsq());
    cases.extend(finger());
    cases.extend(redis());
    cases.extend(postgresql());
    cases.extend(mysql());
    cases.extend(ldap());
    cases.extend(ipp());
    cases.extend(syslog());
    cases.extend(ntp());
    cases.extend(telnet());
    cases.extend(tcp());
    cases.extend(ftp());
    cases.extend(udp());
    cases.extend(prometheus());
    cases.extend(otlp());
    cases.extend(docker());
    cases.extend(vault());
    cases.extend(bolt());
    cases.extend(smtp());
    cases.extend(pop3());
    cases.extend(imap());
    cases.extend(nntp());
    cases.extend(memcached());
    cases.extend(mqtt());
    cases.extend(coap());
    cases.extend(modbus());
    cases.extend(snmp());
    cases.extend(sip());
    cases.extend(websocket());
    cases.extend(nostr());
    cases
}

// ---------------------------------------------------------------------------
// HTTP — curl. The reference case: an independent client, an unambiguous
// status line, and four instructions an operator would plausibly type.
// ---------------------------------------------------------------------------

fn curl(path: &str) -> Probe {
    let url = format!("http://127.0.0.1:{{PORT}}{}", path);
    Probe::client("curl", &["-sS", "-i", "--max-time", "230", url.as_str()])
}

fn http() -> Vec<EvalCase> {
    vec![
        EvalCase::new(
            "http/hello-page",
            "http",
            "Serve a page that says hello.",
            curl("/"),
            Expect::contains(&["HTTP/1.1 200", "hello"]),
        ),
        EvalCase::new(
            "http/admin-404",
            "http",
            "Return 404 Not Found for anything under /admin. Serve every other path \
             with a short ordinary page.",
            curl("/admin/secrets"),
            Expect::contains(&["HTTP/1.1 404"]),
        ),
        EvalCase::new(
            "http/json-status",
            "http",
            "Answer /status with the JSON body {\"status\":\"ok\"} and say it is JSON.",
            curl("/status"),
            Expect::contains(&["application/json", "\"status\"", "ok"]),
        ),
        EvalCase::new(
            "http/permanent-redirect",
            "http",
            "Redirect / permanently to https://example.com/.",
            curl("/"),
            // 301 and 308 are both permanent redirects (RFC 9110 15.4.2 and 15.4.9); 308
            // additionally keeps the method. The committed baseline scored every 308 as a
            // miss, which measured this file's expectation rather than the model.
            Expect::contains(&["example.com"]).matching(r"(?m)^HTTP/1\.1 30[18]\b"),
        ),
    ]
}

// ---------------------------------------------------------------------------
// DNS — dig. The strongest evidence in the suite: dig parses the whole message
// and will not print an answer it could not decode, so a pass here means the
// model built a wire-correct packet with the right transaction id.
// ---------------------------------------------------------------------------

fn dig(name: &str, rtype: &str) -> Probe {
    Probe::client(
        "dig",
        &[
            "@127.0.0.1",
            "-p",
            "{PORT}",
            "+time=230",
            "+tries=1",
            name,
            rtype,
        ],
    )
}

fn dns() -> Vec<EvalCase> {
    vec![
        EvalCase::new(
            "dns/a-record",
            "dns",
            "Answer example.com with 1.2.3.4.",
            dig("example.com", "A"),
            Expect::contains(&["1.2.3.4"]),
        ),
        EvalCase::new(
            "dns/wildcard-a",
            "dns",
            "Whatever name is asked for, answer 10.0.0.1.",
            dig("anything.test", "A"),
            Expect::contains(&["10.0.0.1"]),
        ),
        EvalCase::new(
            "dns/txt-record",
            "dns",
            "Answer text queries for hello.test with the text netget-eval-ok.",
            dig("hello.test", "TXT"),
            Expect::contains(&["netget-eval-ok"]),
        ),
        EvalCase::new(
            "dns/nxdomain",
            "dns",
            "Say the name does not exist for anything under blocked.test. Answer \
             everything else with 127.0.0.1.",
            dig("evil.blocked.test", "A"),
            Expect::contains(&["NXDOMAIN"]),
        ),
    ]
}

// ---------------------------------------------------------------------------
// WHOIS — `nc`, not the system `whois`, and the reason is worth recording
// because `whois` is counted among the "67 of 100 real clients already
// installed" in PROTOCOL_QUALITY.md.
//
// **macOS `whois` segfaults when `-p` follows `-h`.** Measured against a bare
// listener: `whois -h 127.0.0.1 -p N netget.example` exits 139 (SIGSEGV) having
// sent zero bytes, while `whois -p N -h 127.0.0.1 …` exits 71 and also sends
// nothing, and `-p` without `-h` goes looking for the real registry. There is no
// argument order that reaches a loopback port, so this client cannot evaluate
// this protocol on this machine at all — the three whois cases in the first
// smoke run all reported `event_never_reached_model` because the client died
// 1.2ms after connecting.
//
// WHOIS is one line of text in and free text out, so `nc` loses little here
// beyond the label, which is why these rows say `generic-transport`.
// ---------------------------------------------------------------------------

fn whois_probe(query: &str) -> Probe {
    let line = format!("{}\r\n", query);
    Probe::generic("nc", &["-w", "235", "127.0.0.1", "{PORT}"]).stdin(line.as_str())
}

fn whois() -> Vec<EvalCase> {
    vec![
        EvalCase::new(
            "whois/registrar-line",
            "whois",
            "Answer every query with a whois record whose registrar is \
             NETGET-EVAL-REGISTRAR.",
            whois_probe("netget.example"),
            Expect::contains(&["NETGET-EVAL-REGISTRAR"]),
        )
        .note("macOS whois segfaults with -p; driven with nc."),
        EvalCase::new(
            "whois/registrant-and-status",
            "whois",
            "For netget.example, report the registrant organisation as Example \
             Holdings Ltd and the domain status as clientTransferProhibited.",
            whois_probe("netget.example"),
            Expect::contains(&["Example Holdings", "clientTransferProhibited"]),
        ),
        EvalCase::new(
            "whois/no-match",
            "whois",
            "Report that no match was found for any domain ending in .invalid. \
             Answer anything else with an ordinary record.",
            whois_probe("nothing.invalid"),
            Expect::default().matching(r"(?i)no match|not found|no entries|no data found"),
        ),
    ]
}

// ---------------------------------------------------------------------------
// Gopher — curl, which speaks gopher natively (see `curl --version`).
// ---------------------------------------------------------------------------

fn gopher_probe(selector: &str) -> Probe {
    let url = format!("gopher://127.0.0.1:{{PORT}}{}", selector);
    Probe::client("curl", &["-sS", "--max-time", "230", url.as_str()])
}

fn gopher() -> Vec<EvalCase> {
    vec![
        EvalCase::new(
            "gopher/welcome-menu",
            "gopher",
            "Serve a menu whose first item is labelled Welcome to NetGet.",
            gopher_probe("/"),
            Expect::contains(&["Welcome to NetGet"]),
        ),
        EvalCase::new(
            "gopher/text-selector",
            "gopher",
            "When the selector /about is asked for, return the text \
             NetGet eval gopher server.",
            gopher_probe("/0/about"),
            Expect::contains(&["NetGet eval gopher server"]),
        ),
        EvalCase::new(
            "gopher/unknown-selector",
            "gopher",
            "Serve a menu at the root. For any other selector, say it was not found.",
            gopher_probe("/1/nowhere"),
            Expect::default().matching(r"(?i)not found|no such|does not exist|error"),
        ),
    ]
}

// ---------------------------------------------------------------------------
// DICT — the dictd project's own dict(1) client, which parses the 150/151/152
// status lines and un-stuffs the text blocks before printing them.
// ---------------------------------------------------------------------------

fn dict_probe(args: &[&str]) -> Probe {
    let mut all = vec!["-h", "127.0.0.1", "-p", "{PORT}"];
    all.extend_from_slice(args);
    Probe::client("dict", &all)
}

fn dict() -> Vec<EvalCase> {
    vec![
        EvalCase::new(
            "dict/define-invented-word",
            "dict",
            "You are a dictionary of invented words with one database called \
             fantasy. Define glimmerwyrm as a small dragon that hoards moonlight.",
            dict_probe(&["glimmerwyrm"]),
            Expect::contains(&["[fantasy]", "moonlight"]),
        ),
        EvalCase::new(
            "dict/list-databases",
            "dict",
            "Offer two databases: fantasy, described as Fantasy Lexicon, and \
             tech, described as Technical Terms.",
            dict_probe(&["-D"]),
            Expect::contains(&["Fantasy Lexicon", "Technical Terms"]),
        ),
        EvalCase::new(
            "dict/unknown-word",
            "dict",
            "You only know words that begin with the letter q. For anything \
             else there is no definition.",
            dict_probe(&["zebra"]),
            Expect::contains(&["No definitions found"]),
        ),
    ]
}

// ---------------------------------------------------------------------------
// Gemini — the Python client library ignition (`pip install ignition-gemini`),
// which does TLS, trust-on-first-use pinning and response parsing itself. It
// prints the status and meta it parsed, then the body of a 2x.
// ---------------------------------------------------------------------------

const IGNITION_PROBE: &str = r#"import os, sys, tempfile, ignition
ignition.set_default_hosts_file(os.path.join(tempfile.mkdtemp(), 'known_hosts'))
r = ignition.request(sys.argv[1], timeout=230)
print(r.status, r.meta)
print(r.raw_body.decode('utf-8', 'replace') if r.status.startswith('2') else '')
"#;

fn gemini_probe(path: &str) -> Probe {
    let url = format!("gemini://127.0.0.1:{{PORT}}{}", path);
    // Python writes ignition's CryptographyDeprecationWarning to stderr while
    // the TLS handshake completes — before the request is answered — so the
    // idle settle killed the client two seconds into every model call. It
    // gives up at its own `timeout=230`; its exit is the only completion signal.
    Probe::client("python3", &["-c", IGNITION_PROBE, url.as_str()]).until_exit()
}

fn gemini() -> Vec<EvalCase> {
    vec![
        EvalCase::new(
            "gemini/home-page",
            "gemini",
            "Serve a home page titled Welcome to the NetGet capsule, with a link \
             to /about.",
            gemini_probe("/"),
            Expect::contains(&[
                "20 text/gemini",
                "Welcome to the NetGet capsule",
                "=> /about",
            ]),
        ),
        EvalCase::new(
            "gemini/ask-for-input",
            "gemini",
            "The page /guestbook asks the visitor for their name before showing \
             anything.",
            gemini_probe("/guestbook"),
            Expect::default().matching(r"(?m)^1[01] "),
        ),
        EvalCase::new(
            "gemini/not-found",
            "gemini",
            "Only the home page exists. Every other page does not exist.",
            gemini_probe("/nowhere"),
            Expect::default().matching(r"(?m)^51 "),
        ),
    ]
}

// ---------------------------------------------------------------------------
// Beanstalkd — the Python client library greenstalk (`pip install greenstalk`),
// which parses reply lines, byte-counted job bodies and the YAML reports
// itself. It prints what it got back, or the name of the exception it raised.
// ---------------------------------------------------------------------------

// A raw string, never `"…\n\` continuations: a continuation drops the next
// line's leading whitespace, which for Python is the block structure, so the
// probe dies with an IndentationError before it connects and the run reads as
// an event that never reached the model. `probe_check.rs` runs this probe
// against a mocked model.
const GREENSTALK_PROBE: &str = r#"import sys, greenstalk
c = greenstalk.Client(('127.0.0.1', int(sys.argv[1])), watch=sys.argv[3])
try:
    if sys.argv[2] == 'put':
        print('INSERTED', c.put('resize image 7'))
    elif sys.argv[2] == 'reserve':
        j = c.reserve(timeout=200)
        print('RESERVED', j.id, j.body)
    else:
        print(c.stats())
except greenstalk.Error as e:
    print(type(e).__name__)
"#;

fn beanstalkd_probe(mode: &str, tube: &str) -> Probe {
    Probe::client("python3", &["-c", GREENSTALK_PROBE, "{PORT}", mode, tube])
}

fn beanstalkd() -> Vec<EvalCase> {
    vec![
        EvalCase::new(
            "beanstalkd/accept-a-job",
            "beanstalkd",
            "You are a work queue. Accept every job that is submitted and number \
             the jobs starting from 100.",
            beanstalkd_probe("put", "default"),
            Expect::default().matching(r"INSERTED \d+"),
        ),
        EvalCase::new(
            "beanstalkd/hand-out-a-job",
            "beanstalkd",
            "You are a work queue. The images tube holds one waiting job, number 7, \
             whose text is: resize photo.jpg to 640 wide.",
            beanstalkd_probe("reserve", "images"),
            Expect::contains(&["RESERVED 7", "photo.jpg"]),
        ),
        EvalCase::new(
            "beanstalkd/queue-statistics",
            "beanstalkd",
            "You are a work queue with 5 ready jobs and 2 buried jobs, running \
             version 1.13.",
            beanstalkd_probe("stats", "default"),
            Expect::contains(&["'current-jobs-ready': 5", "'current-jobs-buried': 2"]),
        ),
    ]
}

// ---------------------------------------------------------------------------
// Zabbix trapper — the Zabbix project's own zabbix_sender, which prints the
// processed/failed counts it scanned from the response.
// ---------------------------------------------------------------------------

fn zabbix_probe(host: &str, key: &str, value: &str) -> Probe {
    Probe::client(
        "zabbix_sender",
        &[
            "-z",
            "127.0.0.1",
            "-p",
            "{PORT}",
            "-s",
            host,
            "-k",
            key,
            "-o",
            value,
        ],
    )
}

fn zabbix() -> Vec<EvalCase> {
    vec![
        EvalCase::new(
            "zabbix/accept-known-host",
            "zabbix",
            "You are a Zabbix server monitoring the hosts web1 and db1. Accept every \
             value reported for them.",
            zabbix_probe("web1", "system.cpu.load", "0.42"),
            Expect::contains(&["processed: 1; failed: 0"]),
        ),
        EvalCase::new(
            "zabbix/reject-unknown-host",
            "zabbix",
            "You are a Zabbix server monitoring only the host web1. Values reported \
             for any other host cannot be stored.",
            zabbix_probe("mystery-box", "system.cpu.load", "0.42"),
            Expect::contains(&["processed: 0; failed: 1"]),
        ),
    ]
}

// ---------------------------------------------------------------------------
// Gearman — the gearmand project's gearman(1) client, which prints a job's
// WORK_DATA and WORK_COMPLETE payloads and exits 1 with "Job failed" on
// WORK_FAIL.
// ---------------------------------------------------------------------------

fn gearman_probe(function: &str, workload: &str) -> Probe {
    Probe::client(
        "gearman",
        &[
            "-h",
            "127.0.0.1",
            "-p",
            "{PORT}",
            "-t",
            "230000",
            "-f",
            function,
            workload,
        ],
    )
}

fn gearman() -> Vec<EvalCase> {
    vec![
        EvalCase::new(
            "gearman/reverse-text",
            "gearman",
            "You are a Gearman worker. The function reverse returns its input \
             spelled backwards.",
            gearman_probe("reverse", "stressed"),
            Expect::contains(&["desserts"]),
        ),
        EvalCase::new(
            "gearman/unknown-function-fails",
            "gearman",
            "You are a Gearman worker that only knows the function reverse. Any \
             other function must fail.",
            gearman_probe("translate", "hello"),
            Expect::contains(&["Job failed"]),
        ),
    ]
}

// ---------------------------------------------------------------------------
// NSQ — the NSQ project's own go-nsq clients: to_nsq publishes each stdin line
// and exits non-zero naming the error on a refusal; nsq_tail subscribes and
// prints each message body it receives, exiting after -n of them.
// ---------------------------------------------------------------------------

fn to_nsq_probe(topic: &str, lines: &str) -> Probe {
    Probe::client(
        "to_nsq",
        &["-nsqd-tcp-address", "127.0.0.1:{PORT}", "-topic", topic],
    )
    .stdin(lines)
    .until_exit()
}

fn nsq_tail_probe(topic: &str, n: &str) -> Probe {
    Probe::client(
        "nsq_tail",
        &[
            "-nsqd-tcp-address",
            "127.0.0.1:{PORT}",
            "-topic",
            topic,
            "-n",
            n,
        ],
    )
    .until_exit()
}

fn nsq() -> Vec<EvalCase> {
    vec![
        EvalCase::new(
            "nsq/deliver-waiting-messages",
            "nsq",
            "You are an NSQ broker. Accept every subscription. The topic orders holds \
             two waiting messages, in this order: order 1 shipped, then order 2 packed.",
            nsq_tail_probe("orders", "2"),
            Expect::contains(&["order 1 shipped", "order 2 packed"]),
        ),
        EvalCase::new(
            "nsq/accept-publish",
            "nsq",
            "You are an NSQ broker. Accept every message published to any topic.",
            to_nsq_probe("events", "user signed up\n"),
            // to_nsq exits zero after each synchronous Publish read its OK. go-nsq 1.1.0
            // releases the router WaitGroup before logging "exiting router", so main can
            // return before that goroutine writes its last line. A refusal is fatal.
            Expect::default()
                .exits_with(0)
                .not_containing(&["E_PUB_FAILED"]),
        ),
        EvalCase::new(
            "nsq/refuse-closed-topic",
            "nsq",
            "You are an NSQ broker. The topic archive is closed and refuses every \
             publish. Every other topic accepts messages.",
            to_nsq_probe("archive", "old record\n"),
            Expect::contains(&["E_PUB_FAILED"]),
        ),
    ]
}

// ---------------------------------------------------------------------------
// OTLP/HTTP — otel-cli, an OpenTelemetry exporter that sends one span over
// http/protobuf. With --fail it exits non-zero on any response but a success;
// --tp-print makes it print TRACEPARENT= only once the export was accepted, and
// a refusal prints "server returned … code".
// ---------------------------------------------------------------------------

fn otel_cli_probe(service: &str, span: &str) -> Probe {
    Probe::client(
        "otel-cli",
        &[
            "span",
            "--endpoint",
            "http://127.0.0.1:{PORT}",
            "--protocol",
            "http/protobuf",
            "--insecure",
            "--service",
            service,
            "--name",
            span,
            "--timeout",
            "60s",
            "--fail",
            "--verbose",
            "--tp-print",
        ],
    )
    .until_exit()
}

fn otlp() -> Vec<EvalCase> {
    vec![
        EvalCase::new(
            "otlp/accept-known-service",
            "otlp",
            "You are an OpenTelemetry collector. Accept all telemetry the checkout \
             service sends.",
            otel_cli_probe("checkout", "charge card"),
            Expect::contains(&["TRACEPARENT="]),
        ),
        EvalCase::new(
            "otlp/refuse-unknown-service",
            "otlp",
            "You are an OpenTelemetry collector that only takes data from the checkout \
             service. Refuse telemetry from every other service; it is not allowed to \
             send here.",
            otel_cli_probe("inventory", "count stock"),
            Expect::contains(&["server returned"]).not_containing(&["TRACEPARENT="]),
        ),
        EvalCase::new(
            "otlp/refuse-debug-spans",
            "otlp",
            "You are an OpenTelemetry collector. Accept all traces, except that spans \
             named debug-probe are invalid data and must be refused.",
            otel_cli_probe("checkout", "debug-probe"),
            Expect::contains(&["server returned"]).not_containing(&["TRACEPARENT="]),
        ),
    ]
}

// ---------------------------------------------------------------------------
// Finger — no installed finger client accepts a port (BSD `finger` hard-wires
// 79, which needs root to bind). Driven with `nc`, and labelled
// `generic-transport` so the weaker evidence is visible in the table.
// ---------------------------------------------------------------------------

fn finger_probe(query: &str) -> Probe {
    Probe::generic("nc", &["-w", "235", "127.0.0.1", "{PORT}"]).stdin(query)
}

fn finger() -> Vec<EvalCase> {
    vec![
        EvalCase::new(
            "finger/user-record",
            "finger",
            "When someone asks about the user alice, report her real name as \
             Alice Liddell and that she is logged in.",
            finger_probe("alice\r\n"),
            Expect::contains(&["Alice Liddell"]),
        )
        .note("BSD finger cannot target a non-default port; driven with nc."),
        EvalCase::new(
            "finger/unknown-user",
            "finger",
            "Only the user alice exists. Say so for anyone else.",
            finger_probe("bob\r\n"),
            Expect::default().matching(r"(?i)no such user|not found|does not exist|no one|unknown"),
        ),
        EvalCase::new(
            "finger/user-list",
            "finger",
            "When no user is named, list the two users alice and bob.",
            finger_probe("\r\n"),
            Expect::contains(&["alice", "bob"]),
        ),
    ]
}

// ---------------------------------------------------------------------------
// Redis — redis-cli, the reference client, which decodes RESP for itself.
// ---------------------------------------------------------------------------

fn redis_cli(args: &[&str]) -> Probe {
    let mut full = vec!["-h", "127.0.0.1", "-p", "{PORT}", "-t", "230"];
    full.extend_from_slice(args);
    Probe::client("redis-cli", &full)
}

fn redis() -> Vec<EvalCase> {
    vec![
        EvalCase::new(
            "redis/get-string",
            "redis",
            "Answer a read of the key greeting with the text hello-netget.",
            redis_cli(&["GET", "greeting"]),
            Expect::contains(&["hello-netget"]),
        ),
        EvalCase::new(
            "redis/ping",
            "redis",
            "Answer a ping with PONG.",
            redis_cli(&["PING"]),
            Expect::contains(&["PONG"]),
        ),
        EvalCase::new(
            "redis/key-list",
            "redis",
            "When asked to list all keys, report exactly three: alpha, beta and gamma.",
            redis_cli(&["KEYS", "*"]),
            Expect::contains(&["alpha", "beta", "gamma"]),
        ),
        EvalCase::new(
            "redis/counter",
            "redis",
            "When the key counter is incremented, report the new value as 42.",
            redis_cli(&["INCR", "counter"]),
            Expect::contains(&["42"]),
        ),
    ]
}

// ---------------------------------------------------------------------------
// PostgreSQL — psql. Note this exercises far more than one answer: the model
// has to get through the startup packet and authentication before any query
// arrives, so a failure here may be at the handshake rather than at the query.
// ---------------------------------------------------------------------------

fn psql(sql: &str) -> Probe {
    Probe::client(
        "psql",
        &[
            "-h",
            "127.0.0.1",
            "-p",
            "{PORT}",
            "-U",
            "evaluser",
            "-d",
            "evaldb",
            "-w",
            "-t",
            "-A",
            "-c",
            sql,
        ],
    )
    .env("PGCONNECT_TIMEOUT", "230")
    .env("PGSSLMODE", "disable")
}

fn postgresql() -> Vec<EvalCase> {
    vec![
        EvalCase::new(
            "postgresql/select-literal",
            "postgresql",
            "Let anyone log in without a password, and answer the query SELECT 1 with \
             one row holding the number 1.",
            psql("SELECT 1"),
            Expect::contains(&["1"]),
        ),
        EvalCase::new(
            "postgresql/current-user",
            "postgresql",
            "Let anyone log in without a password. Report the current user as \
             netget_eval.",
            psql("SELECT current_user"),
            Expect::contains(&["netget_eval"]),
        ),
        EvalCase::new(
            "postgresql/users-table",
            "postgresql",
            "Let anyone log in without a password. There is a table called users with \
             a name column holding alice, bob and carol.",
            psql("SELECT name FROM users"),
            Expect::contains(&["alice", "bob", "carol"]),
        ),
    ]
}

// ---------------------------------------------------------------------------
// MySQL — the **8.0** client, by absolute path, and the reason is a finding the
// first sweep produced from the wire.
//
// NetGet's MySQL server offers `mysql_native_password`, which the 9.x client no
// longer ships. All nine runs against Homebrew's `mysql` 9.3.0 died before a
// query existed:
//
//     ERROR 2059 (HY000): Authentication plugin 'mysql_native_password'
//     cannot be loaded: dlopen(…/mysql/9.3.0/lib/plugin/mysql_native_password.so)
//
// — recorded as `event_never_reached_model`, which is exactly right: the model
// was never asked. `src/server/mysql/AGENTS.md` already says to use an 8.0
// client, so this is confirmation rather than news; what it *does* show is that
// MySQL's Beta rating rests on `mysql_async`, which still supports the old
// plugin and is therefore more permissive than the shipping client. That is the
// "one client can agree with one bug" case PROTOCOL_QUALITY Tier 1 names.
//
// An absolute path rather than `mysql` on PATH: whichever version is linked is
// not something an eval should be at the mercy of, and when this path is absent
// the case is recorded `client-missing` rather than silently passing.
// ---------------------------------------------------------------------------

const MYSQL_8_CLIENT: &str = "/opt/homebrew/opt/mysql@8.0/bin/mysql";

fn mysql_cli(sql: &str) -> Probe {
    Probe::client(
        MYSQL_8_CLIENT,
        &[
            "-h",
            "127.0.0.1",
            "-P",
            "{PORT}",
            "-u",
            "evaluser",
            "--protocol=TCP",
            "--connect-timeout=230",
            "-N",
            "-B",
            "-e",
            sql,
        ],
    )
}

fn mysql() -> Vec<EvalCase> {
    vec![
        EvalCase::new(
            "mysql/select-literal",
            "mysql",
            "Let anyone log in without a password, and answer SELECT 1 with one row \
             holding the number 1.",
            mysql_cli("SELECT 1"),
            Expect::contains(&["1"]),
        ),
        EvalCase::new(
            "mysql/server-version",
            "mysql",
            "Let anyone log in without a password. Report the server version as \
             8.0.36-netget-eval.",
            mysql_cli("SELECT VERSION()"),
            Expect::contains(&["8.0.36-netget-eval"]),
        ),
        EvalCase::new(
            "mysql/users-table",
            "mysql",
            "Let anyone log in without a password. There is a table called users with \
             a name column holding alice, bob and carol.",
            mysql_cli("SELECT name FROM users"),
            Expect::contains(&["alice", "bob", "carol"]),
        ),
    ]
}

// ---------------------------------------------------------------------------
// LDAP — ldapsearch, OpenLDAP's own client.
// ---------------------------------------------------------------------------

fn ldapsearch(base: &str, filter: &str) -> Probe {
    // Bind, then search, one model call each. A bind answered with a
    // diagnostic message makes ldapsearch print `ldap_bind: Success (0)` and
    // carry on — so it talks between the two calls, and the idle settle used to
    // kill it there, before the search was ever sent.
    Probe::client(
        "ldapsearch",
        &[
            "-x",
            "-H",
            "ldap://127.0.0.1:{PORT}",
            "-b",
            base,
            "-s",
            "sub",
            "-o",
            "nettimeout=230",
            "-l",
            "230",
            filter,
        ],
    )
    .until_exit()
}

fn ldap() -> Vec<EvalCase> {
    vec![
        EvalCase::new(
            "ldap/single-person",
            "ldap",
            "Accept anonymous connections. A search under dc=example,dc=com finds one \
             person, Alice Liddell, whose mail address is alice@example.com.",
            ldapsearch("dc=example,dc=com", "(objectClass=*)"),
            Expect::contains(&["Alice Liddell", "alice@example.com"]),
        ),
        EvalCase::new(
            "ldap/two-people",
            "ldap",
            "Accept anonymous connections. Under ou=people,dc=example,dc=com there are \
             two users, alice and bob.",
            ldapsearch("ou=people,dc=example,dc=com", "(objectClass=*)"),
            Expect::contains(&["alice", "bob"]),
        ),
        EvalCase::new(
            "ldap/empty-result",
            "ldap",
            "Accept anonymous connections. There is nothing at all under \
             dc=other,dc=com — searches there succeed and find no one.",
            ldapsearch("dc=other,dc=com", "(objectClass=*)"),
            Expect::default()
                .matching(r"(?i)result:\s*0\s+success")
                .not_containing(&["Alice", "cn="]),
        ),
    ]
}

// ---------------------------------------------------------------------------
// IPP — ipptool, shipped with CUPS, with CUPS's own Get-Printer-Attributes
// test file. It validates the IPP encoding itself, so a pass is strong.
// ---------------------------------------------------------------------------

const IPPTOOL_GET_ATTRS: &str = "/usr/share/cups/ipptool/get-printer-attributes.test";

fn ipptool() -> Probe {
    // `-v` echoes the request before it is sent and the answer only once it
    // arrives, with the whole model call in between — so this client is done
    // when it exits, never when it goes quiet.
    Probe::client(
        "ipptool",
        &[
            "-tv",
            "-T",
            "230",
            "ipp://127.0.0.1:{PORT}/printers/eval",
            IPPTOOL_GET_ATTRS,
        ],
    )
    .until_exit()
}

fn ipp() -> Vec<EvalCase> {
    vec![
        EvalCase::new(
            "ipp/printer-name",
            "ipp",
            "There is one printer called NetGet-Eval-Printer. It is idle and accepting \
             jobs.",
            ipptool(),
            Expect::contains(&["NetGet-Eval-Printer"]),
        ),
        EvalCase::new(
            "ipp/printer-stopped",
            "ipp",
            "The printer is called Eval-Stopped-Printer, it is stopped, and it is not \
             accepting jobs.",
            ipptool(),
            Expect::contains(&["Eval-Stopped-Printer"]),
        ),
    ]
}

// ---------------------------------------------------------------------------
// Syslog — one-way, so the observable is netget's own log rather than the wire.
// macOS `logger` is BSD and has no -n/-P, so it cannot target a remote port;
// `nc -u` carries the datagram instead.
// ---------------------------------------------------------------------------

fn syslog_probe(message: &str) -> Probe {
    Probe::generic("nc", &["-u", "-w", "1", "127.0.0.1", "{PORT}"]).stdin(message)
}

fn syslog() -> Vec<EvalCase> {
    vec![
        EvalCase::new(
            "syslog/store-message",
            "syslog",
            "Keep every message that arrives.",
            syslog_probe("<14>Oct 11 22:14:15 evalhost netget-eval: disk almost full\n"),
            Expect::executed_action(&["store_syslog_message"]),
        )
        .note("BSD logger cannot target a remote port; driven with nc -u."),
        EvalCase::new(
            "syslog/drop-healthchecks",
            "syslog",
            "Throw away any message whose text mentions healthcheck. Keep everything \
             else.",
            syslog_probe("<14>Oct 11 22:14:15 evalhost netget-eval: healthcheck ok\n"),
            Expect::executed_action(&["ignore_syslog_message"]),
        ),
    ]
}

// ---------------------------------------------------------------------------
// NTP — recorded, never run. Neither `sntp` nor `ntpdate` accepts a
// destination port (sntp's -r only *sources* from 123), and binding 123 needs
// root. Left in the suite with the reason so the day a client appears the case
// is already written — and so the results file says "no client", not "passed".
// ---------------------------------------------------------------------------

fn ntp() -> Vec<EvalCase> {
    vec![EvalCase::unavailable(
        "ntp/current-time",
        "ntp",
        "Answer time requests with the correct current time, stratum 2.",
        "no installed NTP client accepts a destination port: sntp's -r only selects \
         the source port and ntpdate has no port option, so an unprivileged \
         loopback port is unreachable. Binding 123 needs root.",
    )]
}

// ---------------------------------------------------------------------------
// Telnet — curl speaks telnet:// and performs real option negotiation.
// ---------------------------------------------------------------------------

fn telnet_probe(input: Option<&str>) -> Probe {
    // `-N`: curl buffers a telnet session's output when stdout is a pipe, so without it
    // nothing reached the probe until `--max-time` ended the session — every telnet run took
    // 233s whatever the model did, and the idle settle never had a byte to settle on.
    let probe = Probe::client(
        "curl",
        &[
            "-sS",
            "-N",
            "--max-time",
            "230",
            "telnet://127.0.0.1:{PORT}",
        ],
    );
    match input {
        Some(text) => probe.stdin(text),
        None => probe,
    }
}

fn telnet() -> Vec<EvalCase> {
    vec![
        EvalCase::new(
            "telnet/banner",
            "telnet",
            "Greet everyone who connects with the banner NETGET EVAL TELNET.",
            telnet_probe(None),
            Expect::contains(&["NETGET EVAL TELNET"]),
        ),
        EvalCase::new(
            "telnet/login-prompt",
            "telnet",
            "Ask for a login name as soon as somebody connects.",
            telnet_probe(None),
            Expect::default().matching(r"(?i)login|username|user name"),
        ),
        EvalCase::new(
            "telnet/answer-command",
            "telnet",
            "If somebody types the word time, answer with the line \
             It is always noon here.",
            telnet_probe(Some("time\r\n")),
            Expect::contains(&["It is always noon here"]),
        ),
    ]
}

// ---------------------------------------------------------------------------
// TCP — nc. Generic transport by construction: raw TCP has no protocol for a
// third-party client to implement.
// ---------------------------------------------------------------------------

fn nc_tcp(input: &str) -> Probe {
    Probe::generic("nc", &["-w", "235", "127.0.0.1", "{PORT}"]).stdin(input)
}

fn tcp() -> Vec<EvalCase> {
    vec![
        EvalCase::new(
            "tcp/fixed-reply",
            "tcp",
            "Reply to anything a client sends with the single line PONG-EVAL.",
            nc_tcp("hello\n"),
            Expect::contains(&["PONG-EVAL"]),
        ),
        EvalCase::new(
            "tcp/echo",
            "tcp",
            "Echo back exactly what the client sent.",
            nc_tcp("netget-eval-ping\n"),
            Expect::contains(&["netget-eval-ping"]),
        ),
        EvalCase::new(
            "tcp/uppercase",
            "tcp",
            "Send back the client's text in upper case.",
            nc_tcp("hello eval\n"),
            Expect::contains(&["HELLO EVAL"]),
        ),
    ]
}

// ---------------------------------------------------------------------------
// FTP — inetutils `ftp`, which takes the port as a positional argument.
// ---------------------------------------------------------------------------

fn ftp_probe(script: &str) -> Probe {
    // Several model calls in a row (banner, USER, PASS, PWD) with `-v` narrating each one as it
    // lands, so the client talks between calls; the idle settle cut it off after the banner
    // whenever the next answer took more than two seconds. It exits on `quit`.
    //
    // The script is `\n`-terminated. The ftp client reads its stdin by line and keeps a
    // trailing `\r` as part of the command, so `pwd\r` and `quit\r` were `?Invalid command`
    // and never reached the server - `ftp/working-directory` could not pass whatever the
    // model did.
    Probe::client("ftp", &["-n", "-v", "127.0.0.1", "{PORT}"])
        .stdin(script)
        .until_exit()
}

fn ftp() -> Vec<EvalCase> {
    vec![
        EvalCase::new(
            "ftp/banner",
            "ftp",
            "Greet every connection with the banner NetGet Eval FTP, and let anyone log \
             in anonymously.",
            ftp_probe("quit\n"),
            Expect::contains(&["NetGet Eval FTP"]),
        ),
        EvalCase::new(
            "ftp/anonymous-login",
            "ftp",
            "Let anyone log in anonymously and tell them the login succeeded.",
            ftp_probe("user anonymous eval@example.com\nquit\n"),
            Expect::default().matching(r"(?i)230|logged in|login successful"),
        ),
        EvalCase::new(
            "ftp/working-directory",
            "ftp",
            "Let anyone log in anonymously. The current directory is /eval.",
            ftp_probe("user anonymous eval@example.com\npwd\nquit\n"),
            Expect::contains(&["/eval"]),
        ),
    ]
}

// ---------------------------------------------------------------------------
// UDP — nc -u. Same caveat as TCP.
// ---------------------------------------------------------------------------

fn nc_udp(input: &str) -> Probe {
    Probe::generic("nc", &["-u", "-w", "235", "127.0.0.1", "{PORT}"]).stdin(input)
}

fn udp() -> Vec<EvalCase> {
    vec![
        EvalCase::new(
            "udp/fixed-reply",
            "udp",
            "Answer every datagram with the text UDP-EVAL-OK.",
            nc_udp("hello\n"),
            Expect::contains(&["UDP-EVAL-OK"]),
        ),
        EvalCase::new(
            "udp/echo",
            "udp",
            "Send every datagram straight back to whoever sent it, unchanged.",
            nc_udp("netget-eval-datagram\n"),
            Expect::contains(&["netget-eval-datagram"]),
        ),
    ]
}

// ---------------------------------------------------------------------------
// Prometheus — curl fetches /metrics and pipes it to promtool, the Prometheus
// project's own parser and linter. `PROMTOOL-OK` is printed only when promtool
// exits 0, so a case passes only if the model's metrics rendered into an
// exposition a real scraper accepts. `tee /dev/stderr` keeps the body in the
// probe output for the content checks.
// ---------------------------------------------------------------------------

fn promtool_scrape() -> Probe {
    Probe::client(
        "sh",
        &[
            "-c",
            "curl -sS --max-time 230 http://127.0.0.1:{PORT}/metrics | tee /dev/stderr \
             | promtool check metrics && echo PROMTOOL-OK",
        ],
    )
}

fn prometheus() -> Vec<EvalCase> {
    vec![
        EvalCase::new(
            "prometheus/queue-depth-gauge",
            "prometheus",
            "Expose a gauge named netget_eval_queue_depth whose value is 17.",
            promtool_scrape(),
            Expect::contains(&["netget_eval_queue_depth 17", "PROMTOOL-OK"]),
        ),
        EvalCase::new(
            "prometheus/requests-by-status",
            "prometheus",
            "Count HTTP requests by status code: 1500 requests answered 200 and 12 answered \
             404 so far.",
            promtool_scrape(),
            Expect::contains(&["PROMTOOL-OK"]).matching(r#"(?i)="?200"?[,}][^\n]* 1500"#),
        ),
        EvalCase::new(
            "prometheus/latency-histogram",
            "prometheus",
            "Report request latency in seconds as a histogram with buckets at 0.1, 0.5 and 1 \
             second; 40 requests so far, 30 of them under 0.1s.",
            promtool_scrape(),
            Expect::contains(&["_bucket", "le=\"+Inf\"", "PROMTOOL-OK"]),
        ),
    ]
}

// ---------------------------------------------------------------------------
// Docker — the real docker CLI pointed at NetGet with -H. DOCKER_HOST and
// DOCKER_CONTEXT are overridden and DOCKER_CONFIG is a throwaway path, so the
// machine's own daemon is never consulted.
// ---------------------------------------------------------------------------

fn docker_cli(args: &[&str]) -> Probe {
    let mut all = vec!["-H", "tcp://127.0.0.1:{PORT}"];
    all.extend_from_slice(args);
    Probe::client("docker", &all)
        .env("DOCKER_HOST", "")
        .env("DOCKER_CONTEXT", "default")
        .env("DOCKER_CONFIG", "/tmp/netget-eval-docker-config")
}

fn docker() -> Vec<EvalCase> {
    vec![
        EvalCase::new(
            "docker/ps-running-container",
            "docker",
            "Act as a Docker host running one container named eval-web from the image \
             nginx:1.27, publishing host port 8080 to container port 80.",
            docker_cli(&["ps"]),
            Expect::contains(&["eval-web", "nginx:1.27", "8080->80/tcp"]),
        ),
        EvalCase::new(
            "docker/ps-all-includes-stopped",
            "docker",
            "Act as a Docker host with a running container eval-api (image api:2) and a \
             stopped container eval-migrate (image api:2) that exited with code 0.",
            docker_cli(&["ps", "-a"]),
            Expect::contains(&["eval-api", "eval-migrate", "Exited (0)"]),
        ),
        EvalCase::new(
            "docker/inspect-missing",
            "docker",
            "Act as a Docker host with no containers at all.",
            docker_cli(&["inspect", "eval-ghost"]),
            Expect::default().matching(r"(?i)no such (object|container)"),
        ),
    ]
}

// ---------------------------------------------------------------------------
// Vault — HashiCorp's vault CLI with VAULT_ADDR at NetGet. HOME is a throwaway
// path so no token helper from the operator's own config is read.
// ---------------------------------------------------------------------------

fn vault_cli(args: &[&str]) -> Probe {
    Probe::client("vault", args)
        .env("VAULT_ADDR", "http://127.0.0.1:{PORT}")
        .env("VAULT_TOKEN", "hvs.netget-eval")
        .env("HOME", "/tmp/netget-eval-vault-home")
}

fn vault() -> Vec<EvalCase> {
    vec![
        EvalCase::new(
            "vault/read-a-field",
            "vault",
            "Act as a Vault server. The secret at app/db in the secret mount holds the username \
             payments and the password NETGET-EVAL-PW.",
            vault_cli(&["kv", "get", "-field=password", "secret/app/db"]),
            Expect::contains(&["NETGET-EVAL-PW"]),
        ),
        EvalCase::new(
            "vault/list-keys",
            "vault",
            "Act as a Vault server whose secret mount has three secrets under app: db, stripe \
             and smtp.",
            vault_cli(&["kv", "list", "secret/app"]),
            Expect::contains(&["db", "stripe", "smtp"]),
        ),
        EvalCase::new(
            "vault/missing-secret",
            "vault",
            "Act as a Vault server with an empty secret mount.",
            vault_cli(&["kv", "get", "secret/app/nothing"]),
            Expect::default().matching(r"(?i)no value found"),
        ),
    ]
}

// ---------------------------------------------------------------------------
// Bolt — Neo4j's own cypher-shell (Java, neo4j-java-driver). HOME is a
// throwaway path so no history or config from the operator's own profile is
// read, and --non-interactive keeps it from waiting on a terminal.
// ---------------------------------------------------------------------------

fn bolt_shell(query: &str) -> Probe {
    Probe::client(
        "cypher-shell",
        &[
            "-a",
            "bolt://127.0.0.1:{PORT}",
            "-u",
            "neo4j",
            "-p",
            "netget-eval",
            "--non-interactive",
            "--format",
            "plain",
            query,
        ],
    )
    .env("HOME", "/tmp/netget-eval-cypher-shell-home")
    // The JVM prints a ThreadPriorityPolicy warning to stderr at startup, before
    // cypher-shell has connected, so the idle settle killed it two seconds into
    // the login's model call. It exits once the query is answered or refused.
    .until_exit()
}

fn bolt() -> Vec<EvalCase> {
    vec![
        EvalCase::new(
            "bolt/people-by-name",
            "bolt",
            "Act as a Neo4j graph database that accepts any login. The graph has three Person \
             nodes, named Ada, Grace and Linus.",
            bolt_shell("MATCH (p:Person) RETURN p.name AS name"),
            Expect::contains(&["name", "Ada", "Grace", "Linus"]),
        ),
        EvalCase::new(
            "bolt/count",
            "bolt",
            "Act as a Neo4j graph database that accepts any login. It holds exactly 42 Movie \
             nodes and nothing else.",
            bolt_shell("MATCH (m:Movie) RETURN count(m) AS movies"),
            Expect::contains(&["movies", "42"]),
        ),
        EvalCase::new(
            "bolt/syntax-error",
            "bolt",
            "Act as a Neo4j graph database that accepts any login. Reject any query that is \
             not valid Cypher with Neo4j's syntax error.",
            bolt_shell("SELECT name FROM people"),
            Expect::default().matching(r"(?i)(invalid|syntax|unexpected|expected)"),
        ),
    ]
}

// ---------------------------------------------------------------------------
// The mail and news clients below are Python's standard library — `smtplib`,
// `poplib`, `imaplib`, `nntplib` — each a separate implementation of its
// protocol that parses the replies itself: a reply code, a `+OK`, a tagged
// completion, a multi-line block with its terminating dot. They print what they
// parsed, or the name of the exception they raised.
//
// Each is a session of several model calls (the greeting is one, and every
// command after it another), and the client narrates between them, so each
// probe runs `until_exit()`. The sessions stop at the command the case is
// about: every extra command is another model call inside the probe's 240s.
// ---------------------------------------------------------------------------

const SMTPLIB_PROBE: &str = r#"import sys, smtplib
port, mode = int(sys.argv[1]), sys.argv[2]
def text(msg):
    return msg.decode('utf-8', 'replace').replace('\n', ' | ')
try:
    s = smtplib.SMTP(local_hostname='eval-client.example', timeout=230)
    code, msg = s.connect('127.0.0.1', port)
    print('GREETING', code, text(msg))
    if mode == 'rcpt':
        code, msg = s.ehlo()
        print('EHLO', code, text(msg))
        code, msg = s.mail('postmaster@example.com')
        print('MAIL', code, text(msg))
        code, msg = s.rcpt(sys.argv[3])
        print('RCPT', code, text(msg))
    s.close()
except Exception as e:
    print(type(e).__name__, e)
"#;

fn smtp_probe(mode: &str, recipient: &str) -> Probe {
    Probe::client("python3", &["-c", SMTPLIB_PROBE, "{PORT}", mode, recipient]).until_exit()
}

fn smtp() -> Vec<EvalCase> {
    const DOMAIN_POLICY: &str = "Accept mail addressed to anyone at example.com. Refuse mail \
                                 for any other domain.";
    vec![
        EvalCase::new(
            "smtp/named-banner",
            "smtp",
            "Greet every connection with the banner NetGet Eval Mail.",
            smtp_probe("greet", "-"),
            Expect::contains(&["GREETING 220", "NetGet Eval Mail"]),
        ),
        EvalCase::new(
            "smtp/accept-local-domain",
            "smtp",
            DOMAIN_POLICY,
            smtp_probe("rcpt", "alice@example.com"),
            Expect::default().matching(r"(?s)\nMAIL 250\b.*\nRCPT 25[01]\b"),
        ),
        EvalCase::new(
            "smtp/refuse-other-domain",
            "smtp",
            DOMAIN_POLICY,
            smtp_probe("rcpt", "bob@elsewhere.test"),
            // The refusal has to land on the recipient: a sender refused at MAIL would
            // make RCPT a 503 bad-sequence, which is a 5xx for the wrong reason.
            Expect::default().matching(r"(?s)\nMAIL 250\b.*\nRCPT 5\d\d\b"),
        ),
    ]
}

const POPLIB_PROBE: &str = r#"import sys, poplib
port, mode = int(sys.argv[1]), sys.argv[2]
def text(b):
    return b.decode('utf-8', 'replace')
try:
    p = poplib.POP3('127.0.0.1', port, timeout=230)
    print('GREETING', text(p.getwelcome()))
    print('USER', text(p.user('eval')))
    print('PASS', text(p.pass_('eval-password')))
    if mode == 'stat':
        count, size = p.stat()
        print('STAT', count, size)
    else:
        resp, lines, octets = p.retr(1)
        print('RETR', text(resp))
        for line in lines:
            print(text(line))
except Exception as e:
    print(type(e).__name__, e)
"#;

fn pop3_probe(mode: &str) -> Probe {
    Probe::client("python3", &["-c", POPLIB_PROBE, "{PORT}", mode]).until_exit()
}

fn pop3() -> Vec<EvalCase> {
    vec![
        EvalCase::new(
            "pop3/message-count",
            "pop3",
            "Accept any login. The mailbox holds 7 messages.",
            pop3_probe("stat"),
            Expect::default().matching(r"(?m)^STAT 7 \d+"),
        ),
        EvalCase::new(
            "pop3/message-subject",
            "pop3",
            "Accept any login. The mailbox holds one message, from alice@example.com, with \
             the subject Quarterly figures are in.",
            pop3_probe("retr"),
            Expect::contains(&["RETR +OK", "Subject: Quarterly figures are in"]),
        ),
    ]
}

const IMAPLIB_PROBE: &str = r#"import sys, imaplib
port, mode = int(sys.argv[1]), sys.argv[2]
def text(b):
    return b.decode('utf-8', 'replace') if isinstance(b, bytes) else str(b)
try:
    m = imaplib.IMAP4('127.0.0.1', port, timeout=230)
    print('GREETING', text(m.welcome))
    typ, data = m.login('eval', 'eval-password')
    print('LOGIN', typ)
    if mode == 'list':
        typ, data = m.list()
        print('LIST', typ)
        for line in data:
            print(text(line))
    else:
        typ, data = m.select('INBOX')
        print('SELECT', typ, [text(d) for d in data])
except Exception as e:
    print(type(e).__name__, e)
"#;

fn imap_probe(mode: &str) -> Probe {
    Probe::client("python3", &["-c", IMAPLIB_PROBE, "{PORT}", mode]).until_exit()
}

fn imap() -> Vec<EvalCase> {
    vec![
        EvalCase::new(
            "imap/list-folders",
            "imap",
            "Accept any login. The account has three folders: INBOX, Archive and Receipts.",
            imap_probe("list"),
            Expect::contains(&["LIST OK", "INBOX", "Archive", "Receipts"]),
        ),
        EvalCase::new(
            "imap/inbox-count",
            "imap",
            "Accept any login. The INBOX holds 12 messages.",
            imap_probe("select"),
            // imaplib's select() returns the untagged EXISTS count, not the completion,
            // so ['12'] is the count it parsed out of `* 12 EXISTS`.
            Expect::contains(&["SELECT OK ['12']"]),
        ),
    ]
}

const NNTPLIB_PROBE: &str = r#"import sys, nntplib
port, mode, arg = int(sys.argv[1]), sys.argv[2], sys.argv[3]
try:
    n = nntplib.NNTP('127.0.0.1', port, readermode=False, usenetrc=False, timeout=230)
    print('GREETING', n.getwelcome())
    if mode == 'group':
        resp, count, first, last, name = n.group(arg)
        print('GROUP', resp)
        print('COUNT', count, 'FIRST', first, 'LAST', last, 'NAME', name)
    else:
        resp, groups = n.list()
        print('LIST', resp)
        for g in groups:
            print('ACTIVE', g.group, g.last, g.first, g.flag)
except Exception as e:
    print(type(e).__name__, e)
"#;

fn nntp_probe(mode: &str, arg: &str) -> Probe {
    // nntplib reads the greeting and then issues CAPABILITIES before the command
    // under test, so every case is at least three model calls.
    Probe::client("python3", &["-c", NNTPLIB_PROBE, "{PORT}", mode, arg]).until_exit()
}

fn nntp() -> Vec<EvalCase> {
    vec![
        EvalCase::new(
            "nntp/group-article-count",
            "nntp",
            "You are a news server carrying the group comp.lang.eval, which holds 42 articles \
             numbered 1 to 42.",
            nntp_probe("group", "comp.lang.eval"),
            Expect::contains(&["COUNT 42 FIRST 1 LAST 42"]),
        ),
        EvalCase::new(
            "nntp/list-groups",
            "nntp",
            "You are a news server carrying exactly two groups: comp.lang.eval and \
             alt.netget.test.",
            nntp_probe("list", "-"),
            Expect::contains(&["ACTIVE comp.lang.eval", "ACTIVE alt.netget.test"]),
        ),
        EvalCase::new(
            "nntp/unknown-group",
            "nntp",
            "You are a news server carrying only the group comp.lang.eval. No other group \
             exists.",
            nntp_probe("group", "alt.nothing.here"),
            // 411 is "no such newsgroup"; nntplib raises NNTPTemporaryError carrying it.
            Expect::default().matching(r"NNTPTemporaryError 411\b"),
        ),
    ]
}

// ---------------------------------------------------------------------------
// Memcached — pymemcache (`pip install pymemcache`), not libmemcached's memcat,
// and the reason is measured: every libmemcached tool (`memcat`, `memstat`,
// `memping`) gives up after its built-in 5-second poll timeout, and none of
// them has an option to raise it. Against a listener that answered after 8s,
// `memcat` printed `Error on motd(NOT FOUND)` at 5.01s. A model answer takes
// 5-90s, so memcat would score the harness. pymemcache is an independent
// Python client that parses the `VALUE`/`STAT` framing itself and takes a
// timeout.
// ---------------------------------------------------------------------------

const PYMEMCACHE_PROBE: &str = r#"import sys
from pymemcache.client.base import Client
c = Client(('127.0.0.1', int(sys.argv[1])), connect_timeout=30, timeout=230)
try:
    if sys.argv[2] == 'get':
        v = c.get(sys.argv[3])
        print('MISS' if v is None else 'VALUE ' + v.decode('utf-8', 'replace'))
    else:
        for k, v in sorted(c.stats().items()):
            k = k.decode('utf-8', 'replace') if isinstance(k, bytes) else k
            v = v.decode('utf-8', 'replace') if isinstance(v, bytes) else v
            print('STAT', k, v)
except Exception as e:
    print(type(e).__name__, e)
"#;

fn memcached_probe(mode: &str, key: &str) -> Probe {
    Probe::client("python3", &["-c", PYMEMCACHE_PROBE, "{PORT}", mode, key])
}

fn memcached() -> Vec<EvalCase> {
    vec![
        EvalCase::new(
            "memcached/get-value",
            "memcached",
            "You are a cache. The key motd holds the value netget-eval-cache-hit.",
            memcached_probe("get", "motd"),
            Expect::contains(&["VALUE netget-eval-cache-hit"]),
        )
        .note("libmemcached's tools time out after 5s; driven with pymemcache."),
        EvalCase::new(
            "memcached/missing-key",
            "memcached",
            "You are a cache that holds only the key motd. Every other key is missing.",
            memcached_probe("get", "nothing-here"),
            Expect::contains(&["MISS"]).not_containing(&["VALUE"]),
        ),
        EvalCase::new(
            "memcached/stats-version",
            "memcached",
            "You are a cache server running version 1.6.21 with 12 items stored.",
            memcached_probe("stats", "-"),
            Expect::contains(&["STAT version 1.6.21"]),
        ),
    ]
}

// ---------------------------------------------------------------------------
// MQTT — Eclipse Mosquitto's mosquitto_sub, a C client on libmosquitto. `-k 300`
// because libmosquitto reconnects when a CONNACK has not arrived within its
// keepalive (measured: a fresh CONNECT 61s after the first against a silent
// listener at the default 60), which would put a second CONNECT in front of the
// model mid-case. `-W 230` bounds the whole session.
// ---------------------------------------------------------------------------

fn mosquitto_sub(client_id: &str, topic: &str) -> Probe {
    Probe::client(
        "mosquitto_sub",
        &[
            "-V",
            "mqttv311",
            "-h",
            "127.0.0.1",
            "-p",
            "{PORT}",
            "-k",
            "300",
            "-i",
            client_id,
            "-t",
            topic,
            "-C",
            "1",
            "-W",
            "230",
            "-v",
        ],
    )
}

fn mqtt() -> Vec<EvalCase> {
    vec![
        EvalCase::new(
            "mqtt/retained-message",
            "mqtt",
            "You are an MQTT broker that accepts every client. The topic \
             sensors/greenhouse/temp holds the retained reading 19.5.",
            mosquitto_sub("eval-subscriber", "sensors/greenhouse/temp"),
            // `-v` prints "<topic> <payload>" for a PUBLISH libmosquitto decoded.
            Expect::contains(&["sensors/greenhouse/temp 19.5"]),
        ),
        EvalCase::new(
            "mqtt/refuse-client-id",
            "mqtt",
            "You are an MQTT broker. Refuse any client whose client id starts with guest; \
             accept everyone else.",
            mosquitto_sub("guest-7", "eval/#"),
            // libmosquitto's wording for a CONNACK with a non-zero return code.
            Expect::contains(&["Connection Refused"]),
        ),
    ]
}

// ---------------------------------------------------------------------------
// CoAP — libcoap's coap-client. `-N` sends the request Non-confirmable: a
// Confirmable one is retransmitted after ~2s, ~6s, ~14s and ~30s, and this
// server has no deduplication cache, so every retransmission would be another
// model call while the first is still being answered. A Non-confirmable
// request is sent once and `-B 230` is how long libcoap waits for the answer
// (measured: still waiting after 3 minutes against a silent listener).
// ---------------------------------------------------------------------------

fn coap_probe(path: &str) -> Probe {
    let uri = format!("coap://127.0.0.1:{{PORT}}{}", path);
    Probe::client(
        "coap-client",
        &["-N", "-B", "230", "-m", "get", uri.as_str()],
    )
}

fn coap() -> Vec<EvalCase> {
    vec![
        EvalCase::new(
            "coap/text-resource",
            "coap",
            "You are a greenhouse sensor. The resource /temperature returns the text 19.5 C.",
            coap_probe("/temperature"),
            Expect::contains(&["19.5 C"]),
        ),
        EvalCase::new(
            "coap/not-found",
            "coap",
            "You are a greenhouse sensor whose only resource is /temperature. Every other \
             path does not exist.",
            coap_probe("/humidity"),
            Expect::contains(&["4.04"]),
        ),
    ]
}

// ---------------------------------------------------------------------------
// Modbus — pymodbus (installed), not libmodbus's mbpoll, and the reason is the
// same as memcached's: mbpoll's response timeout is capped at 10 seconds
// (`-o # Time-out in seconds (0.01 - 10.00)`), shorter than most model answers.
// pymodbus is an independent Python implementation that decodes the MBAP
// header, the function code and the exception PDU itself; `timeout=230,
// retries=0` makes it wait once and never resend.
// ---------------------------------------------------------------------------

const PYMODBUS_PROBE: &str = r#"import sys
from pymodbus.client import ModbusTcpClient
c = ModbusTcpClient('127.0.0.1', port=int(sys.argv[1]), timeout=230, retries=0)
if not c.connect():
    print('CONNECT FAILED')
    sys.exit(1)
try:
    rr = c.read_holding_registers(int(sys.argv[2]), count=int(sys.argv[3]), device_id=1)
    if rr.isError():
        print('EXCEPTION', getattr(rr, 'exception_code', rr))
    else:
        print('REGISTERS', rr.registers)
except Exception as e:
    print(type(e).__name__, e)
finally:
    c.close()
"#;

fn modbus_probe(address: &str, count: &str) -> Probe {
    Probe::client("python3", &["-c", PYMODBUS_PROBE, "{PORT}", address, count])
}

fn modbus() -> Vec<EvalCase> {
    vec![
        EvalCase::new(
            "modbus/holding-registers",
            "modbus",
            "You are a PLC. Holding registers 0, 1 and 2 hold 1200, 350 and 42.",
            modbus_probe("0", "3"),
            Expect::contains(&["REGISTERS [1200, 350, 42]"]),
        )
        .note("mbpoll's timeout is capped at 10s; driven with pymodbus."),
        EvalCase::new(
            "modbus/illegal-address",
            "modbus",
            "You are a PLC with ten holding registers at addresses 0 to 9, all zero. There is \
             nothing at any other address.",
            modbus_probe("500", "2"),
            // Exception code 2, ILLEGAL DATA ADDRESS, as pymodbus decoded it.
            Expect::contains(&["EXCEPTION 2"]),
        ),
    ]
}

// ---------------------------------------------------------------------------
// SNMP — Net-SNMP's snmpget, v2c. `-On` prints OIDs numerically so the output
// does not depend on installed MIBs; `-t 230 -r 0` waits once and never resends.
// ---------------------------------------------------------------------------

fn snmpget(oids: &[&str]) -> Probe {
    let mut args = vec![
        "-On",
        "-v",
        "2c",
        "-c",
        "public",
        "-t",
        "230",
        "-r",
        "0",
        "127.0.0.1:{PORT}",
    ];
    args.extend_from_slice(oids);
    Probe::client("snmpget", &args)
}

const SYS_DESCR: &str = "1.3.6.1.2.1.1.1.0";
const SYS_NAME: &str = "1.3.6.1.2.1.1.5.0";

fn snmp() -> Vec<EvalCase> {
    vec![
        EvalCase::new(
            "snmp/sysdescr",
            "snmp",
            "You are a network switch. Its system description is NetGet Eval Switch 1.0.",
            snmpget(&[SYS_DESCR]),
            Expect::contains(&["STRING: NetGet Eval Switch 1.0"]),
        ),
        EvalCase::new(
            "snmp/sysdescr-and-sysname",
            "snmp",
            "You are a network switch named eval-core-01, whose system description is \
             NetGet Eval Switch 1.0.",
            snmpget(&[SYS_DESCR, SYS_NAME]),
            Expect::contains(&["NetGet Eval Switch 1.0", "eval-core-01"]),
        ),
    ]
}

// ---------------------------------------------------------------------------
// SIP — sipsak, which sends OPTIONS in its default (shoot) mode and exits 0 only
// on a 2xx whose Via, Call-ID and CSeq match its request. `--timer-t1=10000`
// because sipsak retransmits a non-INVITE request on T1 doubling (measured at
// T1=5000: resends at 5s, 15s, 35s and 75s) and this server answers each copy
// with its own model call; at 10s a typical answer sees one resend at most.
// `-vv` prints the request before it is answered, so this is `until_exit()`.
// ---------------------------------------------------------------------------

fn sipsak_probe() -> Probe {
    Probe::client(
        "sipsak",
        &["--timer-t1=10000", "-vv", "-s", "sip:eval@127.0.0.1:{PORT}"],
    )
    .until_exit()
}

fn sip() -> Vec<EvalCase> {
    vec![
        EvalCase::new(
            "sip/available",
            "sip",
            "You are a SIP phone that is online. Tell anyone who checks whether you are \
             reachable that you are available.",
            sipsak_probe(),
            Expect::default().matching(r"SIP/2\.0 200\b"),
        ),
        EvalCase::new(
            "sip/busy",
            "sip",
            "You are a SIP phone in do-not-disturb mode. Tell anyone who checks on you that \
             you are busy.",
            sipsak_probe(),
            // RFC 3261 §11.2: the answer to OPTIONS is the one an INVITE would get, so
            // busy is 486 Busy Here (or 600 Busy Everywhere).
            Expect::default().matching(r"SIP/2\.0 (486|600)\b"),
        ),
    ]
}

// ---------------------------------------------------------------------------
// WebSocket — websocat, which does its own RFC 6455 handshake and framing and
// prints each text message it receives on a line. Its stdin is held open: at
// EOF websocat closes the connection, which would hang up before the model had
// answered. Every connection costs two model calls (handshake, then open)
// before the first message is handled.
// ---------------------------------------------------------------------------

fn websocat_probe(send: Option<&str>) -> Probe {
    let probe = Probe {
        hold_stdin: true,
        ..Probe::client("websocat", &["ws://127.0.0.1:{PORT}/"])
    };
    match send {
        Some(text) => probe.stdin(text),
        None => probe,
    }
}

fn websocket() -> Vec<EvalCase> {
    vec![
        EvalCase::new(
            "websocket/echo",
            "websocket",
            "Echo every message a client sends straight back to it, unchanged.",
            websocat_probe(Some("netget-eval-ws-ping\n")),
            Expect::contains(&["netget-eval-ws-ping"]),
        ),
        EvalCase::new(
            "websocket/greeting",
            "websocket",
            "Greet every client with the message Welcome to NetGet Eval as soon as it \
             connects.",
            websocat_probe(None),
            Expect::contains(&["Welcome to NetGet Eval"]),
        ),
    ]
}

// ---------------------------------------------------------------------------
// Nostr — nak, fiatjaf's Go client (go-nostr). `nak req` prints each event it
// received and verified, then exits at EOSE; `nak event` signs with the key
// given, publishes and prints "success" or the relay's refusal. nak prints
// "connecting to ..." on stderr before the exchange, so completion is its exit.
// ---------------------------------------------------------------------------

/// The key the eval's notes are signed with. Any valid secp256k1 secret works;
/// this one is fixed so a run is reproducible.
const NOSTR_EVAL_KEY: &str = "7f7ff03d123792d6ac594bfa67bf6d0c0ab55b6b1fdb6249303fe861f1ccba9a";

fn nak_publish(content: &str) -> Probe {
    Probe::client(
        "nak",
        &[
            "event",
            "--sec",
            NOSTR_EVAL_KEY,
            "-c",
            content,
            "ws://127.0.0.1:{PORT}",
        ],
    )
    .until_exit()
}

fn nostr() -> Vec<EvalCase> {
    vec![
        EvalCase::new(
            "nostr/serve-notes",
            "nostr",
            "When someone subscribes to short text notes, give them two notes: \
             Stalker is a masterpiece, and Solaris is slower but worth it.",
            Probe::client("nak", &["req", "-k", "1", "ws://127.0.0.1:{PORT}"]).until_exit(),
            Expect::contains(&["Stalker is a masterpiece", "Solaris is slower but worth it"]),
        ),
        EvalCase::new(
            "nostr/refuse-adverts",
            "nostr",
            "Take notes from anyone, but refuse any note that advertises something for \
             sale, telling the author that adverts are not allowed.",
            nak_publish("Buy cheap watches now, 50% off"),
            Expect::contains(&["adverts are not allowed"]).not_containing(&["success"]),
        ),
        EvalCase::new(
            "nostr/accept-film-note",
            "nostr",
            "This relay is for notes about films. Accept them.",
            nak_publish("Stalker is a masterpiece of slow cinema"),
            Expect::contains(&["success"]),
        ),
    ]
}
