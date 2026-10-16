#!/usr/bin/env python3
"""Generate the Beta-evidence table from the source tree, for servers or for clients.

CLAUDE.md carries a hand-maintained list of which protocols are Beta and what their
evidence is. That list has been wrong three times, in both directions: it under-rated
`etcd` and `modbus` while they already had official-client tests, and it over-rated
`ssh` on the strength of `russh` — which is the server's *own* library, so the "peer"
was the server. A generated table cannot drift.

For every registered protocol on the selected side this prints:

  state          the DevelopmentState its own metadata() declares
  peer           the third-party binaries and crates its tests actually drive
  circular       any of those crates that its own src/<side>/<p>/ also imports, which
                 means the peer is the same implementation as the framer and the
                 evidence proves only that a crate agrees with itself
  optional       any of those crates declared `optional = true` in Cargo.toml, which
                 means the dependency is not compiled where the gate runs
  ignored        how many of its tests are #[ignore]d
  skip-gate      whether a test prints a skip message and returns success anyway

The last four are the three ways CLAUDE.md says evidence fails to execute, plus the
circular case. `--check` exits non-zero only on what a script can be *sure* of.
Circular and optional dependencies are printed as review flags instead, because both
have accepted exceptions (`quic`/quinn and `webrtc`/webrtc-rs use the server's own
crate in the opposite role, completing a real handshake) and no static rule can tell
those from the `ssh`/russh case.

THE TWO BARS ARE NOT THE SAME, which is why `--side` is more than a path swap.

A **server** proves itself against a third-party *client*. A **client** proves itself
against a third-party *server* — and CLAUDE.md's client bar adds two conditions the
server bar does not have:

  * **The peer must not be NetGet's own server.** Pointing NetGet's redis client at
    NetGet's redis server proves the two agree, which is what they were both written to
    do. This is the circular case wearing the other hat, and it is by far the largest
    group: the September 2026 hand audit put it at ~60 of 98. It is detected here as
    `self-served` — a test that builds a `ServerForm`, calls `start_netget_server` or
    sends an `open_server` action — and it is blocking when nothing else backs the
    rating up.
  * **`#[ignore]` disqualifies, not just a skip gate.** The server bar treats a partly
    ignored suite as a review flag, because a suite may legitimately ignore its
    adapter-claiming tests while its real evidence runs. The client bar does not: the
    audit's second-largest group was "real peer, unreachable evidence — and every one
    of those tests is `#[ignore]`d". So peers are attributed **per file**, and a peer
    that appears only in files where every test is ignored is reported as unreachable
    and fails `--check` on the client side.

What this cannot check, on either side, is the fourth client condition — that the
client acts on the model's answer, asserted on the wire. `tests/client_event_wiring_test.rs`
is the ratchet for that; this script names it as a review item rather than pretending
to decide it, because "the LLM was called" and "the client did what it said" look
identical to a scan.

Usage:
    python3 scripts/beta_evidence_table.py                      # Beta servers, markdown
    python3 scripts/beta_evidence_table.py --side client --all  # every client
    python3 scripts/beta_evidence_table.py --check              # exit 1 on a defective Beta
    python3 scripts/beta_evidence_table.py --side client --experimental-with-evidence
                                                                # promotion candidates
"""

from __future__ import annotations

import argparse
import re
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Crates that are infrastructure rather than a protocol peer: importing them says
# nothing about who validated the wire format.
INFRASTRUCTURE = {
    "std", "core", "alloc", "super", "crate", "self",
    "tokio", "tokio_util", "tokio_test", "futures", "futures_util", "async_trait",
    "serde", "serde_json", "anyhow", "thiserror", "tracing", "log",
    "tempfile", "rand", "once_cell", "lazy_static", "parking_lot", "itertools",
    "bytes", "byteorder", "chrono", "time", "uuid", "regex", "url", "libc", "nix",
    "ctor", "hex", "base64", "sha1", "sha2", "md5", "md_5", "urlencoding",
    "netget", "helpers", "mod", "axum", "axum_server", "http", "http_body_util",
    # Test fixtures. Each of these is a real Cargo dependency a test genuinely reaches
    # for, which is why the "is it a known dep?" filter does not catch them — and none
    # of them speaks a protocol to anything. Reporting them as peers put the `tls`
    # client in the promotion-candidate list (`rcgen` makes it a certificate, while its
    # actual peer is a `tokio_rustls::TlsAcceptor` — rustls agreeing with rustls, which
    # CLAUDE.md names as the disqualifying case) and gave the `git` client `dirs`.
    "rcgen", "dirs",
}

# A generic HTTP client proves an HTTP server answers, not that the protocol layered
# ON TOP of it is right. CLAUDE.md rules that class out of Beta explicitly (couchdb,
# openapi, spark, yarn, …).
#
# It is not ruled out for a protocol that *is* HTTP, and getting that wrong is easy:
# an earlier version of this script reported `http` itself as having no peer. Which
# case a protocol is in is derivable rather than a judgement — `stack_name()` spells
# the layering out, so "…>HTTP" is HTTP and "…>HTTP>Maven" is something on top of it.
GENERIC_HTTP = {"reqwest", "hyper", "hyper_util", "ureq", "isahc"}

# Binaries that are shells, build tools or checksum utilities rather than a protocol
# client. `shasum` is an oracle for a digest, not a peer that speaks the protocol.
NOT_A_PEER_BINARY = {
    "sh", "bash", "zsh", "which", "echo", "cat", "true", "false", "sleep", "env",
    "shasum", "sha256sum", "sha1sum", "md5sum", "python3", "python", "node", "protoc",
    "cargo", "rustc", "unzip", "zip", "tar", "gzip", "cp", "mv", "rm", "mkdir",
}

# ...with one exception, because `python3` on its own is a language runtime and
# `python3` driving a stdlib protocol module is a real, independent client.
#
# `tests/server/imap/real_client_test.rs` runs `python3 -c "import imaplib; ..."`, and
# imaplib does the framing, the `{n}` literal reading and the tag matching itself — it is
# a second implementation of IMAP by any standard, and it needs no install. Excluding it
# because the binary is spelled `python3` reported that protocol as having only its Rust
# peer, which is the under-rating direction this script exists to avoid.
#
# Only modules that *speak a protocol* belong here. `json`, `subprocess` and friends do
# not, and a python3 invocation that imports none of these stays excluded.
PYTHON_STDLIB_PROTOCOL_MODULES = (
    "imaplib", "smtplib", "poplib", "ftplib", "nntplib", "telnetlib",
    "http.client", "xmlrpc.client",
)

# Third-party Python client libraries that are a protocol peer in their own right, driven the
# same way (python3 spawned, the library imported by the driver). Same bar as the stdlib list:
# the library must do the protocol's framing and parsing itself, and the server must not use
# it. `ignition` (pip `ignition-gemini`) opens TLS through CPython's ssl module, pins the
# certificate trust-on-first-use and parses the Gemini response header and body; NetGet's
# Gemini server is rustls plus hand-written framing. `greenstalk` (pip `greenstalk`) splits
# beanstalkd reply lines, reads RESERVED/FOUND/OK payloads by their byte count and parses the
# YAML reports itself; NetGet's Beanstalkd server is hand-written and uses no beanstalk library.
# `nostr_sdk` (pip `nostr-sdk`) is rust-nostr's bindings: its own NIP-01 messages, filters,
# event ids and signature checks; NetGet's relay uses no Nostr library.
# `smbprotocol` (pip `smbprotocol`) frames SMB2 over Direct TCP, runs NTLMSSP through pyspnego
# and parses every response itself; NetGet's SMB server is hand-written and links no SMB
# library.
PYTHON_THIRD_PARTY_PROTOCOL_CLIENTS = (
    "ignition",
    "greenstalk",
    "nostr_sdk",
    "smbprotocol",
)

# The same exception on the other side of the wire: a Python library that is a protocol
# *server* in its own right, spawned by a client test through `RealServer::builder("python3")`
# with the script the test writes importing it. `pymodbus` frames Modbus/TCP with its own
# framer and answers from its own datastore; NetGet's Modbus client frames with NetGet's codec.
# Without this entry the modbus client read as having only `mbpoll`, which is the tool that
# reads the device back, not the device. `os_ken` (pip `os-ken`, OpenStack's Ryu) is an
# OpenFlow controller with its own `ofproto_v1_3_parser`, handshake and datapath bookkeeping;
# NetGet's OpenFlow switch frames with NetGet's own codec.
PYTHON_THIRD_PARTY_PROTOCOL_SERVERS = (
    "pymodbus",
    "os_ken",
)

SKIP_MESSAGE = re.compile(
    r"""(?ix)
    (?:e?println!|warn!|info!|eprint!)\s*\(\s*
    (?:[^;]{0,400}?)
    (?:\bSKIP|\bskipping\b|\bskipped\b|not\ installed|not\ found|not\ available)
    """
)
RETURN_OK = re.compile(r"return\s+Ok\(\(\)\)\s*;|^\s*return\s*;", re.M)

# A few crates spell their library differently from their Cargo key, so a `use`
# statement does not name the dependency. Keep this list short and obvious.
LIB_NAME_ALIASES = {
    "rust_s3": "s3",
}


# A test that builds one of these is driving NetGet's own server of the same protocol.
#
# For a *client* that is the circular case — the peer is the implementation this
# repository wrote to agree with it — and it is what ~60 of 98 clients rest on. It is
# not a defect on the server side (a server test starting a server is just the setup),
# so it is only interpreted under `--side client`.
SELF_SERVED_MARKERS = (
    "ServerForm",
    "start_netget_server",
    '"open_server"',
    "open_server",
)


def declared_states(side: str) -> dict[str, str]:
    """Each protocol's own state, declared through a metadata builder or struct field.

    OSPF's client constructs ProtocolMetadataV2 directly; scanning only .state(...)
    silently omitted it from the inventory.
    """
    pattern = re.compile(
        r"(?:\.state\(\s*|\bstate\s*:\s*)"
        r"(?:crate::protocol::metadata::)?DevelopmentState::([A-Za-z]+)"
    )
    out: dict[str, str] = {}
    base = ROOT / "src" / side
    for actions in sorted(list(base.glob("*/actions.rs")) + list(base.glob("*/*/actions.rs"))):
        rel = actions.relative_to(base).parent.as_posix()
        m = pattern.search(actions.read_text(errors="ignore"))
        if m:
            out[rel] = m.group(1)
    return out


def http_native(protocol: str, side: str) -> bool:
    """True when the protocol's own stack ends at HTTP, so an HTTP peer is its peer.

    `ETH>IP>TCP>HTTP` is HTTP; `ETH>IP>TCP>HTTP>Maven` is Maven carried over HTTP, and
    for that one a generic HTTP library proves the transport and nothing above it.

    The rule is the same in both directions, only the role flips: for a server it says
    whether `reqwest` counts as a client, for a client whether an `axum` router (or
    `nginx`) counts as a server.
    """
    actions = ROOT / "src" / side / protocol / "actions.rs"
    if not actions.is_file():
        return False
    m = re.search(
        r'fn\s+stack_name\s*\([^)]*\)\s*->\s*&\'static\s+str\s*\{[^}]*?"([^"]+)"',
        actions.read_text(errors="ignore"),
        re.S,
    )
    if not m:
        return False
    return m.group(1).split(">")[-1].upper() in {"HTTP", "HTTPS", "HTTP/1.1", "HTTP2"}


def cargo_dependencies() -> dict[str, bool]:
    """Every declared dependency, mapped to whether it is an **optional dev-dependency**.

    Keys are normalised to the crate's Rust identifier (`-` becomes `_`), which is
    how a `use` statement spells it.

    **This used to return `optional = true` alone, and that made its loudest finding
    wrong.** The hole worth flagging is a crate that the job running the gate never
    builds, and only an `optional = true` entry under `[dev-dependencies]` is that:
    a plain optional `[dependencies]` entry is compiled exactly when its feature is
    on, which is exactly when its protocol's tests run.

    Measured 16 September 2026: **142 optional regular dependencies and ZERO optional
    dev-dependencies**, so every one of the dozen "AMQP/lapin hole" warnings this
    produced was a false positive — including the one for lapin itself, which is a
    plain `[dependencies]` entry. A warning that fires on a dozen protocols for a
    condition none of them has trains the reader to skip the whole section.

    The real gap those protocols share is that the blocking CI job compiles 6 of 116
    features, which is true of 110 protocols and is not a property of any one of them.
    It belongs in the header, not on a row.
    """
    text = (ROOT / "Cargo.toml").read_text(errors="ignore")
    deps: dict[str, bool] = {}
    section = None
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("["):
            section = stripped.strip("[]")
            continue
        if section is None or "dependencies" not in section:
            continue
        m = re.match(r'^([A-Za-z0-9_-]+)\s*=\s*(.*)$', stripped)
        if not m:
            continue
        name, rest = m.group(1), m.group(2)
        optional = ("optional = true" in rest or "optional=true" in rest) and (
            "dev-dependencies" in section
        )
        key = name.replace("-", "_")
        deps[key] = optional
        # `foo = { package = "bar" }` means `use bar::` is what the code writes.
        pkg = re.search(r'package\s*=\s*"([^"]+)"', rest)
        if pkg:
            deps[pkg.group(1).replace("-", "_")] = optional
        if key in LIB_NAME_ALIASES:
            deps[LIB_NAME_ALIASES[key]] = optional
    return deps


def imported_crates(directory: Path, known: set[str]) -> set[str]:
    """Third-party crates a directory reaches for.

    Both spellings matter. `use async_imap::…` is the usual one, but a test may also
    write `async_nats::connect(…)` inline with no `use` at all — `tests/server/nats`
    does, and an earlier version of this script reported NATS as having no peer
    because of it.

    The inline form is matched only against names that really are Cargo dependencies.
    Matching every lowercase `x::` instead reported `u16`, `mpsc`, `str` and `collect`
    as third-party peers, which is worse than missing one: a table full of noise gets
    ignored, and an ignored table drifts exactly like the hand-maintained list it
    replaces.
    """
    if not directory.is_dir():
        return set()
    found: set[str] = set()
    for f in directory.rglob("*.rs"):
        code = strip_line_comments(f.read_text(errors="ignore"))
        found |= crates_in_code(code, known)
    return found


USE_FORM = re.compile(r"^\s*use\s+([a-z][a-z0-9_]*)\s*::", re.M)
# Captures the crate *and* the segment after it, because the second one decides whether
# the first is a peer — see `crates_in_code`.
INLINE_FORM = re.compile(r"(?<![A-Za-z0-9_:])([a-z][a-z0-9_]*)\s*::\s*([a-z][a-z0-9_]*)?")


def strip_line_comments(text: str) -> str:
    """Drop `//` tails, so prose *about* a crate or a gate is not read as one.

    This repository has hit the matching-prose-about-the-pattern false positive three
    times, and twice in this script's own history.
    """
    return "\n".join(line.split("//")[0] for line in text.splitlines())


def crates_in_code(code: str, known: set[str]) -> set[str]:
    """Third-party crate names one already-comment-stripped body of code reaches for.

    One subtlety on top of the two the module docstring records. `quinn::rustls::crypto::
    ring::default_provider()` names `quinn` inline while using it purely as a **re-export**
    of another crate — `tests/client/kubernetes` does exactly that to install a crypto
    provider, and it made the kubernetes client report `quinn` as its peer, which put a
    client whose test starts no server at all into the promotion-candidate list. So an
    inline `a::b::` where `b` is itself a Cargo dependency is read as reaching for `b`,
    not for `a`. Only the inline form needs this: a real dependence writes `use quinn::…`,
    and `USE_FORM` is untouched.
    """
    found: set[str] = set()
    for m in USE_FORM.finditer(code):
        crate = m.group(1)
        if crate not in INFRASTRUCTURE and crate in known:
            found.add(crate)
    for m in INLINE_FORM.finditer(code):
        crate, inner = m.group(1), m.group(2)
        if inner and inner in known and inner != crate:
            continue  # `a::b::` — the crate being used is `b`, which its own match catches
        if crate not in INFRASTRUCTURE and crate in known:
            found.add(crate)
    return found


def test_directory(protocol: str, side: str) -> Path:
    base = ROOT / "tests" / side
    for candidate in (protocol.replace("/", "_"), protocol, protocol.split("/")[-1]):
        path = base / candidate
        if path.is_dir():
            return path
    return base / protocol.replace("/", "_")


def scan_tests(directory: Path, known: set[str]) -> dict:
    """Binaries driven, crates driven, #[ignore] counts, skip gates, and self-served tests.

    Peers are attributed **per file** as well as in aggregate, because the client bar
    turns on reachability: a peer named only in a file where every test is `#[ignore]`d
    is a peer nothing ever speaks to. The aggregate alone cannot see that — `nats`
    would look identical to `mqtt`, and one of them runs.
    """
    binaries: set[str] = set()
    crates: set[str] = set()
    ignored: list[str] = []
    total = 0
    skip_gates: list[str] = []
    self_served: list[str] = []
    per_file: list[dict] = []
    if not directory.is_dir():
        return {
            "binaries": binaries,
            "crates": crates,
            "ignored": ignored,
            "tests": 0,
            "skip_gates": skip_gates,
            "self_served": self_served,
            "per_file": per_file,
        }

    for f in sorted(directory.rglob("*.rs")):
        text = f.read_text(errors="ignore")
        code = strip_line_comments(text)
        file_binaries: set[str] = set()
        file_crates = crates_in_code(code, known)
        crates |= file_crates

        # `Command::new("dig")` is the easy case. `Command::new(&binary)`, where the
        # path was resolved earlier, is just as common — `radius` and `memcached` both
        # do it, and an earlier version of this script reported both as having no peer.
        # So the absolute paths and `tool("name")` lookups those helpers use count too.
        for m in re.finditer(r'Command::new\(\s*"([^"]+)"', code):
            name = m.group(1).split("/")[-1]
            if name not in NOT_A_PEER_BINARY:
                file_binaries.add(name)
        if re.search(r"Command::new\(\s*&?[a-z_]", code):
            for m in re.finditer(r'"(?:/opt/homebrew/bin|/usr/local/bin|/usr/bin|/bin|/sbin|/usr/sbin)/([a-z0-9_.-]+)"', code):
                if m.group(1) not in NOT_A_PEER_BINARY:
                    file_binaries.add(m.group(1))
            for m in re.finditer(r'(?:tool|which_in_path|find_binary|require_tool)\(\s*"([a-z0-9_.-]+)"', code):
                if m.group(1) not in NOT_A_PEER_BINARY:
                    file_binaries.add(m.group(1))
        # A third-party *server* spawned through `tests/helpers/real_server.rs`. The helper
        # resolves and spawns the binary itself, so the test file never writes
        # `Command::new("mosquitto")` — the builder's first argument is the only place the
        # name appears, and without this the client suites that exist to drive a real
        # server (`mqtt`, `redis`, `etcd`, `http`) reported only their CLI tools, or, for
        # `http`, no peer at all.
        for m in re.finditer(r'RealServer::builder\(\s*"([^"]+)"', code):
            name = m.group(1).split("/")[-1]
            if name not in NOT_A_PEER_BINARY:
                file_binaries.add(name)
        if re.search(r'RealServer::builder\(\s*"python3?"', code):
            for library in PYTHON_THIRD_PARTY_PROTOCOL_SERVERS:
                if re.search(r"^\s*(?:import|from)\s+" + re.escape(library) + r"\b", code, re.M):
                    file_binaries.add(f"python3 {library}")
        # The python-stdlib exception (see PYTHON_STDLIB_PROTOCOL_MODULES): a file that
        # spawns python3 AND carries a driver importing a stdlib protocol module is
        # driving that module as a peer, not using python as a shell.
        if re.search(r'Command::new\(\s*"python3?"', code):
            for module in PYTHON_STDLIB_PROTOCOL_MODULES:
                if re.search(r"\b(?:import|from)\s+[\w., ]*\b" + re.escape(module) + r"\b", code):
                    file_binaries.add(f"python3 -m {module}")
            for library in PYTHON_THIRD_PARTY_PROTOCOL_CLIENTS:
                if re.search(r"^\s*(?:import|from)\s+" + re.escape(library) + r"\b", code, re.M):
                    file_binaries.add(f"python3 {library}")
        binaries |= file_binaries

        file_tests = len(re.findall(r"#\[(?:tokio::)?test", code))
        file_ignored = 0
        total += file_tests
        for m in re.finditer(r"#\[ignore[^\]]*\]", code):
            file_ignored += 1
            ignored.append(f"{f.name}:{code[:m.start()].count(chr(10)) + 1}")

        if any(marker in code for marker in SELF_SERVED_MARKERS):
            self_served.append(f.name)

        per_file.append({
            "name": f.name,
            "binaries": file_binaries,
            "crates": file_crates,
            "tests": file_tests,
            "ignored": file_ignored,
        })

        lines = text.splitlines()
        for i, line in enumerate(lines):
            if "//" in line and line.strip().startswith("//"):
                continue  # a comment describing a gate is not a gate
            if not SKIP_MESSAGE.search(line):
                continue
            window = "\n".join(lines[i:i + 8])
            if RETURN_OK.search(window):
                skip_gates.append(f"{f.name}:{i + 1}")

    return {
        "binaries": binaries,
        "crates": crates,
        "ignored": ignored,
        "tests": total,
        "skip_gates": skip_gates,
        "self_served": self_served,
        "per_file": per_file,
    }


def unreachable_peers(scan: dict, peers: set[str]) -> list[str]:
    """Peers named only in files where **every** test is `#[ignore]`d.

    A file with no `#[test]` at all (a helper, a `mod.rs`) is not evidence either way,
    so it neither rescues a peer nor condemns one — only a file that has tests and
    ignores all of them counts against.
    """
    reachable: set[str] = set()
    seen: set[str] = set()
    for f in scan["per_file"]:
        named = (f["binaries"] | f["crates"]) & peers
        if not named:
            continue
        seen |= named
        if f["tests"] > 0 and f["ignored"] >= f["tests"]:
            continue  # this file's evidence never runs
        if f["tests"] > 0:
            reachable |= named
    return sorted(seen - reachable)


def rows(side: str) -> list[dict]:
    known = cargo_dependencies()
    known_names = set(known)
    result = []
    for protocol, state in sorted(declared_states(side).items()):
        tests = test_directory(protocol, side)
        scan = scan_tests(tests, known_names)
        test_crates = scan["crates"]
        src_crates = imported_crates(ROOT / "src" / side / protocol, known_names)

        native = http_native(protocol, side)
        peers = sorted(c for c in test_crates if native or c not in GENERIC_HTTP)
        generic = [] if native else sorted(c for c in test_crates if c in GENERIC_HTTP)
        binaries = sorted(b for b in scan["binaries"] if b not in GENERIC_HTTP)
        circular = sorted(set(peers) & src_crates)
        independent = set(binaries) | (set(peers) - set(circular))

        result.append({
            "protocol": protocol,
            "state": state,
            "binaries": binaries,
            "crates": peers,
            "circular": circular,
            "optional": sorted(c for c in peers if known.get(c)),
            "optional_status": {c: known.get(c) for c in peers},
            "generic_only": generic,
            "ignored": scan["ignored"],
            "tests": scan["tests"],
            "skip_gates": scan["skip_gates"],
            "self_served": scan["self_served"],
            "unreachable": unreachable_peers(scan, independent),
            "has_tests": tests.is_dir(),
        })
    return result


def independent_peers(row: dict) -> list[str]:
    """The peers that are neither this repository's own code nor a generic HTTP client.

    A crate the server itself imports is excluded: that is the `ssh`/russh case, where
    the "peer" is the server's own library and the test proves only that a crate agrees
    with itself.
    """
    return row["binaries"] + [c for c in row["crates"] if c not in row["circular"]]


# Protocols where "no third-party peer" is correct rather than a defect, with the reason.
#
# Keep this tiny and argued. An entry here is a claim that no second implementation could
# exist to be pointed at — not that nobody has got to it, which is what the baselines in the
# ratchet tests are for.
TRANSPORT_IS_THE_PROTOCOL = {
    "tcp": (
        "the transport IS the protocol, so the independent implementation is the peer's OS "
        "network stack, which every test on both sides already goes through. A 'third-party "
        "TCP client' here would be testing tokio."
    ),
    "udp": (
        "as `tcp`: the datagram layer is the protocol, and the peer's kernel is the "
        "independent implementation."
    ),
}


def blocking_defects(row: dict, side: str) -> list[str]:
    """Failures a script can be sure about, which `--check` fails the build on."""
    out = []
    peers = independent_peers(row)
    if not peers and side == "server" and row["protocol"] in TRANSPORT_IS_THE_PROTOCOL:
        # Reported in the table as usual; just not a failure.
        return out
    if not peers:
        if row["generic_only"]:
            out.append(
                "only a generic HTTP library (" + ", ".join(row["generic_only"]) + ")"
            )
        elif row["crates"]:
            out.append("only circular peers (" + ", ".join(row["circular"]) + ")")
        elif side == "client" and row["self_served"]:
            out.append(
                "self-served: the only peer is NetGet's own server, driven from "
                + ", ".join(row["self_served"])
                + " — the two were written to agree, so the exchange measures nothing"
            )
        else:
            out.append("no independent peer found")
    if row["skip_gates"]:
        out.append("skip-and-pass gate at " + ", ".join(row["skip_gates"]))
    if row["tests"] and len(row["ignored"]) >= row["tests"]:
        out.append(f"every test #[ignore]d ({len(row['ignored'])}/{row['tests']})")
    if side == "client" and row["unreachable"]:
        # The client bar names `#[ignore]` alongside a skip gate: unreachable evidence
        # is not evidence, however good the reason for parking it. On the server side
        # this stays a review flag, because a suite may legitimately ignore its
        # adapter-claiming tests while its real evidence runs.
        out.append(
            "peer only in tests that never run: "
            + ", ".join(row["unreachable"])
            + " — every test naming it is #[ignore]d"
        )
    return out


def review_flags(row: dict, side: str) -> list[str]:
    """Things a human has to read the test to settle. Deliberately NOT build-failing.

    Two of them have documented, accepted exceptions:

    * **Circular.** `quic` (quinn) and `webrtc` (webrtc-rs) both use the same crate the
      server uses, and CLAUDE.md accepts both — because the crate is driven in the
      *opposite role*, completing a real handshake, rather than called as a codec.
      No static rule can tell those two apart, so this reports and does not decide.
    * **`#[ignore]` on some tests.** A suite may legitimately ignore its
      adapter-claiming or root-requiring tests while its real evidence runs.
    """
    out = []
    peers = independent_peers(row)
    if row["circular"] and peers:
        out.append(
            "peer shared with the server: "
            + ", ".join(row["circular"])
            + " — read the test: same crate in the opposite role is the accepted quic/webrtc case"
        )
    only_optional = peers and all(row["optional_status"].get(p) is True for p in peers)
    if only_optional:
        out.append(
            "every peer is an `optional = true` **dev**-dependency ("
            + ", ".join(peers)
            + ") — never built by a job that does not enable it, so the evidence does "
            "not run where the gate runs"
        )
    elif row["optional"]:
        out.append(
            "optional `dev`-dependency among the peers: " + ", ".join(row["optional"])
        )
    if row["ignored"] and (not row["tests"] or len(row["ignored"]) < row["tests"]):
        out.append(f"{len(row['ignored'])} of {row['tests']} tests #[ignore]d")
    if not row["has_tests"]:
        out.append("no test directory at all")
    if side == "client":
        if peers and row["self_served"]:
            out.append(
                "also drives NetGet's own server ("
                + ", ".join(row["self_served"])
                + ") — check the rating rests on the independent peer, not on that"
            )
        out.append(
            "the fourth client condition is not checkable here: that the client acts on "
            "the model's answer, asserted on the wire. `tests/client_event_wiring_test.rs` "
            "catches the source shape; only reading the test settles the assertion"
        )
    return out


def client_groups(rows_in: list[dict]) -> list[tuple[str, list[str]]]:
    """Split non-Beta clients the four ways the September 2026 audit found by hand.

    Each protocol lands in exactly one group, tested in order of how close it is to the
    bar, so the first group is the cheapest work rather than the largest. The groups are
    *derived* here; the value of that is precisely that the hand-written version in
    CLAUDE.md will drift and this will not.
    """
    reachable_peer: list[str] = []
    unreachable: list[str] = []
    wrong_peer: list[str] = []
    self_served: list[str] = []
    nothing: list[str] = []

    for r in rows_in:
        peers = independent_peers(r)
        name = r["protocol"]
        if peers and not r["unreachable"] and not r["skip_gates"]:
            reachable_peer.append(name)
        elif peers:
            unreachable.append(name)
        elif r["generic_only"] or r["circular"]:
            wrong_peer.append(name)
        elif r["self_served"]:
            self_served.append(name)
        else:
            nothing.append(name)

    return [
        (
            "real peer, evidence runs — read the test, this is a promotion candidate",
            reachable_peer,
        ),
        (
            "real peer, unreachable evidence (#[ignore]d or skip-gated) — un-ignoring it is the work",
            unreachable,
        ),
        (
            "wrong peer: a generic HTTP library, or the same crate the client is built on",
            wrong_peer,
        ),
        (
            "self-served: the peer is NetGet's own server of the same protocol",
            self_served,
        ),
        ("no peer of any kind found in its tests", nothing),
    ]


# Where `tests/helpers/real_server.rs` (`find_binary`) looks after PATH. A server binary the
# helper can spawn is installed for the purpose of this table, whether or not it is on PATH:
# Homebrew keeps `slapd` in openldap's libexec, Ubuntu keeps `sshd`/`slapd`/`mysqld` in
# /usr/sbin and the PostgreSQL server binaries in /usr/lib/postgresql/<major>/bin.
HELPER_FALLBACK_DIRS = (
    "/opt/homebrew/sbin", "/opt/homebrew/bin", "/opt/homebrew/opt/openldap/libexec",
    "/usr/local/sbin", "/usr/local/bin", "/usr/local/opt/openldap/libexec",
    "/usr/sbin", "/usr/bin", "/sbin", "/bin",
)


def is_installed(program: str) -> bool:
    """`shutil.which`, then the directories the real-server helper also searches."""
    if shutil.which(program):
        return True
    dirs = [Path(d) for d in HELPER_FALLBACK_DIRS]
    dirs += sorted(Path("/usr/lib/postgresql").glob("*/bin"), reverse=True)
    return any((d / program).is_file() for d in dirs)


def render(selected: list[dict], show_availability: bool, side: str) -> str:
    extra = " | self-served |" if side == "client" else " |"
    lines = [
        "| protocol | state | peer (binary / crate) | circular | optional dep | #[ignore]d | skip gate"
        + extra,
        "|---|---|---|---|---|---|---|" + ("---|" if side == "client" else ""),
    ]
    for r in selected:
        peer_parts = []
        for b in r["binaries"]:
            mark = ""
            if show_availability:
                # A peer may be spelled `python3 -m imaplib`; only the program is on PATH.
                mark = " ✓" if is_installed(b.split()[0]) else " ✗"
            peer_parts.append(f"`{b}`{mark}")
        peer_parts += [f"`{c}`" for c in r["crates"]]
        if not peer_parts:
            peer_parts = ["**none**" + (f" (generic: {', '.join(r['generic_only'])})" if r["generic_only"] else "")]
        row = "| {p} | {s} | {peer} | {circ} | {opt} | {ign} | {skip} |".format(
            p=r["protocol"],
            s=r["state"],
            peer=", ".join(peer_parts),
            circ=", ".join(r["circular"]) or "-",
            opt=", ".join(r["optional"]) or "-",
            ign=f"{len(r['ignored'])}/{r['tests']}" if r["ignored"] else "-",
            skip=", ".join(r["skip_gates"]) or "-",
        )
        if side == "client":
            row += " {} |".format("yes" if r["self_served"] else "-")
        lines.append(row)
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--side",
        choices=("server", "client"),
        default="server",
        help="which tree to report on (default: server). The bars differ — see the module "
        "docstring; the client one additionally rules out NetGet's own server as a peer "
        "and treats #[ignore]d evidence as disqualifying.",
    )
    parser.add_argument("--all", action="store_true", help="every protocol, not only Beta")
    parser.add_argument("--check", action="store_true", help="exit 1 if a Beta rating's evidence cannot execute")
    parser.add_argument(
        "--experimental-with-evidence",
        action="store_true",
        help="Experimental protocols that already have an independent peer — promotion candidates",
    )
    parser.add_argument(
        "--no-availability",
        action="store_true",
        help="do not mark whether each binary is installed on this machine",
    )
    args = parser.parse_args()

    side = args.side
    all_rows = rows(side)
    show = not args.no_availability

    if args.experimental_with_evidence:
        candidates = [
            r for r in all_rows
            if r["state"] == "Experimental" and (r["binaries"] or r["crates"])
            and not r["circular"] and not r["skip_gates"] and not r["ignored"]
            and not (side == "client" and not independent_peers(r))
        ]
        print(f"# Experimental {side} protocols whose evidence already executes\n")
        print("Each has an independent peer, no circular crate, no skip gate and no `#[ignore]`.")
        if side == "client":
            print("A candidate may still be self-served — read the `self-served` column: a peer")
            print("that is NetGet's own server of the same protocol is not a peer.")
        print("Read the test before promoting: this cannot tell a peer completing a session")
        print("from a codec being called, and that distinction is the whole rating.\n")
        print(render(candidates, show, side))
        return 0

    selected = all_rows if args.all else [r for r in all_rows if r["state"] == "Beta"]
    title = f"every {side} protocol" if args.all else f"every Beta {side} protocol"
    print(f"# Evidence behind {title}\n")
    print("Generated by `scripts/beta_evidence_table.py` — do not hand-maintain this.")
    if show:
        print("A ✓ or ✗ after a binary says whether it is installed on the machine that ran this.")
    if side == "client":
        print("The peer of a client is a **server**, and never NetGet's own server of the same")
        print("protocol — the `self-served` column is that case, which the September 2026 audit")
        print("put at roughly 60 of 98 clients.")
    print()
    print(render(selected, show, side))

    beta = [r for r in all_rows if r["state"] == "Beta"]
    problems = [(r, blocking_defects(r, side)) for r in beta]
    problems = [(r, d) for r, d in problems if d]
    print("\n## Beta ratings with no evidence a script can find\n")
    if problems:
        print("Each of these is either over-rated or driving its peer in a way this scan")
        print("cannot see. Read the test before concluding which.\n")
        for r, d in problems:
            print(f"- **{r['protocol']}** — {'; '.join(d)}")
    else:
        print("None.")

    flagged = [(r, review_flags(r, side)) for r in beta]
    flagged = [(r, fl) for r, fl in flagged if fl]
    print("\n## Beta ratings a human should re-read\n")
    if flagged:
        print("Not failures. These are the cases where whether the evidence counts depends")
        print("on what the test does with the peer, which no static scan can decide.\n")
        for r, fl in flagged:
            print(f"- **{r['protocol']}** — {'; '.join(fl)}")
    else:
        print("None.")

    if side == "client":
        print("\n## Why the Experimental clients are Experimental\n")
        print("The September 2026 hand audit divided them four ways. This is the same split,")
        print("derived rather than remembered — the groups are ordered by how far each is from")
        print("the bar, so the top group is the cheapest work and the bottom is the deepest.\n")
        groups = client_groups([r for r in all_rows if r["state"] != "Beta"])
        for label, names in groups:
            print(f"- **{label}** ({len(names)}): {', '.join(names) if names else '—'}")

    counts: dict[str, int] = {}
    for r in all_rows:
        counts[r["state"]] = counts.get(r["state"], 0) + 1
    print(f"\n## Counts ({side})\n")
    for state, n in sorted(counts.items()):
        print(f"- {state}: {n}")

    if args.check and problems:
        print(f"\nFAIL: {len(problems)} Beta protocol(s) rest on evidence that cannot execute.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
