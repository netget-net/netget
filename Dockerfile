# syntax=docker/dockerfile:1
#
# NetGet in a container: the feature set of the glibc Linux `-full` release archives
# (.github/workflows/release.yml), on Debian bookworm. The runtime stage installs the three
# libraries that set links, so unlike the plain archives npm ships it carries packet capture,
# Bluetooth LE and the NFC client.
#
#   docker build -t netget .
#   docker run --rm -p 18040:18040 -e NETGET_MCP_TOKEN="$(openssl rand -hex 32)" netget
#
# The default command serves MCP over HTTP on 0.0.0.0:18040. A non-loopback MCP endpoint
# refuses to start without a bearer token, so pass NETGET_MCP_TOKEN (or override the command).
# Protocol servers bind 127.0.0.1 unless told otherwise: give `start_server` a `host` of
# `0.0.0.0` and publish the port (`-p 8080:8080`) to reach one from outside the container.
#
# For a model, point at a backend the container can reach, e.g.
#   docker run ... netget --mcp-http 18040 --listen-addr 0.0.0.0 \
#       --ollama-url http://host.docker.internal:11434
# (or `--openai-url <URL> --model <name>` with NETGET_API_KEY), or add `--llm-agent` to have
# the calling MCP agent answer every request itself.
#
# The image runs as the unprivileged user `netget` (uid 10001), so ports below 1024 and the
# packet-capture protocols (ARP, DataLink, LLDP, CDP, STP, EAPOL, IS-IS) are refused; those
# need `--user 0 --cap-add NET_RAW --cap-add NET_ADMIN` (and usually `--network host`).
# Bluetooth LE needs
# the host's BlueZ D-Bus socket and NFC a PC/SC daemon, which a container does not have by
# default. Everything else needs nothing beyond a published port.

ARG RUST_VERSION=1
ARG DEBIAN_RELEASE=bookworm

FROM rust:${RUST_VERSION}-${DEBIAN_RELEASE} AS builder

# Build-time native dependencies:
#   cmake, clang/libclang  aws-lc-sys (cmake) and mysql_common (bindgen)
#   libpcap-dev            the `libpcap` feature (packet-capture protocols)
#   libdbus-1-dev          the `bluetooth` feature (BlueZ over D-Bus)
#   libpcsclite-dev        the `pcsc` feature (the NFC client)
# protoc is not needed: build.rs uses protoc-bin-vendored. OpenSSL is vendored.
# Unpinned on purpose: bookworm's security updates would break an exact version pin.
# hadolint ignore=DL3008
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        cmake clang libclang-dev pkg-config perl make \
        libpcap-dev libdbus-1-dev libpcsclite-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .

# Keep in step with the `-full` glibc Linux entries of release.yml's build matrix.
ARG NETGET_FEATURES=mcp-stdio,mcp-http,sqlite,vendored-openssl,libpcap,bluetooth,pcsc
ENV CARGO_BUILD_JOBS=2 \
    CARGO_INCREMENTAL=0 \
    LZMA_API_STATIC=1

RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,target=/src/target,sharing=locked \
    cargo build --release --locked --no-default-features --features "${NETGET_FEATURES}" \
    && install -D -m 0755 target/release/netget /out/netget

FROM debian:${DEBIAN_RELEASE}-slim AS runtime

# Runtime libraries for the three system-library features, CA roots for the clients that
# speak TLS to real services, and tini: NetGet installs no SIGTERM handler, and PID 1 gets
# no default one, so without an init `docker stop` would wait out its timeout and SIGKILL.
# hadolint ignore=DL3008
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates tini libpcap0.8 libdbus-1-3 libpcsclite1 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 netget \
    && useradd --system --uid 10001 --gid netget --home-dir /data --shell /usr/sbin/nologin netget \
    && install -d -o netget -g netget -m 0750 /data

COPY --from=builder /out/netget /usr/local/bin/netget

# NetGet writes netget.log, `append_to_log` files and file-backed SQLite databases into its
# working directory; /data is the one place the unprivileged user can write. Mount a volume
# there to keep them.
WORKDIR /data
VOLUME ["/data"]
USER 10001:10001

EXPOSE 18040

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/netget"]
CMD ["--mcp-http", "18040", "--listen-addr", "0.0.0.0"]
