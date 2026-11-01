# frozen_string_literal: true

# DRAFT Homebrew formula for NetGet. It is not published: no tap exists yet, and creating one
# (e.g. netget-net/homebrew-tap, so users run `brew install netget-net/tap/netget`) is the
# maintainer's call.
#
# It installs the prebuilt macOS (and plain glibc Linux) binary from the GitHub release rather than
# building from source: a source build compiles ~540 protocol implementations and needs cmake,
# libclang and samba. The release archives hold the bare `netget` binary at their root
# (.github/workflows/release.yml, "Package"), and each has a `.sha256` beside it plus a
# `SHA256SUMS` manifest; the checksums below are v0.3.9's, from that manifest.
#
# Updating for a release: bump `version`, and replace each sha256 with the matching line of
#   gh release download v<version> --repo netget-net/netget -p SHA256SUMS -O - | grep -v windows
class Netget < Formula
  desc "Network protocol stubbing driven by an LLM, a script, a static rule or a person"
  homepage "https://netget.net"
  version "0.3.9"
  license "AGPL-3.0-or-later"

  livecheck do
    url :stable
    strategy :github_latest
  end

  on_macos do
    on_arm do
      url "https://github.com/netget-net/netget/releases/download/v#{version}/netget-aarch64-apple-darwin.tar.gz"
      sha256 "01bfdeafa94c7bd6ec28686cca1115997f88b9052f4f6a1c896862f5ddea6645"
    end
    on_intel do
      url "https://github.com/netget-net/netget/releases/download/v#{version}/netget-x86_64-apple-darwin.tar.gz"
      sha256 "49f95ea8d10ec9d2814e67f7de5f8617cc2d6f639ca4a15977cfe4e88f7ca1f9"
    end
  end

  on_linux do
    # The plain glibc archives, which link nothing beyond glibc and zlib (the same binaries npm
    # ships). From the release after v0.3.9 there are also `-full` archives
    # (netget-<target>-full.tar.gz) carrying packet capture, Bluetooth LE and the NFC client;
    # switching to them would need `depends_on "dbus"`, `"libpcap"` and `"pcsc-lite"`.
    on_arm do
      url "https://github.com/netget-net/netget/releases/download/v#{version}/netget-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "996faa133c16f1653d85e45486ca83e6d06c850930f7485db8cded27b1d68f01"
    end
    on_intel do
      url "https://github.com/netget-net/netget/releases/download/v#{version}/netget-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "5325e246d4b7c885aeaec0c7c1cf3d8bbb79d56a8406f81fb6ee0bc81621dcdd"
    end
  end

  def install
    bin.install "netget"
  end

  def caveats
    <<~EOS
      NetGet writes netget.log (and any append_to_log files) into the directory it runs from.

      For LLM-driven responses, run Ollama locally or pass --openai-url and --model (with the
      key in NETGET_API_KEY). Manual, static and scripted responses need no model.

      To use it from an MCP client, register `netget --mcp` as a stdio server, e.g.
        claude mcp add netget -- #{opt_bin}/netget --mcp
    EOS
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/netget --version")

    # A real MCP round trip: initialize, then list_protocols must name a protocol that every
    # build carries. stdin closing ends the session.
    requests = [
      '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05",' \
      '"capabilities":{},"clientInfo":{"name":"brew-test","version":"1"}}}',
      '{"jsonrpc":"2.0","method":"notifications/initialized"}',
      '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list_protocols","arguments":{}}}',
    ].join("\n")
    output = pipe_output("#{bin}/netget --mcp 2>/dev/null", "#{requests}\n")
    assert_match "Server Protocols", output
    assert_match "Telnet", output
  end
end
