# @smotana/netget

LLM-controlled network protocol servers & clients — about 290 servers and 250 clients across 310 protocols (HTTP, DNS, SSH, MySQL, Redis, OPC UA, BACnet/IP, DNP3, IEC 104, EtherNet/IP, S7comm, NMDC/ADC peer transfers, Soulseek, Gnutella, NNTP, …) driven by an LLM, with a built-in [MCP](https://modelcontextprotocol.io) server mode.

This package is a small launcher that runs the platform-native `netget` binary. The binary itself is installed via a platform-specific optional dependency (e.g. `@smotana/netget-darwin-arm64`); if that is unavailable, the launcher downloads the matching binary from [GitHub Releases](https://github.com/netget-net/netget/releases) into your user cache.

## Quick start (MCP server)

```bash
npx @smotana/netget --mcp
```

Add to Claude Code:

```bash
claude mcp add netget -- npx -y @smotana/netget --mcp
```

Or in `claude_desktop_config.json` / `.mcp.json`:

```json
{
  "mcpServers": {
    "netget": {
      "command": "npx",
      "args": ["-y", "@smotana/netget", "--mcp"]
    }
  }
}
```

Industrial protocols include both server and client roles and remain Experimental.
Their selected operations, security policies, and exclusions are available through
`list_protocols` in MCP mode.

## Runtime requirements

NetGet needs an LLM backend at runtime: a local [Ollama](https://ollama.ai) (default, `http://localhost:11434`) or any OpenAI-compatible endpoint via `--openai-url`, `--model`, and `--api-key` (or `NETGET_API_KEY`).

## Interactive TUI

```bash
npx @smotana/netget
```

## Notes

- The binaries this package installs need no system library on Linux or Windows, so there they leave out the protocols that link one (packet capture, Bluetooth LE, the NFC client); macOS ships those libraries and its binaries include them. On glibc Linux the GitHub release also has `-full` archives with those protocols (they need `libpcap0.8 libdbus-1-3 libpcsclite1`); point `NETGET_BINARY` at one to use it through this launcher. No prebuilt binary carries the USB virtual devices or the SMB client. For every protocol: `cargo install --locked netget-tool`. Per-platform details: https://github.com/netget-net/netget/blob/master/docs/guides/INSTALL.md
- Fallback downloads require the release's `SHA256SUMS`; the matching SHA-256 is
  verified while streaming before extracting the expected executable. Missing or
  ambiguous manifests and mismatches fail closed. Older releases without a manifest
  can still be installed through their platform package or `NETGET_BINARY`.
- Archives are capped at 512 MiB and downloads/extraction at two minutes; caches are
  separated by version, platform, architecture and libc. A mirror must publish the
  same manifest format. The manifest authenticates bytes relative to the trusted
  release/mirror source; it is not an independent publisher signature.
- Env overrides: `NETGET_BINARY` (use a specific binary), `NETGET_DOWNLOAD_BASE` (alternate download mirror).

## License

AGPL-3.0-or-later. Source: https://github.com/netget-net/netget
