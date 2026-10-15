# @smotana/netget

LLM-controlled network protocol server & client — 240 protocol features (HTTP, DNS, SSH, MySQL, Redis, OPC UA, BACnet/IP, DNP3, IEC 104, EtherNet/IP, S7comm, NMDC/ADC peer transfers, Soulseek, Gnutella, NNTP, …) driven by an LLM, with a built-in [MCP](https://modelcontextprotocol.io) server mode.

This package is a small launcher that runs the platform-native `netget` binary. The binary itself is installed via a platform-specific optional dependency (e.g. `@smotana/netget-darwin-arm64`); if that is unavailable, the launcher downloads the matching binary from [GitHub Releases](https://github.com/smotanacom/netget/releases) into your user cache.

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

- Prebuilt binaries need no system library, so on Linux and Windows they leave out the protocols that link one (packet capture, Bluetooth LE, the NFC client, USB devices, the SMB client); macOS ships those libraries and its binaries include them. For every protocol everywhere: `cargo install --locked netget-tool` (see https://github.com/smotanacom/netget).
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

AGPL-3.0-or-later. Source: https://github.com/smotanacom/netget
