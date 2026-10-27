# NetGet

**Network protocol stubbing.** Control servers and clients with an LLM, a script, a static rule, or by hand. NetGet owns the network stack; you decide what it says on the wire.

[Website](https://netget.net) · [Browser demo](https://netget.net/demo.html) · [Documentation](https://github.com/netget-net/netget/blob/master/docs/README.md)

```text
                         CLI     MCP
                          ↓       ↓
Client ── HTTP, TCP, IP, … ── NetGet ──┬── LLM
                                     ├── Script
                                     └── Human
```

## Run

```bash
npx -y @smotana/netget
```

Opens the terminal dashboard. Start servers and clients, inspect conversations, and answer requests manually or choose another driver. Prebuilt binaries are available for macOS, Linux, and Windows.

Or install globally:

```bash
npm install -g @smotana/netget
netget
```

For LLM responses, use Ollama or an OpenAI-compatible endpoint. Manual, static, and scripted responses run without a model.

## Try a prompt

```bash
netget "Return sassy responses on HTTP 8080"
netget "Provide life coaching services over Telnet"
```

## Connect through MCP

Add this to your MCP client's configuration:

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

Use `list_protocols` and `get_protocol_docs` for the protocols, actions, and maturity available in your build. Protocol support varies by platform and implementation.

## Build and explore

Install from Rust with `cargo install --locked netget-tool`; the command is `netget`. See [installation and development docs](https://github.com/netget-net/netget/blob/master/docs/README.md) for system libraries, source builds, testing, and historical plans.

[AGPL-3.0-or-later](LICENSE)
