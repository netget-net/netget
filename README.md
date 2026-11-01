# NetGet

**Network protocol stubbing.** Control servers and clients with an LLM, a script, a static rule, or by hand. NetGet owns the network stack; you decide what it says on the wire.

[Website](https://netget.net) · [Browser demo](https://netget.net/demo.html) · [Documentation](https://github.com/netget-net/netget/blob/master/docs/README.md)

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

Release archives, `cargo install`, Docker, and which protocols each platform's binary carries (on Linux, packet capture, Bluetooth LE and NFC are in the separate `-full` archives) are in the [install guide](docs/guides/INSTALL.md).

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

## Answer network requests as the agent

Run `netget --mcp-http 18040 --llm-agent` and create a protocol server with the
`start_server` MCP tool. Each request waits for the calling agent to answer it.
Compact events, claim recovery, and timings are available through the agent MCP tools.

For hosts that consume JSON lines, `netget --agent-connect http://127.0.0.1:18040/mcp`
maintains the connection and reconnects after interruptions. It writes requests to
stdout and accepts `{"request_id":1,"claim_token":"<from request>","actions":[...]}` answers on stdin.
See the [agent workflow and listener contract](src/mcp_stdio/AGENTS.md#agent-llm-backend---llm-agent).

`netget --mcp --llm-agent` also advertises the draft **SEP-3415 Events extension**
(`io.modelcontextprotocol/events`): `events/list`, cursor-based `events/poll`, and
`events/stream` notifications over stdio. Clients choose their delivery mode;
webhooks are not supported. Subscriptions can watch pending agent requests, manual
intercepts and recorded access-log entries. Existing claim and answer tools remain
the control path.

The same stdio server advertises **Claude Code Channels**. During Claude's research
preview, add `--llm-agent` to the MCP server's arguments above to have the calling
agent answer network requests, then enable the server named `netget` with:

```sh
claude --dangerously-load-development-channels server:netget
```

Channel opt-in and organization policy are controlled by Claude Code. NetGet emits
actionable request notifications, and the agent answers through its MCP tools.
See the [event contract](src/mcp_stdio/AGENTS.md#events-extension-and-claude-code-channels)
for schemas, replay limits and protocol compatibility.

## Build and explore

Install from Rust with `cargo install --locked netget-tool`; the command is `netget`, and this build includes every protocol, the USB devices and SMB client that no prebuilt binary carries among them. See [installation and development docs](https://github.com/netget-net/netget/blob/master/docs/README.md) for system libraries, source builds, testing, and historical plans.

[AGPL-3.0-or-later](LICENSE)
