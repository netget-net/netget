# Documentation

Start with the [project overview](../README.md) or the [browser demo](https://netget.net/demo.html).
For current protocol support and maturity, run `netget --mcp` and call `list_protocols` /
`get_protocol_docs`. Plans and historical documents are not a protocol inventory.

## Installation and development

- [Install](guides/INSTALL.md) — npm, release archives, Cargo, Docker, and which protocols each
  prebuilt binary carries.
- [Build from source](guides/BUILDING.md) — system libraries and portable builds.
- [macOS dependency notes](guides/SYSTEM_DEPENDENCIES_macOS.md).
- [Android / Termux](guides/TERMUX_INSTALL.md).
- [Contributor instructions](../AGENTS.md) — architecture, protocol conventions, builds and checks.
- [Tests](../tests/README.md), [fuzzing](../fuzz/README.md), and [browser build](../web/README.md).
- [MCP implementation](../src/mcp_stdio/AGENTS.md), [dashboard](../src/tui/AGENTS.md), and [scripting](../src/scripting/AGENTS.md).
- [External protocol example](../examples/external_protocol/README.md).

## Planning and evidence

These are working records; verify individual claims against current source and tests.

- [Improvement backlog](planning/IMPROVEMENTS.md).
- [Protocol roadmap](planning/PROTOCOL_ROADMAP.md) and [quality plan](planning/PROTOCOL_QUALITY.md).
- [Protocol expansion candidates](planning/PROTOCOL_EXPANSION_CANDIDATES.md).
- [Client feasibility research](planning/CLIENT_PROTOCOL_FEASIBILITY.md).
- [Real-model evaluation results](../eval-results/EVAL_RESULTS.md) and [comparison evidence](../eval-results/2026-10-02-shared-prompts/README.md).
- [Codebase review](archive/CODEBASE_REVIEW_2026-10-01.md) and [audit evidence](../audit/).

## Historical reference

[Archived documents](archive/README.md) preserve superseded designs, migration notes, and
previous documentation. Their UI, API, license, and protocol claims may be obsolete.
Existing topic folders and research notes in this directory are retained as reference;
use the source-local instructions above when implementing changes.
