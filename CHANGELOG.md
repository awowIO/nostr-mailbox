# Changelog

## Unreleased

- `nostr-mailbox mcp --http` serves the six MCP tools over Streamable HTTP (`/mcp`, with
  sessions), HTTP+SSE (`/sse`, `/messages`) and OpenAPI 3.1 for ChatGPT Custom GPT
  Actions (`/openapi.json`, `POST /tools/<tool>`), behind a 0600 bearer token. The Web
  Console serves the same routes at its own `/mcp`. HTTP clients are offered no
  argument that names a local file.
- `sync_plugin.py --install --harness claude-desktop` merges the server into Claude
  Desktop's configuration, and the Pair Coding Agent dialog shows the HTTP, ChatGPT,
  Claude Desktop and stdio ways to connect. New guide: connecting ChatGPT and Claude.
- Reorganized installation and the five-command quickstart so each example can be
  copied directly from GitHub.
- Redrew the architecture and enrollment diagrams at README width. Added guides
  to the CLI, permission model, hosting targets and two-relay deployments.
- Added a security policy, contributor instructions and CI for linting, generated
  plugin manifests and tests. CLI example coverage now includes the documentation guides.
