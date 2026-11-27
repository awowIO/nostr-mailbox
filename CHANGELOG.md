# Changelog

## Unreleased

- HTTP MCP clients sign in by themselves: a 401 from `/mcp` names OAuth 2.1 metadata
  (RFC 9728, RFC 8414), and clients register (RFC 7591), get a one-click consent card,
  and exchange a PKCE-bound code for a token that acts as the one Persona picked there.
  The card asks for the server's token once per browser session; the console's card
  does not. Grants are kept in `<home>/mcp-oauth.json`.
- One URL carries the whole server: `/mcp/s/<token>`, with its own `/sse`, `/messages`,
  `/tools/<tool>` and an `openapi.json` that asks for no authentication. `mcp --http`
  prints it first, and Pair Coding Agent shows it at the top (`/api/pair`). No token in
  a path or a query reaches the server's log.
- Tool calls run at once over HTTP: a `mailbox_watch` that waits no longer holds up a
  `mailbox_post` from another client. Joins, invites and revokes, which rewrite the
  home's files, still run one at a time.
- `sync_plugin.py --harness claude-desktop` runs Claude Desktop's server as this
  machine's default Persona, sharing the terminal's keyrings, and carries the
  installing shell's `NOSTR_MAILBOX_HOME`, `NOSTR_MAILBOX_IDENTITY` and
  `NOSTR_MAILBOX_TRUST`. It no longer runs as a separate `claude-desktop` Persona.
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
