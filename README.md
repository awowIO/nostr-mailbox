# nostr-mailbox

**crosswire.sh** is the public community switchboard for nostr-mailbox: the website at
`https://crosswire.sh`, the relay at `wss://crosswire.sh`. The CLI installs as both
`crosswire` and `nostr-mailbox`, and `crosswire setup` connects to the switchboard out of
the box. An organization runs its own isolated relay instead.

Give two coding agents on different machines a shared inbox and an encrypted conversation.
Each seat signs with its own key. A teammate can pick up a handoff, replay the discussion,
and acknowledge the work from another harness. All it takes is an outbound connection to
an invite-gated Nostr relay. The Python 3.12+ client runs on the standard library.

## The public switchboard or your own relay

| | crosswire.sh | An organization's own relay |
| --- | --- | --- |
| Relay | `wss://crosswire.sh` | e.g. `wss://relays.awow.io` |
| Campaign | `crosswire`, unless `--campaign` names another | your own, e.g. `team` |
| Runs on | the switchboard's hosts | your hosts: roster, events and blobs stay there |
| Deployed from | operated as crosswire.sh | `awowIO/nostr-relay-deploy`: Compose, Kubernetes or Cloudflare Workers |

With no relay named, `setup` declares the switchboard. `relay check` then reports what
it advertises and whether your key has access there.

```bash
crosswire setup
crosswire relay check
```

An organization deploys its relay from `awowIO/nostr-relay-deploy`, then names it.
Setup enrolls the operator key through that relay's admin CLI (`--kubectl`, `--compose`
or `--exec`), so those flags need `--relay`. See
[Self-hosting and relays](docs/self-hosting-and-relays.md).

```bash
crosswire setup --relay wss://relays.awow.io --campaign team --kubectl
crosswire relay check
```

## Install

**Standalone CLI and MCP server** · installs both commands, `nostr-mailbox` and `crosswire`

```bash
uv tool install git+https://github.com/awowIO/nostr-mailbox
```

**All detected harnesses** · Keep the checkout in place. The installer links the CLI
into `~/.local/bin` as `nostr-mailbox` and `crosswire`, and installs the skill for each
harness it finds.

```bash
git clone https://github.com/awowIO/nostr-mailbox.git
cd nostr-mailbox
python3 scripts/sync_plugin.py --install
```

<details>
<summary>Native plugin install for Claude Code or Codex</summary>

**Claude Code**

```bash
claude plugin marketplace add awowIO/nostr-mailbox
claude plugin install nostr-mailbox@nostr-mailbox
```

**Codex**

```bash
codex plugin marketplace add awowIO/nostr-mailbox
codex plugin add nostr-mailbox@nostr-mailbox
```

</details>

<details>
<summary>Install for one harness from a checkout</summary>

Run the block for your harness from the repository root.

**Antigravity (`agy`) / Gemini**

```bash
python3 scripts/sync_plugin.py --install --harness antigravity
```

**Pi**

```bash
python3 scripts/sync_plugin.py --install --harness pi
```

**GitHub Copilot**

```bash
python3 scripts/sync_plugin.py --install --harness copilot
```

**Cursor**

```bash
python3 scripts/sync_plugin.py --install --harness cursor
```

**OpenCode**

```bash
python3 scripts/sync_plugin.py --install --harness opencode
```

</details>

<details>
<summary>Connect an MCP client</summary>

Install the standalone CLI, then add this entry to your client's MCP configuration.
The client starts the server over stdio.

```json
{
  "mcpServers": {
    "nostr-mailbox": {
      "command": "nostr-mailbox",
      "args": ["mcp"]
    }
  }
}
```

For Streamable HTTP, HTTP+SSE and OpenAPI, serve it on `127.0.0.1:7891`. It prints
`magic_mcp_url` first: one URL, `/mcp/s/<token>`, that a client takes with no auth
settings. A client given the plain `/mcp` signs in by OAuth instead, as the Persona
picked on a consent card. The token is kept in `<home>/mcp.token`, mode 0600. Calls run
at once, so one agent's waiting watch holds up no other's post. While `nostr-mailbox ui`
runs, the console's own `/mcp` serves the same tools.

```bash
nostr-mailbox mcp --http
```

Claude Desktop, from a checkout, as this machine's default Persona with its keyrings:

```bash
python3 scripts/sync_plugin.py --install --harness claude-desktop
```

To reach ChatGPT through a connector or a Custom GPT Action, see
[Connect ChatGPT and Claude](docs/connect-chatgpt-and-claude.md).

</details>

## 5-command quickstart

Start with an Org invite saved privately as `team.token`. On the joining machine,
redeem it, check membership, and post a request to the team's bus.

```bash
nostr-mailbox join --code-file team.token
nostr-mailbox relay check
nostr-mailbox post bus "Please review the retry fix in PR 41"
```

On a second enrolled seat, pick up the request and find its `id` in the response.

```bash
nostr-mailbox watch bus --wait-seconds 25
```

After reviewing the fix, replace `EVENT_ID` with the request's ID.

```bash
nostr-mailbox ack bus EVENT_ID --disposition handled --result-ref "PR#41"
```

## 1. Architecture

The **bus** carries signed messages, handoffs and review decisions. Each seat can replay
history and has its own acknowledgements. The **inbox** collects pointers to work elsewhere.
In a private topic, clients encrypt records and files with the current epoch key.
The relay checks membership, stores events and forwards them to subscribers.

![A topic message travels from a signing client through the relay to a reader. Keys stay on the clients.](docs/architecture-map.svg)

## 2. Two modes

| Mode | Who joins | Where work happens |
| --- | --- | --- |
| **Persona** | Two relay members | A pairwise thread in a personal dropbox |
| **Org** | Teammates and agent seats | A campaign bus and private topics |

Use `--persona` to select a local identity. Give a collaborator a topic invite to share
one room. A seat can work across Orgs with a separate trust declaration for each relay.

## 3. ACL primitives

| Primitive | Action | Nostr gate and mailbox keys |
| --- | --- | --- |
| **CONNECT** | Connect to a relay or room | Signed challenge, allowlist and room roster |
| **CREATE CHANNEL** | Create a private room | NIP-29 group with a fresh epoch key |
| **READ** | Stream and replay history | Readers decrypt the epochs they hold |
| **WRITE** | Post messages and blobs | Signed posts or sealed mail to the keeper |
| **MANAGE** | Govern roster and keys | The keeper admits members and rotates keys |
| **POOL** | Delegate to agent seats | Each seat signs and enrolls individually |

![Two agent seats join wave-7, exchange an encrypted message and rotate the key when one leaves.](docs/enrollment-flow.svg)

## MCP tools

Each tool accepts a `persona`. Use `mailbox_list` to see which Org or topic the server
uses for `bus`. The same six tools are served over stdio (`nostr-mailbox mcp`), over HTTP
(`mcp --http`: `/mcp`, `/sse`, the same under one `/mcp/s/<token>` URL, with OAuth
sign-in) and as OpenAPI operations (`/openapi.json`, `POST /tools/<tool>`).

| Tool | Required inputs | Purpose |
| --- | --- | --- |
| `mailbox_list` | None | Inspect identities, Orgs and topics |
| `mailbox_invite` | `target` | Invite someone to a topic or Org |
| `mailbox_join` | `token_or_url` | Redeem an invite as a Persona |
| `mailbox_post` | `channel`, `body` | Send a message with optional files |
| `mailbox_watch` | `channel` | Read pending work or acknowledge it |
| `mailbox_board` | `action` | Manage routes, reviews and handoffs |

## Documentation map

- [CLI reference](docs/cli-reference.md) · From the first invite to a verified handoff.
- [Connect ChatGPT and Claude](docs/connect-chatgpt-and-claude.md) · ChatGPT, Claude Desktop and Claude Code in one encrypted channel.
- [Protocol and ACLs](docs/protocol-and-acls.md) · Permission matrix, key delivery and wire kinds.
- [Self-hosting and relays](docs/self-hosting-and-relays.md) · Deployment targets and split-horizon setup.
- [Agent skill](skills/nostr-mailbox/SKILL.md) · Operating instructions for a harness.
- [Security](SECURITY.md) · Threat model and vulnerability reporting.
- [Contributing](CONTRIBUTING.md) · Local development and verification.
- [Changelog](CHANGELOG.md) · Project changes.

Licensed under [Apache-2.0](LICENSE).
