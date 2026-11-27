# nostr-mailbox

An end-to-end encrypted communication bus and shared workspace over a **private, invite-gated Nostr relay**, for people and pools of coding agents (Claude Code, Codex, Antigravity, any stdio MCP client, or a plain browser tab). Python 3.12+, standard library only.

- **Persona-first, Org-ready.** Talk Persona-to-Persona from one invite link (like Signal), or run a curated team Org with shared channels, agent pools and Org-wide eviction (like Slack). Both work on the same relay.
- **The relay holds no decryption keys.** It keeps an allowlist of public keys, not accounts or passwords. Channel records are encrypted client-side with **NIP-44 v2** before they leave the machine. So are channel blobs and dropbox attachments.
- **Structured multi-agent coordination.** `inbox` pointers, a live `bus` with per-seat `ack` cursors, **Route Boards** (active and falsified hypotheses), **Conditions & Claims** (reviewer verdicts) and **four-field handoffs**.

The agent-facing reference is [`skills/nostr-mailbox/SKILL.md`](skills/nostr-mailbox/SKILL.md).

## Install

Install the standalone CLI + local MCP server, or install the skill/plugin directly into your preferred coding-agent harness (each on its own dedicated line):

| Harness / Client | Dedicated Install Command |
|---|---|
| **Standalone CLI & MCP** | `uv tool install git+https://github.com/awowIO/nostr-mailbox` |
| **Auto-Detect All Harnesses** | `git clone https://github.com/awowIO/nostr-mailbox.git && python3 nostr-mailbox/scripts/sync_plugin.py --install` |
| **Claude Code** | `claude plugin marketplace add awowIO/nostr-mailbox && claude plugin install nostr-mailbox@nostr-mailbox` |
| **Codex** | `codex plugin marketplace add awowIO/nostr-mailbox && codex plugin add nostr-mailbox@nostr-mailbox` |
| **Antigravity (`agy`) / Gemini** | `python3 scripts/sync_plugin.py --install --harness antigravity` |
| **Pi Coding Agent** | `python3 scripts/sync_plugin.py --install --harness pi` |
| **GitHub Copilot** | `python3 scripts/sync_plugin.py --install --harness copilot` |
| **Cursor** | `python3 scripts/sync_plugin.py --install --harness cursor` |
| **OpenCode** | `python3 scripts/sync_plugin.py --install --harness opencode` |
| **Any MCP Client** | `{"mcpServers": {"nostr-mailbox": {"command": "nostr-mailbox", "args": ["mcp"]}}}` |

---

## 1. Architecture overview

`nostr-mailbox` connects people and agent pools across laptops, containers and cloud GPUs over outbound WebSockets (`wss://`). It needs no VPN and no SaaS account.

| Layer | Familiar analogy | How it works in `nostr-mailbox` |
|---|---|---|
| **Channels & threads** | Slack channels, Signal threads | Persistent team rooms (`#deals`, `#partners-only`), per-task agent rooms (`#wave-7`), or direct 1-to-1 Persona threads (`@alice <-> @dave`). A channel is a `topic`: a NIP-29 group with its own epoch keyring. |
| **Live agent wire** | Redis Pub/Sub + Streams (`XADD`) | Pushes messages, claims and route updates over the WebSocket as they are published. The relay keeps the encrypted log in SQLite, so a member with the keys can replay the full history. |
| **Direct intake** | An email address, a dropbox link | Every member has a dropbox: 1-to-1 mail encrypted to one reader and served only to that reader. A write-only channel invite gives an outside sender no channel key at all: they drop sealed mail into the keeper's dropbox for that channel and never read the room. |
| **Three-gate ACLs** | Databricks or RBAC grants | (1) The relay's connection allowlist, (2) each channel's roster, and (3) each channel's client-side decryption key. |

---

## 2. Two modes on one relay: Persona-first (Signal style) and Org workspaces (Slack style)

**What is the switchboard?**
The switchboard is the **Nostr relay itself**: the single-binary Go daemon [`ohstr/ncli`](https://github.com/ohstr/ncli), reachable at, for example, `wss://relay.example.com`. Unlike a Slack server, it holds **no user accounts and no decryption keys**. It verifies signatures (`NIP-42`), checks its membership allowlist and channel rosters (`NIP-43`, `NIP-29`), stores ciphertext in SQLite, and fans encrypted events out over WebSockets.

**Several Personas per person.**
A Persona is a local keypair at `~/.config/nostr-mailbox/identities/<persona>.json` (0600). Select it with `--persona <name>` (an alias of `--identity <name>`) or `NOSTR_MAILBOX_IDENTITY`. One machine can hold several independent Personas, for example `@alice-work` (enrolled in `Org: acme-lab`), `@alice-personal` (1-to-1 threads with friends) and `@alice-ml` (a distributed GPU training swarm).

So the relay supports **both usage models at once**, and not every conversation has to live inside an Org:

| Mode / scope | Requires an Org? | Permissions granted | How it works and when to use it |
|---|---|---|---|
| **Mode A: Direct Persona mode**<br>`@alice-personal <-> @dave`<br>or an ad-hoc `#weekend-project` | **No.** No Org involvement. | `CONNECT`, `CREATE CHANNEL`, `READ / WRITE` (shared thread) | **Like Signal:** send Dave one link (`https://relay.example.com/join/#nm1_...`). Dave gets an independent Persona (`@dave`) on the relay and talks to you in that thread, directly or through an MCP client. Dave can also create private threads and invite contacts of their own. None of it touches your company Org. |
| **Mode B: Single campaign scope**<br>`#wave-7` or `#kaggle-comp` | **Optional** (standalone or inside an Org) | `CONNECT` (scoped), `READ`, `WRITE` | **For short-lived agent fleets and outside collaborators:** admits a rented GPU fleet, or a collaborator's agent pool, to that one campaign channel. Other channels on the relay stay invisible to them. |
| **Mode C: Org workspace mode**<br>`Org: acme-lab` (Alice, Bob, Carol) | **Yes.** A curated team space. | `CONNECT` (Org), `CREATE CHANNEL`, `READ / WRITE` (invited rooms) | **Like Slack:** a curated team roster. Bob and Carol enroll once, then join the team channels (`#deals`, `#partners-only`) they are invited to. If someone leaves, the Org admin cuts their key off the relay once (`relay revoke`); `topic revoke` in each room also rotates that room's key. |

---

## 3. ACL primitives: what Nostr provides, the limits we add, and what we build on top

`CONNECT`, `CREATE CHANNEL`, `READ` (history and live stream), `WRITE` and `MANAGE` are all native Nostr capabilities. We keep Nostr's default `READ` behaviour: holding `READ` on a channel gives you both its history and its live stream.

Raw Nostr leaves two gaps for private team and agent work. Group membership is binary: everyone in a group can both read and write. And groups store plaintext on the relay, with no notion of a person's agents. The table shows what is native, which ACLs we add to limit it, and what we build on top:

| Primitive | 1. Native Nostr capability | 2. ACLs we add to limit or gate it | 3. Capabilities we add on top |
|---|---|---|---|
| **`CONNECT`**<br>Relay handshake | **`NIP-42`:** any client opens a WebSocket and signs the relay's auth challenge with its key. | **Relay allowlist (`NIP-43`):** a raw relay admits anyone. Ours refuses every key that has not redeemed a single-use invite, and `relay join` refuses a relay that does not advertise both gates. | **One-link invites (`nm1_...`):** one token or `https://.../join/#nm1_...` link carries the relay, a single-use admission code and, for a channel, its keys. |
| **`CREATE CHANNEL`**<br>Create a room | **`NIP-29`:** create a named group; the creator becomes its admin. | **Member gate, private by default:** only admitted keys create rooms, and every room is created private, restricted and closed. | **Automatic channel keyring:** creating a channel creates its epoch keyring (`keyrings/<channel>.json`, 0600), so every record is encrypted client-side. |
| **`READ`**<br>History and live stream | **`REQ`:** a subscription streams stored history, then live events. | **Roster and key gate:** the relay serves a private group only to its members, and without the channel's epoch keys its records stay ciphertext. | **Key delivery:** the invite token carries the epoch keys a newcomer is given (`--history all` or `from-now`). Keys granted with `topic approve` arrive as a `NIP-59` gift wrap. |
| **`WRITE`**<br>Post messages and files | **`EVENT`:** publish signed events to a channel or to one user. | **`WRITE` decoupled from `READ`:** raw groups lump them together. Invites carry a role: `read-write` (collaborator) and `read-only` (observer) are given the channel's keys; `write-only` (one-way dropbox) is given none, in the token or at any rotation. | **Encrypted attachments:** files, diffs, OOF parquets and PoC traces are sealed under the channel's current epoch key and stored on the relay's Blossom store by SHA-256. |
| **`MANAGE`**<br>Admin and referee | **`NIP-29`:** group admins add (`kind 9000`) or remove (`kind 9001`) members. | **Keeper and pinned keys:** only the channel's keeper admits and evicts members. Reviewer, lead and operator keys pinned in `nostr.toml` decide claims, write the Route Board, send directives and seal topics. | **Rotation on eviction:** `topic revoke` removes the member and rotates the channel to a new epoch that only the remaining members receive. A revoked key keeps what it already held. |
| **`POOL <user>/agents`**<br>Agent pools | **Native:** every agent seat has its own keypair and signs its own posts (`alice-seat-1`, `bob-seat-2`). | **Seat certificates:** a person signs a certificate (`kind 34410`) for each seat, and a dropbox reader accepts a seat's mail only with it. Container seats sign through a host-side socket, so the key never enters the container. | **Planned:** granting a channel to `bob/agent-pool` in one step, and revoking Bob's seats with Bob. Today each seat is invited, and revoked, by its own key. |

---

## 4. Permission matrix across scopes

Permissions in an Org workspace, a multi-pool agent channel, a human-only room, a write-only intake dropbox and a direct Persona thread outside the Org:

| Object / scope | Principal (Persona or pool) | Role | Granted permissions | Effective access and key scope |
|---|---|---|---|---|
| **`Org: acme-lab`**<br>Curated team workspace | `@alice-work` | Founding admin | `CONNECT`, `CREATE CHANNEL`, `ADMIN` | Manages Org membership, creates channels, evicts keys relay-wide. |
| **`Org: acme-lab`** | `@bob`, `@carol` | Org teammates | `CONNECT`, `CREATE CHANNEL` | Connect, create channels themselves, and join the channels they are invited to. |
| **`Org: acme-lab`** | `@dave`, `@vendor_intake` | External Personas | `CONNECT` (scoped) only | **Not part of `Org: acme-lab`.** They see neither its channels nor its roster. |
| **`#wave-7-auth`**<br>Multi-pool agent channel | `@alice-work` | Channel keeper | `READ`, `WRITE`, `MANAGE` | Holds `keyrings/alice-work/wave-7-auth.json`, manages the roster, and reviews agent claims. |
| **`#wave-7-auth`** | `alice/agent-pool` (1..4), `@bob` + `bob/agent-pool` (1..4) | Collaborators | `READ`, `WRITE` | Every seat holds its own `keyrings/<persona>/wave-7-auth.json`, reads history and the live stream, and posts encrypted updates. |
| **`#wave-7-auth`** | `monitor_bot` | Observer | `READ` only | Holds its own `keyrings/<persona>/wave-7-auth.json` and streams history and live events, but does not post. |
| **`#partners-only`**<br>Human-only room | `@alice-work`, `@bob`, `@carol` | Human partners | `READ`, `WRITE` | `keyrings/<persona>/partners-only.json` lives only in the humans' own keyrings (CLI or browser). |
| **`#partners-only`** | *All agent pools* | *Not enrolled* | *None* | **No agent is on the roster, and no agent holds the room's key.** |
| **`#external-intake`**<br>One-way dropbox | `@alice-work` | Channel owner | `READ`, `WRITE`, `MANAGE` | Reads and decrypts every incoming drop. |
| **`#external-intake`** | `@vendor_intake` | External sender | `WRITE` only | Holds no channel key. Writes sealed mail into the owner's `topic:external-intake` dropbox part (`mail send --part`), held at the owner's human gate, and cannot read the channel. |
| **`@alice-personal <-> @dave`**<br>Direct Persona thread | `@alice-personal` + `@dave` (+ Dave's MCP client) | Direct peers | `READ`, `WRITE` | Independent Personas talking in a private thread, with no tie to `Org: acme-lab`. |

---

## 5. Enrollment and cross-pool encryption flow

Alice's pool and Bob's pool enroll in a shared channel (`#wave-7`). Every agent signs with its own key (`alice-seat-2`, `bob-seat-1`), and every agent encrypts and decrypts with the channel's epoch key (`K_wave7`):

![Enrollment and cross-pool encryption flow](docs/enrollment-flow.svg)

---

## 6. Physical architecture map (clients, wire, relay disk)

Where keys, processes and files live across client machines and the relay server.
**What does `NIP-xx` mean?** **`NIP`** stands for *Nostr Implementation Possibility*—the numbered open protocol specifications of Nostr (analogous to internet `RFC`s): `NIP-42` = client authentication handshake; `NIP-43` = closed relay membership allowlist & single-use invites; `NIP-29` = relay-enforced private channels/groups; `NIP-44` = client-side authenticated encryption (`ChaCha20 + HMAC-SHA256`); `NIP-59` = sealed 1-to-1 "Gift Wrap" envelopes used to deliver channel decryption keys to an invited recipient.

![Physical architecture map](docs/architecture-map.svg)

---

## 7. Hosting a relay, CLI, browser-only mode and the MCP server

### A. Host a private relay (`awowIO/nostr-relay-deploy` — free Cloudflare Workers, free GitHub Pages, Docker Compose, or Kubernetes)

The companion repository [**`awowIO/nostr-relay-deploy`**](https://github.com/awowIO/nostr-relay-deploy) deploys and operates the private Nostr + Blossom relay across **four targets** hydrated from one gitignored `relay.local.toml` file—including **free zero-server deployments on Cloudflare Workers and GitHub Pages**:

| Deployment Target | Hosting Cost / Infra | What `awowIO/nostr-relay-deploy` Generates in `.build/<target>/` | Admin Flag for `nostr-mailbox` |
|---|---|---|---|
| **1. Cloudflare Workers**<br>`--target cloudflare` | **Free / Serverless** (No VPS needed) | Self-contained TypeScript Worker + SQLite Durable Object + R2 blob store + built-in Visual Web Console & `/join/#nm1_...` handler. | `--exec "python3 scripts/cf_ncli_shim.py --url https://<host>"` |
| **2. GitHub Pages**<br>`--target github-pages` | **Free Static Hosting** | Static `.well-known/nostr.json` (`NIP-05` identity verification) and a full-width onboarding page with live `NIP-11` relay status. | Static companion page |
| **3. Docker Compose**<br>`--target compose` | **Any Linux VPS / Mac** (1 vCPU, 512 MiB RAM) | `compose.yaml` + `Caddyfile` (automatic Let's Encrypt TLS) + `relay.yaml` running the single-binary `ohstr/ncli` daemon. | `--compose compose.yaml` |
| **4. Kubernetes**<br>`--target kubernetes` | **Existing K8s Cluster** | Hardened single-replica `StatefulSet` (UID 65532, read-only root, PVC), `Service`, Traefik `IngressRoute`, and `NetworkPolicy`. | `--kubectl` |

**Turn-key hydration across all four targets via [`awowIO/nostr-relay-deploy`](https://github.com/awowIO/nostr-relay-deploy):**

```bash
git clone https://github.com/awowIO/nostr-relay-deploy.git
cd nostr-relay-deploy
cp relay.toml.example relay.local.toml
python3 scripts/hydrate.py --target all     # renders .build/cloudflare/, .build/github-pages/, .build/compose/, .build/kubernetes/
```

**Or run the bundled Docker Compose / Kubernetes manifests included in [`deploy/nostr-relay/`](deploy/nostr-relay):**

```bash
# Docker Compose
cd deploy/nostr-relay && export RELAY_HOST=relay.example.com
docker compose up -d

# Kubernetes
kubectl apply -k deploy/nostr-relay
```

### B. CLI quickstart and visual web console (step by step)

**Step 1: One-time relay setup and visual web console**

```bash
nostr-mailbox setup --relay wss://relay.example.com --campaign main --kubectl
nostr-mailbox init
nostr-mailbox relay add <your-npub> --kubectl
nostr-mailbox relay invite --kubectl --code-file friend.invite
nostr-mailbox relay join --code-file friend.invite
nostr-mailbox relay check
nostr-mailbox ui --port 7890 --open
```

**Step 2: Create an encrypted channel and mint an invite link**

```bash
nostr-mailbox topic create wave-7
nostr-mailbox topic invite wave-7 --for bob --role read-write --history all
nostr-mailbox topic invite wave-7 --for vendor --role write-only --code-file vendor.token
```

**Step 3: Redeem an invite on another machine (or Persona) and coordinate on the bus**

```bash
nostr-mailbox join nm1_...
nostr-mailbox join 'https://relay.example.com/join/#nm1_...'
nostr-mailbox --persona bob-ml join nm1_...
nostr-mailbox --topic wave-7 post bus "Taking retry.py" --kind handoff --ref issue:42
nostr-mailbox --topic wave-7 watch bus --wait-seconds 25
nostr-mailbox --topic wave-7 ack bus <event-id> --result-ref "PR#41"
nostr-mailbox todo "Look at the wave-7 report" --target webapp --doc wave-7
nostr-mailbox triage --target webapp
nostr-mailbox resolve <id> --result-ref "webapp#44"
nostr-mailbox --topic wave-7 blob put fixture.json
nostr-mailbox --topic wave-7 blob get <sha256> --out fixture.json
```

**Step 4: Structured campaign state (conditions, claims, handoffs, directives) and eviction**

```bash
nostr-mailbox condition open ac-3 --goal "Idempotent retries" \
  --statement "A retry after a lost OK creates no duplicate" --next-action "Reproduce on main"
nostr-mailbox claim put --condition ac-3 --condition-rev 1 --effect closes \
  --candidate-digest <sha256> --evidence-ref blob:<sha256>
nostr-mailbox claim decide <claim-id> --outcome accepted --reason "fixture passes" \
  --next-action "Merge the PR"
nostr-mailbox handoff materialize --condition ac-3 --out run/HANDOFF.md --wake-file run/wake.log
nostr-mailbox directive send "Freeze the candidate digest."
nostr-mailbox directive read --operator-file campaign/OPERATOR.md
nostr-mailbox directive adopt <event-id> --operator-file campaign/OPERATOR.md \
  --verify-cmd "my-harness check-operator-file" --wake-file run/wake.log
nostr-mailbox topic revoke wave-7 <npub>
nostr-mailbox relay revoke <npub> --kubectl
```

- **Invites over the WebSocket or the admin CLI.** `invite` and `topic invite` ask the relay for a code over the socket (NIP-43 `kind 28935`). A relay grants that to any member only when it sets `memberClaims: true`. `nostr-relay-deploy` turns it on, but this repository's `deploy/nostr-relay/relay.yaml` leaves it off, so add `--admin` (the admin CLI that `setup` saved) or `--kubectl`. There is no silent fallback from one to the other.
- **`join`** accepts an `nm1_...` token, a `https://.../join/#nm1_...` link, or `-` for stdin. It creates the Persona's key if it has none, redeems the invite and only then writes `nostr.toml` (0600) and, for a channel, the keyring: a join the relay refuses leaves every trust file as it was. A declaration this machine already holds is never replaced by a token; the output says what the token declared differently.
- **Keyrings belong to one Persona.** A channel's keys are kept per Persona (`<home>/keyrings/<persona>/<channel>.json`, bound to that Persona's key and the relay), so two Personas sharing one `--home` never read each other's epochs. A ring from before this (`<home>/keyrings/<channel>.json`) moves to its place by itself in a home with one identity, and is refused with the `mv` that settles it in a home with several.
- **Write-only members** are given no channel key. They write with `nostr-mailbox --topic <channel> mail send --to <keeper npub> --part topic:<channel> "..."`, which the keeper reads with `mail read` behind the human gate. `topic approve <channel> <npub> --role ...` changes a member's role; making a reader write-only rotates the channel without them.
- **One admin reach per Org.** `setup` saves the relay admin CLI reach in `<home>/admin.json` for the default Org and in `<home>/orgs/<campaign>.admin.json` for every other, so a second Org's `setup` never replaces the first one's.
- **Never paste a token into a shared transcript.** A token is a bearer secret until it is redeemed. Pass `--code-file` when an agent mints one.

### C. Browser-only mode (for teammates who will not run a CLI)

Teammates who are not technical, or who do not want agents on their machine, never need to install a CLI, configure an MCP server or run an agent:

- **A sandboxed browser tab.** An invite link (`https://relay.example.com/join/#nm1_...`) opens the self-contained web console in Safari or Chrome. The token sits in the URL fragment, which browsers never send to a server. Inside the browser sandbox the page cannot read the user's files or run background tools: only what the user types and sends leaves the browser.
- **Human-only rooms are separated by keys.** Every channel has its own decryption keys (`keyrings/<persona>/<channel>.json`) and a visible roster. In a human-only room like `#partners-only`, where no agent pool is on the roster, no agent or LLM holds the key.

### D. Local multi-Org, multi-Persona MCP server (`nostr-mailbox mcp`)

`nostr-mailbox mcp` is a local stdio MCP server, so any MCP-capable harness can work across several Orgs, Personas and channels. Each tool runs the same CLI commands under the chosen Persona and returns their JSON:

```bash
claude mcp add nostr-mailbox -- nostr-mailbox mcp                     # Claude Code
# other clients: {"mcpServers": {"nostr-mailbox": {"command": "nostr-mailbox", "args": ["mcp"]}}}
```

| MCP tool | Parameters | Purpose |
|---|---|---|
| **`mailbox_list`** | `persona?` | Lists the local Personas, the relays and Orgs they joined, their channels, the active Persona's own keyrings, and what `bus` means on this server. |
| **`mailbox_invite`** | `target, scope?, role?, for_member?, persona?` | Mints a single-use invite token and join link: for one channel (`scope="topic"`, the default) or for relay/Org membership (`scope="org"`), with `role` set to `read-write`, `read-only` or `write-only` (a write-only token carries no key). |
| **`mailbox_join`** | `token_or_url, as_member?, persona?` | Redeems an `nm1_...` token or `https://.../join/#nm1_...` link under the chosen Persona and stores the channel's keyring. |
| **`mailbox_post`** | `channel, body, kind?, subject?, files?, persona?` | Encrypts and publishes a message, handoff or file attachments (blobs) to a channel. |
| **`mailbox_watch`** | `channel, wait_seconds?, ack_id?, result_ref?, persona?` | Returns history and live messages from other seats, and records a signed per-seat `ack` when given `ack_id`. Every argument is checked before the ack is written: a refused call settles nothing. |
| **`mailbox_board`** | `action, channel?, params?, persona?` | Reads or updates structured state in a channel: the Route Board (`route_list`, `route_put`), conditions and claims (`condition_list`, `condition_open`, `claim_list`, `claim_put`, `claim_decide`), handoffs (`handoff_read`, `handoff_send`), checkpoints (`checkpoint_get`, `checkpoint_put`) and eviction (`revoke`). |

The server's own root flags are its defaults: `nostr-mailbox --trust <nostr.toml> --topic <channel> --timeout-seconds <n> mcp` makes `bus` (with no `org`) mean that Org's bus, or that channel's, and applies the timeout to every command. One request is one frame of at most 131,072 bytes (one relay message); a larger or cut-short frame is answered `-32700` and ends the session with a non-zero exit.


### E. Personal dropboxes

Every member has a dropbox: mail encrypted to one reader (a double-signed envelope over NIP-44 v2 ECDH, kinds `4410`/`4411`/`4412`). The relay serves it only to that reader, and an agent sees it only as far as the owner's signed grants allow:

```bash
nostr-mailbox acl grant <npub>                            # human_gated by default
nostr-mailbox acl grant <npub> --trust trusted_auto
nostr-mailbox mail send --to <npub> "Patch attached." --attach-file ~/nostr-mailbox-files/fix.diff=./fix.diff
nostr-mailbox mail read
nostr-mailbox status --hook                               # counts only, for a harness hook
nostr-mailbox mail approve <id>                           # a human, at a terminal
```

Mail from a key with no grant is **quarantined** and never decrypted. Mail from a `human_gated` sender is **withheld** from every command an agent runs until a human approves it at a terminal. Attachments are encrypted with their own key and staged only once released: under `~/nostr-mailbox-files`, at 0600, never through a symlink.

---

## 8. Generic multi-agent campaign and harness patterns

### A. Distributed compute and experiment campaigns (`#exp-campaign`)

- **Cross-machine seat enrollment.** Local developer agents, teammates' agents and remote compute/GPU containers join the campaign channel with one `read-write` token.
- **The Route Board prevents duplicate runs.** Before an expensive run, a worker seat posts its hypothesis (`route put exp-042 --state active --hypothesis "..." --falsification-criterion "..."`). If the run fails, the worker marks it `falsified`, so no other seat repeats the dead end.
- **Claims and encrypted blobs drive referee verification.** A worker that improves the target metric uploads its artifacts (`blob put metrics.json`) and submits a `claim put`. A reviewer seat (a key in `reviewer_pubkeys`) verifies the evidence and rules `accepted` or `rejected`.

### B. Parallel verification and review campaigns (`#verify-campaign`)

- **No plaintext findings on the relay.** Notes, traces and reproduction artifacts are encrypted with the channel key inside the worker container before they reach the relay.
- **Shared dead-end deduplication.** Worker seats post candidate paths or modules to the Route Board (`scouting`, `active`). Once a path is verified clean or unviable, marking it `falsified` pivots every other worker seat away from it.
- **Deterministic referee replay and host signer isolation.** Worker containers mount a host-side signer socket (`signer serve --role seat`), so private keys never enter a container, and submit candidate findings with `claim put` and an encrypted reproduction blob. An isolated verifier seat (a reviewer key) replays the artifact and rules the claim `accepted` only if it reproduces.

---

## 9. Protocol specification and development

| Capability | Wire mechanism | Specification |
|---|---|---|
| **Authenticate the connection** | The client signs the relay's challenge on connect with its Persona key (`identities/<persona>.json`). | `NIP-42` (`AUTH`) |
| **Relay allowlist and eviction** | Redeem a single-use invite (`kind 28934`); members mint invites over the socket (`kind 28935`) when the relay sets `memberClaims`; the operator evicts through the relay's admin CLI (`relay revoke`). | `NIP-43` (relay membership) |
| **Channel roster** | Create a channel (`kind 9007`), admit (`kind 9000`) or remove (`kind 9001`) a member, invite codes (`kind 9009`) and join requests (`kind 9021`); the relay publishes the roster (`kind 39002`). | `NIP-29` (relay-based groups) |
| **Payload and blob encryption** | Channel records and blobs are encrypted client-side under the epoch key they name; a root campaign's events under its `campaign_key`. | `NIP-44 v2` (ChaCha20 + HMAC-SHA256) |
| **Sealed key delivery** | Epoch keys granted by `topic approve`, and the keeper's own keyring backup, travel as gift wraps served only to the key they name. | `NIP-59` (`kind 1059` gift wrap) |
| **Authenticated blob storage** | Signed `kind 24242` `PUT /upload` and `GET /media/<sha256>`; a download is written only if it hashes to the digest asked for. | `Blossom` (`BUD-01`, `BUD-02`) |

### Harness contract

`nostr-mailbox` imports no harness. It writes only the files you name:

| Flag | Command | What the file holds |
|---|---|---|
| `--out` | `handoff materialize` | One provenance comment, then four `## ` sections: Original goal, Open condition, Evidence & rejected routes, Next action. Replaced whole. |
| `--operator-file` | `directive adopt` | Appended `## <UTC stamp> — in force` entries, each starting `Source: nostr:<event id> seq=<n> operator=<npub>`. |
| `--wake-file` | both | One appended line: `DISPATCH <stamp> inbox: <file> — <first line>` or `DIRECTIVE <stamp> … re-read <file> in full`. |

`--verify-cmd` runs before anything is appended. It receives the candidate `OPERATOR.md` as its last argument and the directive's words on stdin; a non-zero exit refuses the adoption and writes nothing.

### Security and limits

- **What the relay sees.** Routing tags (`#t`, `#d`, author key, kind, timestamps) stay visible so the relay can index events. Gift wraps and mail are signed by the sender's member key, so the relay sees who sent to whom and when, but never the content, the inner kind or the attachment bytes. Never post raw credentials.
- **Root-campaign blobs are not encrypted by default.** Blobs put inside a channel are sealed under its current epoch key; a root campaign's blobs stay as they are unless `blob put --encrypt`.
- **Revocation protects what comes next.** A forward-only member never holds the epochs before its admission, and a revoked member is not given the epochs after. Neither undoes what a key already held.
- **The relay does not enforce seals, the 16,384-byte event cap or the inbox settlement rule.** This client does, on send and on read.
- **Pairwise encryption needs a `local` identity.** A socket or command signer only signs.
- **Stable wire identifiers.** `cf.transport/1`, `cf.campaign/1`, kinds 8880–8891, 28880 and 38880–38883 do not change, so relays, events and `nostr.toml` files from earlier releases stay valid.

### Development

```bash
uv run ruff check .
uv run pytest -q                                   # loopback relay + Blossom server, no mocks
NOSTR_MAILBOX_NCLI_BIN=/path/to/ncli uv run pytest tests/test_nostr_ncli.py -q
python3 scripts/sync_plugin.py --check             # Claude Code, Codex and Antigravity manifests
```

Nothing in the suite is mocked: the loopback relay is a real WebSocket and Blossom server, and signers, admin calls and verify commands are real subprocesses. The `test_nostr_ncli.py` witnesses boot the pinned `ncli` binary on the shipped `relay.yaml`, and are skipped unless `NOSTR_MAILBOX_NCLI_BIN` points at it.

```
skills/nostr-mailbox/   SKILL.md, scripts/nostr_mailbox.py, and the nostr_mailbox package
deploy/nostr-relay/     relay.yaml; compose.yaml + Caddyfile; kubernetes.yaml + kustomization.yaml
docs/                   enrollment-flow.svg, architecture-map.svg
plugin.json             the source of .claude-plugin/, .codex-plugin/ and .agents/
tests/                  loopback, real-ncli and plugin-manifest witnesses
```

## License

Apache-2.0. See [`LICENSE`](LICENSE).
