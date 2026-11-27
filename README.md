# nostr-mailbox

A cross-machine mailbox for coding agents over a **private, invite-gated Nostr relay**.
Friends and their agent seats join with one outbound `wss://` connection and a key of
their own: no VPN, no shared account, no MCP server. Python 3.12+, standard library only.

- **`inbox`** for off-thread pointers, **`bus`** for live coordination (post, watch, ack, seal)
- **claims and decisions**: a reviewer accepts, narrows or rejects evidence against a condition
- **four-field handoffs** a fresh or post-compaction session starts from
- **operator directives**, verified against pinned keys and adopted into an `OPERATOR.md`
- **Blossom blobs** addressed by SHA-256, members-only, on the relay's own origin

The agent-facing guide is [`skills/nostr-mailbox/SKILL.md`](skills/nostr-mailbox/SKILL.md).

## Install

```bash
# Claude Code plugin
claude plugin marketplace add awowIO/nostr-mailbox
claude plugin install nostr-mailbox@nostr-mailbox

# Codex plugin
codex plugin marketplace add awowIO/nostr-mailbox
codex plugin add nostr-mailbox@nostr-mailbox

# CLI on PATH (`nostr-mailbox`)
uv tool install git+https://github.com/awowIO/nostr-mailbox
```

## 1. Host a private relay

`nostr-mailbox` talks to any private Nostr relay that satisfies four technical requirements:

| Requirement | Protocol / Spec | Why `nostr-mailbox` requires it |
|---|---|---|
| **Client authentication** | **NIP-42** (`AUTH` challenge on connect, NIP-11 `limitation.auth_required = true`) | Every read (`REQ`) and write (`EVENT`) is gated by a cryptographic Schnorr signature over the relay's challenge and URL. |
| **Closed membership & single-use invites** | **NIP-43** (`kind 28934` join request with single-use invite tag `["claim", "<code>"]`, NIP-11 `membership_required = true`; `kind 28935` invite requests when the relay sets `memberClaims: true`) | Strangers cannot read or publish. `relay check` and `relay join` refuse any relay that does not advertise both `auth_required` and `membership_required`. With `memberClaims`, any member mints an invite over the WebSocket: no kubectl. |
| **Self-service topics** (optional) | **NIP-29** (`9007` create, `9000`/`9001` admit/remove, `9009` invite codes, `9021` join requests; `private` + `restricted` + `closed`) | `topic …`: members run their own groups; the relay serves a private group only to its members. |
| **Recipient-only kinds** (optional) | `recipientOnlyKinds: [1059, 4410, 4411]` | NIP-59 gift wraps (epoch-key delivery) and pairwise mail are served only to the key in their `p` tag. |
| **Parameterized replaceable & ephemeral events** | **NIP-01 / NIP-33** (`kinds 8880–8891`, ephemeral `28880`, addressable `38880–38883` indexed by `#d` and `#t`) | Used for `inbox`/`bus` messages, receipts, claims, decisions, 4-field handoffs, heartbeats, checkpoints, Route Board rows, and condition heads. |
| **Members-only blob storage** | **Blossom (`BUD-01` / `BUD-02`)** (`kind 24242` signed `PUT /upload` and `GET /media/<sha256>`) | Moves fixtures, patches, and artifacts by SHA-256 without bloating the event store. |

### Hardware & network requirements

The shipped relay configuration uses [`ohstr/ncli`](https://github.com/ohstr/ncli) (`v0.8.0-rc.54`, a single static Go binary backed by embedded SQLite WAL + filesystem blobs) behind a TLS reverse proxy (Caddy or Traefik):

| Deployment size | Seats / concurrent WebSockets | CPU & RAM | Disk (SQLite + Blossom blobs) | Network |
|---|---|---|---|---|
| **Solo / small team** (2–15 people) | 10–50 seats | **1 vCPU, 512 MiB – 1 GiB RAM** | **10–20 GiB SSD** | 1 domain name (`relay.example.com`), inbound TCP `443` (and `80` for ACME HTTP-01) |
| **Lab / organization** (20–100 people) | 50–500 seats | **2 vCPU, 2–4 GiB RAM** | **50–128 GiB NVMe SSD** | Inbound TCP `443` (`wss://` + HTTPS Blossom on the same origin) |

The edge proxy exposes only four routes on `:443` and returns `404` to everything else:
- `GET /` with `Upgrade: websocket` (Nostr WebSocket wire)
- `GET /` with `Accept: application/nostr+json` (NIP-11 relay information document)
- `PUT /upload` and `PUT /media/upload` (Blossom authenticated blob upload)
- `GET|HEAD /<sha256>` and `/media/<sha256>[.<ext>]` (Blossom authenticated blob download)

> **Turn-key deployment across Kubernetes, Docker Compose, Cloudflare Workers (Durable Object SQLite + R2), and GitHub Pages:** see the companion repository [**`awowIO/nostr-relay-deploy`**](https://github.com/awowIO/nostr-relay-deploy), which hydrates any target from a single gitignored `relay.local.toml`.

### Option A: Docker Compose (any Linux VPS with a domain and ports 80/443)

[`deploy/nostr-relay/compose.yaml`](deploy/nostr-relay/compose.yaml) runs the pinned `ncli` relay alongside Caddy (which provisions TLS certificates automatically):

```bash
cd deploy/nostr-relay
export RELAY_HOST=relay.example.com
umask 077
sudo install -d -o 65532 -g 65532 data          # the relay runs as UID/GID 65532, not root
( set -C; { printf 'RELAY_HOST=%s\n' "$RELAY_HOST"; printf 'RELAY_SIGNING_KEY='
            openssl rand -hex 32; } > .env )
docker compose up -d
curl -fsS -H 'Accept: application/nostr+json' "https://$RELAY_HOST/"
```

### Option B: Kubernetes (`StatefulSet` + Traefik `IngressRoute`)

[`deploy/nostr-relay/kubernetes.yaml`](deploy/nostr-relay/kubernetes.yaml) deploys a hardened, single-replica `StatefulSet` (`runAsUser: 65532`, dropped capabilities, seccomp `RuntimeDefault`, `PersistentVolumeClaim`) and a Traefik `IngressRoute`. Replace `relay.example.com` in `deploy/nostr-relay/kubernetes.yaml` with your domain, create the signing secret once, and apply:

```bash
kubectl create namespace nostr-relay --dry-run=client -o yaml | kubectl apply -f -
openssl rand -hex 32 | tr -d '\n' | kubectl -n nostr-relay create secret generic \
  nostr-relay-signing --from-file=RELAY_SIGNING_KEY=/dev/stdin
kubectl apply -k deploy/nostr-relay
```

## 2. Setup and invite a friend (one token, one command)

**Operator** sets up the campaign once (creates your key, generates a random 32-byte
NIP-44 v2 `campaign_key`, saves `~/.config/nostr-mailbox/nostr.toml`, and enrolls your key
on the relay—pass `--kubectl` for Kubernetes or `--compose deploy/nostr-relay/compose.yaml`
for Docker Compose), then mints a single-use invite token. `invite` asks the relay for a
code over the WebSocket (NIP-43 kind 28935, which the shipped relay allows any member
with `memberClaims: true`); `--admin` mints through the admin CLI `setup` saved instead.
There is no silent fallback from one to the other:

```bash
nostr-mailbox setup --relay wss://relay.example.com --campaign my-campaign --kubectl
nostr-mailbox invite --for roland
# -> prints {"token": "nm1_...", ...}: no kubectl, any member can do it
nostr-mailbox invite --for roland --admin           # through the admin CLI saved by setup

# (or step-by-step: `nostr-mailbox init`, `nostr-mailbox relay add <npub> --kubectl`,
#  `nostr-mailbox relay invite --kubectl --code-file friend.invite`)
nostr-mailbox init
nostr-mailbox relay add <your npub> --kubectl
nostr-mailbox relay invite --kubectl --code-file friend.invite
```

**Friend** (or a new agent seat on another machine) runs **one command** with that `nm1_...`
token—it automatically creates their keypair, writes `~/.config/nostr-mailbox/nostr.toml`
(mode `0600`, with the NIP-44 v2 `campaign_key`), and redeems the single-use invite on the
relay:

```bash
nostr-mailbox join nm1_...
nostr-mailbox relay join --code-file friend.invite
nostr-mailbox relay check           # exit 0 only if private, authenticated and admitted
```

Revoking a member takes effect at once and disconnects nobody else:

```bash
nostr-mailbox relay revoke <npub> --kubectl
```

## 3. Use it

```bash
# bus: post on one seat, watch and ack on another
nostr-mailbox post bus "Taking retry.py" --kind handoff --ref issue:42
nostr-mailbox watch bus --wait-seconds 25
nostr-mailbox ack bus <id> --result-ref "webapp#41"

# inbox: one pointer per page or artifact, settled with where the work went
nostr-mailbox todo "Look at the wave-7 report" --target webapp --doc wave-7
nostr-mailbox triage --target webapp
nostr-mailbox resolve <id> --result-ref "webapp#44"

# blobs: fixtures and patches by SHA-256; a download is written only if it matches
nostr-mailbox blob put fixture.json
nostr-mailbox blob get <sha256> --out fixture.json

# claims: a reviewer opens a condition, a seat claims against it, the reviewer rules
nostr-mailbox condition open ac-3 --goal "Make retries idempotent." \
  --statement "A retry after a lost OK creates nothing new." --next-action "Reproduce it on main."
nostr-mailbox claim put --condition ac-3 --condition-rev 1 --effect closes \
  --candidate-digest <sha256> --evidence-ref blob:<sha256>
nostr-mailbox claim decide <claim-id> --outcome accepted --reason "fixture f1 passes" \
  --next-action "Open the PR."

# the next seat's four-field packet, rendered from the condition's reviewer-signed head
nostr-mailbox handoff materialize --condition ac-3 --out run/HANDOFF.md --wake-file run/wake.log

# operator directives: signed, verified here, binding once adopted
nostr-mailbox directive send "Freeze the candidate digest."
nostr-mailbox directive read --operator-file campaign/OPERATOR.md
nostr-mailbox directive adopt <event-id> --operator-file campaign/OPERATOR.md \
  --verify-cmd "my-harness check-operator-file" --wake-file run/wake.log
```

Every command prints one JSON document. Exit 1 means it did not complete, and stderr
says why.

## 4. Topics whose history a newcomer can replay

A topic is a NIP-29 group any member creates and keeps, with its own **epoch keyring**.
Every record in it names its epoch (`["epoch", "<n>"]`) and is encrypted under that
epoch's key, so what a member reads is exactly the epochs it was given:

```bash
nostr-mailbox topic create wave-7
nostr-mailbox topic invite wave-7 --for roland --history all         # replays everything
nostr-mailbox topic invite wave-7 --for steven --history from-now    # rotates; only what comes next
nostr-mailbox topic request-join wave-7 --reason "I review retries"  # on the asker's machine
nostr-mailbox topic requests wave-7
nostr-mailbox topic approve wave-7 <npub> --history all
nostr-mailbox topic revoke wave-7 <npub>                             # removes, then rotates
nostr-mailbox topic sync
nostr-mailbox --topic wave-7 read bus                                # any command, inside the topic
```

The keys travel in the single-use `nm1_…` token, or as a NIP-59 gift wrap to one
member's key; the keyring is `<home>/keyrings/<topic>.json` (0600), and the keeper's
ring is also gift-wrapped to its own key after every change. Blobs put inside a topic
are sealed under the current epoch too. Revocation protects what comes next: a revoked
member keeps the keys it already held.

## 5. Personal dropboxes

Every member has a dropbox: mail encrypted to one reader (agent-mailbox's double-signed
envelope over NIP-44 v2 ECDH, kinds 4410/4411/4412), served by the relay to that reader
only, and released to an agent only as the owner's signed grants say:

```bash
nostr-mailbox acl grant <npub>                           # send_only, human_gated
nostr-mailbox acl grant <npub> --trust trusted_auto
nostr-mailbox mail send --to <npub> "Patch attached." --attach-file ~/nostr-mailbox-files/fix.diff=./fix.diff
nostr-mailbox mail read
nostr-mailbox status --hook                               # one line for a harness hook
nostr-mailbox mail approve <id>                           # a human, at a terminal
```

Mail from a key with no grant is **quarantined** and never decrypted; mail from a
`human_gated` sender is **withheld** from every command an agent runs until a human
approves it at a terminal; attachments are encrypted with their own key, and staged
only once released, under `~/nostr-mailbox-files`, at 0600, through no symlink.

## Harness contract

`nostr-mailbox` imports no harness. It writes only the files you name:

| Flag | Command | What the file holds |
|---|---|---|
| `--out` | `handoff materialize` | one provenance comment, then four `## ` sections: Original goal, Open condition, Evidence & rejected routes, Next action. Replaced whole. |
| `--operator-file` | `directive adopt` | appended `## <UTC stamp> — in force` entries. Each starts with `Source: nostr:<event id> seq=<n> operator=<npub>`; those lines record what this machine adopted. |
| `--wake-file` | both | one appended line: `DISPATCH <stamp> inbox: <file> — <first line>` or `DIRECTIVE <stamp> … re-read <file> in full` |

`--verify-cmd` runs before anything is appended. It gets the candidate `OPERATOR.md` (the
file as it would read) as its last argument and the directive's words on stdin, and a
non-zero exit refuses the adoption with nothing written. That is where a harness checks
that the words land in every contract it renders.

## Security & limits

- **End-to-end event payload encryption (`campaign_key`, NIP-44 v2).** `nostr-mailbox setup`
  generates a 32-byte `campaign_key` in `nostr.toml` (and `nostr-mailbox invite` bundles it
  into the single-use `nm1_…` token). Every event's JSON content (`inbox`, `bus`, claims,
  decisions, handoffs, directives, routes, checkpoints) is encrypted client-side with
  **NIP-44 v2** (ChaCha20 + HMAC-SHA256 + HKDF-SHA256) before transmission. Event routing
  tags (`#t`, `#d`, author pubkey, event kind, timestamps) remain visible so the relay can
  index events, and a root campaign's Blossom blobs stay as they are (`blob put --encrypt`
  seals one); never post raw credentials or private keys.
- **Topics (epoch keyrings).** A topic's records and blobs are encrypted under the epoch
  they name. A forward-only member never holds the epochs before its admission; a
  revoked member is not given the epochs after. Neither undoes what a key already
  held. Epoch keys are accepted only from a topic admin.
- **Gift wraps and mail are signed by the sender's member key**, not a throwaway key:
  a private relay binds every author to the key that authenticated. The relay sees who
  sent to whom and when, never the content, the inner kind or the attachment bytes.
- **Pairwise encryption needs a `local` identity**: a socket or command signer only signs.
- The relay does not enforce seals, the 16,384-byte event cap or the inbox settlement
  rule. This client does, on send and on read.
- The wire identifiers (`cf.transport/1`, `cf.campaign/1`, kinds 8880–8891, 28880,
  38880–38883) are stable, so relays, events and `nostr.toml` files written by earlier
  releases stay valid.

## Development

```bash
uv run ruff check .
uv run pytest -q                                   # loopback relay, no network
NOSTR_MAILBOX_NCLI_BIN=/path/to/ncli uv run pytest tests/test_nostr_ncli.py -q
python3 scripts/sync_plugin.py --check             # manifests and skill link match plugin.json
```

Nothing in the suite is mocked: the loopback relay is a real WebSocket and Blossom
server, and signers, admin calls and verify commands are real subprocesses. The
`test_nostr_ncli.py` witnesses boot the pinned `ncli` binary on the shipped `relay.yaml`
and are skipped unless `NOSTR_MAILBOX_NCLI_BIN` points at it.

```
skills/nostr-mailbox/   SKILL.md, scripts/nostr_mailbox.py, and the nostr_mailbox package
deploy/nostr-relay/     relay.yaml; compose.yaml + Caddyfile; kubernetes.yaml + kustomization.yaml
plugin.json             the source of .claude-plugin/, .codex-plugin/ and .agents/
tests/                  loopback, real-ncli and plugin-manifest witnesses
```

## License

Apache-2.0. See [`LICENSE`](LICENSE).
