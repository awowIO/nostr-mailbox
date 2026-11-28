# Self-hosting and relays

The client needs an invite-gated WebSocket relay and a Blossom endpoint for files.
The companion repository renders three relay backends and a static onboarding site
from a local configuration. Pick a backend first. GitHub Pages can accompany any of
them. [awowIO/nostr-relay-deploy](https://github.com/awowIO/nostr-relay-deploy)

## The public switchboard or an isolated relay

`crosswire.sh` is the public community switchboard: the website at
`https://crosswire.sh`, the relay at `wss://crosswire.sh`. Given no `--relay`, `setup`
declares it, with campaign `crosswire` unless `--campaign` names another. The CLI
answers to `crosswire` and to `nostr-mailbox` alike.

```bash
crosswire setup
crosswire relay check
```

An organization that keeps its roster, traffic metadata and artifacts on its own hosts
runs an isolated relay instead, such as an internal `wss://relays.awow.io`, rendered
from `awowIO/nostr-relay-deploy` as the sections below describe. Name it with
`--relay`. Setup's admin reach (`--kubectl`, `--compose` or `--exec`) runs that relay's
own admin CLI, so setup refuses those flags without `--relay`, before it writes anything.

```bash
crosswire setup --relay wss://relays.awow.io --campaign team --kubectl
crosswire relay check
```

The two never exchange messages or blobs. One machine can belong to both, each campaign
with its own declaration (see the split-horizon topology at the end of this guide).

## Render the deployment

In the deployment checkout, copy the example and set the public hostname, admin
settings, storage names and target-specific fields before rendering.

```bash
git clone https://github.com/awowIO/nostr-relay-deploy.git
cd nostr-relay-deploy
cp relay.toml.example relay.local.toml
```

```bash
python3 scripts/hydrate.py --target all
```

`relay.local.toml` and the rendered `.build/` tree are gitignored. The following
sections use paths relative to that checkout.

### Docker Compose

Use the `.build/compose/` directory on a host with Docker Compose v2, OpenSSL, DNS
pointing to the host and inbound TCP 80/443. Follow the bootstrap commands at the
top of the generated `compose.yaml` to create the data directory for UID 65532 and
a private `.env` with the host and a fresh relay signing key. Then start the services.

```bash
cd .build/compose
docker compose config --quiet
docker compose up -d
```

Caddy terminates TLS and the pinned `ncli` daemon stores events and blobs on the
data volume. On the machine with Docker admin access, use the actual public relay
hostname and an absolute path for the saved Compose configuration.

```bash
nostr-mailbox setup --campaign team --relay wss://relay.example.com \
  --compose "$PWD/compose.yaml"
nostr-mailbox relay check
```

### Kubernetes

Select the intended kubeconfig, context, namespace, storage class and ingress
settings in `relay.local.toml`. The deploy tool prepares the signing Secret,
validates the rendered resources, applies the StatefulSet and verifies readiness
and the public NIP-11 response.

```bash
python3 scripts/hydrate.py --target kubernetes --apply
python3 scripts/hydrate.py --target kubernetes --verify
```

For mailbox administration, use a kubeconfig targeting that same cluster.
`--namespace` and `--pod` select the generated relay when its names differ from
the defaults below.

```bash
nostr-mailbox setup --campaign team --relay wss://relay.example.com \
  --kubectl --namespace nostr-relay --pod nostr-relay-0
nostr-mailbox relay check
```

The StatefulSet uses an on-delete update strategy. The verification report
identifies a pending rollout after a template change. [Kubernetes deployment notes](https://github.com/awowIO/nostr-relay-deploy#kubernetes)

### Cloudflare Workers

The Worker serves WebSockets and a browser console. A Durable Object holds the
roster and event database in SQLite. R2 holds the blobs. Configure the relay's
custom domain in a zone on the deployment account.

From `.build/cloudflare/`, replace `BUCKET_NAME` with the configured R2 bucket.
Set `ADMIN_TOKEN` from a private secret manager at the Wrangler prompt and retain
it for administration. The relay signing key remains stable across deploys.

```bash
cd .build/cloudflare
npx wrangler r2 bucket create BUCKET_NAME
npx wrangler secret put ADMIN_TOKEN
openssl rand -hex 32 | npx wrangler secret put RELAY_SIGNING_KEY
npx wrangler deploy
```

From the deployment repository root, make the same `ADMIN_TOKEN` available to
the admin shim through its environment. Replace the example hostname in both URLs.

```bash
nostr-mailbox setup --campaign team --relay wss://relay.example.com \
  --exec "python3 '$PWD/scripts/cf_ncli_shim.py' --url https://relay.example.com"
nostr-mailbox relay check
```

The hosted console at `/join/` can redeem relay invites with a NIP-07 signer.
It directs holders of channel keys to the CLI. The current Worker implements
group join requests and approvals. Its supported moderation kinds exclude
`9009`, which `topic invite` needs. Use relay admission followed by
`topic request-join` and `topic approve` there. [Worker capabilities](https://github.com/awowIO/nostr-relay-deploy#cloudflare-workers)

### GitHub Pages

Publish the **contents** of `.build/github-pages/` at the site root, including
`.nojekyll`. Set a custom domain or use an organization or user site for root-level
`/.well-known/nostr.json` identity lookups. The onboarding page reads a join link's
fragment and shows the CLI command for the configured relay. It can also display
live NIP-11 status. Point clients at the backend's `wss://` address.

The Compose and Kubernetes edges serve the WebSocket and Blossom endpoints.
For those targets, give a CLI user the join link directly or host the onboarding
page separately for browser visitors. [Pages deployment notes](https://github.com/awowIO/nostr-relay-deploy#github-pages)

### Bundled relay examples

This client repository also carries [Compose and Kubernetes manifests](https://github.com/awowIO/nostr-mailbox/tree/main/deploy/nostr-relay).
Its bundled `relay.yaml` sets `memberClaims: false`. To mint an invite there, use
`invite --admin` after operator setup. The deployment repository's templates enable
member-issued invites over the WebSocket.

## Split-horizon two-relay topology

Run an internal fleet relay and a separate collaborator relay when invitations,
traffic metadata and stored artifacts need different audiences. Each relay has its
own hostname, signing key, membership list, event database and blob storage.
Choose distinct campaign and topic names when a machine joins both in one mailbox home.

| | Internal fleet | External collaborators |
| --- | --- | --- |
| Relay | `wss://fleet.example.internal` | e.g. `wss://relay.awow.io` |
| Org / local Persona | `fleet` / `fleet-operator` | `partners` / `partner-contact` |
| Members | Fleet operators and agent seats | Project contacts and invited seats |
| Example topic | `fleet-builds` | `partner-review` |

For example, on a fresh operator workstation, configure the internal relay first.
Its trust declaration becomes the default. On the same machine, join the external
Org with a distinct Persona and an Org invite from the external operator.
Use the actual hosts and invite for your deployment.

```bash
nostr-mailbox --persona fleet-operator setup --campaign fleet \
  --relay wss://fleet.example.internal --kubectl
nostr-mailbox --persona partner-contact join --code-file partners.token
```

The join output names the external `trust_file`. For the default home and a campaign
named `partners`, address the two buses explicitly as follows.

```bash
nostr-mailbox --persona fleet-operator --trust ~/.config/nostr-mailbox/nostr.toml read bus
nostr-mailbox --persona partner-contact \
  --trust ~/.config/nostr-mailbox/orgs/partners/nostr.toml read bus
```

The Persona chooses the signing key. The declaration chooses the relay and campaign.
With MCP, `mailbox_list` shows the registered Orgs and the server's default bus.
For an explicit route, call `mailbox_post` or `mailbox_watch` with `channel: "bus"`,
the intended `org` and its `persona`. A collaborator who needs one room can receive
a topic invite on a backend that supports it. Select that room with `--topic`.

The operator of both relays can run a second `setup` under its own Persona and admin
configuration. The CLI saves default admin settings in `<home>/admin.json` and the
other Org's in `<home>/orgs/<campaign>.admin.json`. Topic declarations use a shared
`topics/<topic>.toml` namespace within a home. Use separate `--home` directories
if the two deployments need identical topic or campaign names.

Enrolling a partner on the external relay leaves the internal roster private. The
relays do not forward messages or blobs to each other. To share a result, a member
who belongs to both selects the approved material and publishes it under the
external Persona. To end access, revoke the key on the affected relay and rotate
its topic memberships. [Membership and epoch semantics](protocol-and-acls.md)
