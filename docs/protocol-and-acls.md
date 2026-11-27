# Protocol and ACLs

A Persona signs as one public key. An Org is a campaign trust declaration naming
a relay and its operators. A topic is a private NIP-29 group with a roster on that
relay and an epoch keyring on each reader's machine. These are three distinct
decisions about which key can use the relay, which group it can subscribe to, and
which records it can decrypt.

## Permission matrix across scopes

In this example Alice operates the team's relay and keeps `wave-7`. Bob's work
Persona and two agent seats collaborate there. Alice's personal Persona talks to
Dave through a separate dropbox thread.

| Scope | Principal | Access |
| --- | --- | --- |
| Team Org | Alice, relay operator | Enroll or evict a relay key and create topics. |
| Team Org | Bob and Carol, members | Use the Org bus and create private topics. |
| Team relay | Vendor with a topic invite | Connect and access the invited topic with its assigned keys. |
| Multi-pool topic | Alice, keeper | Read, post, admit members and rotate epochs. |
| Multi-pool topic | Bob and enrolled seats | Read granted history and post signed records. |
| Multi-pool topic | Monitor, read-only | Receive epochs and follow the stream. |
| Human-only topic | Alice, Bob and Carol | Read and post with the humans' topic keys. |
| Human-only topic | Agent seats outside the roster | No group subscription or epoch keys. |
| Intake topic | Alice, keeper | Read sealed submissions and manage grants. |
| Intake topic | Vendor, write-only | Send to Alice's dropbox part with no epoch keys. |
| Pairwise thread | Alice-personal and Dave | Exchange mail addressed to each reader's public key. |

Each agent seat enrolls and leaves by its own key. A signed seat certificate can
identify the seat that sealed a piece of personal mail. It grants no inherited
membership in its person's topics. In a human-only room, the participants also
control which local processes can read their keys and plaintext.

### Who can change the record?

- **Relay administrator** uses the relay's admin interface to admit and evict public keys.
  A bundled Org invite can carry its campaign key. A topic invite carries
  only the topic declaration and the epoch keys appropriate to the role.
- **Topic keeper** creates the group, chooses a role and history window for each
  admission, and rotates the epoch on removal.
- **Campaign operator** signs directives and journal seals. A lead or operator can
  update the Route Board. A reviewer or operator can open conditions and decide
  another seat's claim. Clients check these keys against the trust declaration.
- **Dropbox owner** signs grants and revocations. The owner chooses which peers can
  write, which mailbox parts they may use, and which messages require human approval.

## Role-scoped key delivery

| Topic invite | Epoch keys delivered | How the recipient participates |
| --- | --- | --- |
| `read-write` | Selected history and later epochs | Decrypts and publishes topic records. |
| `read-only` | Selected history and later epochs | Observes the room with a reader's keys. |
| `write-only` | None, including at rotation | Sends sealed mail to the keeper. |

**Read-only is an observer role.** The group relay accepts a signed post from an
enrolled observer. The web console holds that post for human review, and the CLI
reader shows it. Treat a strict ban on publishing as a separate enforcement requirement.

**Write-only access is enforced by key distribution.** The keeper's `topic sync`
grants the sender access to the `topic:<topic>` part of the keeper's dropbox. The
keeper reads the submissions through the human gate. A write-only invite has no
`--history` option. Changing an existing reader to write-only rotates the epoch.

A topic token bundles a one-use relay invite, a group code, a redemption secret and,
for readers, the granted epochs. Possession of that token already exposes those
keys. Approved requests receive their epochs in a gift wrap addressed to the
recipient. The keeper reconciles grants and readers retrieve deliveries with
`topic sync`. The keeper also writes a self-addressed encrypted keyring backup.

| History choice | When the key changes | What the new reader can open |
| --- | --- | --- |
| `--history all` | Admission reuses the current epoch | All granted epochs back to the first |
| `--history from-now` | The keeper rotates before issuing keys | Records encrypted under the new epoch onward |

Rotation at revocation distributes a fresh key to remaining readers. An evicted
reader keeps previously received keys and plaintext. Relay eviction alone changes
relay access. Revoke the topic membership to rotate the topic's keys.

## Local keyring isolation

The default home is `~/.config/nostr-mailbox`. A different `--home` selects a
different set of files. `--persona NAME` selects the identity within it.

| Location under the home | Contents |
| --- | --- |
| `identities/<persona>.json` | Local signing identity or external signer configuration |
| `keyrings/<persona>/<topic>.json` | Epochs held by that Persona and keeper state when applicable |
| `topics/<topic>.toml` | Relay and trust declaration for the topic |
| `nostr.toml` | Default Org declaration, including its campaign key when configured |
| `orgs/<campaign>/nostr.toml` | Additional Org's root declaration |

The CLI stores each ring at `<home>/keyrings/<persona>/<topic>.json` with mode
`0600` and checks the owning key and relay when opening it. A pre-Persona keyring
at `keyrings/<topic>.json` migrates automatically when the home has one matching
identity. With several identities, the CLI asks the operator to assign it to its owner.
Processes running as the file owner can read that owner's files. Use separate OS
accounts when the local users themselves need isolation.

## Nostr glossary and wire kinds

A **NIP** is a Nostr Implementation Possibility. These specifications define the
messages that the mailbox layers its own roles, key delivery and campaign records on.
See the [upstream NIP index](https://github.com/nostr-protocol/nips).

| Protocol | On the wire | Mailbox use |
| --- | --- | --- |
| NIP-11 | HTTP relay information document | Discover authentication and membership gates. |
| NIP-42 | `AUTH`, kind `22242` | Sign the relay challenge for this connection. |
| NIP-43 | `28934` claim, `28935` invite | Redeem one use or request a member-issued invite. |
| NIP-29 | `9007`, `9009`, `9021` | Create a group, issue a group code, request entry. |
| NIP-29 | `9000`, `9001`, `39002` | Add or remove a member and read the relay's roster. |
| NIP-44 v2 | Encrypted payload | Encrypt locally with ChaCha20 and authenticate with HMAC-SHA256. |
| NIP-59 | `1059` wrap, inner `13` seal | Deliver epoch keys privately to one reader. |
| Blossom | HTTP authorization, kind `24242` | Sign uploads and downloads by content digest. |

This relay binds an event author to the authenticated member. The mailbox therefore
signs the outer gift wrap with the sender's member key. The relay sees its sender,
recipient and timestamp. It stores an encrypted seal containing the epoch-key rumor.

### Mailbox event kinds

The trust declaration uses `cf.transport/1`. Structured campaign payloads use
`cf.campaign/1`. The kind and routing tags remain visible for filtering.

| Kinds | Records in numeric order |
| --- | --- |
| `8880`–`8883` | Goal revision, claim, decision, route transition |
| `8884`–`8887` | Handoff, directive, documentation wave receipt, review wake |
| `8888`–`8891` | Acknowledgement, seal, promotion, message |
| `8892` | Epoch keys inside a gift wrap |
| `28880` | Ephemeral heartbeat |
| `38880`–`38883` | Replaceable goal, condition, route and checkpoint heads |
| `4410`–`4412` | Personal mail envelope, receipt and inner seal |
| `4420`–`4423` | Dropbox grant, revocation, invite and claim |
| `34410` | Person-signed seat certificate |

The client enforces the 16,384-byte event limit, seal manifest and inbox settlement
rules when interpreting a journal. A seat's acknowledgement settles the message for
that seat. A heartbeat is transient. See the [CLI examples](cli-reference.md) and
[security model](../SECURITY.md).
