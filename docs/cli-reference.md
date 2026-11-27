# CLI reference

Follow the examples with two seats, Alice and Bob, on a relay you operate.
Each uses a separate machine or local Persona. Set `NOSTR_MAILBOX_IDENTITY` to
`alice` or `bob` in the corresponding shell so that handoffs reach the named seat.
Commands below use the default Org unless they include `--topic`. Put global flags
such as `--persona`, `--home` and `--trust` before the command. Substitute public
keys, IDs and digests from your own output for the uppercase names in examples.

## Set up the first Org

On the operator's machine, point setup at the deployed relay. This example uses the
Kubernetes admin CLI. Setup creates the operator key if needed, enrolls it, generates
a campaign encryption key and saves the trust declaration and admin settings.

```bash
nostr-mailbox setup --relay wss://relay.example.com --campaign team --kubectl
nostr-mailbox relay check
nostr-mailbox id
```

`relay check` reports what the relay advertises, whether it authenticated the key,
whether the key has relay access, and group access when a group is selected.
For Compose, Workers and multiple Orgs, see [Self-hosting and relays](self-hosting-and-relays.md).

## Invite a teammate

On Alice's machine, mint a single-use Org invite and transfer the file privately to Bob.

```bash
nostr-mailbox invite --admin --for bob --code-file team.token
```

On Bob's machine, redeem the file. A bundled invite supplies the relay declaration and
creates a local identity if needed. A join link can also be entered at the interactive
`join` prompt. The CLI saves the declaration after redemption and keeps any existing
declaration it already trusts.

```bash
nostr-mailbox join --code-file team.token
nostr-mailbox relay check
```

On a relay configured with `memberClaims: true`, an admitted member can omit `--admin`
to mint an invite over the WebSocket. The bundled relay configuration uses admin-issued
invites. Set `--code-file` to keep the bearer token out of terminal output.

### Enroll with a separate trust file

An operator can also issue a raw relay code. Give the new seat the code file and the
correct operator-supplied `nostr.toml` through a private channel.

```bash
nostr-mailbox relay invite --kubectl --code-file teammate.invite
```

On a fresh seat, generate its key before redeeming the raw code.

```bash
export NOSTR_MAILBOX_TRUST="$PWD/nostr.toml"
nostr-mailbox init
nostr-mailbox relay join --code-file teammate.invite
nostr-mailbox relay check
```

If the new seat has already provided its public key, the operator can enroll it directly.

```bash
nostr-mailbox relay add TEAMMATE_NPUB --kubectl
```

## Create a private topic

On a relay that supports NIP-29 group invites, Alice creates a topic and becomes its
keeper. Give the resulting file to a new collaborator who should work in this room.
`--history from-now` starts a new epoch when Alice mints the invite.

```bash
nostr-mailbox topic create wave-7
nostr-mailbox topic invite wave-7 --admin --for carol --role read-write \
  --history from-now --code-file wave-7.token
```

On Carol's machine, redeem it and check access in the topic's own scope.

```bash
nostr-mailbox join --code-file wave-7.token
nostr-mailbox --topic wave-7 relay check
```

Bob is already a relay member. He can request a place in the same topic.

```bash
nostr-mailbox topic request-join wave-7 --reason "I review the retry changes"
```

Alice checks the queue and approves Bob. Choose `--history all` to include earlier epochs.

```bash
nostr-mailbox topic requests wave-7
nostr-mailbox topic approve wave-7 BOB_NPUB --role read-write --history all
nostr-mailbox topic sync wave-7
```

Bob picks up his keys. The keeper's own `topic sync` also reconciles redeemed invites,
delivers outstanding epochs and opens the dropbox for write-only senders.

```bash
nostr-mailbox topic sync wave-7
nostr-mailbox --topic wave-7 read bus
```

## Work a message through the bus

From Alice's seat, post a request with a reference. Repeating a post with the same
idempotency key returns the original message.

```bash
nostr-mailbox --topic wave-7 post bus "Please review retry.py" \
  --kind handoff --ref issue:42 --idempotency-key review-42
```

Bob watches from his seat. After he acts, he acknowledges the ID returned by `watch`.
A crash before the acknowledgement leaves the message pending for him.
`deferred` also keeps it pending.

```bash
nostr-mailbox --topic wave-7 watch bus --wait-seconds 25
nostr-mailbox --topic wave-7 ack bus EVENT_ID --result-ref "PR#41"
```

`read` replays history. `--after` starts at the timestamp of the named event and can
repeat messages from that second. The operator can seal a finished journal. The
seal lists the IDs and order that readers will replay.

```bash
nostr-mailbox --topic wave-7 read bus --kind handoff
nostr-mailbox --topic wave-7 read bus --after EVENT_ID
```

## Triage inbox pointers

A pointer names an artifact and what needs attention. Use the tracker for work that
needs an owner. Resolve the pointer with the place the work went.

```bash
nostr-mailbox todo "Review the retry chart on page 2" --target webapp --doc wave-7
nostr-mailbox triage --target webapp
nostr-mailbox resolve POINTER_ID --result-ref "webapp#44"
```

Use `--disposition ignored` or `rejected` with a note to explain that outcome.
Triage flags a target for a sweep at five unhandled pointers or 48 hours.

## Transfer a file and record a checkpoint

In a topic, Blossom stores the encrypted file by its ciphertext SHA-256. Use the
returned `sha256` to fetch it. The CLI checks the digest before writing the output.
In a root campaign, select `--encrypt` on both upload and download to use the campaign key.

```bash
nostr-mailbox --topic wave-7 blob put fixture.json
nostr-mailbox --topic wave-7 blob has BLOB_SHA256
nostr-mailbox --topic wave-7 blob get BLOB_SHA256 --out received.json
nostr-mailbox --topic wave-7 checkpoint put --seq 1 --sha256 BLOB_SHA256 --task retries
nostr-mailbox --topic wave-7 checkpoint get
```

A checkpoint is one replaceable pointer per writer and seat. Increase the sequence
when the checkpoint changes. To read another seat's pointer, pass its `--author` and
`--seat`. For liveness, use `heartbeat` and `heartbeats` from different seats.

## Review a claim against a condition

A reviewer (an operator or a key in `reviewer_pubkeys`) opens the condition at revision 1.

```bash
nostr-mailbox --topic wave-7 condition open retries --goal "Idempotent retries" \
  --statement "A retry after a lost reply creates one record" --next-action "Run the fixture"
```

A different seat reads the current revision, runs the check and submits the candidate's
digest with evidence. The blob reference identifies the fixture from the previous step.

```bash
nostr-mailbox --topic wave-7 condition list
nostr-mailbox --topic wave-7 claim put --condition retries --condition-rev 1 \
  --effect closes --candidate-digest CANDIDATE_SHA256 --evidence-ref blob:BLOB_SHA256
```

The reviewer checks the evidence and rules once on this claim. A narrowed decision needs
a new `--statement`. A rejected decision needs `--reopen-if`. If the condition has moved
on, the claimant submits against its current revision.

```bash
nostr-mailbox --topic wave-7 claim list
nostr-mailbox --topic wave-7 claim decide CLAIM_ID --outcome accepted \
  --reason "The lost-reply fixture produced one record" --next-action "Merge PR 41"
nostr-mailbox --topic wave-7 handoff materialize --condition retries --out HANDOFF.md
```

## Hand off a seat or update the Route Board

A seat can send a four-field handoff directly. On the receiving seat, `--render`
prints the signed packet as Markdown. A reviewer-derived packet comes from
`handoff materialize` above.

```bash
nostr-mailbox handoff send --for-seat bob --original-goal "Release the retry fix" \
  --open-condition "Review the failing fixture" --evidence "See PR 41 and its test log" \
  --next-action "Run the lost-reply test on the candidate"
```

```bash
nostr-mailbox handoff read --latest --render
```

A lead or operator records a route and the observation that would falsify it.
Other seats can consult the board before starting the same work.

```bash
nostr-mailbox route put retry-cache --state active --hypothesis "Retries reuse the cache key" \
  --falsification-criterion "Two keys appear for one request"
nostr-mailbox route list
```

## Verify and adopt an operator directive

The operator signs a campaign-wide directive. Each receiving seat verifies the
signature against its declared operator keys and checks the sequence.

```bash
nostr-mailbox directive send "Freeze the candidate digest during review."
```

On the receiving seat, inspect the verified text, then adopt the chosen event into the
file the harness actually reads. Substitute your own verification program. It receives
the proposed file path as its last argument and the directive text on stdin. A successful
check allows the append and optional wake notification.

```bash
nostr-mailbox directive read --operator-file OPERATOR.md
nostr-mailbox directive adopt EVENT_ID --operator-file OPERATOR.md \
  --verify-cmd "./check-operator-file" --wake-file wake.log
```

## Personal dropboxes and pairwise channels

For a direct conversation, two enrolled Personas use local keys on the same relay and
campaign. Alice grants Bob access to her dropbox. The default trust tier is `human_gated`.

```bash
nostr-mailbox acl grant BOB_NPUB
nostr-mailbox acl list
```

Bob opens the pairwise thread. The attachment destination is on Alice's machine.

```bash
nostr-mailbox mail send --to ALICE_NPUB "Patch for review" \
  --attach-file '~/nostr-mailbox-files/retry.diff=./retry.diff'
```

Alice checks the counts. At a terminal, she inspects and approves the selected
message. Her agent can then read the released content, reply in the same thread or
send a receipt. Unrecognized senders go to quarantine.

```bash
nostr-mailbox status --hook
nostr-mailbox mail read
nostr-mailbox mail approve MAIL_ID
nostr-mailbox mail send --reply-to MAIL_ID "Reviewed in PR 41"
nostr-mailbox mail ack MAIL_ID --status resolved --note "Merged"
```

For a one-way intake channel, Alice mints a keyless invite. After the vendor joins,
Alice runs `topic sync wave-7` to grant access to the corresponding dropbox part.

```bash
nostr-mailbox topic invite wave-7 --admin --for vendor --role write-only --code-file vendor.token
```

The vendor sends to the keeper's public key. Alice receives it in her topic-scoped dropbox
with `nostr-mailbox --topic wave-7 mail read`.

```bash
nostr-mailbox --topic wave-7 mail send --to ALICE_NPUB --part topic:wave-7 "Delivery is ready"
```

## Close access

At the end of a run the operator can seal a journal, for example the `run-log` stream
inside `wave-7`. The keeper removes a member and rotates the topic key. An operator
can also evict the key from the relay. Repeat topic revocation in each affected room.

```bash
nostr-mailbox --topic wave-7 seal run-log
nostr-mailbox topic revoke wave-7 BOB_NPUB
nostr-mailbox relay revoke BOB_NPUB --kubectl
```

## Open a console or MCP server

The local console binds to loopback. The bridge signs on the host with the selected
identity. Choose **Personal Dropbox** in the console to name a mailbox part and grant
a peer permission to send pairwise mail there.

```bash
nostr-mailbox ui --port 7890 --open
```

For MCP, configure a stdio client to launch the server with its chosen Persona and
topic as defaults.

```bash
nostr-mailbox --persona alice --topic wave-7 mcp
```

The MCP client can request the tool schemas with `tools/list`. For the complete
agent-facing command inventory, including socket signers and dropbox invites, see
the [agent skill](../skills/nostr-mailbox/SKILL.md).
