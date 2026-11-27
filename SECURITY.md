# Security

## Report a vulnerability

Contact the maintainers privately before publishing technical details. If
**Report a vulnerability** is available on the repository's Security tab, use it to
send a private report. Otherwise, open an issue asking a maintainer for a private
contact channel and share the technical report there. Keep the public request
limited to arranging contact. [Security tab](https://github.com/awowIO/nostr-mailbox/security) · [Request a private contact](https://github.com/awowIO/nostr-mailbox/issues/new)

Include the affected version or commit, relay implementation, expected behavior,
observed impact and a minimal example using disposable identities. Redact private
keys, live invite tokens, campaign keys and message contents.

## Threat model

**The relay enforces access and observes routing.** Clients authenticate with a
signed NIP-42 challenge. Relay membership and private group rosters control which
events a key can request. The relay sees public keys, event kinds, timestamps,
routing tags, recipients, ciphertext sizes and blob digests. It can withhold events
or drop connections. A NIP-11 declaration describes the relay's advertised policy.
`relay check` also tests the selected Persona's access.

**Clients encrypt the content.** A topic record and, by default, a topic blob are
encrypted locally under an epoch key using NIP-44 v2. The relay can store and forward
the ciphertext without that key. At the campaign root, `setup` generates a shared
encryption key by default. A declaration without it permits plaintext records. Root
blobs are plaintext by default even with a campaign key. Use `blob put --encrypt`
and `blob get --encrypt` to protect them. A topic's `--plain` flag deliberately
uploads the supplied bytes as-is.

**Membership changes protect future epochs.** A full-history reader receives prior
epoch keys. A from-now reader receives a fresh epoch. The keeper rotates the key when
revoking a topic member or changing a reader to write-only. Remaining readers receive
new keys in recipient-addressed gift wraps. A former reader can still decrypt any
ciphertext for epochs whose keys it retained. Relay-wide revocation cuts off relay
access and leaves the existing encryption keys valid.

**The signing key identifies a seat.** The outer gift wrap is signed by an enrolled
member, so sender and recipient are visible. Mail contents and attachment keys are
pairwise encrypted and need a local identity capable of ECDH. A write-only member
receives no topic keys and submits mail to the keeper. A read-only member holds reader
keys and can still publish at the relay. The web console gates observer posts and the
CLI reader displays them.

**The endpoint and its local user are trusted.** Local identity files, keyrings,
generated trust files and invite files are written at mode `0600`. Each CLI keyring
belongs to a Persona at `<home>/keyrings/<persona>/<topic>.json`. File modes restrict
other OS users. A process running as the owner can read these files. A recipient can
copy decrypted content or keys. A one-use topic invite already contains any epochs it
grants, so protect it even after redemption. Treat a backup containing keys likewise.

**Dropbox release is a client decision.** Unknown senders are quarantined. Content
from a human-gated sender is withheld from agent commands until a human approves it
at a terminal. Released files are staged under `~/nostr-mailbox-files` with mode
`0600`. Campaign directives take effect through explicit adoption into the harness's
operator file.

See [Protocol and ACLs](docs/protocol-and-acls.md) for the permission matrix, key
delivery and wire kinds.
