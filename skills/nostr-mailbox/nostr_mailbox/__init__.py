"""nostr_mailbox: an agent mailbox over a private, invite-gated Nostr relay.

Friends and their agent seats on other machines join a campaign with one outbound
`wss://` connection and a key of their own: no VPN, no shared account. Standard
library only, so it runs wherever Python 3.12 does; `nostr-mailbox[nostr]` adds
libsecp256k1 for constant-time signing.

    secp256k1  BIP-340 Schnorr sign / verify
    bech32     npub1… / nsec1… (NIP-19)
    event      the NIP-01 event, its id, and verify_event
    identity   key files (0600) and local / command / socket signers; NIP-44 ECDH
    nip44      NIP-44 v2: campaign and pairwise (ECDH) conversation keys, the cipher
    ws         RFC 6455 WebSocket
    relay      RelayClient (NIP-42 AUTH, NIP-43 invite claim and kind-28935 invite
               minting), NIP-11, RelayAdmin (ncli)
    profile    campaign kinds, Trust, epoch keys, handoffs, claims, decisions,
               conditions, routes, verified directives
    giftwrap   NIP-59 rumor / seal (13) / gift wrap (1059)
    groups     NIP-29 topics: create, admit, remove, invite codes, join requests
    keyring    the Topic Epoch Key Ring: 0600 storage, delivery, sync, the keeper
    pairwise   agent-mailbox envelopes (4410/4411), seals (4412), seat certs (34410)
    acl        mailbox grants, revokes, one-time invites and BIP-340 claim proofs
    mailbox    personal dropboxes: quarantine, the human gate, 0600 file staging
    backend    CampaignSession, NostrRelayChannelBackend (the ChannelBackend protocol)
    blossom    content-addressed blobs with digest verification
    bridge     the two places a signed event leaves the relay as a file a harness reads:
               a four-field handoff file and an adopted entry in an OPERATOR.md
    loopback   an in-process relay and blob server for offline witnesses
    cli        `nostr-mailbox …` and the nostr-mailbox skill script

The whole package is standard library, so the skill script loads it by path from the
skill folder on a machine where nothing has been installed."""
__version__ = "0.1.0"

from .acl import AclError, Grant
from .backend import (
    BUS,
    INBOX,
    CampaignSession,
    ChannelBackend,
    IdempotencyConflict,
    Message,
    NostrRelayChannelBackend,
    NotAuthorized,
    PartialBatch,
    Receipt,
    SealBroken,
    StaleRecord,
    TopicSealed,
    UnknownMessage,
)
from .blossom import Blob, BlossomClient, BlossomError, DigestMismatch
from .bridge import BridgeError, adopt_directive, deliver_handoff
from .event import Event, InvalidEvent, NostrError, kind_class, verify_event
from .giftwrap import GiftWrapError, Rumor
from .groups import Topic, TopicError
from .identity import (
    CommandSigner,
    Identity,
    IdentityError,
    LocalSigner,
    Signer,
    SignerError,
    SignerServer,
    SocketSigner,
    create_identity,
    load_identity,
)
from .keyring import KeyRing, KeyRingError
from .loopback import LoopbackBlossom, LoopbackRelay
from .mailbox import Dropbox, MailError
from .pairwise import EnvelopeError
from .profile import (
    MAX_EVENT_BYTES,
    Checkpoint,
    Claim,
    Condition,
    Decision,
    Directive,
    DirectiveLedger,
    DirectiveRejected,
    EpochKeys,
    EventTooLarge,
    Handoff,
    Heartbeat,
    Kind,
    ProfileError,
    Route,
    Trust,
    resolve_directives,
    verify_directive,
)
from .relay import (
    HistoryTruncated,
    RelayAdmin,
    RelayAdminError,
    RelayClient,
    RelayError,
    RelayInfo,
    RelayProtocolError,
    RelayRejected,
    RelayTimeout,
    fetch_info,
)

__all__ = [
    "BUS", "INBOX", "MAX_EVENT_BYTES",
    "AclError", "Dropbox", "EnvelopeError", "EpochKeys", "GiftWrapError", "Grant",
    "KeyRing", "KeyRingError", "MailError", "Rumor", "Topic", "TopicError",
    "Blob", "BlossomClient", "BlossomError", "BridgeError", "CampaignSession",
    "ChannelBackend",
    "Checkpoint", "Claim", "CommandSigner", "Condition", "Decision", "DigestMismatch",
    "Directive", "DirectiveLedger", "DirectiveRejected", "Event", "EventTooLarge",
    "Handoff", "Heartbeat", "HistoryTruncated", "IdempotencyConflict", "Identity",
    "IdentityError", "InvalidEvent", "Kind", "LocalSigner", "LoopbackBlossom",
    "LoopbackRelay", "Message", "NostrError", "NostrRelayChannelBackend",
    "NotAuthorized", "PartialBatch", "ProfileError", "Receipt", "RelayAdmin",
    "RelayAdminError", "RelayClient", "RelayError", "RelayInfo", "RelayProtocolError",
    "RelayRejected", "RelayTimeout", "Route", "SealBroken", "Signer", "SignerError",
    "SignerServer", "SocketSigner", "StaleRecord", "TopicSealed", "Trust",
    "UnknownMessage", "adopt_directive", "create_identity", "deliver_handoff",
    "fetch_info", "kind_class", "load_identity", "resolve_directives", "verify_directive",
    "verify_event",
]
