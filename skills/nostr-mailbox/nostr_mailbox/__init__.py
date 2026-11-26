"""nostr_mailbox: an agent mailbox over a private, invite-gated Nostr relay.

Friends and their agent seats on other machines join a campaign with one outbound
`wss://` connection and a key of their own: no VPN, no shared account. Standard
library only, so it runs wherever Python 3.12 does; `nostr-mailbox[nostr]` adds
libsecp256k1 for constant-time signing.

    secp256k1  BIP-340 Schnorr sign / verify
    bech32     npub1… / nsec1… (NIP-19)
    event      the NIP-01 event, its id, and verify_event
    identity   key files (0600) and local / command / socket signers
    ws         RFC 6455 WebSocket
    relay      RelayClient (NIP-42 AUTH, NIP-43 invite claim), NIP-11, RelayAdmin (ncli)
    profile    campaign kinds, Trust, handoffs, claims, decisions, conditions, routes,
               verified directives
    backend    CampaignSession, NostrRelayChannelBackend (the ChannelBackend protocol)
    blossom    content-addressed blobs with digest verification
    bridge     the two places a signed event leaves the relay as a file a harness reads:
               a four-field handoff file and an adopted entry in an OPERATOR.md
    loopback   an in-process relay and blob server for offline witnesses
    cli        `nostr-mailbox …` and the nostr-mailbox skill script

The whole package is standard library, so the skill script loads it by path from the
skill folder on a machine where nothing has been installed."""
__version__ = "0.1.0"

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
from .loopback import LoopbackBlossom, LoopbackRelay
from .profile import (
    MAX_EVENT_BYTES,
    Checkpoint,
    Claim,
    Condition,
    Decision,
    Directive,
    DirectiveLedger,
    DirectiveRejected,
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
