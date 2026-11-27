"""Personal mailbox permissions: who may drop mail into whose mailbox, derived only from
events the mailbox owner signed. Adapted from agent-mailbox (`acl.py`, PROTOCOL.md §5).

    4420 grant   (owner)    [["mbx",o],["p",peer],["scope",s],["trust",t],
                             ["read_replies","true|false"],["part",p]…,["relay",url],
                             ["access_until",ts]?]
    4421 revoke  (owner)    [["mbx",o],["p",peer]]  or  [["mbx",o],["e",invite id]]
    4422 invite  (owner)    [["mbx",o],["invite_key",pk], terms…, ["relay",url],
                             ["label",name]?, ["claim_until",ts]?]
    4423 claim   (invitee)  [["mbx",o],["e",invite id],["p",o],["invite_sig",sig]]
                            content {"name": <self-declared handle>}

`scope` is `send_only` (drop into `inbox`, read replies in threads you opened),
`topic_scoped` (named parts) or `full_peer`. `trust` is how the OWNER's agent treats
the peer: `human_gated` (default: content withheld until a human approves) or
`trusted_auto`. A one-time invite is a fresh key pair: the owner publishes its public
half, hands the secret out in an `inv_…` token, and the claim proves possession with
a BIP-340 signature over sha256("agent-mailbox/claim/v1" ‖ invite id ‖ claimant), so a
relay that sees a claim cannot replay it for any other key.

A claim grants nothing by itself (agent-mailbox's `owner_confirm` mode for standard
relays). A relay here does not enforce one claim per invite, and a claimant chooses its
own `created_at`: "earliest claim wins" would let anyone holding the token backdate a
claim and take the invite from its first claimant. The owner's client records the
first valid claim it observes, with the time it observed it (checked against the
invite's deadline), and confirms that one with an ordinary owner-signed grant carrying
`["e", <invite id>]`; from then on the invite is spent, whatever is claimed after,
however it is dated. A claim dated before its invite is refused outright, and so is
every unconfirmed claim of an invite the owner revoked, however it is dated.

Grants are bound to the relay they were issued on (`relay`); a grant or invite bound
elsewhere is ignored. A revoke counts wherever it was issued: ignoring one is the
unsafe direction. Deadlines use their own tags, not NIP-40 `expiration`, so a relay
that deletes expired events cannot erase the history a claim is checked against."""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from collections.abc import Iterable
from dataclasses import dataclass, field

from . import bech32, secp256k1
from .event import Event, InvalidEvent, verify_event
from .profile import ProfileError

GRANT, REVOKE, INVITE, CLAIM = 4420, 4421, 4422, 4423
ACL_KINDS = (GRANT, REVOKE, INVITE, CLAIM)
SCOPES = ("send_only", "topic_scoped", "full_peer")
SCOPE_ALIASES = {"part_access": "topic_scoped"}
TRUST_TIERS = ("human_gated", "trusted_auto")
DEFAULT_TRUST = "human_gated"
CLAIM_DOMAIN = b"agent-mailbox/claim/v1"
INVITE_PREFIX = "inv_"
INVITE_VERSION = 2                      # agent-mailbox's self-contained invite token
_PART = re.compile(r"^(inbox|bus|topic:[a-z0-9][a-z0-9._-]*)$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_STAMP = re.compile(r"^[0-9]{1,12}$")


class AclError(ProfileError):
    """An ACL artifact that is malformed, or a claim that does not verify."""


def validate_part(part, *, allow_wildcard: bool = False) -> str:
    if allow_wildcard and part == "*":
        return part
    if not isinstance(part, str) or len(part) > 128 or not _PART.fullmatch(part):
        raise AclError(f"mailbox part {part!r} must be inbox, bus or topic:<slug>")
    return part


def normalize_scope(scope: str) -> str:
    scope = SCOPE_ALIASES.get(scope, scope)
    if scope not in SCOPES:
        raise AclError(f"scope {scope!r} must be one of {SCOPES} (or part_access)")
    return scope


def default_parts(scope: str, parts: Iterable[str]) -> tuple[str, ...]:
    parts = tuple(dict.fromkeys(validate_part(p, allow_wildcard=True) for p in parts))
    if parts:
        return parts
    if scope == "send_only":
        return ("inbox",)
    if scope == "full_peer":
        return ("*",)
    raise AclError("topic_scoped access names at least one part (e.g. topic:my-project)")


def _deadline(event: Event, *names: str) -> int | None:
    for name in names:
        values = event.values(name)
        if values:
            if not _STAMP.fullmatch(values[0]):
                raise AclError(f"{name} {values[0]!r} is not a unix timestamp")
            return int(values[0])
    return None


@dataclass(frozen=True)
class Grant:
    mailbox: str
    grantee: str
    scope: str
    parts: tuple[str, ...]
    trust: str
    read_replies: bool
    source: str                         # "grant" or "invite"
    proof: tuple[str, ...]              # the ids of the signed events it derives from
    granted_at: int
    expires_at: int | None = None

    def allows_part(self, part: str) -> bool:
        return "*" in self.parts or part in self.parts

    def to_dict(self) -> dict:
        return {"grantee": self.grantee,
                "npub": bech32.encode(bech32.NPUB, bytes.fromhex(self.grantee)),
                "scope": self.scope, "parts": list(self.parts), "trust": self.trust,
                "read_replies": self.read_replies, "source": self.source,
                "proof": list(self.proof), "granted_at": self.granted_at,
                "expires_at": self.expires_at}


@dataclass
class AclState:
    owner: str
    grants: dict[str, Grant] = field(default_factory=dict)
    rejected: list[tuple[str, str]] = field(default_factory=list)     # (event id, why)
    claimed_invites: dict[str, str] = field(default_factory=dict)     # invite → confirmed
    pending_claims: dict[str, Event] = field(default_factory=dict)    # invite → valid claim
    valid_claims: dict[str, list[Event]] = field(default_factory=dict)  # every one, oldest first
    invites: dict[str, Event] = field(default_factory=dict)


def terms_tags(scope: str, parts: Iterable[str], trust: str,
               read_replies: bool) -> list[list[str]]:
    scope = normalize_scope(scope)
    if trust not in TRUST_TIERS:
        raise AclError(f"trust tier {trust!r} must be one of {TRUST_TIERS}")
    tags = [["scope", scope], ["trust", trust],
            ["read_replies", "true" if read_replies else "false"]]
    return tags + [["part", p] for p in default_parts(scope, parts)]


def parse_terms(event: Event) -> tuple[str, tuple[str, ...], str, bool]:
    scope = normalize_scope((event.values("scope") or [""])[0])
    parts = default_parts(scope, event.values("part"))
    trust = (event.values("trust") or [DEFAULT_TRUST])[0]
    if trust not in TRUST_TIERS:
        raise AclError(f"trust tier {trust!r} is unknown")
    read_replies = (event.values("read_replies") or ["true"])[0] == "true"
    return scope, parts, trust, read_replies


def claim_message(invite_id: str, claimant: str) -> bytes:
    """What the invite key signs: one invite, bound to one claimant key."""
    return hashlib.sha256(CLAIM_DOMAIN + bytes.fromhex(invite_id)
                          + bytes.fromhex(claimant)).digest()


def claim_proof(invite_id: str, claimant: str, invite_secret: bytes) -> str:
    return secp256k1.schnorr_sign(claim_message(invite_id, claimant), invite_secret).hex()


def check_claim(invite: Event, claim: Event) -> None:
    """`AclError` unless `claim` validly claims `invite` (both signature-verified)."""
    owner = invite.pubkey
    if invite.kind != INVITE or claim.kind != CLAIM:
        raise AclError("not an invite and a claim")
    if invite.values("mbx") != [owner]:
        raise AclError("the invite is not signed by the owner of the mailbox it names")
    if claim.values("e") != [invite.id] or claim.values("mbx") != [owner]:
        raise AclError("the claim does not name this invite and mailbox")
    if claim.pubkey == owner:
        raise AclError("an owner does not claim their own invite")
    key, proof = (invite.values("invite_key") or [""])[0], (claim.values("invite_sig") or [""])[0]
    try:
        valid = secp256k1.schnorr_verify(claim_message(invite.id, claim.pubkey),
                                         bytes.fromhex(key), bytes.fromhex(proof))
    except ValueError as exc:
        raise AclError(f"the claim proof is not hex: {exc}") from exc
    if not valid:
        raise AclError("the claim proof was not signed by the invite key")
    if claim.created_at < invite.created_at:
        raise AclError("the claim is dated before the invite it claims")
    until = _deadline(invite, "claim_until", "expiration")
    if until is not None and claim.created_at > until:
        raise AclError("the invite had expired when it was claimed")


def derive(owner: str, events: Iterable[Event], *, relay: str, at: int) -> AclState:
    """Fold owner-signed grants, revokes and invites into the grants in force at `at`.
    Per grantee the newest artifact wins and a revoke beats a grant with the same
    timestamp. A claim only waits (`pending_claims`, the first valid one per invite)
    until the owner confirms it; one confirmed spends its invite, and one of a revoked
    invite is never valid: a claimant dates its own claim."""
    state = AclState(owner=owner)
    # Oldest first, so the first confirmation of an invite is the one that stands.
    mine = sorted((e for e in events if e.values("mbx") == [owner] and e.kind in ACL_KINDS),
                  key=lambda e: (e.created_at, e.id))
    revoked_invites: set[str] = set()
    timeline: dict[str, list[tuple[int, int, str, Grant | None]]] = {}

    def bound(event: Event) -> bool:
        if event.values("relay") == [relay]:
            return True
        state.rejected.append((event.id, f"bound to relay {event.values('relay')}, not "
                                         f"{relay!r}"))
        return False

    invites = {e.id: e for e in mine if e.kind == INVITE and e.pubkey == owner and bound(e)}
    for event in mine:
        if event.pubkey != owner:
            if event.kind in (GRANT, REVOKE, INVITE):
                state.rejected.append((event.id, "not signed by the mailbox owner"))
            continue
        if event.kind == REVOKE:
            revoked_invites.update(event.values("e"))
            for grantee in event.values("p"):
                timeline.setdefault(grantee, []).append(
                    (event.created_at, 1, event.id, None))
        elif event.kind == GRANT and bound(event):
            grantee = (event.values("p") or [""])[0]
            try:
                scope, parts, trust, read_replies = parse_terms(event)
                expires = _deadline(event, "access_until", "expiration")
            except AclError as exc:
                state.rejected.append((event.id, str(exc)))
                continue
            if not _HEX64.fullmatch(grantee) or grantee == owner:
                state.rejected.append((event.id, "a grant names one peer other than the owner"))
                continue
            confirms = [i for i in event.values("e") if i in invites]
            taken = [i for i in confirms if state.claimed_invites.get(i, grantee) != grantee]
            if taken:                       # an invite is confirmed once, for one key
                state.rejected.append((event.id, "the invite was already confirmed for "
                                                 "another key"))
                continue
            for invite_id in confirms:
                state.claimed_invites.setdefault(invite_id, grantee)
            timeline.setdefault(grantee, []).append((event.created_at, 0, event.id, Grant(
                owner, grantee, scope, parts, trust, read_replies,
                "invite" if confirms else "grant", (*confirms, event.id), event.created_at,
                expires)))

    state.invites = invites
    for claim in sorted((e for e in mine if e.kind == CLAIM),
                        key=lambda e: (e.created_at, e.id)):
        invite = invites.get((claim.values("e") or [""])[0])
        if invite is None:
            state.rejected.append((claim.id, "the claim names no invite of this mailbox"))
            continue
        if state.claimed_invites.get(invite.id, claim.pubkey) != claim.pubkey:
            state.rejected.append((claim.id, "the invite was already claimed and confirmed "
                                             "for another key"))
            continue
        if invite.id in state.claimed_invites:
            continue                        # the claim the owner confirmed
        if invite.id in revoked_invites:
            state.rejected.append((claim.id, "the invite was revoked by its owner"))
            continue
        try:
            check_claim(invite, claim)
            parse_terms(invite)
        except AclError as exc:
            state.rejected.append((claim.id, str(exc)))
            continue
        state.valid_claims.setdefault(invite.id, []).append(claim)
        state.pending_claims.setdefault(invite.id, claim)

    for grantee, entries in timeline.items():
        entries.sort(key=lambda item: item[:3])
        final = entries[-1][3]
        if final is not None and (final.expires_at is None or at < final.expires_at):
            state.grants[grantee] = final
    return state


# ------------------------------------------------------------------- decisions
def can_read(owner: str, reader: str, *, author: str, recipient: str, part: str,
             thread_opener: str, grants: dict[str, Grant]) -> bool:
    if reader in (owner, author):
        return True
    if reader != recipient:
        return False
    grant = grants.get(reader)
    if grant is None or not grant.allows_part(part):
        return False
    if grant.scope == "send_only":
        return grant.read_replies and thread_opener == reader
    return True


def write_denial(owner: str, author: str, *, recipient: str, part: str, thread_opener: str,
                 grants: dict[str, Grant]) -> str | None:
    """None if `author` may write this envelope into `owner`'s mailbox, else why not.
    The thread opener comes from the thread's own commitment (`pairwise.thread_id`), so
    a thread cannot change part or opener whatever order a relay delivers it in."""
    if author != owner:
        grant = grants.get(author)
        if grant is None:
            return ("restricted: the sender holds no owner-signed grant on this mailbox "
                    "(default-deny)")
        if not grant.allows_part(part):
            return f"restricted: the sender's {grant.scope} grant does not cover {part!r}"
        if grant.scope == "send_only":
            if recipient != owner:
                return "restricted: a send_only peer addresses only the mailbox owner"
            if thread_opener != author:
                return "restricted: a send_only peer writes only in threads it opened"
    if recipient == owner:
        return None
    if not can_read(owner, recipient, author=author, recipient=recipient, part=part,
                    thread_opener=thread_opener, grants=grants):
        return "restricted: the reader has no access to this part or thread"
    return None


# ------------------------------------------------------------------ invite tokens
def encode_invite_token(invite: Event, secret: bytes) -> str:
    """`inv_` + base64url(0x02 ‖ invite secret ‖ the owner-signed invite as JSON)."""
    raw = bytes([INVITE_VERSION]) + secret + json.dumps(
        invite.to_dict(), separators=(",", ":")).encode()
    return INVITE_PREFIX + base64.urlsafe_b64encode(raw).decode().rstrip("=")


def decode_invite_token(token: str) -> tuple[bytes, Event]:
    token = token.strip()
    if not token.startswith(INVITE_PREFIX):
        raise AclError(f"a mailbox invite token starts with {INVITE_PREFIX!r}")
    body = token[len(INVITE_PREFIX):]
    try:
        raw = base64.urlsafe_b64decode(body + "=" * (-len(body) % 4))
    except (binascii.Error, ValueError) as exc:
        raise AclError(f"the invite token is not base64url: {exc}") from exc
    if len(raw) < 34 or raw[0] != INVITE_VERSION:
        raise AclError("the invite token is truncated or of an unsupported version")
    secret = raw[1:33]
    try:
        invite = verify_event(json.loads(raw[33:]))
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError, InvalidEvent) as exc:
        raise AclError("the invite inside the token does not verify") from exc
    if invite.kind != INVITE or invite.values("mbx") != [invite.pubkey]:
        raise AclError("the token does not carry an owner-signed mailbox invite")
    try:
        holds = secp256k1.pubkey_gen(secret).hex()
    except secp256k1.Secp256k1Error as exc:
        raise AclError(f"the invite secret is unusable: {exc}") from exc
    if invite.values("invite_key") != [holds]:
        raise AclError("the token's secret is not the invite's key")
    return secret, invite
