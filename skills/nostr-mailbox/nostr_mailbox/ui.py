"""`nostr-mailbox ui`: the Visual Web Console, served from this workstation.

A standard-library HTTP server on loopback serves `web/index.html` at `/` and a small
JSON API backed by this machine's own files: the campaign's `nostr.toml`, `admin.json`
and the 0600 identity key. The page talks to the relay itself (a browser WebSocket,
NIP-42) and asks this server to sign, so the key never enters the browser. The same
`index.html` also runs on its own, served from the relay's origin, with a key held in
the tab or in a NIP-07 extension.

Who may call it. The server binds loopback only and refuses any other address: whoever
can load the page can sign as this key. Every `/api/` request must carry the per-run
token written into the page it served (`X-NM-Token`) and name this server in its `Host`
header, which a DNS-rebinding page cannot (it names its own). A write must also send
JSON, and when it carries an `Origin`, that origin must be this one. A page on another
site cannot read the token: nothing here answers CORS.

What it signs. `/api/sign` applies `identity.SignerServer`'s own policy: the kinds the
console uses plus those of the role this key holds in the campaign (`cli.ROLE_KINDS`), a
NIP-42 proof for the pinned relay only, and a blob authorization for the campaign's blob
server only. `/api/nip44` is the NIP-07 `nip44.encrypt/decrypt` pair, for key rings
and mailbox envelopes; it needs a key held in the identity file (`local` signer).

Personas. Every identity file under `<home>/identities/` is a persona; `/api/state`
lists them and `/api/persona` switches the one this console signs as (or creates one,
0600). Each request runs as the persona active when it arrived, start to finish.

Invite links. The page is also served at `/join` and `/join/`, so a link such as
`http://127.0.0.1:7890/join/#nm1_…&topic=retry&role=read-only&ticket=…` opens the
console with the invite filled in. The token stays in the fragment, which a browser
never sends to a server; redeeming it takes one click on the page.

Topics. A shared topic is a NIP-29 group whose records are ordinary campaign records
tagged `["epoch", n]` and encrypted under `nip44.campaign_conversation_key(K_n,
campaign)`, so `Trust(group=topic, campaign_key=K_n)` reads epoch n with the unchanged
CLI. The keys travel as NIP-59 key rings (rumor 8892 → seal 13 → gift wrap 1059) signed
by the granter's member key: a private relay refuses events whose author is not the key
that authenticated, so there is no ephemeral wrapper key. `TopicDesk` below is the
Python half of that protocol; the page carries the other half, and the witnesses in
tests/test_web_ui.py hold the two to the same wire.

Roles. The admin's 9000 names each member's role in its NIP-29 role slot:
`read-write` (written `member`, as every 9000 before roles was), `read-only` or
`write-only`. A read-only member is given the key ring, and every console reader holds
the messages it writes at the human gate, as it holds a revoked key's late writes. A
write-only member is never given a key ring: it writes sealed mail (kind 4410) into the
admin's `topic:<topic>` dropbox part, under a `topic_scoped`, `human_gated` grant. The relay
does not enforce roles, and neither does the CLI's reader; the console's readers do.

Invite tickets. `/api/topics/<group>/invite` mints a relay invite and a ticket, and
records only the ticket's sha256 with the role and history it was minted for, in
`<home>/invites/<group>.json` (0600). The newcomer's join request (9021) presents the
ticket, and the admin's `/api/topic/grant` with that ticket applies those recorded terms
to that one key, once."""
from __future__ import annotations

import argparse
import base64
import contextlib
import copy
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import socket
import stat
import sys
import tempfile
import threading
import traceback
import webbrowser
from dataclasses import dataclass, replace
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from . import __version__, bech32, nip44
from .backend import (
    DISPOSITIONS,
    INBOX,
    CampaignSession,
    Message,
    NostrRelayChannelBackend,
    NotAuthorized,
)
from .blossom import BlossomError
from .event import DEFAULT_WAIT_S, Event, InvalidEvent, NostrError, dumps, event_id, now, order
from .event import verify_event as _verify_event
from .identity import (
    AUTH_KIND,
    BLOSSOM_AUTH_KIND,
    DEFAULT_NAME,
    MAX_REQUEST_BYTES,
    Identity,
    IdentityError,
    SignerServer,
    create_identity,
    home,
    load_identity,
)
from .mailbox import Dropbox
from .profile import EpochKeys, ProfileError, Trust
from .relay import INVITE_CLAIM_KIND, INVITE_TTL, NCLI_CONFIG, RelayAdmin, RelayError

DEFAULT_PORT = 7890
DEFAULT_HOST = "127.0.0.1"
PAGE = Path(__file__).with_name("web") / "index.html"
TOKEN_SLOT = '<meta name="nm-bridge" content="">'
TOKEN_HEADER = "X-NM-Token"

# The wire of shared topics and mailboxes, beside the campaign kinds of profile.Kind.
NIP59_SEAL, GIFT_WRAP = 13, 1059
KEYRING_KIND = 8892
PUT_USER, REMOVE_USER, DELETE_EVENT, CREATE_GROUP, JOIN_REQUEST = 9000, 9001, 9005, 9007, 9021
MAIL_KINDS = frozenset({4410, 4411, 4412, 4420, 4421})
KEYRING_SCHEMA = "cf.keyring/1"
GRANT_MODES = ("full_history", "forward_only")
TOPIC_ID = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")   # a NIP-29 id that is also a slug
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
# What the console signs whatever role the key holds: its profile, the NIP-59 seal and
# wrap of a key ring, the agent-mailbox envelope, and the NIP-29 topic moderation that
# the relay and every reader check against the topic's admins anyway.
CONSOLE_KINDS = frozenset({0, NIP59_SEAL, GIFT_WRAP, PUT_USER, REMOVE_USER, DELETE_EVENT,
                           CREATE_GROUP, JOIN_REQUEST, *MAIL_KINDS})
# A member's role in a topic, and what the admin's 9000 writes in its NIP-29 role slot.
ROLES = ("read-write", "read-only", "write-only")
ROLE_TAG = {"read-write": "member", "read-only": "read-only", "write-only": "write-only"}
JOIN_PATHS = ("/join", "/join/")
INVITES = "invites"
INVITE_BOOK_SCHEMA = "cf.topic-invites/1"
_TOPIC_INVITE = re.compile(r"^/api/topics/([a-z0-9][a-z0-9_-]{0,63})/invite$")
_EXPORT = re.compile(r"^([a-z0-9][a-z0-9_-]{0,63})-epoch-([1-9][0-9]*)\.toml$")


def role_of(tag: list) -> str:
    """The role a 9000's `p` tag gives: its third element when that names read-only or
    write-only, read-write otherwise (NIP-29's `member`, or no role at all)."""
    named = tag[2] if len(tag) > 2 else ""
    return named if named in ("read-only", "write-only") else "read-write"


def ticket_digest(ticket: str) -> str:
    return hashlib.sha256(ticket.encode("utf-8")).hexdigest()


class ConsoleError(NostrError):
    """A request this console will not carry out as asked."""

    status = HTTPStatus.BAD_REQUEST


class NotSetUp(ConsoleError):
    """The workstation has no identity or no campaign yet."""

    status = HTTPStatus.CONFLICT


class Refused(ConsoleError):
    """A request outside what this console lets a page do."""

    status = HTTPStatus.FORBIDDEN


class TopicError(ProfileError):
    """A topic, key ring or gift wrap that is not well formed, or an action on a topic
    this key may not take."""


# =========================================================== NIP-59 key rings
def gift_wrap(session: CampaignSession, secret: bytes, recipient: str, kind: int,
              tags: list, content: str) -> Event:
    """rumor → seal (13) → wrap (1059), both signed by this session's member key."""
    stamp = now(session.clock)
    me = session.pubkey
    rumor = {"id": event_id(me, stamp, kind, tags, content), "pubkey": me,
             "created_at": stamp, "kind": kind, "tags": tags, "content": content}
    conv = nip44.conversation_key(secret, bytes.fromhex(recipient))
    seal = session.relay.sign(NIP59_SEAL, [], nip44.encrypt(dumps(rumor), conv))
    return session.relay.sign(GIFT_WRAP, [["p", recipient]],
                              nip44.encrypt(dumps(seal.to_dict()), conv))


def unwrap(wrap: Event, secret: bytes) -> dict:
    """The rumor inside a gift wrap addressed to `secret`'s key, or `TopicError`."""
    if wrap.kind != GIFT_WRAP:
        raise TopicError(f"kind {wrap.kind} is not a gift wrap")
    try:
        seal = _verify_event(json.loads(nip44.decrypt(
            wrap.content, nip44.conversation_key(secret, bytes.fromhex(wrap.pubkey)))))
        if seal.kind != NIP59_SEAL:
            raise TopicError(f"the wrap holds kind {seal.kind}, not a seal (13)")
        rumor = json.loads(nip44.decrypt(
            seal.content, nip44.conversation_key(secret, bytes.fromhex(seal.pubkey))))
    except (nip44.Nip44Error, InvalidEvent, json.JSONDecodeError) as exc:
        raise TopicError(f"the gift wrap does not open: {exc}") from exc
    if not isinstance(rumor, dict) or set(rumor) != {"id", "pubkey", "created_at", "kind",
                                                     "tags", "content"}:
        raise TopicError("the rumor is not an unsigned event")
    if rumor["pubkey"] != seal.pubkey:
        raise TopicError("the rumor names another author than the key that sealed it")
    try:
        ident = event_id(rumor["pubkey"], rumor["created_at"], rumor["kind"], rumor["tags"],
                         rumor["content"])
    except (InvalidEvent, TypeError) as exc:
        raise TopicError(f"the rumor cannot be hashed: {exc}") from exc
    if ident != rumor["id"]:
        raise TopicError("the rumor id is not the hash of the rumor")
    return rumor


def keyring_content(campaign: str, topic: str, name: str, epochs: dict[int, str],
                    current: int, mode: str) -> str:
    return json.dumps({"schema": KEYRING_SCHEMA, "campaign": campaign, "topic": topic,
                       "name": name, "epochs": {str(n): epochs[n] for n in sorted(epochs)},
                       "current": current, "mode": mode}, separators=(",", ":"))


def parse_keyring(rumor: dict, campaign: str) -> dict:
    if rumor["kind"] != KEYRING_KIND:
        raise TopicError(f"kind {rumor['kind']} is not a key ring ({KEYRING_KIND})")
    try:
        body = json.loads(rumor["content"])
    except json.JSONDecodeError as exc:
        raise TopicError(f"key ring content is not JSON: {exc}") from exc
    if not isinstance(body, dict) or body.get("schema") != KEYRING_SCHEMA:
        raise TopicError(f"a key ring carries schema {KEYRING_SCHEMA}")
    if body.get("campaign") != campaign:
        raise TopicError(f"key ring of campaign {body.get('campaign')!r}, not {campaign!r}")
    topic = body.get("topic")
    if not isinstance(topic, str) or not TOPIC_ID.match(topic):
        raise TopicError(f"key ring topic {topic!r} is not a topic id")
    if [t[1] for t in rumor["tags"] if t[0] == "h" and len(t) > 1] != [topic]:
        raise TopicError("key ring h tag does not name its topic")
    raw = body.get("epochs")
    epochs: dict[int, str] = {}
    for n, key in (raw.items() if isinstance(raw, dict) else ()):
        if not re.fullmatch(r"[1-9][0-9]*", n) or not isinstance(key, str) \
                or not _SHA256.match(key):
            raise TopicError(f"key ring epoch {n!r} is malformed")
        epochs[int(n)] = key
    if not epochs:
        raise TopicError("key ring holds no epoch")
    name = body.get("name") if isinstance(body.get("name"), str) else topic
    return {"topic": topic, "name": name, "epochs": epochs, "granter": rumor["pubkey"],
            "created_at": rumor["created_at"], "mode": str(body.get("mode", ""))}


@dataclass(frozen=True)
class TopicState:
    """One topic as this key sees it: its roster from admin-signed NIP-29 events, and
    the epoch keys from the key rings its admins (or this key) sent. `epochs` maps each
    epoch to the first key delivered for it; a second, different key for the same epoch
    is a rotation race and is named in `conflicts`."""
    topic: str
    name: str
    creator: str | None
    admins: frozenset[str]
    members: tuple[str, ...]
    roles: dict[str, str]
    epochs: dict[int, str]
    conflicts: tuple[int, ...]
    requests: tuple[dict, ...]

    @property
    def current(self) -> int | None:
        return max(self.epochs) if self.epochs else None

    def to_dict(self) -> dict:
        """What the page may see. Never a key."""
        npub = _npub
        return {"topic": self.topic, "name": self.name,
                "creator": npub(self.creator) if self.creator else None,
                "admins": sorted(npub(k) for k in self.admins),
                "members": [npub(k) for k in self.members],
                "roles": {npub(k): self.roles[k] for k in self.members},
                "epochs": sorted(self.epochs), "current": self.current,
                "conflicts": list(self.conflicts),
                "requests": [{**r, "npub": npub(r["pubkey"])} for r in self.requests]}


def topic_state(trust: Trust, topic: str, group_events: list[Event], rings: list[dict],
                me: str) -> TopicState:
    """The rules of web/index.html's `topicScope`, in Python."""
    created = order(e for e in group_events
                    if e.kind == CREATE_GROUP and e.values("h")[:1] == [topic])
    creator = created[0].pubkey if created else None
    admins = frozenset(trust.operator_pubkeys | ({creator} if creator else set()))
    member: dict[str, bool] = {creator: True} if creator else {}
    role: dict[str, str] = {creator: "read-write"} if creator else {}
    touched: dict[str, int] = {creator: created[0].created_at} if creator else {}
    for e in order(group_events):
        if (e.kind not in (PUT_USER, REMOVE_USER) or e.values("h")[:1] != [topic]
                or e.pubkey not in admins):
            continue
        for tag in e.tags:
            if len(tag) > 1 and tag[0] == "p" and _SHA256.match(tag[1]):
                member[tag[1]] = e.kind == PUT_USER
                role[tag[1]] = role_of(tag) if e.kind == PUT_USER else role.get(tag[1],
                                                                                 "read-write")
                touched[tag[1]] = e.created_at
    declined = {ident for e in group_events
                if e.kind == DELETE_EVENT and e.pubkey in admins and e.values("h")[:1] == [topic]
                for ident in e.values("e")}
    requests = tuple(
        {"id": e.id, "pubkey": e.pubkey, "created_at": e.created_at, "reason": e.content,
         "ticket": (e.values("ticket") or [None])[0]}
        for e in order(group_events)
        if e.kind == JOIN_REQUEST and e.values("h")[:1] == [topic] and e.id not in declined
        and not member.get(e.pubkey) and touched.get(e.pubkey, -1) < e.created_at)
    epochs: dict[int, str] = {}
    conflicts: set[int] = set()
    standing = sorted((r for r in rings if r["topic"] == topic
                       and (r["granter"] in admins or r["granter"] == me)),
                      key=lambda r: r["created_at"])
    for ring in standing:
        for n, key in ring["epochs"].items():
            if n in epochs and epochs[n] != key:
                conflicts.add(n)
            epochs.setdefault(n, key)
    members = tuple(pk for pk, yes in member.items() if yes)
    return TopicState(topic=topic, name=standing[-1]["name"] if standing else topic,
                      creator=creator, admins=admins, members=members,
                      roles={pk: role[pk] for pk in members}, epochs=epochs,
                      conflicts=tuple(sorted(conflicts)), requests=requests)


class TopicSession(CampaignSession):
    """A `CampaignSession` whose records go to one epoch of one scope: `enter` swaps in
    the scope's trust (its group and that epoch's key) and every record it signs carries
    `["epoch", n]`. The relay connection is the same one throughout."""

    epoch: int | None = None

    def enter(self, trust: Trust, epoch: int | None) -> TopicSession:
        if epoch is not None and trust.campaign_key:
            trust = replace(trust, epoch_keys=EpochKeys(
                trust.campaign, {epoch: trust.campaign_key}, epoch))
        self.trust, self.epoch = trust, epoch
        return self

    def sign_record(self, kind, record_type, payload, *, topic=None, tags=(), created_at=None):
        extra = ([["epoch", str(self.epoch)]]
                 if self.epoch is not None and self.trust.ring is None else [])
        return super().sign_record(kind, record_type, payload, topic=topic,
                                   tags=[*tags, *extra], created_at=created_at)


class TopicDesk:
    """Create, grant and revoke shared topics, and resolve their key rings, for the key
    of one session. `secret` is that key: a key ring is pairwise NIP-44. `dropbox` is
    this key's mailbox, which a write-only grant opens a part of."""

    def __init__(self, session: TopicSession, secret: bytes, dropbox: Dropbox | None = None):
        self.session, self.secret, self.dropbox = session, secret, dropbox
        self._rings: list[dict] | None = None

    @property
    def trust(self) -> Trust:
        return self.session.trust

    @property
    def me(self) -> str:
        return self.session.pubkey

    def rings(self) -> list[dict]:
        """Every key ring addressed to this key, opened. A wrap that does not open is
        recorded in the session's `rejected` with the reason."""
        if self._rings is None:
            out = []
            for wrap in self.session.relay.query_all({"kinds": [GIFT_WRAP], "#p": [self.me]}):
                try:
                    rumor = unwrap(wrap, self.secret)
                    if rumor["kind"] == KEYRING_KIND:
                        out.append(parse_keyring(rumor, self.trust.campaign))
                except TopicError as exc:
                    self.session.rejected.append((wrap.id, f"gift wrap: {exc}"))
            self._rings = out
        return self._rings

    def state(self, topic: str) -> TopicState:
        if not TOPIC_ID.match(topic):
            raise TopicError(f"topic id {topic!r} must match {TOPIC_ID.pattern}")
        events = self.session.relay.query_all({
            "kinds": [CREATE_GROUP, PUT_USER, REMOVE_USER, DELETE_EVENT, JOIN_REQUEST],
            "#h": [topic]})
        return topic_state(self.trust, topic, events, self.rings(), self.me)

    def topics(self) -> list[TopicState]:
        created = self.session.relay.query_all({"kinds": [CREATE_GROUP],
                                                "authors": [self.me]})
        names = {r["topic"] for r in self.rings()} | {
            t for e in created for t in e.values("h")[:1] if TOPIC_ID.match(t)}
        return [self.state(name) for name in sorted(names)]

    def scope_trust(self, state: TopicState, epoch: int | None = None) -> tuple[Trust, int]:
        """The trust that reads and writes one epoch of `state` (the current one unless
        named): the campaign's, with the topic as its group and that epoch's key."""
        n = state.current if epoch is None else epoch
        if n is None or n not in state.epochs:
            held = sorted(state.epochs) or "none"
            raise TopicError(f"this key holds no key for epoch {n} of topic {state.topic!r} "
                             f"(held: {held})")
        return replace(self.trust, group=state.topic, campaign_key=state.epochs[n]), n

    def _ring(self, recipient: str, state_topic: str, name: str, epochs: dict[int, str],
              current: int, mode: str) -> str:
        wrap = gift_wrap(self.session, self.secret, recipient, KEYRING_KIND,
                         [["h", state_topic], ["t", self.trust.campaign]],
                         keyring_content(self.trust.campaign, state_topic, name, epochs,
                                         current, mode))
        self.session.relay.publish(wrap)
        self._rings = None
        return wrap.id

    def _publish(self, kind: int, tags: list) -> Event:
        event = self.session.relay.sign(kind, tags, "")
        self.session.relay.publish(event)
        return event

    def create(self, topic: str, name: str | None = None) -> dict:
        if not TOPIC_ID.match(topic):
            raise TopicError(f"topic id {topic!r} must match {TOPIC_ID.pattern}")
        taken = self.session.relay.query_all({"kinds": [CREATE_GROUP], "#h": [topic]})
        if taken:
            raise TopicError(f"topic {topic!r} already exists (created by "
                             f"{_npub(order(taken)[0].pubkey)})")
        created = self._publish(CREATE_GROUP, [["h", topic], ["private"], ["restricted"],
                                               ["closed"]])
        wrap = self._ring(self.me, topic, name or topic, {1: os.urandom(32).hex()}, 1,
                          "create")
        return {"topic": topic, "created": created.id, "epoch": 1, "keyring": wrap}

    def _admin(self, state: TopicState) -> None:
        if self.me not in state.admins:
            raise NotAuthorized(f"only an admin of topic {state.topic!r} grants or revokes; "
                                "nothing was sent")

    def grant(self, topic: str, member: str, mode: str, role: str = "read-write") -> dict:
        """full_history: every epoch held goes to the newcomer. forward_only: the topic
        rotates to epoch k+1 for every member, and the newcomer gets that epoch alone.
        A read-only member gets the same key ring; a write-only one gets none, and a
        grant into this key's `topic:<topic>` dropbox part instead (`mode` does not
        apply)."""
        if role not in ROLES:
            raise TopicError(f"role {role!r} must be one of {ROLES}")
        if role != "write-only" and mode not in GRANT_MODES:
            raise TopicError(f"grant mode {mode!r} must be one of {GRANT_MODES}")
        if role == "write-only" and self.dropbox is None:
            raise TopicError("a write-only grant opens a part of this key's dropbox, and this "
                             "desk was given none; nothing was sent")
        state = self.state(topic)
        self._admin(state)
        member = bech32.pubkey_hex(member)
        put = self._publish(PUT_USER, [["h", topic], ["p", member, ROLE_TAG[role]]])
        out: dict = {"put_user": put.id, "role": role}
        if role == "write-only":
            part = f"topic:{topic}"
            mail = self.dropbox.grant(member, scope="topic_scoped", parts=[part],
                                      trust="human_gated", read_replies=True)
            out.update(mode=None, mailbox={"owner": _npub(self.me), "part": part,
                                           "scope": mail.scope, "trust": mail.trust})
            if member in state.members and state.roles.get(member) != "write-only":
                out.update(self._rotate(state, remove=member))   # it held keys until now
            return out
        if mode == "full_history":
            wrap = self._ring(member, topic, state.name, state.epochs, state.current,
                              "full_history")
            return {**out, "mode": mode, "epochs": sorted(state.epochs), "wraps": [wrap]}
        return {**out, "mode": mode, **self._rotate(state, add=member)}

    def revoke(self, topic: str, member: str) -> dict:
        state = self.state(topic)
        self._admin(state)
        member = bech32.pubkey_hex(member)
        if member == state.creator:
            raise TopicError("the creator of a topic is its admin and is not removed from it")
        removed = self._publish(REMOVE_USER, [["h", topic], ["p", member]])
        return {"remove_user": removed.id, **self._rotate(state, remove=member)}

    def _rotate(self, state: TopicState, *, add: str | None = None,
                remove: str | None = None) -> dict:
        n = (state.current or 0) + 1
        fresh = os.urandom(32).hex()
        readers = {pk for pk in state.members if state.roles.get(pk) != "write-only"}
        members = (readers | {self.me} | ({add} if add else set())) - {remove}
        wraps = []
        for pk in sorted(members):
            ring = {**state.epochs, n: fresh} if pk == self.me else {n: fresh}
            wraps.append(self._ring(pk, state.topic, state.name, ring, n,
                                    "forward_only" if pk == add else "rotate"))
        return {"epoch": n, "recipients": [_npub(pk) for pk in sorted(members)],
                "wraps": wraps}


def _npub(pubkey: str) -> str:
    return bech32.encode(bech32.NPUB, bytes.fromhex(pubkey))


_INVITE_NOTE = ("a bearer invite: whoever holds the token joins once. Both links keep it in "
                "the URL fragment, which a browser never sends to a server. join_url opens "
                "the newcomer's own `nostr-mailbox ui` at its default address; web_link "
                "opens the page only where the relay's origin serves it")


def _join_url(token: str, *, topic: str | None = None, role: str | None = None,
              ticket: str | None = None) -> str:
    """The 1-click link: `nostr-mailbox ui`'s own `/join/` page with the token, and the
    topic, role and ticket beside it, in the fragment."""
    extra = "".join(f"&{name}={value}" for name, value in
                    (("topic", topic), ("role", role), ("ticket", ticket)) if value)
    return f"http://{DEFAULT_HOST}:{DEFAULT_PORT}/join/#{token}{extra}"


def _one_liner(token: str) -> str:
    return f"uvx --from git+https://github.com/awowIO/nostr-mailbox nostr-mailbox join {token}"


# ================================================================ the console
def _page_csp(page: str) -> str:
    """The page's Content-Security-Policy: its own inline scripts by hash and nothing
    else, so markup that ever slipped into the DOM could not run."""
    hashes = [base64.b64encode(hashlib.sha256(body.encode()).digest()).decode()
              for body in re.findall(r"<script(?:\s[^>]*)?>(.*?)</script>", page, re.S)]
    if not hashes:
        raise ConsoleError(f"{PAGE} holds no script; the console page is incomplete")
    scripts = " ".join(f"'sha256-{h}'" for h in hashes)
    return ("default-src 'none'; " f"script-src {scripts}; style-src 'unsafe-inline'; "
            "img-src 'self' data: blob:; connect-src 'self' ws: wss: https:; "
            "base-uri 'none'; form-action 'none'; frame-ancestors 'none'")


class Console:
    """What every request needs: where this workstation keeps its files, which persona
    it signs as, and how long to wait for a relay. Files are read per request, so
    `setup` or `join` run elsewhere is picked up without a restart. A request works on
    `pinned()`, a copy that keeps the persona it started with."""

    def __init__(self, *, base: str | Path | None = None, identity: str = DEFAULT_NAME,
                 trust_path: str | Path | None = None, timeout_s: float = DEFAULT_WAIT_S,
                 quiet: bool = False):
        self.home = home(base)
        self.identity_name, self.timeout_s, self.quiet = identity, timeout_s, quiet
        self.trust_path = Path(trust_path) if trust_path else self.home / "nostr.toml"
        self.admin_path = self.home / "admin.json"
        self.token = secrets.token_urlsafe(32)
        raw = PAGE.read_text(encoding="utf-8")
        if raw.count(TOKEN_SLOT) != 1:
            raise ConsoleError(f"{PAGE} must hold exactly one {TOKEN_SLOT!r}")
        self.page = raw.replace(TOKEN_SLOT, f'<meta name="nm-bridge" content="{self.token}">')
        self.csp = _page_csp(self.page)
        self.root = self                        # the console every pinned copy came from
        self._persona_lock = threading.Lock()
        self._book_lock = threading.Lock()

    def pinned(self) -> Console:
        """This console as one request sees it: the persona active when the request
        arrived, for the whole request, whatever `persona` switches meanwhile."""
        with self.root._persona_lock:
            return copy.copy(self.root)

    # ---- files
    def identity(self) -> Identity | None:
        """The identity, None when it was never created; a file that exists but is
        unusable (wrong mode, malformed) raises."""
        if not (self.home / "identities" / f"{self.identity_name}.json").exists():
            return None
        return load_identity(self.identity_name, base=self.home)

    def need_identity(self) -> Identity:
        ident = self.identity()
        if ident is None:
            raise NotSetUp(f"no identity {self.identity_name!r} under {self.home}: run "
                           "`nostr-mailbox setup` or join with an nm1_ token first")
        return ident

    def trust(self) -> Trust | None:
        return Trust.load(self.trust_path) if self.trust_path.is_file() else None

    def need_trust(self) -> Trust:
        trust = self.trust()
        if trust is None:
            raise NotSetUp(f"no campaign at {self.trust_path}: run `nostr-mailbox setup` "
                           "or join with an nm1_ token first")
        return trust

    def secret(self) -> bytes:
        """The raw key, for NIP-44 pairwise work. Only a `local` identity holds one."""
        ident = self.need_identity()
        if ident.signer_spec["type"] != "local":
            raise Refused(f"identity {ident.name!r} signs out of process "
                          f"({ident.signer_spec['type']}); pairwise NIP-44 needs the key, "
                          "so key rings and mailbox envelopes cannot be opened here")
        secret = bech32.decode(bech32.NSEC, ident.signer_spec["nsec"])
        ident.signer(timeout_s=self.timeout_s)        # proves the secret is this pubkey's
        return secret

    def role(self, trust: Trust, pubkey: str) -> str:
        if pubkey in trust.operator_pubkeys:
            return "operator"
        if pubkey in trust.reviewer_pubkeys:
            return "reviewer"
        if pubkey in trust.lead_pubkeys:
            return "lead"
        return "seat"

    def admin(self) -> RelayAdmin:
        """The relay admin `setup` saved, read loudly: no admin.json means no invites."""
        if not self.admin_path.is_file():
            raise NotSetUp(f"no {self.admin_path}: run `nostr-mailbox setup --kubectl` (or "
                           "--compose / --exec) once so this workstation can mint invites")
        try:
            data = json.loads(self.admin_path.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            raise ConsoleError(f"{self.admin_path} is unreadable: {exc}") from exc
        prefix = data.get("exec_prefix") if isinstance(data, dict) else None
        if not isinstance(prefix, list) or not all(isinstance(x, str) for x in prefix):
            raise ConsoleError(f"{self.admin_path} carries no exec_prefix list")
        return RelayAdmin(prefix, timeout_s=self.timeout_s,
                          config=str(data.get("config") or NCLI_CONFIG))

    def session(self) -> TopicSession:
        trust, ident = self.need_trust(), self.need_identity()
        return TopicSession(trust, ident.signer(timeout_s=self.timeout_s),
                            timeout_s=self.timeout_s)

    def enter_scope(self, session: TopicSession, group: str | None,
                    epoch: int | None = None) -> TopicDesk | None:
        """Point `session` at the root campaign (no group, or the campaign's own) or at
        one epoch of a shared topic, whose key comes from this key's key rings."""
        trust = session.trust
        if group in (None, "", trust.group):
            session.enter(trust, 1 if trust.campaign_key else None)
            return None
        desk = TopicDesk(session, self.secret())
        scoped, n = desk.scope_trust(desk.state(group), epoch)
        session.enter(scoped, n)
        return desk

    # ---- personas
    def personas(self) -> list[dict]:
        """Every identity file under `<home>/identities/`, by name. One that does not load
        is listed with the reason, never left out."""
        folder = self.home / "identities"
        out = []
        for path in sorted(folder.glob("*.json")) if folder.is_dir() else ():
            entry: dict = {"name": path.stem, "active": path.stem == self.identity_name}
            try:
                ident = load_identity(path.stem, base=self.home)
            except IdentityError as exc:
                entry["error"] = str(exc)
            else:
                entry.update(npub=ident.npub, pubkey=ident.pubkey,
                             signer=ident.signer_spec["type"])
            out.append(entry)
        return out

    def persona(self, body: dict) -> dict:
        """Switch the persona this console signs as, for every tab, from the next request
        on. `create: true` makes a fresh 0600 key under that name first, and never
        replaces one that exists."""
        name = body.get("name")
        if not isinstance(name, str) or not name:
            raise ConsoleError("persona needs a name")
        if body.get("create") is True:
            create_identity(name, base=self.home)
        else:
            load_identity(name, base=self.home)       # it exists and it loads, or it says why
        with self.root._persona_lock:
            self.root.identity_name = name
        self.identity_name = name
        return self.state()

    def exports(self) -> dict[str, list[int]]:
        """Which topic epochs `/api/topic/export` has written for a coding agent on this
        workstation: names only, never a key."""
        folder = self.home / "exports"
        held: dict[str, list[int]] = {}
        for path in sorted(folder.glob("*.toml")) if folder.is_dir() else ():
            match = _EXPORT.match(path.name)
            if match:
                held.setdefault(match.group(1), []).append(int(match.group(2)))
        return {topic: sorted(epochs) for topic, epochs in held.items()}

    # ---- invite tickets
    def _book_path(self, topic: str) -> Path:
        return self.home / INVITES / f"{topic}.json"

    def _book(self, topic: str) -> dict:
        """The invites minted for one topic: ticket digest → terms. Refused when anyone
        but this user can read it."""
        path = self._book_path(topic)
        try:
            mode = stat.S_IMODE(path.stat().st_mode)
        except FileNotFoundError:
            return {"schema": INVITE_BOOK_SCHEMA, "topic": topic, "tickets": {}}
        if mode & 0o077:
            raise ConsoleError(f"{path} is mode {mode:04o}; an invite book must be 0600 "
                               f"(chmod 600 {path})")
        try:
            book = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            raise ConsoleError(f"{path} is unreadable: {exc}") from exc
        if (not isinstance(book, dict) or book.get("schema") != INVITE_BOOK_SCHEMA
                or book.get("topic") != topic or not isinstance(book.get("tickets"), dict)):
            raise ConsoleError(f"{path} is not a {INVITE_BOOK_SCHEMA} book for topic {topic!r}")
        return book

    def _book_save(self, topic: str, book: dict) -> None:
        path = self._book_path(topic)
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd, staged = tempfile.mkstemp(dir=path.parent, prefix=f".{topic}.", suffix=".part")
        try:
            with os.fdopen(fd, "w") as fh:
                json.dump(book, fh, indent=1, sort_keys=True)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(staged, path)
        finally:
            with contextlib.suppress(FileNotFoundError):     # replaced: nothing to clean
                os.unlink(staged)

    def invites(self) -> dict:
        """Every topic invite minted here, as the admin's page matches join requests to
        them: the ticket's digest and its terms, never the ticket."""
        folder = self.home / INVITES
        topics = sorted(p.stem for p in folder.glob("*.json")) if folder.is_dir() else []
        return {"topics": {t: [{"ticket_sha256": digest, **terms}
                               for digest, terms in sorted(self._book(t)["tickets"].items())]
                           for t in topics if TOPIC_ID.match(t)}}

    # ---- the API
    def state(self) -> dict:
        ident, trust = self.identity(), self.trust()
        out = {"mode": "bridge", "version": __version__, "home": str(self.home),
               "identity": ident.describe() if ident else None, "seat": self.identity_name,
               "active_persona": self.identity_name, "personas": self.personas(),
               "exports": self.exports(),
               "trust_file": str(self.trust_path), "trust": None, "role": None,
               "admin": {"configured": self.admin_path.is_file(), "path": str(self.admin_path)},
               "capabilities": {"nip44": bool(ident) and ident.signer_spec["type"] == "local",
                                "invite": self.admin_path.is_file(),
                                "join": trust is None}}
        if trust is not None:
            out["trust"] = {
                "schema": "cf.transport/1", "relay": trust.relay, "campaign": trust.campaign,
                "group": trust.group, "blossom": trust.blossom,
                "relay_auth_url": trust.relay_auth_url, "allow_cleartext": trust.allow_cleartext,
                "campaign_key": trust.campaign_key, "keyring": getattr(trust, "keyring", None),
                "operator_pubkeys": sorted(trust.operator_pubkeys),
                "lead_pubkeys": sorted(trust.lead_pubkeys),
                "reviewer_pubkeys": sorted(trust.reviewer_pubkeys)}
            if ident is not None:
                out["role"] = self.role(trust, ident.pubkey)
        return out

    def sign(self, body: dict) -> dict:
        from .cli import ROLE_KINDS, SEAT_BLOB_VERBS
        trust, ident = self.need_trust(), self.need_identity()
        kinds = CONSOLE_KINDS | ROLE_KINDS[self.role(trust, ident.pubkey)]
        policy = SignerServer(self.home / "unused.sock", ident.signer(timeout_s=self.timeout_s),
                              allow_kinds=kinds, relay=trust.relay_auth_url or trust.relay,
                              blossom_server=trust.blossom_server,
                              blossom_verbs=SEAT_BLOB_VERBS)
        # SignerServer's one-request answer, without its socket: the same checks, the
        # same refusals, in the same words.
        answer = policy._answer(dumps({"method": "sign_event", "event": body.get("event")}))
        if "error" in answer:
            raise Refused(answer["error"])
        return answer

    def nip44(self, body: dict) -> dict:
        op, peer = body.get("op"), body.get("peer")
        try:
            peer = bech32.pubkey_hex(str(peer))
        except bech32.Bech32Error as exc:
            raise ConsoleError(f"peer: {exc}") from exc
        conv = nip44.conversation_key(self.secret(), bytes.fromhex(peer))
        if op == "encrypt":
            plain = body.get("plaintext")
            if not isinstance(plain, str) or not plain:
                raise ConsoleError("encrypt needs a non-empty plaintext string")
            return {"result": nip44.encrypt(plain, conv)}
        if op == "decrypt":
            payload = body.get("payload")
            if not isinstance(payload, str):
                raise ConsoleError("decrypt needs a payload string")
            return {"result": nip44.decrypt(payload, conv)}
        raise ConsoleError(f"op {op!r} must be encrypt or decrypt")

    def join(self, body: dict) -> dict:
        """`nostr-mailbox join <token>` as the active persona (its key is made 0600 if it
        has none). On a workstation with no campaign the token's becomes this one's; with
        a campaign, only a token for that same relay and campaign is redeemed, and
        `nostr.toml` is left as it is. It never installs plugins: the home is named
        explicitly, which is the CLI's own switch."""
        from . import cli
        token = body.get("token")
        if not isinstance(token, str) or not token.startswith("nm1_"):
            raise ConsoleError("join needs an nm1_ invite token")
        _, bundle, _, _ = cli._decode_invite_token(token)
        offered = Trust.from_mapping(bundle, source="nm1_ invite token")
        existing = self.trust()
        if existing is not None and (offered.relay, offered.campaign) != (existing.relay,
                                                                          existing.campaign):
            raise Refused(f"this workstation already has campaign {existing.campaign!r} on "
                          f"{existing.relay} at {self.trust_path}; this token is for "
                          f"{offered.campaign!r} on {offered.relay}, and joining it here "
                          "would replace that. Use the CLI with --home")
        member = body.get("member")
        args = argparse.Namespace(token=token, code_file=None, member=member or None,
                                  trust=str(self.trust_path), home=str(self.home),
                                  identity=self.identity_name,
                                  timeout_seconds=self.timeout_s)
        return {**cli.cmd_relay_join(args), "persona": self.identity_name}

    def invite(self, body: dict) -> dict:
        from . import cli
        trust, admin = self.need_trust(), self.admin()
        member, topic = body.get("member") or None, body.get("topic") or None
        if topic is not None and not TOPIC_ID.match(str(topic)):
            raise ConsoleError(f"topic {topic!r} must match {TOPIC_ID.pattern}")
        invite = admin.create_invite(ttl=str(body.get("ttl") or INVITE_TTL))
        token = cli._encode_invite_token(trust, invite["code"], member=member)
        fragment = f"#join={token}" + (f"&topic={topic}" if topic else "")
        return {"token": token, "member": member, "topic": topic,
                "max_uses": invite["max_uses"], "expires_at": invite["expires_at"],
                "web_link": f"{trust.blossom_origin}/{fragment}",
                "join_url": _join_url(token, topic=topic),
                "one_liner": _one_liner(token), "note": _INVITE_NOTE}

    def topic_invite(self, topic: str, body: dict) -> dict:
        """A single-use invite into one topic, for one role: a relay invite (the `nm1_`
        token, which the CLI joins with as well) and a ticket that the newcomer's join
        request presents, so the admin admits them on the terms minted here. Only an
        admin of the topic mints one, and the relay invite is minted before anything is
        recorded."""
        from . import cli
        role = str(body.get("role") or "read-write")
        if role not in ROLES:
            raise ConsoleError(f"role {role!r} must be one of {ROLES}")
        history = None if role == "write-only" else str(body.get("history") or "full_history")
        if history is not None and history not in GRANT_MODES:
            raise ConsoleError(f"history {history!r} must be one of {GRANT_MODES}")
        member = body.get("member") or None
        if member is not None and not isinstance(member, str):
            raise ConsoleError("member is a name")
        trust, admin = self.need_trust(), self.admin()
        with self.session() as session:
            desk = TopicDesk(session, self.secret())
            state = desk.state(topic)
            desk._admin(state)
            if state.creator is None:
                raise TopicError(f"topic {topic!r} has no kind 9007 this key can read on "
                                 f"{trust.relay}: create it first. Nothing was minted")
            me = session.pubkey
        invite = admin.create_invite(ttl=str(body.get("ttl") or INVITE_TTL))
        token = cli._encode_invite_token(trust, invite["code"], member=member)
        ticket = secrets.token_urlsafe(32)          # as strong as the console's own token
        with self.root._book_lock:
            book = self._book(topic)
            book["tickets"][ticket_digest(ticket)] = {
                "role": role, "history": history, "member": member, "minted_by": me,
                "created_at": invite.get("created_at"), "expires_at": invite["expires_at"],
                "admitted": None, "admitted_at": None}
            self._book_save(topic, book)
        return {"token": token, "topic": topic, "role": role, "history": history,
                "member": member, "max_uses": invite["max_uses"],
                "expires_at": invite["expires_at"],
                "join_url": _join_url(token, topic=topic, role=role, ticket=ticket),
                "web_link": f"{trust.blossom_origin}/#join={token}&topic={topic}&role={role}"
                            f"&ticket={ticket}",
                "one_liner": _one_liner(token),
                "note": _INVITE_NOTE + ". The ticket rides in the link only: a newcomer who "
                        "joins with the CLI one-liner asks with `topic request-join`, and "
                        "you choose their role when you approve"}

    def topic_create(self, body: dict) -> dict:
        with self.session() as session:
            return TopicDesk(session, self.secret()).create(str(body.get("topic", "")),
                                                            body.get("name") or None)

    def _desk(self, session: TopicSession) -> TopicDesk:
        ident = self.need_identity()
        dropbox = Dropbox(session, session.signer,
                          state_path=self.home / "mail" / f"{ident.name}.json",
                          user_home=Path.home(), profile_home=self.home)
        return TopicDesk(session, self.secret(), dropbox)

    def topic_grant(self, body: dict) -> dict:
        """Grant one key a role in a topic. With `ticket`, the terms are the ones that
        ticket was minted for, and the key must be the one join request presenting it:
        a ticket two keys present is contested and admits nobody."""
        topic, member = str(body.get("topic", "")), str(body.get("member", ""))
        ticket = body.get("ticket")
        with self.session() as session:
            desk = self._desk(session)
            if ticket is None:
                return desk.grant(topic, member, str(body.get("mode", "")),
                                  str(body.get("role") or "read-write"))
            if not isinstance(ticket, str) or not ticket:
                raise ConsoleError("ticket is the string from the invite link")
            return self._admit(desk, session, topic, bech32.pubkey_hex(member), ticket, body)

    def _admit(self, desk: TopicDesk, session: TopicSession, topic: str, pubkey: str,
               ticket: str, body: dict) -> dict:
        state = desk.state(topic)
        desk._admin(state)
        with self.root._book_lock:
            book = self._book(topic)
            terms = book["tickets"].get(ticket_digest(ticket))
            if terms is None:
                raise Refused(f"this workstation minted no such ticket for topic {topic!r}")
            if terms["admitted"]:
                raise Refused(f"this ticket already admitted {_npub(terms['admitted'])}")
            stamp = now(session.clock)
            if stamp > terms["expires_at"]:
                raise Refused(f"this ticket expired at {terms['expires_at']} (now {stamp})")
            presenters = {r["pubkey"] for r in state.requests if r["ticket"] == ticket}
            if pubkey not in presenters:
                raise Refused(f"no pending join request from {_npub(pubkey)} presents this "
                              "ticket")
            if len(presenters) > 1:
                raise Refused(f"{len(presenters)} keys present this ticket, so it admits none "
                              "of them; approve one by hand with the role you choose")
            for given, minted in (("role", terms["role"]), ("mode", terms["history"])):
                if body.get(given) not in (None, "", minted):
                    raise Refused(f"this ticket was minted for {given} {minted!r}, not "
                                  f"{body.get(given)!r}")
            granted = desk.grant(topic, pubkey, terms["history"] or "", terms["role"])
            terms.update(admitted=pubkey, admitted_at=stamp)
            self._book_save(topic, book)
        return {**granted, "ticket": "admitted", "member": _npub(pubkey)}

    def topic_revoke(self, body: dict) -> dict:
        with self.session() as session:
            return TopicDesk(session, self.secret()).revoke(str(body.get("topic", "")),
                                                            str(body.get("member", "")))

    def topics(self) -> dict:
        with self.session() as session:
            desk = TopicDesk(session, self.secret())
            listed = [state.to_dict() for state in desk.topics()]
            return self._rejected(session, {"topics": listed})

    def topic_export(self, body: dict) -> dict:
        """A nostr.toml for one epoch of a topic, written 0600 under <home>/exports/, so a
        coding agent reads and writes that epoch with the unchanged CLI (`--trust`)."""
        from . import cli
        topic = str(body.get("topic", ""))
        with self.session() as session:
            desk = TopicDesk(session, self.secret())
            scoped, n = desk.scope_trust(desk.state(topic))
        path = self.home / "exports" / f"{topic}-epoch-{n}.toml"
        mapping = {"schema": "cf.transport/1", "relay": scoped.relay,
                   "campaign": scoped.campaign, "group": scoped.group,
                   "operator_pubkeys": [_npub(k) for k in sorted(scoped.operator_pubkeys)],
                   "lead_pubkeys": [_npub(k) for k in sorted(scoped.lead_pubkeys)],
                   "reviewer_pubkeys": [_npub(k) for k in sorted(scoped.reviewer_pubkeys)],
                   "blossom": scoped.blossom, "relay_auth_url": scoped.relay_auth_url,
                   "campaign_key": scoped.campaign_key,
                   "allow_cleartext": scoped.allow_cleartext}
        cli._write_trust_file(path, mapping)
        return {"trust_file": str(path), "topic": topic, "epoch": n, "mode": "0600",
                "note": f"reads and writes epoch {n} only; a rotation needs a fresh export"}

    def post(self, body: dict) -> dict:
        from . import cli
        topic = str(body.get("topic") or "bus")
        text = body.get("body")
        if not isinstance(text, str):
            raise ConsoleError("post needs a body string")
        refs = [str(r) for r in body.get("refs") or []]
        subject, kind = str(body.get("subject") or ""), str(body.get("kind") or "message")
        with self.session() as session:
            self.enter_scope(session, body.get("group"))
            channel = NostrRelayChannelBackend(session)
            if topic == INBOX and body.get("target"):
                key = body.get("idempotency_key") or cli._content_key(
                    INBOX, text, subject, body["target"], body.get("surface"), body.get("doc"),
                    body.get("page"), refs)
                receipt = channel.todo(text, target=str(body["target"]), key=key,
                                       surface=body.get("surface"), doc=body.get("doc"),
                                       page=body.get("page"), refs=tuple(refs), subject=subject)
            else:
                reply_to = body.get("reply_to") or None
                key = body.get("idempotency_key") or cli._content_key(
                    topic, text, kind, subject, refs, reply_to)
                receipt = channel.post(topic, Message(body=text, kind=kind, subject=subject,
                                                      refs=tuple(refs), reply_to=reply_to),
                                       key=key)
            return self._rejected(session, {**receipt.to_dict(), "epoch": session.epoch,
                                            "group": session.trust.group})

    def ack(self, body: dict) -> dict:
        topic = str(body.get("topic") or "bus")
        ids = body.get("msg_ids") or ([body["msg_id"]] if body.get("msg_id") else [])
        if not ids or not all(isinstance(i, str) for i in ids):
            raise ConsoleError("ack needs msg_ids (or msg_id)")
        disposition = str(body.get("disposition") or "handled")
        if disposition not in DISPOSITIONS:
            raise ConsoleError(f"disposition {disposition!r} must be one of {DISPOSITIONS}")
        epoch = body.get("epoch")
        if epoch is not None and type(epoch) is not int:
            raise ConsoleError("epoch is an integer")
        with self.session() as session:
            self.enter_scope(session, body.get("group"), epoch)
            receipts = NostrRelayChannelBackend(session).ack_many(
                topic, str(body.get("seat") or self.identity_name), ids,
                disposition=disposition, result_ref=body.get("result_ref") or None,
                note=body.get("note") or None)
            return self._rejected(session, {"acked": [r.to_dict() for r in receipts],
                                            "epoch": session.epoch})

    def blob_get(self, sha256: str) -> tuple[bytes, str]:
        with self.session() as session:
            return session.blobs().download(sha256), "application/octet-stream"

    def blob_put(self, data: bytes, content_type: str) -> dict:
        with self.session() as session:
            return session.blobs().upload(data, content_type=content_type).to_dict()

    @staticmethod
    def _rejected(session: CampaignSession, result: dict) -> dict:
        if session.rejected:
            result["rejected"] = [{"id": i, "reason": why} for i, why in session.rejected]
        if session.relay.notices:
            result["relay_notices"] = session.relay.notices
        return result


# ================================================================== HTTP
class _Server(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, console: Console):
        self.console = console
        if ":" in address[0]:                   # ::1 needs an IPv6 socket
            self.address_family = socket.AF_INET6
        super().__init__(address, _Handler)
        host, port = self.server_address[:2]
        names = {str(host), "localhost"}
        self.allowed_hosts = {f"[{h}]:{port}" if ":" in h else f"{h}:{port}" for h in names}
        self.origins = {f"http://{h}" for h in self.allowed_hosts}


class _Handler(BaseHTTPRequestHandler):
    server: _Server
    protocol_version = "HTTP/1.1"
    server_version = f"nostr-mailbox-ui/{__version__}"

    def log_message(self, format: str, *args) -> None:       # noqa: A002 (stdlib name)
        if not self.server.console.quiet:
            sys.stderr.write(f"ui: {self.address_string()} {format % args}\n")

    # ---- plumbing
    def _send(self, status: int, body: bytes, content_type: str, extra: dict | None = None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        for name, value in (extra or {}).items():
            self.send_header(name, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, status: int, value) -> None:
        self._send(status, json.dumps(value, ensure_ascii=False).encode(),
                   "application/json; charset=utf-8")

    def _error(self, status: int, exc: BaseException) -> None:
        self._json(status, {"error": str(exc), "type": type(exc).__name__})

    def _gate(self, *, write: bool) -> None:
        """The three checks every API call passes before anything is read or signed."""
        if self.headers.get("Host") not in self.server.allowed_hosts:
            raise Refused(f"Host {self.headers.get('Host')!r} is not this console; a page "
                          "that reaches loopback under another name is turned away")
        given = self.headers.get(TOKEN_HEADER, "")
        if not hmac.compare_digest(given.encode(), self.server.console.token.encode()):
            raise Refused(f"missing or wrong {TOKEN_HEADER}: the token is in the page this "
                          "console serves at /")
        if write:
            origin = self.headers.get("Origin")
            if origin is not None and origin not in self.server.origins:
                raise Refused(f"Origin {origin!r} is not this console")
            if self.headers.get("Sec-Fetch-Site") not in (None, "same-origin", "none"):
                raise Refused("a cross-site request is not served")

    def _body(self, *, json_body: bool = True):
        length = self.headers.get("Content-Length")
        if length is None or not length.isdigit():
            raise ConsoleError("a request body needs a Content-Length")
        size = int(length)
        if json_body:
            if not (self.headers.get("Content-Type") or "").startswith("application/json"):
                raise ConsoleError("send JSON (Content-Type: application/json)")
            if size > MAX_REQUEST_BYTES:
                raise ConsoleError(f"a request is at most {MAX_REQUEST_BYTES:,} bytes (twice the "
                                   f"campaign event cap); this one is {size:,}")
        raw = self.rfile.read(size)
        if not json_body:
            return raw
        try:
            value = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ConsoleError(f"the body is not JSON: {exc}") from exc
        if not isinstance(value, dict):
            raise ConsoleError("the body is a JSON object")
        return value

    def _serve(self, route) -> None:
        console = self.server.console.pinned()
        try:
            route(console)
        except NotAuthorized as exc:
            self._error(HTTPStatus.FORBIDDEN, exc)
        except ConsoleError as exc:
            self._error(exc.status, exc)
        except (IdentityError, ProfileError) as exc:
            self._error(HTTPStatus.BAD_REQUEST, exc)
        except (RelayError, BlossomError) as exc:
            self._error(HTTPStatus.BAD_GATEWAY, exc)
        except NostrError as exc:
            self._error(HTTPStatus.BAD_REQUEST, exc)
        except Exception as exc:                # a bug: logged whole, and the page told
            traceback.print_exc(file=sys.stderr)
            self._error(HTTPStatus.INTERNAL_SERVER_ERROR, exc)

    # ---- routes
    def do_GET(self) -> None:                   # noqa: N802 (stdlib name)
        path = urlsplit(self.path).path
        if path in ("/", "/index.html", *JOIN_PATHS):
            if self.headers.get("Host") not in self.server.allowed_hosts:
                self._error(HTTPStatus.FORBIDDEN, Refused("not this console's Host"))
                return
            console = self.server.console
            self._send(HTTPStatus.OK, console.page.encode(), "text/html; charset=utf-8",
                       {"Content-Security-Policy": console.csp})
            return
        if path == "/api/state":
            self._serve(lambda c: (self._gate(write=False), self._json(200, c.state())))
        elif path == "/api/topics":
            self._serve(lambda c: (self._gate(write=False), self._json(200, c.topics())))
        elif path == "/api/invites":
            self._serve(lambda c: (self._gate(write=False), self._json(200, c.invites())))
        elif path.startswith("/api/blob/"):
            sha256 = path.rsplit("/", 1)[1]

            def blob(c: Console) -> None:
                self._gate(write=False)
                if not _SHA256.match(sha256):
                    raise ConsoleError(f"{sha256!r} is not a sha256 in lowercase hex")
                data, kind = c.blob_get(sha256)
                self._send(HTTPStatus.OK, data, kind, {"X-Digest-Verified": "sha256"})
            self._serve(blob)
        else:
            self._error(HTTPStatus.NOT_FOUND, ConsoleError(f"nothing at {path}"))

    do_HEAD = do_GET

    _POSTS = {"/api/sign": Console.sign, "/api/nip44": Console.nip44,
              "/api/join": Console.join, "/api/invite": Console.invite,
              "/api/topic/create": Console.topic_create, "/api/topic/grant": Console.topic_grant,
              "/api/topic/revoke": Console.topic_revoke,
              "/api/topic/export": Console.topic_export,
              "/api/persona": Console.persona,
              "/api/post": Console.post, "/api/ack": Console.ack}

    def do_POST(self) -> None:                  # noqa: N802 (stdlib name)
        path = urlsplit(self.path).path
        if path == "/api/blob":
            def put(c: Console) -> None:
                self._gate(write=True)
                kind = self.headers.get("Content-Type") or "application/octet-stream"
                self._json(200, c.blob_put(self._body(json_body=False), kind))
            self._serve(put)
            return
        method = self._POSTS.get(path)
        invited = _TOPIC_INVITE.match(path)
        if invited:
            def method(c: Console, body: dict) -> dict:
                return c.topic_invite(invited.group(1), body)
        if method is None:
            self._error(HTTPStatus.NOT_FOUND, ConsoleError(f"nothing at {path}"))
            return

        def call(c: Console) -> None:
            self._gate(write=True)
            self._json(200, method(c, self._body()))
        self._serve(call)


def _loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class ConsoleServer:
    """The console on a background thread: `start()`, `url`, `stop()`. Port 0 picks a
    free port, which is how the witnesses run it."""

    def __init__(self, console: Console, *, host: str = DEFAULT_HOST, port: int = DEFAULT_PORT):
        if not _loopback(host):
            raise Refused(f"{host!r} is not a loopback address. This console signs as "
                          "your key for whoever loads its page, so it listens on "
                          "127.0.0.1, ::1 or localhost only")
        self.console = console
        self._server = _Server((host, port), console)
        self._thread = threading.Thread(target=self._server.serve_forever,
                                        name="nostr-mailbox-ui", daemon=True)

    @property
    def url(self) -> str:
        host, port = self._server.server_address[:2]
        return f"http://{'[' + host + ']' if ':' in str(host) else host}:{port}"

    def start(self) -> ConsoleServer:
        self._thread.start()
        return self

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join()

    def __enter__(self) -> ConsoleServer:
        return self.start()

    def __exit__(self, *exc_info) -> None:
        self.stop()


def serve(args) -> dict:
    """`nostr-mailbox ui`: serve until Ctrl-C. Prints one JSON line when it is up."""
    console = Console(base=args.home, identity=args.identity, trust_path=args.trust,
                      timeout_s=args.timeout_seconds)
    server = ConsoleServer(console, host=args.host, port=args.port).start()
    ident = console.identity()
    print(json.dumps({"serving": server.url, "npub": ident.npub if ident else None,
                      "trust_file": str(console.trust_path),
                      "campaign": (t.campaign if (t := console.trust()) else None),
                      "stop": "Ctrl-C"}), flush=True)
    if args.open:
        webbrowser.open(server.url + "/")
    try:
        with contextlib.suppress(KeyboardInterrupt):    # Ctrl-C is how this command ends
            threading.Event().wait()
    finally:
        server.stop()
    return {"stopped": server.url}


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--port", type=int, default=DEFAULT_PORT,
                        help=f"port to listen on (default {DEFAULT_PORT}; 0 picks a free one)")
    parser.add_argument("--host", default=DEFAULT_HOST,
                        help=f"loopback address to bind (default {DEFAULT_HOST})")
    parser.add_argument("--open", action="store_true", help="open the console in a browser")


def main(argv: list[str] | None = None) -> int:
    """`python -m nostr_mailbox.ui`: the same as `nostr-mailbox ui`."""
    from .cli import IDENTITY_ENV, TRUST_ENV, _patience
    ap = argparse.ArgumentParser(prog="python -m nostr_mailbox.ui", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--trust", default=os.environ.get(TRUST_ENV))
    ap.add_argument("--identity", default=os.environ.get(IDENTITY_ENV) or DEFAULT_NAME)
    ap.add_argument("--home", default=None)
    ap.add_argument("--timeout-seconds", type=_patience, default=DEFAULT_WAIT_S)
    add_arguments(ap)
    args = ap.parse_args(argv)
    try:
        print(json.dumps(serve(args)))
    except NostrError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:              # the port is taken, the page is missing
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

__all__ = ["AUTH_KIND", "BLOSSOM_AUTH_KIND", "CONSOLE_KINDS", "Console", "ConsoleServer",
           "GRANT_MODES", "INVITE_CLAIM_KIND", "KEYRING_KIND", "ROLES", "TopicDesk",
           "TopicSession", "TopicState", "gift_wrap", "parse_keyring", "role_of", "serve",
           "ticket_digest", "topic_state", "unwrap"]
