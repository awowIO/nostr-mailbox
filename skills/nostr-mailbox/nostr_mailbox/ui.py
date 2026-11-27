"""`nostr-mailbox ui`: the Visual Web Console, served from this workstation.

A standard-library HTTP server on loopback serves `web/index.html` at `/` and a small
JSON API backed by this machine's own files: the campaign's `nostr.toml`, the admin
reach `setup` saved for that campaign (`cli.admin_file`) and the 0600 identity key. The
page talks to the relay itself (a browser WebSocket, NIP-42) and asks this server to
sign, so the key never enters the browser. The same `index.html` also runs on its own,
served from the relay's origin, with a key held in the tab or in a NIP-07 extension.

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
lists them. A tab names the persona it shows in `X-NM-Persona` on every request, and the
request runs as that persona start to finish, whatever another tab switched to
meanwhile. A request that names none runs as the console's default persona, which is
what a freshly opened tab starts from. `/api/persona` switches the tab that asks, and
the default that new tabs start from (or creates a persona, 0600); other open tabs keep
theirs.

Blobs. Outside a topic a blob is stored as it is, as the CLI does for the root campaign:
`POST /api/blob` uploads the body, `GET /api/blob/<sha256>` returns the blob as stored.
Inside a topic, `POST /api/topics/<topic>/blob` seals the body under the topic's current
epoch and `GET /api/topics/<topic>/blob/<sha256>` opens a blob under every epoch this key
holds, newest first, as `blob put` and `blob get` do (`X-NM-Epoch` names the epoch that
opened it). The digest of what the blob server returned is checked before anything is
opened; a topic blob that no held epoch opens is refused (`Unopened`), and
`GET /api/blob/<sha256>` is the explicit way to fetch it as stored (the CLI's --plain).

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
`<home>/invites/<group>.json` (0600). The token of a topic invite declares the topic
(its group and keyring) and never the campaign's own `campaign_key`: whoever is invited
into one topic is not handed the key to everything else. The newcomer's join request
(9021) presents the ticket, and the admin's `/api/topic/grant` with that ticket applies
those recorded terms to that one key, once.

Pair Coding Agent. `/api/topic/export` gives a coding agent on this workstation a topic
the way the CLI holds one: its declaration under `<home>/topics/` and this persona's own
keyring, every epoch under its own number. `/api/state` names the command prefix
(`--home`, `--persona` when they are not the defaults) that makes the CLI act as this
console does.

MCP. The routes of `nostr-mailbox mcp --http` (`mcp_http`) are served here too: `/mcp`
(Streamable HTTP), `/sse` and `/messages` (HTTP+SSE), `/openapi.json` and
`/tools/<tool>`, so while the console runs, `<console>/mcp` is an MCP server. They keep
this console's Host rule and ask for the home's bearer (`<home>/mcp.token`, made 0600 on
first start), never the page's token, and they answer CORS for loopback origins only. A
call runs as the persona its request names in `X-NM-Persona`, else as the console's
default persona, like every request here. `/api/state` says where they are."""
from __future__ import annotations

import argparse
import base64
import contextlib
import copy
import hashlib
import hmac
import json
import os
import re
import secrets
import shlex
import socket
import stat
import sys
import threading
import traceback
import webbrowser
from dataclasses import dataclass, replace
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from . import __version__, bech32, nip44
from ._files import write_private
from .backend import (
    DISPOSITIONS,
    INBOX,
    CampaignSession,
    Message,
    NostrRelayChannelBackend,
    NotAuthorized,
)
from .blossom import MAX_BLOB_BYTES, BlossomError
from .event import DEFAULT_WAIT_S, Event, InvalidEvent, NostrError, dumps, event_id, now, order
from .event import verify_event as _verify_event
from .groups import ROLE_TAG, ROLES, role_of
from .identity import (
    AUTH_KIND,
    BLOSSOM_AUTH_KIND,
    DEFAULT_HOME,
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
from .mcp_http import TOKEN_FILE, McpHttp, is_loopback, load_token
from .profile import EpochKeys, ProfileError, Trust, slug
from .relay import INVITE_CLAIM_KIND, INVITE_TTL, NCLI_CONFIG, RelayAdmin, RelayError

DEFAULT_PORT = 7890
DEFAULT_HOST = "127.0.0.1"
PAGE = Path(__file__).with_name("web") / "index.html"
TOKEN_SLOT = '<meta name="nm-bridge" content="">'
TOKEN_HEADER = "X-NM-Token"
PERSONA_HEADER = "X-NM-Persona"         # the persona the asking tab shows

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
JOIN_PATHS = ("/join", "/join/")
INVITES = "invites"
INVITE_BOOK_SCHEMA = "cf.topic-invites/1"
_TOPIC_INVITE = re.compile(r"^/api/topics/([a-z0-9][a-z0-9_-]{0,63})/invite$")
_TOPIC_BLOB = re.compile(r"^/api/topics/([a-z0-9][a-z0-9_-]{0,63})/blob$")


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


class Unopened(ConsoleError):
    """A topic blob that none of the epoch keys this key holds opens: sealed in an epoch
    it was not given, or uploaded in plaintext. The page tells it apart by this type."""


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
    if not isinstance(topic, str) or not TOPIC_ID.fullmatch(topic):
        raise TopicError(f"key ring topic {topic!r} is not a topic id")
    if [t[1] for t in rumor["tags"] if t[0] == "h" and len(t) > 1] != [topic]:
        raise TopicError("key ring h tag does not name its topic")
    raw = body.get("epochs")
    epochs: dict[int, str] = {}
    for n, key in (raw.items() if isinstance(raw, dict) else ()):
        if not re.fullmatch(r"[1-9][0-9]*", n) or not isinstance(key, str) \
                or not _SHA256.fullmatch(key):
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
            if len(tag) > 1 and tag[0] == "p" and _SHA256.fullmatch(tag[1]):
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
        if not TOPIC_ID.fullmatch(topic):
            raise TopicError(f"topic id {topic!r} must match {TOPIC_ID.pattern}")
        events = self.session.relay.query_all({
            "kinds": [CREATE_GROUP, PUT_USER, REMOVE_USER, DELETE_EVENT, JOIN_REQUEST],
            "#h": [topic]})
        return topic_state(self.trust, topic, events, self.rings(), self.me)

    def topics(self) -> list[TopicState]:
        created = self.session.relay.query_all({"kinds": [CREATE_GROUP],
                                                "authors": [self.me]})
        names = {r["topic"] for r in self.rings()} | {
            t for e in created for t in e.values("h")[:1] if TOPIC_ID.fullmatch(t)}
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
        if not TOPIC_ID.fullmatch(topic):
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


def _invite_token(trust: Trust, code: str, member: str | None, topic: str | None) -> str:
    """The nm1_ token of an invite. One that names a topic declares that topic (its
    group and keyring, as `cli._as_topic`) and so carries no `campaign_key`: the
    campaign's own key is for those invited into the campaign, not into one topic."""
    from . import cli
    declared = cli._as_topic(trust, topic) if topic else trust
    return cli._encode_invite_token(declared, code, member=member)


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
    it signs as by default, and how long to wait for a relay. Files are read per
    request, so `setup` or `join` run elsewhere is picked up without a restart. A
    request works on `pinned()`, a copy that keeps the persona its tab named (or the
    default one) to the end."""

    def __init__(self, *, base: str | Path | None = None, identity: str = DEFAULT_NAME,
                 trust_path: str | Path | None = None, timeout_s: float = DEFAULT_WAIT_S,
                 quiet: bool = False):
        self.home = home(base)
        self.identity_name, self.timeout_s, self.quiet = identity, timeout_s, quiet
        self.trust_path = Path(trust_path) if trust_path else self.home / "nostr.toml"
        self.token = secrets.token_urlsafe(32)
        raw = PAGE.read_text(encoding="utf-8")
        if raw.count(TOKEN_SLOT) != 1:
            raise ConsoleError(f"{PAGE} must hold exactly one {TOKEN_SLOT!r}")
        self.page = raw.replace(TOKEN_SLOT, f'<meta name="nm-bridge" content="{self.token}">')
        self.csp = _page_csp(self.page)
        self.root = self                        # the console every pinned copy came from
        self._persona_lock = threading.Lock()
        self._book_lock = threading.Lock()

    def pinned(self, persona: str | None = None) -> Console:
        """This console as one request sees it, for the whole request whatever
        `/api/persona` switches meanwhile: as `persona` (the one its tab shows) when named,
        else as the default persona when the request arrived. A name that is not an identity name is
        refused; one with no usable identity fails as a missing identity does."""
        with self.root._persona_lock:
            mine = copy.copy(self.root)
        if persona is not None:
            mine.identity_name = slug(persona, PERSONA_HEADER)
        return mine

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

    @property
    def admin_path(self) -> Path:
        """Where the admin reach of this console's campaign is kept: `cli.admin_file`,
        so a second org's `setup` in this home is never mistaken for this one's."""
        from . import cli
        trust = self.trust()
        return (self.home / "admin.json" if trust is None
                else cli.admin_file(self.home, trust.campaign))

    def admin(self) -> RelayAdmin:
        """The relay admin `setup` saved for this campaign, read loudly: none saved
        means no invites."""
        from . import cli
        saved = cli.load_admin(self.home, self.need_trust().campaign, timeout_s=self.timeout_s,
                               config=NCLI_CONFIG)
        if saved is None:
            raise NotSetUp(f"no {self.admin_path}: run `nostr-mailbox setup --kubectl` (or "
                           "--compose / --exec) once so this workstation can mint invites")
        return saved

    def session(self) -> TopicSession:
        trust, ident = self.need_trust(), self.need_identity()
        return TopicSession(trust, ident.signer(timeout_s=self.timeout_s),
                            timeout_s=self.timeout_s)

    def enter_scope(self, session: TopicSession, group: str | None,
                    epoch: int | None = None) -> TopicDesk | None:
        """Point `session` at the root campaign (no group, or the campaign's own) or at
        one epoch of a shared topic, whose key comes from this key's key rings. A
        workstation invited into one topic declares that topic's keyring and holds no
        campaign key: everything it writes goes to that topic, under its epoch keys."""
        trust = session.trust
        if trust.keyring is None and group in (None, "", trust.group):
            session.enter(trust, 1 if trust.campaign_key else None)
            return None
        desk = TopicDesk(session, self.secret())
        scoped, n = desk.scope_trust(desk.state(group or trust.keyring), epoch)
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
        """Switch the persona of the tab that asks (it names the new one from its next
        request on) and the default persona that new tabs, and requests naming none,
        start from. Other open tabs keep theirs. `create: true` makes a fresh 0600 key
        under that name first, and never replaces one that exists."""
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

    def cli_prefix(self, *scope: str) -> str:
        """`nostr-mailbox` with the root flags a coding agent on this workstation needs to
        act as this console does: --home and --persona when they are not the CLI's own
        defaults, then `scope`. Quoted for a shell."""
        flags = []
        if self.home != Path(DEFAULT_HOME).expanduser():
            flags += ["--home", str(self.home)]
        if self.identity_name != DEFAULT_NAME:
            flags += ["--persona", self.identity_name]
        return shlex.join(["nostr-mailbox", *flags, *scope])

    def exports(self) -> tuple[dict[str, list[int]], dict[str, str]]:
        """Which topics a coding agent on this workstation reads as this persona, and at
        which epochs: the persona's own CLI keyrings (`/api/topic/export` fills one, and
        so does a CLI join). Epoch numbers only, never a key. A ring that does not open
        is named with the reason, never left out."""
        from .keyring import KeyRing
        held: dict[str, list[int]] = {}
        unreadable: dict[str, str] = {}
        folder = self.home / "topics"
        for path in sorted(folder.glob("*.toml")) if folder.is_dir() else ():
            try:
                trust = Trust.load(path)
                ring = (KeyRing.open(self.home, trust, self.identity_name)
                        if trust.keyring else None)
            except ProfileError as exc:
                unreadable[path.stem] = str(exc)
                continue
            if ring is not None and ring.epochs:
                held[trust.keyring] = sorted(ring.epochs)
        return held, unreadable

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
        write_private(self._book_path(topic), json.dumps(book, indent=1, sort_keys=True))

    def invites(self) -> dict:
        """Every topic invite minted here, as the admin's page matches join requests to
        them: the ticket's digest and its terms, never the ticket."""
        folder = self.home / INVITES
        topics = sorted(p.stem for p in folder.glob("*.json")) if folder.is_dir() else []
        return {"topics": {t: [{"ticket_sha256": digest, **terms}
                               for digest, terms in sorted(self._book(t)["tickets"].items())]
                           for t in topics if TOPIC_ID.fullmatch(t)}}

    # ---- the API
    def state(self) -> dict:
        ident, trust = self.identity(), self.trust()
        held, unreadable = self.exports() if ident else ({}, {})
        default = self.trust_path == self.home / "nostr.toml"
        out = {"mode": "bridge", "version": __version__, "home": str(self.home),
               "identity": ident.describe() if ident else None, "seat": self.identity_name,
               "active_persona": self.identity_name, "personas": self.personas(),
               "exports": held, "export_errors": unreadable,
               "cli": self.cli_prefix(*(() if default else ("--trust", str(self.trust_path)))),
               "trust_file": str(self.trust_path), "trust": None, "role": None,
               "admin": {"configured": self.admin_path.is_file(), "path": str(self.admin_path)},
               "mcp": {"path": "/mcp", "sse": "/sse", "openapi": "/openapi.json",
                       "tools": "/tools/", "auth": "bearer",
                       "token_file": str(self.home / TOKEN_FILE)},
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
        trust, admin = self.need_trust(), self.admin()
        member, topic = body.get("member") or None, body.get("topic") or None
        if topic is not None and not TOPIC_ID.fullmatch(str(topic)):
            raise ConsoleError(f"topic {topic!r} must match {TOPIC_ID.pattern}")
        invite = admin.create_invite(ttl=str(body.get("ttl") or INVITE_TTL))
        token = _invite_token(trust, invite["code"], member, topic)
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
        token = _invite_token(trust, invite["code"], member, topic)
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
        """Pair Coding Agent: give a coding agent on this workstation the topic the way
        the CLI holds one. The declaration goes to `<home>/topics/<topic>.toml` and every
        epoch this key holds to this persona's own ring, each under its own number, so
        the agent (`--topic <topic>`, as this persona) writes under the current epoch N
        and not under "epoch 1", and fetches later epochs itself: the CLI syncs its ring
        on every connect, so a rotation needs no fresh export."""
        from . import cli
        from .keyring import KeyRing
        topic = str(body.get("topic", ""))
        with self.session() as session:
            desk = TopicDesk(session, self.secret())
            state = desk.state(topic)
            _, n = desk.scope_trust(state)      # the current epoch is held, or it says why
        declared = cli._as_topic(self.need_trust(), topic)
        path = self.home / cli.TOPICS / f"{topic}.toml"
        if path.exists():
            held = Trust.load(path)
            if (held.campaign, held.keyring) != (declared.campaign, topic):
                raise Refused(f"{path} declares topic {held.keyring!r} of campaign "
                              f"{held.campaign!r}, not {topic!r} of {declared.campaign!r}; "
                              "nothing was written")
            declared = held
        ring = KeyRing.open(self.home, declared, self.identity_name)
        ring.merge(state.epochs)                # a contradicting key: refused, unwritten
        if not path.exists():
            cli._write_trust_file(path, cli._mapping(declared))
        ring.save()
        return {"topic": topic, "epoch": n, "epochs": sorted(ring.epochs),
                "trust_file": str(path), "keyring": str(ring.path), "mode": "0600",
                "persona": self.identity_name, "cli": self.cli_prefix("--topic", topic),
                "note": f"holds epochs {sorted(ring.epochs)} under their own numbers and "
                        f"writes under epoch {n}; the CLI fetches later epochs itself"}

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

    def _hold_epochs(self, session: TopicSession, group: str) -> None:
        """Point `session` at topic `group` with every epoch key this key holds, the
        current one to seal under: what `put_sealed_blob` and `open_sealed_blob` use."""
        desk = TopicDesk(session, self.secret())
        state = desk.state(group)
        scoped, n = desk.scope_trust(state)
        session.trust = replace(scoped, epoch_keys=EpochKeys(scoped.campaign, state.epochs, n))

    def blob_get(self, sha256: str, group: str | None = None) -> tuple[bytes, int | None]:
        """The blob as stored, its digest verified (`cli.cmd_blob_get`). In topic `group`,
        then opened under the epochs this key holds, newest first; returns the epoch
        that opened it."""
        with self.session() as session:
            if group is None:
                return session.blobs().download(sha256), None
            self._hold_epochs(session, group)
            stored = session.blobs().download(sha256)
            try:
                return session.open_sealed_blob(stored)
            except ProfileError as exc:
                raise Unopened(str(exc)) from exc

    def blob_put(self, data: bytes, content_type: str, group: str | None = None) -> dict:
        """`cli.cmd_blob_put`: in topic `group` the bytes are sealed under its current
        epoch, elsewhere uploaded as they are."""
        with self.session() as session:
            if group is None:
                return session.blobs().upload(data, content_type=content_type).to_dict()
            self._hold_epochs(session, group)
            blob, epoch = session.put_sealed_blob(data)
        return {**blob.to_dict(), "sealed": True, "epoch": epoch, "bytes": len(data),
                "plaintext_sha256": hashlib.sha256(data).hexdigest()}

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
        self.mcp = McpHttp(token=load_token(console.home / TOKEN_FILE), defaults=self._mcp_call,
                           host_ok=lambda named: named in self.allowed_hosts)

    def _mcp_call(self, handler: BaseHTTPRequestHandler) -> dict:
        """What an MCP call through the console runs as: the persona its request names in
        X-NM-Persona, else the console's default persona, as every request here; in the
        console's own home and campaign, with its patience."""
        console = self.console.pinned(handler.headers.get(PERSONA_HEADER))
        default = console.trust_path == console.home / "nostr.toml"
        return {"home_dir": console.home, "default_persona": console.identity_name,
                "trust": None if default else str(console.trust_path),
                "timeout_seconds": console.timeout_s}


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
        elif size > MAX_BLOB_BYTES:
            raise ConsoleError(f"a blob is at most {MAX_BLOB_BYTES:,} bytes (the relay's own "
                               f"maxBlobBytes); this one is {size:,}, "
                               f"{100 * size / MAX_BLOB_BYTES:.0f}% of that. Nothing was read")
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

    def _serve(self, route, *, write: bool) -> None:
        """Gate the request, then run `route` on the console pinned to the persona the
        request names, and answer a refusal with its status and its words."""
        try:
            self._gate(write=write)
            route(self.server.console.pinned(self.headers.get(PERSONA_HEADER)))
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
    def _mcp(self) -> bool:
        """Serve the MCP routes (`mcp_http`) when the request is for one of them."""
        if not McpHttp.owns(self.path):
            return False
        self.server.mcp.handle(self)
        return True

    def do_GET(self) -> None:                   # noqa: N802 (stdlib name)
        if self._mcp():
            return
        path = urlsplit(self.path).path
        if path in ("/", "/index.html", *JOIN_PATHS):
            if self.headers.get("Host") not in self.server.allowed_hosts:
                self._error(HTTPStatus.FORBIDDEN, Refused("not this console's Host"))
                return
            console = self.server.console
            self._send(HTTPStatus.OK, console.page.encode(), "text/html; charset=utf-8",
                       {"Content-Security-Policy": console.csp})
            return
        where, _, sha256 = path.rpartition("/")
        topic = _TOPIC_BLOB.fullmatch(where)
        if path == "/api/state":
            self._serve(lambda c: self._json(200, c.state()), write=False)
        elif path == "/api/topics":
            self._serve(lambda c: self._json(200, c.topics()), write=False)
        elif path == "/api/invites":
            self._serve(lambda c: self._json(200, c.invites()), write=False)
        elif where == "/api/blob" or topic:
            def blob(c: Console) -> None:
                if not _SHA256.fullmatch(sha256):
                    raise ConsoleError(f"{sha256!r} is not a sha256 in lowercase hex")
                data, epoch = c.blob_get(sha256, topic.group(1) if topic else None)
                opened = {} if epoch is None else {"X-NM-Epoch": str(epoch)}
                self._send(HTTPStatus.OK, data, "application/octet-stream",
                           {"X-Digest-Verified": "sha256", **opened})
            self._serve(blob, write=False)
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
        if self._mcp():
            return
        path = urlsplit(self.path).path
        topic = _TOPIC_BLOB.fullmatch(path)
        if path == "/api/blob" or topic:
            def put(c: Console) -> None:
                kind = self.headers.get("Content-Type") or "application/octet-stream"
                self._json(200, c.blob_put(self._body(json_body=False), kind,
                                           topic.group(1) if topic else None))
            self._serve(put, write=True)
            return
        method = self._POSTS.get(path)
        invited = _TOPIC_INVITE.fullmatch(path)
        if invited:
            def method(c: Console, body: dict) -> dict:
                return c.topic_invite(invited.group(1), body)
        if method is None:
            self._error(HTTPStatus.NOT_FOUND, ConsoleError(f"nothing at {path}"))
            return
        self._serve(lambda c: self._json(200, method(c, self._body())), write=True)

    def _mcp_only(self) -> None:
        """DELETE and OPTIONS: MCP's (a session's end, a CORS preflight), nothing else's."""
        if not self._mcp():
            self._error(HTTPStatus.NOT_FOUND,
                        ConsoleError(f"nothing at {urlsplit(self.path).path} for {self.command}"))

    do_DELETE = do_OPTIONS = _mcp_only          # noqa: N815 (stdlib names)


class ConsoleServer:
    """The console on a background thread: `start()`, `url`, `stop()`. Port 0 picks a
    free port, which is how the witnesses run it."""

    def __init__(self, console: Console, *, host: str = DEFAULT_HOST, port: int = DEFAULT_PORT):
        if not is_loopback(host):
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
        self._server.mcp.close()                # its open streams end, and their threads
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
                      "mcp": server.url + "/mcp",
                      "mcp_token_file": str(console.home / TOKEN_FILE),
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
