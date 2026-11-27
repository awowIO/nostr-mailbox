"""A private relay, with its blob store, that runs inside the test process on loopback.

`LoopbackRelay` is a real relay in every way a client can observe: a TCP socket, the
RFC 6455 handshake, NIP-01 `EVENT`/`REQ`/`CLOSE`, a NIP-42 challenge on every socket,
NIP-43 single-use invite claims, NIP-01 storage by kind class, a NIP-11 document, and
Blossom on the same origin. The client under test speaks to it through the same code
path it uses for a deployed relay, so a test here exercises caller and callee together.

Where the protocol leaves room, it behaves the way the pinned relay
(`ncli 0.8.0-rc.54` / `nmilat 0.5.0-rc.54`) was read and observed to:

- `limit: 0` means no limit, and replays everything;
- removing a member answers `CLOSED` on its open subscriptions and refuses what it
  asks next, on a socket that stays open;
- a blob authorization is unpadded base64url, must carry a `server` tag naming this
  host, may be dated at most 60 s ahead, and an upload must name its hash;
- blobs answer at `/<sha256>[.ext]` and `/media/<sha256>[.ext]`, uploads at `/upload`
  and `/media/upload`, and a descriptor's URL is the `/media/…` one.

It also runs the self-service switches of the `nostr-relay-deploy` relay.yaml (this
repository's own `deploy/nostr-relay/relay.yaml` leaves `memberClaims` off and sets no
`recipientOnlyKinds`; turning them on is a deployment decision):

- `recipientOnlyKinds: [1059, 4410, 4411]`: gift wraps and pairwise envelopes are
  served only to a socket authenticated as a key in the event's `p` tags;
- `memberClaims: true` (`member_claims=True`): a member's `REQ {"kinds": [28935]}` is
  answered with one relay-signed event carrying a fresh single-use invite code;
- NIP-29 groups (`groups:`): any member creates one (9007), private and closed, and
  becomes its admin; a private group's events are served only to its members, a
  restricted group takes writes only from them, a join (9021) with a group invite code
  (9009) is admitted at once and one without waits for an admin; the relay keeps the
  group state as relay-signed 39000/39001/39002 and refuses those kinds from anyone else.

What it is not: `ncli`, durable, rate-limited, or hardened. It keeps everything in
memory. Agreement with the deployed relay is witnessed against the real binary in
`tests/test_nostr_ncli.py`.

The admin methods (`create_invite`, `add_member`, `remove_member`) are what
`ncli relay invites create` and `ncli relay members add|remove` do on a real relay."""
from __future__ import annotations

import base64
import contextlib
import hashlib
import json
import queue
import re
import secrets
import socket
import threading
import time
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from . import groups, secp256k1, ws
from ._serve import Listener
from .event import (
    ADDRESSABLE,
    EPHEMERAL,
    REPLACEABLE,
    Clock,
    Event,
    InvalidEvent,
    coordinate,
    dumps,
    kind_class,
    matches,
    now,
    sign_with_secret,
    supersedes,
    unsigned,
    verify_event,
)
from .identity import AUTH_KIND, BLOSSOM_AUTH_KIND
from .relay import INVITE_CLAIM_KIND, INVITE_REQUEST_KIND, MAX_MESSAGE_BYTES, NIP11_ACCEPT

AUTH_SKEW_S = 120           # the freshness window the relay report sets for a NIP-42 proof
BLOSSOM_SKEW_S = 60         # nmilat nipB7.ClockSkewTolerance
OUTGOING_BUFFER = 1024      # ncli defaultOutgoingBufferSize: frames queued per client
MAX_LIMIT = 555_555         # ncli defaultMaxLimit, as it advertises
MAX_MESSAGE_LENGTH = 1_101_005      # ncli defaultMaxMessageLength
UPLOAD_PATHS = ("/upload", "/media/upload")
BLOB_PREFIX = "/media"
_BLOB_PATH = re.compile(r"^/(media/)?([0-9a-f]{64})(\.[a-z0-9]{1,8})?$")
_EXTENSIONS = {"application/json": ".json", "text/plain": ".txt", "text/x-diff": ".diff"}
_REASONS = {200: "OK", 400: "Bad Request", 401: "Unauthorized", 403: "Forbidden",
            404: "Not Found", 405: "Method Not Allowed"}
RECIPIENT_ONLY_KINDS = (1059, 4410, 4411)       # relay.yaml recipientOnlyKinds
_GROUP_ID = re.compile(r"^[a-z0-9_-]{1,64}$")   # NIP-29 group ids


@dataclass
class _Group:
    """One NIP-29 group as the relay holds it."""
    admins: set[str]
    members: set[str]
    private: bool = True
    closed: bool = True
    restricted: bool = False
    codes: dict[str, int] = field(default_factory=dict)


def _respond(sock, status: int, body: bytes = b"", *, reason: str = "",
             content_type: str = "application/octet-stream", head_only: bool = False) -> None:
    head = [f"HTTP/1.1 {status} {_REASONS[status]}", f"Content-Type: {content_type}",
            f"Content-Length: {len(body)}", "Connection: close"]
    if reason:
        head.append(f"X-Reason: {reason}")
    with contextlib.suppress(OSError):          # the asker may have hung up
        sock.sendall(("\r\n".join(head) + "\r\n\r\n").encode() + (b"" if head_only else body))


def _body(sock, request: ws.Request) -> bytes:
    """The request body: what arrived with the head, and the rest by Content-Length."""
    wanted = int(request.headers.get("content-length", "0"))
    data = bytearray(request.rest)
    while len(data) < wanted:
        chunk = sock.recv(wanted - len(data))
        if not chunk:
            break
        data += chunk
    return bytes(data)


class _Blobs:
    """Blossom the way the pinned relay serves it. `blobs` is plain to reach so a test
    can corrupt a stored blob and watch the client refuse it."""

    def __init__(self, is_member, clock: Clock, host, origin):
        self.is_member, self.clock = is_member, clock
        self._host, self._origin = host, origin        # callables: known once started
        self.blobs: dict[str, bytes] = {}
        self.types: dict[str, str] = {}

    def _authorize(self, header: str | None, verb: str, sha256: str,
                   *, need_hash: bool) -> tuple[int, str, str]:
        """(0, "", pubkey) when the request may proceed, else (status, reason, "")."""
        token = header[6:] if header and header.startswith("Nostr ") else None
        if not token or set(token) & set("=+/"):
            return 401, "nipB7: missing or malformed Authorization header", ""
        try:
            raw = json.loads(base64.urlsafe_b64decode(token + "=" * (-len(token) % 4)))
            event = verify_event(raw)
        except (ValueError, InvalidEvent) as exc:
            return 401, f"nipB7: authorization has an invalid signature: {exc}", ""
        stamp = now(self.clock)
        expires = event.values("expiration")
        if event.kind != BLOSSOM_AUTH_KIND:
            return 401, "nipB7: wrong kind for authorization event", ""
        if event.values("t") != [verb]:
            return 401, "nipB7: authorization verb does not match requested action", ""
        if event.created_at > stamp + BLOSSOM_SKEW_S:
            return 401, "nipB7: authorization created_at is in the future", ""
        if not expires or not expires[0].isdigit() or int(expires[0]) <= stamp:
            return 401, "nipB7: authorization has expired", ""
        servers = [s.split("://")[-1].rstrip("/").lower() for s in event.values("server")]
        if servers and self._host().lower() not in servers:
            return 403, "nipB7: authorization is not scoped to this server", ""
        if not servers:
            return 403, "authorization must name this server", ""
        hashes = event.values("x")
        if need_hash and not hashes:
            return 401, "authorization must name the blob's hash (x tag)", ""
        if hashes and sha256 not in hashes:
            return 403, "nipB7: authorization does not cover this blob hash", ""
        if not self.is_member(event.pubkey):
            return 403, f"this key may not {'upload' if verb == 'upload' else 'download'} here", ""
        return 0, "", event.pubkey

    def handle(self, sock, request: ws.Request) -> bool:
        """Answer a Blossom request; False when the path is not one."""
        method, path = request.method, request.path
        auth = request.headers.get("authorization")
        if path in UPLOAD_PATHS:
            if method != "PUT":
                _respond(sock, 405, reason="uploads are PUT")
                return True
            body = _body(sock, request)
            sha256 = hashlib.sha256(body).hexdigest()
            status, reason, _ = self._authorize(auth, "upload", sha256, need_hash=True)
            if status:
                _respond(sock, status, reason=reason)
                return True
            kind = request.headers.get("content-type", "application/octet-stream")
            self.blobs[sha256], self.types[sha256] = body, kind
            _respond(sock, 200, dumps({
                "url": f"{self._origin()}{BLOB_PREFIX}/{sha256}{_EXTENSIONS.get(kind, '.bin')}",
                "sha256": sha256, "size": len(body), "type": kind,
                "uploaded": now(self.clock)}).encode(), content_type="application/json")
            return True
        named = _BLOB_PATH.match(path)
        if named is None:
            return False
        if method not in ("GET", "HEAD"):
            _respond(sock, 405, reason="blobs are GET or HEAD")
            return True
        sha256, head_only = named.group(2), method == "HEAD"
        status, reason, _ = self._authorize(auth, "get", sha256, need_hash=False)
        if status:
            _respond(sock, status, reason=reason, head_only=head_only)
        elif sha256 not in self.blobs:
            _respond(sock, 404, reason="blob not found", head_only=head_only)
        else:
            _respond(sock, 200, self.blobs[sha256], head_only=head_only,
                     content_type=self.types.get(sha256, "application/octet-stream"))
        return True


class _Connection:
    """One client. Everything sent to it goes through one bounded queue drained by its
    own thread, so frames stay in order and no shared lock is ever held across a
    socket write. A client that stops reading fills its queue and is dropped."""

    def __init__(self, socket_ws: ws.WebSocket):
        self.ws = socket_ws
        self.challenge = secrets.token_hex(16)
        self.pubkey: str | None = None
        self.subs: dict[str, list[dict]] = {}
        self._out: queue.Queue[str | None] = queue.Queue(maxsize=OUTGOING_BUFFER)
        threading.Thread(target=self._drain, name="cf-loopback-relay-out",
                         daemon=True).start()

    def send(self, message: list) -> None:
        try:
            self._out.put_nowait(dumps(message))
        except queue.Full:
            self.ws.abort()

    def _drain(self) -> None:
        while (text := self._out.get()) is not None:
            try:
                self.ws.send_text(text)
            except ws.WebSocketError:
                return

    def finish(self) -> None:
        self.ws.abort()
        with contextlib.suppress(queue.Full):
            self._out.put_nowait(None)


class LoopbackRelay:
    """`page_cap` makes the relay return at most that many stored events per filter
    whatever the filter asks, the way a relay with a low ceiling would. `public_url` is
    the name the relay knows itself by when it sits behind another address.
    `membership_required=False` makes it an open relay that says so in its NIP-11
    document. `drop_next_ok` makes it store the next event and then cut the connection
    instead of answering OK: the lost reply a retry has to survive. `member_claims`
    lets members mint invite codes over the WebSocket (NIP-43 kind 28935)."""

    def __init__(self, *, clock: Clock = time.time, page_cap: int | None = None,
                 public_url: str | None = None, membership_required: bool = True,
                 member_claims: bool = False):
        self.clock, self.page_cap = clock, page_cap
        self.public_url, self.membership_required = public_url, membership_required
        self.member_claims = member_claims
        self.recipient_only_kinds = frozenset(RECIPIENT_ONLY_KINDS)
        self._secret = secp256k1.generate_secret()        # the relay's own key (NIP-11 self)
        self.pubkey = secp256k1.pubkey_gen(self._secret).hex()
        self.groups: dict[str, _Group] = {}
        self.members: set[str] = set()
        self.drop_next_ok = False
        self.disconnects: list[str] = []
        self.blossom = _Blobs(self._may, lambda: self.clock(), self._blob_host,
                              self._blob_origin)        # one clock, even if it is swapped
        self._invites: dict[str, int] = {}
        self._regular: dict[str, Event] = {}
        self._slots: dict[tuple, Event] = {}
        self._connections: set[_Connection] = set()
        self._lock = threading.RLock()
        self._listener: Listener | None = None
        self.url = ""

    # ------------------------------------------------------------------ lifecycle
    def start(self) -> LoopbackRelay:
        sock = socket.create_server(("127.0.0.1", 0))
        self.url = f"ws://127.0.0.1:{sock.getsockname()[1]}"
        self._listener = Listener(sock, self._connection, "cf-loopback-relay").start()
        return self

    def stop(self) -> None:
        if self._listener is not None:
            self._listener.stop()
            self._listener = None
        with self._lock:
            connections = list(self._connections)
        for connection in connections:
            connection.finish()

    def __enter__(self) -> LoopbackRelay:
        return self.start()

    def __exit__(self, *exc_info) -> None:
        self.stop()

    @property
    def name(self) -> str:
        """The URL a NIP-42 proof must carry."""
        return self.public_url or self.url

    @property
    def http_url(self) -> str:
        """Where this relay's HTTP side (NIP-11, Blossom) is dialled."""
        return "http" + self.url[2:]

    def _blob_host(self) -> str:
        return urlsplit(self.name).netloc

    def _blob_origin(self) -> str:
        parts = urlsplit(self.name)
        return f"{'https' if parts.scheme == 'wss' else 'http'}://{parts.netloc}"

    def _may(self, pubkey: str | None) -> bool:
        with self._lock:
            return pubkey is not None and (not self.membership_required
                                           or pubkey in self.members)

    # ---------------------------------------------------------------------- admin
    def create_invite(self, *, max_uses: int = 1) -> str:
        code = secrets.token_urlsafe(32)
        with self._lock:
            self._invites[code] = max_uses
        return code

    def add_member(self, pubkey: str) -> None:
        with self._lock:
            self.members.add(pubkey)

    def remove_member(self, pubkey: str) -> None:
        """Revoke. The key's open subscriptions are closed with a reason and everything
        it asks afterwards is refused; its socket is left open, as on the real relay."""
        with self._lock:
            self.members.discard(pubkey)
            for connection in self._connections:
                if connection.pubkey == pubkey and self.membership_required:
                    for sub_id in list(connection.subs):
                        connection.send(["CLOSED", sub_id,
                                         "restricted: NIP-43 membership revoked"])
                    connection.subs.clear()

    def stored(self) -> list[Event]:
        with self._lock:
            return [*self._regular.values(), *self._slots.values()]

    def subscriptions(self) -> int:
        """Open REQs across every connection: how a test knows a watcher is listening."""
        with self._lock:
            return sum(len(connection.subs) for connection in self._connections)

    # ----------------------------------------------------------------- connection
    def _connection(self, sock) -> None:
        connection = None
        try:
            request = ws.accept(sock, max_message_bytes=MAX_MESSAGE_LENGTH)
            if request.ws is None:
                self._http(sock, request)
                return
            connection = _Connection(request.ws)
            with self._lock:
                self._connections.add(connection)
            connection.send(["AUTH", connection.challenge])
            while True:
                self._handle(connection, request.ws.recv_text(None))
        except ws.WebSocketError as exc:    # how every connection ends; kept for tests
            self.disconnects.append(str(exc))
        finally:
            if connection is not None:
                with self._lock:
                    self._connections.discard(connection)
                connection.finish()
            with contextlib.suppress(OSError):
                sock.close()

    def _http(self, sock, request: ws.Request) -> None:
        """The relay's HTTP side: its NIP-11 document at `/`, and Blossom."""
        if (request.method == "GET" and request.path == "/"
                and NIP11_ACCEPT in request.headers.get("accept", "")):
            _respond(sock, 200, dumps({
                "name": "nostr-mailbox loopback relay", "self": self.pubkey,
                "supported_nips": [1, 11, 29, 42, 43, 59, 70],
                "limitation": {"auth_required": True,
                               "membership_required": self.membership_required,
                               "max_limit": self.page_cap or MAX_LIMIT,
                               "max_message_length": MAX_MESSAGE_LENGTH},
            }).encode(), content_type=NIP11_ACCEPT)
        elif not self.blossom.handle(sock, request):
            _respond(sock, 404, reason="not served here")

    def _handle(self, connection: _Connection, text: str) -> None:
        try:
            message = json.loads(text)
        except json.JSONDecodeError as exc:
            connection.send(["NOTICE", f"invalid: not JSON ({exc})"])
            return
        if not isinstance(message, list) or not message:
            connection.send(["NOTICE", "invalid: not a client message"])
        elif message[0] == "AUTH" and len(message) == 2:
            self._auth(connection, message[1])
        elif message[0] == "EVENT" and len(message) == 2:
            self._event(connection, message[1])
        elif message[0] == "REQ" and len(message) >= 3:
            self._req(connection, str(message[1]), message[2:])
        elif message[0] == "CLOSE" and len(message) == 2:
            with self._lock:
                connection.subs.pop(str(message[1]), None)
        else:
            connection.send(["NOTICE", f"invalid: unknown message {message[0]!r}"])

    def _verified(self, connection: _Connection, raw) -> Event | None:
        try:
            return verify_event(raw)
        except InvalidEvent as exc:
            ident = raw.get("id", "") if isinstance(raw, dict) else ""
            connection.send(["OK", ident if isinstance(ident, str) else "", False,
                             f"invalid: {exc}"])
            return None

    def _fresh(self, event: Event) -> bool:
        return abs(now(self.clock) - event.created_at) <= AUTH_SKEW_S

    def _auth(self, connection: _Connection, raw) -> None:
        event = self._verified(connection, raw)
        if event is None:
            return
        if event.kind != AUTH_KIND:
            reason = "invalid: not a kind 22242 authentication event"
        elif event.values("relay") != [self.name]:
            reason = "invalid: the proof names a different relay"
        elif event.values("challenge") != [connection.challenge]:
            reason = "invalid: the proof answers a different challenge"
        elif not self._fresh(event):
            reason = f"invalid: the proof is outside the ±{AUTH_SKEW_S}s freshness window"
        else:
            connection.pubkey = event.pubkey
            connection.send(["OK", event.id, True, ""])
            return
        connection.send(["OK", event.id, False, reason])

    def _event(self, connection: _Connection, raw) -> None:
        event = self._verified(connection, raw)
        if event is None:
            return
        if connection.pubkey is None:
            reason = "auth-required: authenticate before publishing"
        elif event.kind == AUTH_KIND:
            reason = "invalid: an authentication proof is never published"
        elif event.pubkey != connection.pubkey:
            reason = "restricted: the author must be the authenticated key"
        elif event.kind == INVITE_CLAIM_KIND:
            accepted, reason = self._claim(event)
            connection.send(["OK", event.id, accepted, reason])
            return
        else:
            with self._lock:                # membership, storage and delivery are one step
                if not self._may(connection.pubkey):
                    reason = "restricted: valid NIP-43 membership required"
                else:
                    accepted, reason, touched = self._nip29(event)
                    if accepted:
                        note = self._store(event) or reason
                        if touched is not None:
                            self._announce(touched)
                        if self.drop_next_ok:
                            self.drop_next_ok = False
                            connection.ws.abort()
                            return
                        connection.send(["OK", event.id, True, note])
                        return
        connection.send(["OK", event.id, False, reason])

    # ------------------------------------------------------------------ NIP-29
    def _nip29(self, event: Event) -> tuple[bool, str, str | None]:
        """Whether a member's event is taken, what to say, and which group's state it
        changed. Called with the lock held. An `h` tag naming no group this relay
        hosts is an ordinary tag, as on a relay without NIP-29."""
        author = event.pubkey
        if event.kind in groups.RELAY_KINDS:
            return False, "restricted: group state (39000-39003) is written by the relay", None
        named = event.values("h")
        if not named:
            return True, "", None
        if len(named) > 1:
            return False, "invalid: an event belongs to one group", None
        gid, group = named[0], self.groups.get(named[0])
        if event.kind == groups.CREATE_GROUP:
            if group is not None:
                return False, f"duplicate: group {gid} already exists", None
            if not _GROUP_ID.match(gid):
                return False, f"invalid: {gid!r} is not a NIP-29 group id", None
            self.groups[gid] = _Group(admins={author}, members={author},
                                      restricted=event.has_tag("restricted"))
            return True, "info: group created; you are its admin", gid
        if group is None:
            return True, "", None
        if event.kind in groups.ADMIN_KINDS:
            if author not in group.admins:
                return False, f"restricted: only an admin of group {gid} may do that", None
            self._moderate(gid, group, event)
            return True, "", gid
        if event.kind == groups.JOIN_REQUEST:
            if author in group.members:
                return True, "duplicate: already a member of the group", None
            codes = event.values("code")
            if codes:
                if group.codes.get(codes[0], 0) < 1:
                    return False, "restricted: that group invite code is invalid or used", None
                group.codes[codes[0]] -= 1
                group.members.add(author)
                return True, "info: welcome to the group", gid
            if group.closed:
                return True, "info: the join request waits for the group's admins", None
            group.members.add(author)
            return True, "info: welcome to the group", gid
        if event.kind == groups.LEAVE_REQUEST:
            group.members.discard(author)
            return True, "", gid
        if group.restricted and author not in group.members:
            return False, f"restricted: only members of group {gid} write to it", None
        return True, "", None

    def _moderate(self, gid: str, group: _Group, event: Event) -> None:
        if event.kind == groups.PUT_USER:
            group.members.update(event.values("p"))
        elif event.kind == groups.REMOVE_USER:
            group.members.difference_update(set(event.values("p")) - group.admins)
        elif event.kind == groups.EDIT_METADATA:
            for flag, on, off in (("private", "private", "public"), ("closed", "closed", "open"),
                                  ("restricted", "restricted", "unrestricted")):
                if event.has_tag(on) or event.has_tag(off):
                    setattr(group, flag, event.has_tag(on))
        elif event.kind == groups.CREATE_INVITE:
            for code in event.values("code"):
                group.codes[code] = 1
        elif event.kind == groups.DELETE_EVENT:
            for ident in event.values("e"):
                held = self._regular.get(ident)
                if held is not None and held.values("h") == [gid]:
                    del self._regular[ident]
        elif event.kind == groups.DELETE_GROUP:
            del self.groups[gid]

    def _announce(self, gid: str) -> None:
        """Publish the group's state as relay-signed addressable events."""
        group = self.groups.get(gid)
        if group is None:
            return
        flags = [["private" if group.private else "public"],
                 ["closed" if group.closed else "open"]]
        flags += [["restricted"]] if group.restricted else []
        admins = [["p", pk, "admin"] for pk in sorted(group.admins)]
        members = [["p", pk] for pk in sorted(group.members)]
        for kind, tags in ((groups.GROUP_METADATA, flags), (groups.GROUP_ADMINS, admins),
                           (groups.GROUP_MEMBERS, members)):
            held = self._slots.get((kind, self.pubkey, gid))
            stamp = max(now(self.clock), held.created_at + 1 if held else 0)
            self._store(sign_with_secret(unsigned(kind, [["d", gid], *tags], "", stamp),
                                         self._secret, self.pubkey))

    def _visible(self, pubkey: str | None, event: Event) -> bool:
        """What a reader may be sent: a recipient-only kind only to its `p` keys, a
        private group's events only to its members."""
        if event.kind in self.recipient_only_kinds:
            return pubkey in event.values("p")
        for gid in event.values("h"):
            group = self.groups.get(gid)
            if group is not None and group.private and pubkey not in group.members:
                return False
        return True

    def _claim(self, event: Event) -> tuple[bool, str]:
        """NIP-43: one fresh, protected claim spends one use of one code."""
        codes = event.values("claim")
        if not event.has_tag("-") or len(codes) != 1 or not self._fresh(event):
            return False, "invalid: a claim is a fresh protected event with one claim tag"
        with self._lock:
            if event.pubkey in self.members:
                return True, "duplicate: this key is already a member"
            if self._invites.get(codes[0], 0) < 1:
                return False, "restricted: that invite is invalid, expired or already used"
            self._invites[codes[0]] -= 1
            self.members.add(event.pubkey)
        return True, "info: welcome"

    def _store(self, event: Event) -> str:
        """Keep the event the way its kind class says, then queue it for every live
        subscription it matches. Called with the lock held; queueing never blocks."""
        cls = kind_class(event.kind)
        if cls in (REPLACEABLE, ADDRESSABLE):
            slot = coordinate(event)
            held = self._slots.get(slot)
            if held is not None and not supersedes(event, held):
                return "duplicate: this address already holds that event or a newer one"
            self._slots[slot] = event
        elif cls != EPHEMERAL:
            if event.id in self._regular:
                return "duplicate: already have this event"
            self._regular[event.id] = event
        for other in self._connections:
            if not self._may(other.pubkey) or not self._visible(other.pubkey, event):
                continue
            for sub_id, filters in other.subs.items():
                if any(matches(flt, event) for flt in filters):
                    other.send(["EVENT", sub_id, event.to_dict()])
        return ""

    def _req(self, connection: _Connection, sub_id: str, filters: list) -> None:
        if connection.pubkey is None:
            connection.send(["CLOSED", sub_id, "auth-required: authenticate before reading"])
            return
        if not all(isinstance(flt, dict) for flt in filters):
            connection.send(["CLOSED", sub_id, "invalid: a filter is a JSON object"])
            return
        with self._lock:        # membership, history, EOSE and registration are one step
            if not self._may(connection.pubkey):
                connection.send(["CLOSED", sub_id,
                                 "restricted: valid NIP-43 membership required"])
                return
            if any(isinstance(flt.get("kinds"), list) and INVITE_REQUEST_KIND in flt["kinds"]
                   for flt in filters):
                self._mint_claim(connection, sub_id)
                return
            sent: set[str] = set()
            try:
                for flt in filters:
                    hits = sorted((e for e in self.stored()
                                   if matches(flt, e) and self._visible(connection.pubkey, e)),
                                  key=lambda e: (-e.created_at, e.id))
                    # a limit of 0 means "no limit" on this relay, as on the real one
                    caps = [cap for cap in (flt.get("limit") or None, self.page_cap)
                            if cap is not None]
                    for event in hits[:min(caps)] if caps else hits:
                        if event.id not in sent:
                            sent.add(event.id)
                            connection.send(["EVENT", sub_id, event.to_dict()])
            except InvalidEvent as exc:
                connection.send(["CLOSED", sub_id, f"unsupported: {exc}"])
                return
            connection.subs[sub_id] = filters
            connection.send(["EOSE", sub_id])

    def _mint_claim(self, connection: _Connection, sub_id: str) -> None:
        """NIP-43 invite request: with member claims on, one fresh single-use code in a
        relay-signed kind 28935 event; with them off, nothing. Lock held."""
        if self.member_claims:
            code = secrets.token_urlsafe(32)
            self._invites[code] = 1
            event = sign_with_secret(unsigned(INVITE_REQUEST_KIND, [["-"], ["claim", code]], "",
                                              now(self.clock)), self._secret, self.pubkey)
            connection.send(["EVENT", sub_id, event.to_dict()])
        connection.send(["EOSE", sub_id])


class LoopbackBlossom:
    """A blob server on an origin of its own, for a campaign that keeps blobs apart
    from its relay. Same rules as the relay's Blossom."""

    def __init__(self, is_member, *, clock: Clock = time.time):
        self._store = _Blobs(is_member, clock, lambda: urlsplit(self.url).netloc,
                             lambda: self.url)
        self._listener: Listener | None = None
        self.url = ""

    @property
    def blobs(self) -> dict[str, bytes]:
        return self._store.blobs

    def _connection(self, sock) -> None:
        try:
            request = ws.accept(sock, max_message_bytes=MAX_MESSAGE_BYTES)
            if request.ws is not None or not self._store.handle(sock, request):
                _respond(sock, 404, reason="not served here")
        except ws.WebSocketError:           # a client that hung up mid-request
            pass
        finally:
            with contextlib.suppress(OSError):
                sock.close()

    def start(self) -> LoopbackBlossom:
        sock = socket.create_server(("127.0.0.1", 0))
        self.url = f"http://127.0.0.1:{sock.getsockname()[1]}"
        self._listener = Listener(sock, self._connection, "cf-loopback-blossom").start()
        return self

    def stop(self) -> None:
        if self._listener is not None:
            self._listener.stop()
            self._listener = None

    def __enter__(self) -> LoopbackBlossom:
        return self.start()

    def __exit__(self, *exc_info) -> None:
        self.stop()
