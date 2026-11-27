"""One authenticated connection to one pinned, private relay.

The client answers the relay's NIP-42 challenge before it does anything else. A
challenge proves little by itself: the pinned relay release sends one on every
connection whether or not it is private. What a relay claims about itself is in its
NIP-11 document (`fetch_info`), what it enforces shows when a key that is not enrolled
is refused, and `relay check` reports the two separately.

Everything a relay delivers is verified before it is handed on: the event's id and
signature (`verify_event`), and that it matches the filter that asked for it. A relay
that delivers an event failing either check has broken the protocol, and the client
raises instead of skipping the frame: a campaign must not keep running against a relay
that forwards forgeries.

Reads are bounded. A stored page is at most `PAGE_LIMIT` events, a live subscription
asks for `LIVE_LIMIT` stored event and discards it, and one relay message is at most
`MAX_MESSAGE_BYTES`. On this relay `limit: 0` means "no limit", so it is never sent.

`RelayAdmin` is the operator's side: thin wrappers over the relay's own admin CLI
(`ncli relay invites create`, `ncli relay members add|remove`), run wherever that CLI
lives (inside the Kubernetes pod or the compose service)."""
from __future__ import annotations

import contextlib
import http.client
import json
import re
import secrets
import ssl
import subprocess
import time
from collections import deque
from dataclasses import dataclass
from urllib.parse import urlsplit

from . import ws
from .event import (
    DEFAULT_WAIT_S,
    Clock,
    Event,
    InvalidEvent,
    NostrError,
    check_wire_shape,
    dumps,
    matches,
    now,
    order,
    unsigned,
    verify_event,
)
from .identity import AUTH_KIND, Signer

INVITE_CLAIM_KIND = 28_934              # NIP-43 join request
INVITE_REQUEST_KIND = 28_935            # NIP-43 invite request: REQ it, the relay mints a code
PROTECTED = ("-",)                      # NIP-70: only the authenticated author may publish
INVITE_TTL = "168h"                     # the relay's own inviteTTL in deploy/nostr-relay/relay.yaml
NCLI_CONFIG = "/app/ncli/relay.yaml"    # where the image keeps its config (compose.yaml)
# Events asked for in one stored page: the relay's own per-session outgoing buffer
# (ncli defaultOutgoingBufferSize), so one page never asks it to queue more than it
# holds for a client. At the campaign's 16,384-byte event cap a full page is 16 MiB;
# on the pure-Python backend its signature checks take about a second, 4% of the
# default wait. The relay itself allows far more (it advertises max_limit 555,555).
PAGE_LIMIT = 1024
# A live subscription must name a limit: on this relay 0 means "no limit" and replays
# the topic. One is the smallest request the protocol has; the event it returns is
# dropped, and only what arrives after EOSE is delivered.
LIVE_LIMIT = 1
# One relay message carries one event. The campaign caps an event at 16,384 bytes
# (profile.MAX_EVENT_BYTES); JSON escaping can at most sextuple a byte (`\\u00XX`), and
# the remainder is the message envelope.
MAX_MESSAGE_BYTES = 8 * 16_384
NIP11_ACCEPT = "application/nostr+json"
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


class RelayError(NostrError):
    """The relay could not be used as asked."""


class RelayProtocolError(RelayError):
    """The relay sent something the protocol does not allow, or an event that fails
    verification."""


class RelayTimeout(RelayError):
    """The relay did not answer in the time allowed."""


class HistoryTruncated(RelayError):
    """A stored read that cannot be shown to be complete. Nothing is returned."""


class RelayRejected(RelayError):
    """The relay said no. `prefix` is the machine-readable part of its reason
    (`auth-required`, `restricted`, `invalid`, `rate-limited`, …)."""

    def __init__(self, what: str, reason: str):
        super().__init__(f"relay refused {what}: {reason or '(no reason given)'}")
        self.reason = reason
        self.prefix = reason.split(":", 1)[0].strip() if ":" in reason else ""


class RelayAdminError(RelayError):
    """The relay's admin CLI failed."""


# ------------------------------------------------------------------------- NIP-11
@dataclass(frozen=True)
class RelayInfo:
    """What a relay says about itself. An operator's assertion, not an observation: a
    relay can advertise a gate it does not enforce, which is why `relay check` also
    tries the gate."""
    url: str
    name: str
    auth_required: bool
    membership_required: bool
    max_limit: int | None
    max_message_length: int | None
    self_pubkey: str | None = None          # NIP-11 `self`: the key the relay signs with
    supported_nips: tuple[int, ...] = ()

    @property
    def advertises_private(self) -> bool:
        return self.auth_required and self.membership_required

    def to_dict(self) -> dict:
        return {**self.__dict__, "advertises_private": self.advertises_private}


def http_origin(url: str) -> tuple[str, str, int | None, str]:
    """(scheme, host, port, path) of the HTTP side of a relay URL: wss→https, ws→http."""
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError as exc:
        raise RelayError(f"not a usable relay URL: {url!r} ({exc})") from exc
    scheme = {"wss": "https", "ws": "http"}.get(parts.scheme)
    if scheme is None or not parts.hostname:
        raise RelayError(f"not a ws:// or wss:// URL: {url!r}")
    return scheme, parts.hostname, port, parts.path or "/"


def fetch_info(url: str, *, timeout_s: float = DEFAULT_WAIT_S,
               allow_cleartext: bool = False) -> RelayInfo:
    """The relay's NIP-11 document, read over HTTP from the same address clients dial."""
    scheme, host, port, path = http_origin(url)
    if scheme == "http" and not allow_cleartext and not ws.is_loopback(host):
        raise ws.CleartextRefused(
            f"{url} is cleartext to a host that is not loopback; use wss://, or declare "
            "allow_cleartext for a relay reached over a private cluster network")
    if scheme == "https":
        conn = http.client.HTTPSConnection(host, port, timeout=timeout_s,
                                           context=ssl.create_default_context())
    else:
        conn = http.client.HTTPConnection(host, port, timeout=timeout_s)
    try:
        with contextlib.closing(conn):
            conn.request("GET", path, headers={"Accept": NIP11_ACCEPT})
            response = conn.getresponse()
            body = response.read(MAX_MESSAGE_BYTES + 1)
    except TimeoutError as exc:
        raise RelayTimeout(f"{url} did not serve its NIP-11 document within "
                           f"{timeout_s}s") from exc
    except (OSError, http.client.HTTPException) as exc:
        raise RelayError(f"cannot read the NIP-11 document of {url}: {exc}") from exc
    if response.status != 200:
        raise RelayError(f"{url} answered the NIP-11 request with HTTP {response.status}")
    try:
        document = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise RelayError(f"the NIP-11 document of {url} is not JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise RelayError(f"the NIP-11 document of {url} is not a JSON object")
    limits = document.get("limitation")
    limits = limits if isinstance(limits, dict) else {}

    def count(name: str) -> int | None:
        return limits[name] if type(limits.get(name)) is int else None

    own = document.get("self")
    nips = document.get("supported_nips")
    return RelayInfo(url=url, name=str(document.get("name", "")),
                     auth_required=limits.get("auth_required") is True,
                     membership_required=limits.get("membership_required") is True,
                     max_limit=count("max_limit"),
                     max_message_length=count("max_message_length"),
                     self_pubkey=own if isinstance(own, str) and _HEX64.match(own) else None,
                     supported_nips=tuple(n for n in nips if type(n) is int)
                     if isinstance(nips, list) else ())


# ------------------------------------------------------------------ subscriptions
class Subscription:
    """An open REQ. `stored()` is the history up to EOSE; `wait()` is the live tail."""

    def __init__(self, client: RelayClient, sub_id: str, flt: dict):
        self._client, self.id, self.filter = client, sub_id, flt
        self._queue: deque[Event] = deque()
        self._seen: set[str] = set()
        self._eose = False
        self._closed_reason: str | None = None
        self._open = True

    def _deliver(self, event: Event) -> None:
        if event.id not in self._seen:
            self._seen.add(event.id)
            self._queue.append(event)

    def _check(self) -> None:
        if self._closed_reason is not None:
            raise RelayRejected("the subscription", self._closed_reason)

    def stored(self) -> list[Event]:
        """Every stored event the relay sends before EOSE, within one wait for the
        whole page."""
        deadline = self._client._deadline()
        while not self._eose:
            self._check()
            self._client._pump(deadline, "the end of stored events (EOSE)")
        events = list(self._queue)
        self._queue.clear()
        return events

    def wait(self, deadline: float) -> Event | None:
        """The next live event, or None once `deadline` (a `time.monotonic()` instant)
        passes with nothing new."""
        while not self._queue:
            self._check()
            try:
                self._client._pump_raw(deadline)
            except ws.WebSocketTimeout:
                return None
        return self._queue.popleft()

    def close(self) -> None:
        if self._open:
            self._open = False
            self._client._subs.pop(self.id, None)
            if self._closed_reason is None:
                with contextlib.suppress(ws.WebSocketClosed):   # nothing left to close
                    self._client._send(["CLOSE", self.id])

    def __enter__(self) -> Subscription:
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()


class RelayClient:
    def __init__(self, url: str, signer: Signer, *, timeout_s: float = DEFAULT_WAIT_S,
                 allow_cleartext: bool = False, clock: Clock = time.time,
                 auth_url: str | None = None):
        """`auth_url` is the URL the relay knows itself by, when that differs from the
        one dialled: a seat inside the cluster dials the Service, and the relay still
        expects its public wss:// URL in the NIP-42 proof."""
        self.url, self.signer, self.timeout_s = url, signer, timeout_s
        self.auth_url = auth_url or url
        self.allow_cleartext, self.clock = allow_cleartext, clock
        # Relay notices are kept as the first, the latest and a count: enough to
        # diagnose with, and a relay that floods them cannot grow this.
        self.first_notice: str | None = None
        self.last_notice: str | None = None
        self.notice_count = 0
        self._ws: ws.WebSocket | None = None
        self._subs: dict[str, Subscription] = {}
        self._awaiting: set[str] = set()
        self._oks: dict[str, tuple[bool, str]] = {}
        # Verified events, in two generations: what the read in progress has touched
        # and what the read before it did. A seat that polls a topic re-reads it whole,
        # and this is what keeps each poll from paying one signature check per event of
        # history. It never holds more than the last two reads brought down.
        self._verified: dict[str, Event] = {}
        self._verified_before: dict[str, Event] = {}
        self._challenge: str | None = None
        self._answered: str | None = None

    # ------------------------------------------------------------------ connection
    def connect(self) -> RelayClient:
        if self._ws is not None:
            raise RelayError(f"already connected to {self.url}")
        self._challenge = self._answered = None     # a challenge belongs to one socket
        self._oks.clear()
        self._awaiting.clear()
        self._ws = ws.connect(self.url, timeout_s=self.timeout_s,
                              allow_cleartext=self.allow_cleartext,
                              max_message_bytes=MAX_MESSAGE_BYTES)
        deadline = self._deadline()
        try:
            while self._challenge is None:
                try:
                    self._pump_raw(deadline)
                except ws.WebSocketTimeout as exc:
                    raise RelayError(
                        f"{self.url} sent no NIP-42 AUTH challenge within {self.timeout_s}s. "
                        "This client only talks to a relay that authenticates every "
                        "socket; a relay that does not is not a private relay") from exc
            self._authenticate()
        except NostrError:
            self.close()
            raise
        return self

    def close(self) -> None:
        if self._ws is not None:
            self._ws.close()
            self._ws = None
        self._subs.clear()
        self._verified.clear()
        self._verified_before.clear()

    def __enter__(self) -> RelayClient:
        return self.connect()

    def __exit__(self, *exc_info) -> None:
        self.close()

    @property
    def pubkey(self) -> str:
        return self.signer.pubkey

    @property
    def notices(self) -> list[str]:
        if self.notice_count == 0:
            return []
        if self.notice_count == 1:
            return [self.first_notice]
        return [self.first_notice, f"(… {self.notice_count - 2} more …)", self.last_notice]

    def _deadline(self) -> float:
        return time.monotonic() + self.timeout_s

    def _send(self, message: list) -> None:
        if self._ws is None:
            raise RelayError(f"not connected to {self.url}")
        self._ws.send_text(dumps(message))

    def _pump_raw(self, deadline: float) -> None:
        """Read and route one relay message; `WebSocketTimeout` at the deadline."""
        if self._ws is None:
            raise RelayError(f"not connected to {self.url}")
        text = self._ws.recv_text(deadline)
        try:
            message = json.loads(text)
        except json.JSONDecodeError as exc:
            raise RelayProtocolError(f"{self.url} sent a frame that is not JSON: {exc}") from exc
        if not isinstance(message, list) or not message or not isinstance(message[0], str):
            raise RelayProtocolError(f"{self.url} sent a frame that is not a relay message")
        verb, args = message[0], message[1:]
        named = bool(args) and isinstance(args[0], str)     # a subscription or event id
        if verb == "EVENT" and len(args) == 2 and named:
            sub = self._subs.get(args[0])
            if sub is None:             # a frame still in flight for a REQ already closed
                return
            event = self._admit(args[1])
            if not matches(sub.filter, event):
                raise RelayProtocolError(
                    f"{self.url} delivered event {event.id[:12]}… that does not match "
                    "the filter that was asked")
            sub._deliver(event)
        elif verb == "EOSE" and len(args) == 1 and named:
            if args[0] in self._subs:
                self._subs[args[0]]._eose = True
        elif verb == "OK" and len(args) >= 2 and named:
            if args[0] in self._awaiting:       # an OK nobody asked for is not kept
                self._oks[args[0]] = (args[1] is True, str(args[2]) if len(args) > 2 else "")
        elif verb == "CLOSED" and named:
            if args[0] in self._subs:
                self._subs[args[0]]._closed_reason = str(args[1]) if len(args) > 1 else ""
        elif verb == "NOTICE" and args:
            self.notice_count += 1
            self.last_notice = str(args[0])
            self.first_notice = self.first_notice or self.last_notice
        elif verb == "AUTH" and len(args) == 1 and named:
            self._challenge = args[0]
        else:
            raise RelayProtocolError(f"{self.url} sent an unexpected {verb!r} message")

    def _admit(self, raw) -> Event:
        """The verified event behind a delivered frame. One this connection already
        verified is recognised only when the frame has the right types and is identical
        to it field for field, so a relay cannot ride a forgery in on a known id."""
        try:
            check_wire_shape(raw)
            known = self._verified.get(raw["id"]) or self._verified_before.get(raw["id"])
            event = known if known is not None and known.to_dict() == raw else verify_event(raw)
        except InvalidEvent as exc:
            raise RelayProtocolError(
                f"{self.url} delivered an event that fails verification ({exc}); "
                "a relay that forwards unverifiable events cannot be trusted") from exc
        self._verified[event.id] = event
        return event

    def _pump(self, deadline: float, awaiting: str) -> None:
        try:
            self._pump_raw(deadline)
        except ws.WebSocketTimeout as exc:
            raise RelayTimeout(f"{self.url} did not send {awaiting} within "
                               f"{self.timeout_s}s (the relay wait in force)") from exc

    def _await_ok(self, event_id: str, what: str, *, written: bool = False) -> str:
        self._awaiting.add(event_id)
        deadline = self._deadline()
        try:
            while event_id not in self._oks:
                self._pump(deadline, f"an OK for {what}")
        except RelayTimeout as exc:
            if written:                 # sent, and the answer is what went missing
                raise RelayTimeout(
                    f"{exc}. The relay may or may not have stored it: run the same "
                    "command again, with the same idempotency key, to find out") from exc
            raise
        finally:
            self._awaiting.discard(event_id)
        accepted, reason = self._oks.pop(event_id)
        if not accepted:
            raise RelayRejected(what, reason)
        return reason

    def _authenticate(self) -> None:
        challenge = self._challenge
        proof = self.sign(AUTH_KIND, [["relay", self.auth_url], ["challenge", challenge]], "")
        self._send(["AUTH", proof.to_dict()])
        self._await_ok(proof.id, "the NIP-42 authentication")
        self._answered = challenge

    def _ready(self) -> None:
        if self._ws is None:
            raise RelayError(f"not connected to {self.url}")
        if self._answered != self._challenge:       # the relay issued a fresh challenge
            self._authenticate()

    # -------------------------------------------------------------------- protocol
    def sign(self, kind: int, tags, content: str, *, created_at: int | None = None) -> Event:
        """An event signed by this connection's key. Every signer hands back a checked
        signature (a local one verifies what it produced, an outside one is verified
        on return), so the event is remembered as verified for when the relay echoes it."""
        stamp = now(self.clock) if created_at is None else created_at
        event = self.signer.sign_event(unsigned(kind, tags, content, stamp))
        self._verified[event.id] = event
        return event

    def publish(self, event: Event) -> str:
        """Send one event and return the relay's OK message. `RelayRejected` if refused."""
        self._ready()
        self._send(["EVENT", event.to_dict()])
        return self._await_ok(event.id, f"event {event.id[:12]}… (kind {event.kind})",
                              written=True)

    def subscribe(self, flt: dict) -> Subscription:
        self._ready()
        sub = Subscription(self, secrets.token_hex(8), flt)
        self._subs[sub.id] = sub
        self._send(["REQ", sub.id, flt])
        return sub

    def subscribe_live(self, flt: dict) -> Subscription:
        """A subscription for what arrives from now on. Returns after EOSE with the one
        stored event the relay may have sent already dropped."""
        sub = self.subscribe({**flt, "limit": LIVE_LIMIT})
        try:
            sub.stored()
        except NostrError:
            sub.close()
            raise
        return sub

    def query(self, flt: dict) -> list[Event]:
        """One REQ, read to EOSE: one page, of at most the filter's `limit`."""
        with self.subscribe(flt) as sub:
            return sub.stored()

    def query_all(self, flt: dict) -> list[Event]:
        """Every stored event matching `flt`, oldest first, or `HistoryTruncated`.

        Pages of `PAGE_LIMIT` walk backwards with `until`, which is inclusive: each
        page re-reads the boundary second and duplicates are dropped by id. A page that
        is full and lies inside one second is the case paging by second cannot get
        past, and it raises instead of returning a history with a hole in it. One
        limit of this check: a relay that silently serves fewer than `PAGE_LIMIT` per
        page could hide such a second. `relay check` compares the relay's advertised
        `max_limit` with `PAGE_LIMIT` for that reason."""
        self._verified_before, self._verified = self._verified, {}
        seen: dict[str, Event] = {}
        until: int | None = None
        while True:
            page = self.query({**flt, "limit": PAGE_LIMIT,
                               **({} if until is None else {"until": until})})
            if len(page) > PAGE_LIMIT:
                raise RelayProtocolError(f"{self.url} answered a REQ for {PAGE_LIMIT} events "
                                         f"with {len(page)}")
            if not page:
                return order(seen.values())
            stamps = [event.created_at for event in page]
            if len(page) == PAGE_LIMIT and min(stamps) == max(stamps):
                raise HistoryTruncated(
                    f"{self.url} holds {PAGE_LIMIT} or more matching events inside the "
                    f"single second {min(stamps)}. A relay pages by second, so the rest of "
                    "that second cannot be reached, and a partial history is not returned")
            fresh = [event for event in page if event.id not in seen]
            seen.update((event.id, event) for event in fresh)
            until = min(stamps) if fresh else min(stamps) - 1

    def request_invite(self, *, relay_pubkey: str | None = None) -> dict:
        """Mint one invite code over this authenticated socket (NIP-43 kind 28935): a
        `REQ {"kinds": [28935], "limit": 1}` that a relay with `memberClaims` answers
        with one relay-signed event carrying `["claim", <code>]`. No admin CLI, no
        kubectl. With `relay_pubkey` (NIP-11 `self`), the event must be signed by it."""
        events = self.query({"kinds": [INVITE_REQUEST_KIND], "limit": 1})
        if not events:
            raise RelayError(
                f"{self.url} answered the NIP-43 invite request (kind {INVITE_REQUEST_KIND}) "
                "with nothing: it does not mint invites over the WebSocket for this key "
                "(memberClaims is off, or it does not implement NIP-43 invite requests). "
                "Mint through the relay's admin CLI instead (--admin, --kubectl, --compose "
                "or --exec)")
        if len(events) != 1:
            raise RelayProtocolError(f"{self.url} answered one invite request with "
                                     f"{len(events)} events")
        event = events[0]
        codes = event.values("claim")
        if len(codes) != 1 or not codes[0]:
            raise RelayProtocolError(f"{self.url} sent a kind {INVITE_REQUEST_KIND} event "
                                     "without exactly one claim tag")
        if relay_pubkey is not None and event.pubkey != relay_pubkey:
            raise RelayProtocolError(
                f"the invite was signed by {event.pubkey[:12]}…, not by the relay key "
                f"{relay_pubkey[:12]}… its NIP-11 document names")
        # How many uses and how long it lives is the relay's policy, not in the event:
        # the shipped relay.yaml gives a member's code one use and seven days.
        return {"code": codes[0], "issued_by": event.pubkey, "created_at": event.created_at,
                "via": "websocket (NIP-43 kind 28935)"}

    def join(self, code: str) -> str:
        """Redeem a single-use invite (NIP-43 kind 28934). The claim is a protected
        event: the relay takes it only from the key that authenticated this socket."""
        claim = self.sign(INVITE_CLAIM_KIND, [list(PROTECTED), ["claim", code]], "")
        self._ready()
        self._send(["EVENT", claim.to_dict()])
        return self._await_ok(claim.id, "the invite claim", written=True)


# -------------------------------------------------------------------------- admin
def invite_code(invite) -> str:
    """The bearer code in an invite, given as the relay prints it (a flat object) or
    wrapped under `invite`."""
    if isinstance(invite, dict) and isinstance(invite.get("invite"), dict):
        invite = invite["invite"]
    code = invite.get("code") if isinstance(invite, dict) else None
    if not isinstance(code, str) or not code:
        raise RelayAdminError("the invite carries no `code`")
    return code


class RelayAdmin:
    """The operator's membership commands, run through the relay's own CLI.

    `exec_prefix` is how to reach that CLI: empty when `ncli` is on this machine,
    `kubectl()` for a Kubernetes StatefulSet, `compose()` for the Docker Compose stack.
    An invite made here is single-use because this wrapper asks for exactly one use
    and checks the relay granted exactly one; the relay's `inviteMaxUses` setting does
    not cap what its admin route issues."""

    def __init__(self, exec_prefix: list[str], *, timeout_s: float,
                 config: str = NCLI_CONFIG):
        self.exec_prefix, self.config, self.timeout_s = list(exec_prefix), config, timeout_s

    @classmethod
    def compose(cls, compose_file: str, *, timeout_s: float, service: str = "relay"):
        return cls(["docker", "compose", "-f", compose_file, "exec", "-T", service],
                   timeout_s=timeout_s)

    @classmethod
    def kubectl(cls, *, timeout_s: float, namespace: str = "nostr-relay",
                pod: str = "nostr-relay-0", container: str = "relay"):
        return cls(["kubectl", "-n", namespace, "exec", pod, "-c", container, "--"],
                   timeout_s=timeout_s)

    def _run(self, *args: str) -> str:
        argv = [*self.exec_prefix, "ncli", "relay", *args, "--config", self.config]
        shown = " ".join(argv)
        try:
            done = subprocess.run(argv, capture_output=True, text=True,
                                  timeout=self.timeout_s, check=False)
        except subprocess.TimeoutExpired as exc:
            raise RelayAdminError(f"`{shown}` gave no answer in {self.timeout_s}s") from exc
        except OSError as exc:
            raise RelayAdminError(f"`{shown}` could not run: {exc}") from exc
        if done.returncode != 0:
            raise RelayAdminError(f"`{shown}` exited {done.returncode}: {done.stderr.strip()}")
        return done.stdout

    def create_invite(self, *, ttl: str = INVITE_TTL) -> dict:
        """One single-use invite, as the relay prints it: `code`, `created_at`,
        `expires_at`, `max_uses`, `uses`. It carries the bearer code, so treat the whole
        value as a secret. Raises unless the relay confirms exactly one unspent use."""
        out = self._run("invites", "create", "--ttl", ttl, "--max-uses", "1", "--json")
        try:
            invite = json.loads(out)
        except json.JSONDecodeError as exc:
            raise RelayAdminError(f"`ncli relay invites create --json` did not print JSON: "
                                  f"{exc}") from exc
        invite_code(invite)
        if invite.get("max_uses") != 1 or invite.get("uses", 0) != 0:
            raise RelayAdminError(
                "the relay created an invite that is not single-use and unspent "
                f"(max_uses={invite.get('max_uses')!r}, uses={invite.get('uses')!r}); it "
                "was not handed out. Revoke it with `ncli relay invites revoke`")
        created, expires = invite.get("created_at"), invite.get("expires_at")
        if type(created) is not int or type(expires) is not int or expires <= created:
            raise RelayAdminError("the relay created an invite without a usable expiry; it "
                                  "was not handed out")
        return invite

    def add_member(self, pubkey: str) -> str:
        return self._run("members", "add", pubkey).strip()

    def remove_member(self, pubkey: str) -> str:
        return self._run("members", "remove", pubkey).strip()
