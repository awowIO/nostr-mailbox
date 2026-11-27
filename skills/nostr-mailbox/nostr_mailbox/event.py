"""The NIP-01 event: its id, its signature, and the one function that lets it in.

`verify_event` is the only way an event received from anywhere becomes an `Event`.
It recomputes the id from the canonical serialization, requires the supplied id to
match, and checks the BIP-340 signature over that digest. A relay checks the same
thing on ingestion; every seat repeats it, because a valid signature is the only
proof of authorship a seat ever gets. Authority is a separate question, answered by
the campaign's roster (`profile.verify_directive`)."""
from __future__ import annotations

import hashlib
import json
import re
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass

from . import secp256k1
from .errors import NostrError

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_HEX128 = re.compile(r"^[0-9a-f]{128}$")
_FIELDS = frozenset({"id", "pubkey", "created_at", "kind", "tags", "content", "sig"})
MAX_KIND = 65_535                       # NIP-01: kind is an integer between 0 and 65535

Clock = Callable[[], float]


# Seconds a seat waits for one relay or signer answer unless told otherwise: the
# long-poll default the Valkey mailbox skill shipped with (`watch --wait-seconds`), kept
# so both mailboxes pace an agent the same way. Every timeout error names the value in
# force.
DEFAULT_WAIT_S = 25.0


class InvalidEvent(NostrError):
    """An event that is malformed, tampered with, or signed by someone else."""


@dataclass(frozen=True)
class Event:
    """A signed event. Build one with `Signer.sign_event` or `verify_event`, never by
    hand: the constructor checks nothing."""
    id: str
    pubkey: str
    created_at: int
    kind: int
    tags: tuple[tuple[str, ...], ...]
    content: str
    sig: str

    def to_dict(self) -> dict:
        return {"id": self.id, "pubkey": self.pubkey, "created_at": self.created_at,
                "kind": self.kind, "tags": [list(t) for t in self.tags],
                "content": self.content, "sig": self.sig}

    def values(self, name: str) -> list[str]:
        """The first value of every tag called `name`."""
        return [t[1] for t in self.tags if t[0] == name and len(t) > 1]

    def has_tag(self, name: str) -> bool:
        return any(t[0] == name for t in self.tags)

    @property
    def wire_bytes(self) -> int:
        """Size of the complete serialized signed event."""
        return len(dumps(self.to_dict()).encode())


def dumps(value) -> str:
    """Compact JSON the way NIP-01 serializes it: no whitespace, UTF-8 left verbatim."""
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False)


def serialize(pubkey: str, created_at: int, kind: int, tags, content: str) -> bytes:
    try:
        return dumps([0, pubkey, created_at, kind, tags, content]).encode("utf-8")
    except UnicodeEncodeError as exc:
        raise InvalidEvent(f"event text is not encodable as UTF-8: {exc}") from exc


def event_id(pubkey: str, created_at: int, kind: int, tags, content: str) -> str:
    return hashlib.sha256(serialize(pubkey, created_at, kind, tags, content)).hexdigest()


def _check_shape(pubkey, created_at, kind, tags, content) -> None:
    if not isinstance(pubkey, str) or not _HEX64.fullmatch(pubkey):
        raise InvalidEvent("pubkey must be 64 lowercase hex characters")
    if type(created_at) is not int or created_at < 0:
        raise InvalidEvent("created_at must be a non-negative integer")
    if type(kind) is not int or not 0 <= kind <= MAX_KIND:
        raise InvalidEvent(f"kind must be an integer in 0..{MAX_KIND}")
    if not isinstance(content, str):
        raise InvalidEvent("content must be a string")
    if not isinstance(tags, (list, tuple)):
        raise InvalidEvent("tags must be an array")
    for tag in tags:
        if (not isinstance(tag, (list, tuple)) or not tag
                or not all(isinstance(item, str) for item in tag)):
            raise InvalidEvent("every tag must be a non-empty array of strings")


def unsigned(kind: int, tags: Iterable[Iterable[str]], content: str, created_at: int) -> dict:
    """The four fields an author chooses; the signer adds pubkey, id and sig."""
    return {"created_at": created_at, "kind": int(kind),      # an IntEnum member is a number
            "tags": [list(t) for t in tags], "content": content}


def sign_with_secret(template: dict, secret: bytes, pubkey: str | None = None) -> Event:
    """Sign an `unsigned` template with a raw secret key. `pubkey` saves re-deriving it
    for a caller that already derived it from this same secret."""
    try:
        pubkey = pubkey or secp256k1.pubkey_gen(secret).hex()
        fields = (pubkey, template["created_at"], template["kind"], template["tags"],
                  template["content"])
        _check_shape(*fields)
        ident = event_id(*fields)
        sig = secp256k1.schnorr_sign(bytes.fromhex(ident), secret).hex()
    except secp256k1.Secp256k1Error as exc:
        raise InvalidEvent(f"cannot sign: {exc}") from exc
    return Event(id=ident, pubkey=pubkey, created_at=fields[1], kind=fields[2],
                 tags=tuple(tuple(t) for t in fields[3]), content=fields[4], sig=sig)


def check_wire_shape(raw) -> tuple:
    """The five signed fields of a received event object after checking every field's
    exact type, or `InvalidEvent`. Exact matters: in Python `True == 1`, so a relay could
    otherwise pass a boolean where a number was signed."""
    if not isinstance(raw, dict):
        raise InvalidEvent("an event is a JSON object")
    if set(raw) != _FIELDS:
        missing, extra = sorted(_FIELDS - set(raw)), sorted(set(raw) - _FIELDS)
        raise InvalidEvent(f"event fields are wrong (missing {missing}, unexpected {extra})")
    fields = (raw["pubkey"], raw["created_at"], raw["kind"], raw["tags"], raw["content"])
    _check_shape(*fields)
    if not isinstance(raw["id"], str) or not _HEX64.fullmatch(raw["id"]):
        raise InvalidEvent("id must be 64 lowercase hex characters")
    if not isinstance(raw["sig"], str) or not _HEX128.fullmatch(raw["sig"]):
        raise InvalidEvent("sig must be 128 lowercase hex characters")
    return fields


def verify_event(raw) -> Event:
    """The verified `Event` behind `raw`, or `InvalidEvent`. Nothing else constructs an
    Event from received data."""
    if isinstance(raw, Event):
        raw = raw.to_dict()
    fields = check_wire_shape(raw)
    ident, sig = raw["id"], raw["sig"]
    if event_id(*fields) != ident:
        raise InvalidEvent(f"id {ident[:12]}… is not the hash of the event: it was altered "
                           "after signing, or serialized differently")
    if not secp256k1.schnorr_verify(bytes.fromhex(ident), bytes.fromhex(fields[0]),
                                    bytes.fromhex(sig)):
        raise InvalidEvent(f"signature on {ident[:12]}… does not verify under its pubkey")
    return Event(id=ident, pubkey=fields[0], created_at=fields[1], kind=fields[2],
                 tags=tuple(tuple(t) for t in fields[3]), content=fields[4], sig=sig)


# --------------------------------------------------------------------- kind classes
REGULAR, REPLACEABLE, EPHEMERAL, ADDRESSABLE = "regular", "replaceable", "ephemeral", "addressable"


def kind_class(kind: int) -> str:
    """How a relay stores this kind (NIP-01). Ephemeral events are forwarded and never
    written; replaceable and addressable ones overwrite their predecessor; everything
    else is kept."""
    if kind in (0, 3) or 10_000 <= kind < 20_000:
        return REPLACEABLE
    if 20_000 <= kind < 30_000:
        return EPHEMERAL
    if 30_000 <= kind < 40_000:
        return ADDRESSABLE
    return REGULAR


def coordinate(event: Event) -> tuple | None:
    """The slot a replaceable or addressable event occupies, None for the other classes."""
    cls = kind_class(event.kind)
    if cls == REPLACEABLE:
        return event.kind, event.pubkey
    if cls == ADDRESSABLE:
        return event.kind, event.pubkey, (event.values("d") or [""])[0]
    return None


def supersedes(new: Event, old: Event) -> bool:
    """NIP-01 replacement: the later timestamp wins, a tie goes to the lower id."""
    return (new.created_at, old.id) > (old.created_at, new.id)


# -------------------------------------------------------------------------- filters
def matches(flt: dict, event: Event) -> bool:
    """NIP-01 filter matching: every condition present must hold."""
    for key, wanted in flt.items():
        if key == "ids":
            if event.id not in wanted:
                return False
        elif key == "authors":
            if event.pubkey not in wanted:
                return False
        elif key == "kinds":
            if event.kind not in wanted:
                return False
        elif key == "since":
            if event.created_at < wanted:
                return False
        elif key == "until":
            if event.created_at > wanted:
                return False
        elif key.startswith("#") and len(key) == 2:
            if not set(event.values(key[1])) & set(wanted):
                return False
        elif key != "limit":
            raise InvalidEvent(f"unsupported filter key {key!r}")
    return True


def order(events: Iterable[Event]) -> list[Event]:
    """Oldest first, ties broken by id: the one journal order every reader agrees on."""
    return sorted(events, key=lambda e: (e.created_at, e.id))


def now(clock: Clock = time.time) -> int:
    return int(clock())
