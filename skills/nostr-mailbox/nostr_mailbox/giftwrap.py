"""NIP-59 gift wraps: an unsigned rumor, sealed (kind 13) and wrapped (kind 1059) for
one recipient, so a relay stores and forwards it without reading it.

    rumor  {pubkey, created_at, kind, tags, content, id}   no signature: deniable
    seal   kind 13, tags [], signed by the rumor's author,
           content = NIP-44 v2 (rumor JSON) under conv(author, recipient)
    wrap   kind 1059, tags [["p", recipient]],
           content = NIP-44 v2 (seal JSON) under conv(wrap signer, recipient)

One departure from NIP-59, made on purpose: the wrap is signed by the sender's own
member key, not a throwaway one. A private relay binds every event's author to the key
that authenticated the socket (NIP-42), so a wrap from an unknown key is refused at the
door. What this costs: the relay sees who wrapped for whom, and when. What it keeps:
the content, the inner kind and the rumor's tags. `unwrap` accepts either form, because
it only ever derives the key from the wrap's own pubkey.

The relay serves a 1059 only to the key in its `p` tag (`recipientOnlyKinds`)."""
from __future__ import annotations

import json
from dataclasses import dataclass

from . import nip44
from .event import Event, InvalidEvent, NostrError, dumps, event_id, unsigned, verify_event
from .identity import Signer, pairwise_key

SEAL_KIND = 13
GIFT_WRAP_KIND = 1059
_RUMOR_FIELDS = frozenset({"id", "pubkey", "created_at", "kind", "tags", "content"})


class GiftWrapError(NostrError):
    """A gift wrap that is not for this key, does not decrypt, or whose layers disagree
    about who wrote it."""


@dataclass(frozen=True)
class Rumor:
    """What a gift wrap carried, once opened. `author` is the key that signed the seal,
    which the rumor's own pubkey had to equal."""
    id: str
    author: str
    kind: int
    created_at: int
    tags: tuple[tuple[str, ...], ...]
    content: str
    wrap_id: str

    def values(self, name: str) -> list[str]:
        return [t[1] for t in self.tags if t[0] == name and len(t) > 1]


def wrap(signer: Signer, recipient: str, kind: int, tags, content: str, *,
         created_at: int) -> Event:
    """A kind-1059 gift wrap for `recipient` carrying a rumor written by `signer`."""
    conv = pairwise_key(signer, recipient)
    rumor = {"pubkey": signer.pubkey, "created_at": created_at, "kind": int(kind),
             "tags": [list(t) for t in tags], "content": content}
    rumor["id"] = event_id(rumor["pubkey"], created_at, rumor["kind"], rumor["tags"], content)
    seal = signer.sign_event(unsigned(SEAL_KIND, [], nip44.encrypt(dumps(rumor), conv),
                                      created_at))
    return signer.sign_event(unsigned(GIFT_WRAP_KIND, [["p", recipient]],
                                      nip44.encrypt(dumps(seal.to_dict()), conv), created_at))


def _open(payload: str, conv: bytes, what: str):
    try:
        return json.loads(nip44.decrypt(payload, conv))
    except nip44.Nip44Error as exc:
        raise GiftWrapError(f"the {what} does not decrypt for this key: {exc}") from exc
    except (json.JSONDecodeError, RecursionError) as exc:   # nesting deep enough to recurse
        raise GiftWrapError(f"the {what} decrypted to something that is not JSON") from exc


def unwrap(event: Event, signer: Signer) -> Rumor:
    """The rumor inside `event`, or `GiftWrapError`. Checked, in order: it is a 1059
    addressed to this key alone; the seal is a validly signed kind 13 with no tags;
    the rumor names the seal's signer as its author and its id is its own hash."""
    if event.kind != GIFT_WRAP_KIND:
        raise GiftWrapError(f"kind {event.kind} is not a gift wrap ({GIFT_WRAP_KIND})")
    if event.values("p") != [signer.pubkey]:
        raise GiftWrapError("this gift wrap is not addressed to this key alone")
    sealed = _open(event.content, pairwise_key(signer, event.pubkey), "gift wrap")
    try:
        seal = verify_event(sealed)
    except InvalidEvent as exc:             # its words can name the sender's own keys
        raise GiftWrapError("the seal inside is not a validly signed event") from exc
    if seal.kind != SEAL_KIND or seal.tags:
        raise GiftWrapError("the inner event is not a NIP-59 seal (kind 13, no tags)")
    rumor = _open(seal.content, pairwise_key(signer, seal.pubkey), "seal")
    if not isinstance(rumor, dict) or set(rumor) != _RUMOR_FIELDS:
        raise GiftWrapError("the rumor is not an unsigned event (id, pubkey, created_at, "
                            "kind, tags, content)")
    if rumor["pubkey"] != seal.pubkey:
        raise GiftWrapError(f"the rumor claims author {str(rumor['pubkey'])[:12]}… but the "
                            f"seal is signed by {seal.pubkey[:12]}…: refused as an "
                            "impersonation")
    fields = (rumor["pubkey"], rumor["created_at"], rumor["kind"], rumor["tags"],
              rumor["content"])
    try:
        ident = event_id(*fields)
    except (InvalidEvent, TypeError) as exc:
        raise GiftWrapError(f"the rumor is malformed: {exc}") from exc
    if (ident != rumor["id"] or type(rumor["kind"]) is not int
            or type(rumor["created_at"]) is not int or not isinstance(rumor["content"], str)
            or not isinstance(rumor["tags"], list)
            or not all(isinstance(t, list) and t and all(isinstance(v, str) for v in t)
                       for t in rumor["tags"])):
        raise GiftWrapError("the rumor's id is not the hash of its fields, or a field has "
                            "the wrong type")
    return Rumor(id=ident, author=seal.pubkey, kind=rumor["kind"],
                 created_at=rumor["created_at"],
                 tags=tuple(tuple(t) for t in rumor["tags"]), content=rumor["content"],
                 wrap_id=event.id)
