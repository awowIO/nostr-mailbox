"""The Topic Epoch Key Ring: which epoch keys this seat holds for one encrypted topic,
how they reach the members who should hold them, and how the keeper keeps it so.

A ring is `epoch → 32-byte key`. Records of the topic name their epoch
(`["epoch", "<n>"]`) and are encrypted under `campaign_conversation_key(K_n, campaign)`.
Who can read what follows from who holds which keys:

- `--history all`: a newcomer is given epochs 1..current and replays the whole journal;
- `--history from-now`: the topic first rotates to current + 1, the existing members
  are given the new epoch, and the newcomer gets only that one;
- revoke: the member is removed from the group, the topic rotates, and the new epoch
  goes to everyone who remains.

Keys travel two ways, both encrypted to one key: inside the single-use `nm1_…` invite
token, or as a NIP-59 gift wrap (`giftwrap`) whose rumor is kind 8892:

    tags    [["h", <topic>], ["t", <campaign>]]
    content {"schema": "cf.keyring/1", "campaign", "topic", "name", "epochs": {"<n>": hex},
             "current", "mode": "create|full_history|forward_only|rotate"}

A seat accepts a delivery only from itself or a topic admin (the topic's creator, the
campaign's operator keys, the inviter named in its token). The keeper (the seat that
created the topic) wraps its whole ring to itself after every change, with the
`registry` it keeps beside the keys, so the ring survives the loss of this machine.

On disk: `<home>/keyrings/<topic>.json`, mode 0600 in a 0700 directory, written whole
or not at all, refused when anyone else can read it."""
from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import stat
import tempfile
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path

from . import giftwrap
from .event import Event, dumps, now
from .groups import Topic
from .identity import Signer
from .profile import EpochKeys, Kind, ProfileError, Trust
from .relay import RelayClient

SCHEMA = "cf.keyring/1"
FILE_SCHEMA = "cf.keyring-file/1"
MODES = ("create", "full_history", "forward_only", "rotate")
HISTORY = ("all", "from-now")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_EPOCH = re.compile(r"^[1-9][0-9]{0,8}$")
_PRIVATE, _PRIVATE_DIR = 0o600, 0o700


class KeyRingError(ProfileError):
    """A keyring file or delivery that is unreadable, someone else's, or contradicts
    the keys already held."""


def keyring_path(home: Path, name: str) -> Path:
    return Path(home) / "keyrings" / f"{name}.json"


def code_digest(code: str) -> str:
    """How the keeper remembers an invite code it handed out: by digest, never the code."""
    return hashlib.sha256(code.encode()).hexdigest()


def _epochs(raw, what: str) -> dict[int, str]:
    if not isinstance(raw, dict) or not raw:
        raise KeyRingError(f"{what}: epochs must be a non-empty object of epoch → key")
    out = {}
    for epoch, key in raw.items():
        if not isinstance(epoch, str) or not _EPOCH.match(epoch):
            raise KeyRingError(f"{what}: epoch {epoch!r} is not a positive integer")
        if not isinstance(key, str) or not _HEX64.match(key):
            raise KeyRingError(f"{what}: the key of epoch {epoch} is not 64 lowercase hex")
        out[int(epoch)] = key
    return out


def _encode_epochs(epochs: Mapping[int, str]) -> dict[str, str]:
    return {str(epoch): epochs[epoch] for epoch in sorted(epochs)}


def empty_registry() -> dict:
    """The keeper's ledger. `rev` counts its backups: a restore takes a backup only when
    its `rev` is higher than the ledger held, never by timestamp, because several
    backups can share one second."""
    return {"members": {}, "invites": {}, "delivered": {}, "rev": 0}


@dataclass
class KeyRing:
    """This seat's ring for one topic. `registry` is present only on the keeper."""
    path: Path
    name: str
    campaign: str
    epochs: dict[int, str] = field(default_factory=dict)
    authorities: set[str] = field(default_factory=set)
    registry: dict | None = None
    seen: set[str] = field(default_factory=set)

    def __repr__(self) -> str:                      # never the keys
        return (f"KeyRing({self.name!r}, epochs={sorted(self.epochs)}, "
                f"keeper={self.registry is not None})")

    # ---------------------------------------------------------------- file
    @classmethod
    def open(cls, home: Path, name: str, campaign: str) -> KeyRing:
        """The ring on disk, or an empty one (nothing is written until `save`)."""
        path = keyring_path(home, name)
        try:
            mode = stat.S_IMODE(path.stat().st_mode)
        except FileNotFoundError:
            return cls(path=path, name=name, campaign=campaign)
        if mode & ~_PRIVATE:
            raise KeyRingError(f"{path} is mode {mode:04o}; a keyring holds secret keys and "
                               f"must be 0600 (chmod 600 {path})")
        try:
            body = json.loads(path.read_text())
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise KeyRingError(f"cannot read the keyring {path}: {exc}") from exc
        if not isinstance(body, dict) or body.get("schema") != FILE_SCHEMA:
            raise KeyRingError(f"{path} is not a {FILE_SCHEMA} keyring file")
        if (body.get("name"), body.get("campaign")) != (name, campaign):
            raise KeyRingError(f"{path} is the keyring of {body.get('name')!r} in campaign "
                               f"{body.get('campaign')!r}, not {name!r} in {campaign!r}")
        ring = cls(path=path, name=name, campaign=campaign,
                   epochs=_epochs(body["epochs"], str(path)) if body.get("epochs") else {},
                   authorities=set(body.get("authorities", [])),
                   registry=body.get("registry"), seen=set(body.get("seen", [])))
        if ring.registry is not None:
            _check_registry(ring.registry, str(path))
        return ring

    def save(self) -> None:
        body = {"schema": FILE_SCHEMA, "name": self.name, "campaign": self.campaign,
                "current": self.current, "epochs": _encode_epochs(self.epochs),
                "authorities": sorted(self.authorities), "seen": sorted(self.seen)}
        if self.registry is not None:
            body["registry"] = self.registry
        self.path.parent.mkdir(mode=_PRIVATE_DIR, parents=True, exist_ok=True)
        fd, staged = tempfile.mkstemp(dir=self.path.parent, prefix=f".{self.name}.",
                                      suffix=".part")          # mkstemp: born 0600
        try:
            with os.fdopen(fd, "w") as fh:
                json.dump(body, fh, indent=2)
                fh.write("\n")
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(staged, self.path)
        finally:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(staged)

    # ---------------------------------------------------------------- keys
    @property
    def current(self) -> int:
        """The epoch this seat writes under: the newest it holds."""
        return max(self.epochs, default=0)

    def keys(self) -> EpochKeys | None:
        return EpochKeys(self.campaign, self.epochs, self.current) if self.epochs else None

    def merge(self, epochs: Mapping[int, str]) -> list[int]:
        """Add `epochs`, returning the ones that are new. A different key for an epoch
        already held is a conflict: nothing is merged, and the error says which."""
        clash = [e for e, key in epochs.items() if self.epochs.get(e, key) != key]
        if clash:
            raise KeyRingError(f"a delivery for topic {self.name!r} carries a different key "
                               f"for epoch(s) {sorted(clash)} than the one held; nothing "
                               "was merged")
        new = sorted(set(epochs) - set(self.epochs))
        self.epochs.update(epochs)
        return new

    def rotate(self) -> int:
        """Open epoch current + 1 under a fresh 32-byte key, and return its number."""
        epoch = self.current + 1
        self.epochs[epoch] = os.urandom(32).hex()
        return epoch

    def content(self, mode: str, epochs: Iterable[int], *, backup: bool = False) -> dict:
        chosen = sorted(set(epochs))
        body = {"schema": SCHEMA, "campaign": self.campaign, "topic": self.name,
                "name": self.name, "epochs": _encode_epochs({e: self.epochs[e] for e in chosen}),
                "current": max(chosen), "mode": mode}
        if backup and self.registry is not None:
            body["registry"] = self.registry
        return body


def _check_registry(registry, what: str) -> None:
    if (not isinstance(registry, dict)
            or not all(isinstance(registry.get(k), dict)
                       for k in ("members", "invites", "delivered"))
            or type(registry.get("rev")) is not int):
        raise KeyRingError(f"{what}: the registry must hold members, invites, delivered "
                           "and an integer rev")


def parse_delivery(rumor: giftwrap.Rumor) -> dict:
    """The content of an epoch-key rumor, checked field by field."""
    try:
        body = json.loads(rumor.content)
    except json.JSONDecodeError as exc:
        raise KeyRingError(f"epoch-key delivery is not JSON: {exc}") from exc
    if not isinstance(body, dict) or body.get("schema") != SCHEMA:
        raise KeyRingError(f"epoch-key delivery is not {SCHEMA}")
    if body.get("mode") not in MODES:
        raise KeyRingError(f"epoch-key delivery mode {body.get('mode')!r} is not one of {MODES}")
    for name in ("campaign", "topic"):
        if not isinstance(body.get(name), str):
            raise KeyRingError(f"epoch-key delivery has no {name}")
    epochs = _epochs(body.get("epochs"), "epoch-key delivery")
    if body.get("current") != max(epochs):
        raise KeyRingError("epoch-key delivery names a current epoch it does not carry")
    if rumor.values("h") != [body["topic"]] or rumor.values("t") != [body["campaign"]]:
        raise KeyRingError("epoch-key delivery's tags do not name the topic it carries")
    if "registry" in body:
        _check_registry(body["registry"], "epoch-key delivery")
    return {**body, "epochs": epochs}


# --------------------------------------------------------------------- on the wire
def deliver(relay: RelayClient, signer: Signer, ring: KeyRing, recipient: str,
            epochs: Iterable[int], mode: str, *, backup: bool = False) -> Event:
    """Gift-wrap `epochs` of `ring` to `recipient` and publish it."""
    body = ring.content(mode, epochs, backup=backup)
    event = giftwrap.wrap(signer, recipient, int(Kind.EPOCH_KEYS),
                          [["h", ring.name], ["t", ring.campaign]], dumps(body),
                          created_at=now(relay.clock))
    relay.publish(event)
    return event


def backup(relay: RelayClient, signer: Signer, ring: KeyRing, mode: str) -> Event:
    """The whole ring, with the keeper's registry (its `rev` advanced), wrapped to this
    key itself. The ring is saved first, so the backup never runs ahead of the file."""
    if ring.registry is not None:
        ring.registry["rev"] += 1
    ring.save()
    return deliver(relay, signer, ring, signer.pubkey, ring.epochs, mode, backup=True)


def sync(relay: RelayClient, signer: Signer, trust: Trust, ring: KeyRing) -> dict:
    """Fetch every gift wrap addressed to this key and merge the epoch keys meant for
    this ring. A delivery from a key that is not a topic admin, or one that contradicts
    a held key, is reported and not merged. The ring is saved if anything changed."""
    me = signer.pubkey
    admins: frozenset[str] | None = None
    imported: list[int] = []
    rejected: list[dict] = []
    restored = False
    changed = False
    for event in relay.query_all({"kinds": [giftwrap.GIFT_WRAP_KIND], "#p": [me]}):
        if event.id in ring.seen:
            continue
        try:
            rumor = giftwrap.unwrap(event, signer)
            if rumor.kind != Kind.EPOCH_KEYS:
                ring.seen.add(event.id)     # a gift wrap for another purpose
                changed = True
                continue
            body = parse_delivery(rumor)
        except (giftwrap.GiftWrapError, KeyRingError) as exc:
            rejected.append({"id": event.id, "reason": str(exc)})
            ring.seen.add(event.id)
            changed = True
            continue
        if (body["topic"], body["campaign"]) != (ring.name, ring.campaign):
            continue                        # another ring's; that ring's sync takes it
        if rumor.author != me:
            if admins is None:
                admins = (Topic(relay, ring.name, operators=trust.operator_pubkeys).admins()
                          | ring.authorities)
            if rumor.author not in admins:
                rejected.append({"id": event.id, "reason": f"from {rumor.author[:12]}…, which "
                                 "is not an admin of this topic; not merged"})
                continue                    # not marked seen: it is asked again next time
        try:
            new = ring.merge(body["epochs"])
        except KeyRingError as exc:
            rejected.append({"id": event.id, "reason": str(exc)})
            continue
        imported += new
        if (rumor.author == me and "registry" in body
                and (ring.registry is None or body["registry"]["rev"] > ring.registry["rev"])):
            ring.registry = body["registry"]
            restored = True
        ring.seen.add(event.id)
        changed = True
    if changed:
        ring.save()
    return {"topic": ring.name, "held_epochs": sorted(ring.epochs), "current": ring.current,
            "imported_epochs": sorted(set(imported)), "registry_restored": restored,
            "keeper": ring.registry is not None, "rejected": rejected}


# ------------------------------------------------------------------- the keeper
def _owed(ring: KeyRing, record: dict) -> list[int]:
    start = 1 if record.get("history") == "all" else int(record.get("from_epoch", ring.current))
    return [epoch for epoch in sorted(ring.epochs) if epoch >= start]


def reconcile(relay: RelayClient, signer: Signer, ring: KeyRing, topic: Topic) -> dict:
    """The keeper's one duty, safe to repeat: every current member of the topic holds
    every epoch it is owed, and nobody else is sent anything.

    First the invites: a join request carrying a code this keeper handed out makes its
    author the invitee (and the keeper publishes the 9000 that says so). Then, per
    member, what it is owed (all epochs for `--history all`, epochs from its first one
    for `from-now`, the current one for a member some other admin added) minus what it
    was already sent, in one gift wrap per member."""
    registry = ring.registry
    if registry is None:
        raise KeyRingError(f"this seat holds topic {ring.name!r}'s keys but not its "
                           "registry: only the keeper (the seat that created it) admits "
                           "and revokes")
    me = signer.pubkey
    members, invites, delivered = (registry["members"], registry["invites"],
                                   registry["delivered"])
    redeemed = []
    for request in topic.join_requests():
        codes = request.values("code")
        invite = invites.get(code_digest(codes[0])) if codes else None
        if invite is None or invite.get("redeemed_by") or request.pubkey == me:
            continue
        invite["redeemed_by"] = request.pubkey
        members[request.pubkey] = {"history": invite["history"], "from_epoch": invite["from_epoch"],
                                   "name": invite.get("for"), "via": "invite"}
        delivered[request.pubkey] = sorted(set(delivered.get(request.pubkey, []))
                                           | set(invite["epochs"]))
        redeemed.append(request.pubkey)
    standing = topic.members()
    for pubkey in redeemed:
        if pubkey not in standing:
            topic.put_user(pubkey)
    standing = topic.members()
    sent: dict[str, list[int]] = {}
    for pubkey in sorted(standing - {me}):
        record = members.setdefault(pubkey, {"history": "from-now", "from_epoch": ring.current,
                                             "name": None, "via": "added by another admin"})
        had = set(delivered.get(pubkey, []))
        owed = [epoch for epoch in _owed(ring, record) if epoch not in had]
        if not owed:
            continue
        mode = ("rotate" if had else
                "full_history" if record.get("history") == "all" else "forward_only")
        deliver(relay, signer, ring, pubkey, owed, mode)
        delivered[pubkey] = sorted(had | set(owed))
        sent[pubkey] = owed
        ring.save()                         # each delivery recorded before the next
    return {"redeemed_invites": redeemed, "delivered": sent,
            "members": sorted(standing - {me})}


def forget(ring: KeyRing, pubkey: str) -> None:
    """Drop what the keeper recorded about a member it is revoking."""
    if ring.registry is None:
        raise KeyRingError(f"only the keeper of topic {ring.name!r} revokes its members")
    ring.registry["members"].pop(pubkey, None)
    ring.registry["delivered"].pop(pubkey, None)
