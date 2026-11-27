"""The campaign on the wire: `CampaignSession` for typed records, and
`NostrRelayChannelBackend`, the mailbox (`inbox`, `bus`, campaign topics) behind the
`ChannelBackend` protocol.

There is no server-side queue here. A stock relay stores signed events and answers
filters; it offers no conditional write. So every mailbox notion is rebuilt from signed
facts each seat can check, and every write that must not race is read back afterwards:

- a message is one logical thing per (author, idempotency key). Its canonical event is
  the earliest copy; receipts, acks, replies and history all name that one, so a retry
  or a second writer with the same key never yields a second message;
- a seat's cursor is the set of acks that seat itself signed, so a crash between
  delivery and ack redelivers the message, and nothing needs unsubscribing;
- a seal is an operator-signed manifest of the exact message ids in the journal.
  A sealed journal is those ids, in that order, and nothing else: a write that was in
  flight when the seal was made is outside it, and a listed message that has gone
  missing is an error, not a shorter history;
- a head (checkpoint, route, condition) only moves forward: an exact retry writes
  nothing, an older or conflicting write is refused, and the winner is read back.

What that costs, stated plainly: `watch`, `history` and `triage` re-read the topic from
the relay on every call. That is fine for `inbox`, `bus` and a wave topic that gets
sealed; it has not been measured at fleet scale.

No fallback: an unreachable relay raises. Nothing here reaches for a second relay, a
file, or a weaker policy."""
from __future__ import annotations

import contextlib
import hashlib
import os
import re
import tempfile
import time
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Protocol, runtime_checkable

from . import keyring as keyrings
from . import nip44
from .blossom import Blob, BlossomClient
from .event import DEFAULT_WAIT_S, Clock, Event, NostrError, now, supersedes
from .identity import Signer
from .profile import (
    EVERY_SEAT,
    MAX_EVENT_BYTES,
    Checkpoint,
    Claim,
    Condition,
    Decision,
    Directive,
    DirectiveLedger,
    EventTooLarge,
    Handoff,
    Heartbeat,
    Kind,
    ProfileError,
    Route,
    Trust,
    admit,
    encode,
    fields,
    resolve_directives,
    slug,
)
from .relay import RelayClient

INBOX, BUS = "inbox", "bus"
TERMINAL_DISPOSITIONS = ("handled", "ignored", "rejected")      # the mailbox wire's own
DISPOSITIONS = (*TERMINAL_DISPOSITIONS, "deferred")             # deferred stays pending
_MESSAGE_KIND = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")          # the mailbox wire's rule
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
# The mailbox skill's compaction tripwire (its rule 2.5): a target holding this many
# unhandled pointers, or one this old, is due for one coherent sweep.
COMPACTION_MAX_ITEMS = 5
COMPACTION_MAX_AGE_HOURS = 48.0


class NotAuthorized(ProfileError):
    """This key may not write that record; refused before anything is sent."""


class TopicSealed(ProfileError):
    """The topic's journal was closed by an operator."""


class SealBroken(ProfileError):
    """A sealed journal that can no longer be reproduced from the relay."""


class IdempotencyConflict(ProfileError):
    """The idempotency key was already used for a different message."""


class StaleRecord(ProfileError):
    """A head write that is older than, or disagrees with, what is already recorded."""


class UnknownMessage(ProfileError):
    """No such message on the topic."""


class PartialBatch(NostrError):
    """A command over several ids that stopped part-way. It says which ids completed,
    which one failed and why, and which were never tried: re-running the same command
    is safe, because a completed id returns its recorded receipt."""

    def __init__(self, completed: list, failed: str, error: Exception, remaining: list[str]):
        super().__init__(f"stopped at {failed[:12]}… after {len(completed)} completed: {error}")
        self.completed, self.failed = completed, failed
        self.error, self.remaining = error, remaining


@dataclass(frozen=True)
class Message:
    """One mailbox message. The fields above the line are what an author writes; the
    transport fills the rest from the signed event when a message is read."""
    body: str
    kind: str = "message"
    subject: str = ""
    refs: tuple[str, ...] = ()
    reply_to: str | None = None
    # ---- set on read
    id: str | None = None
    topic: str | None = None
    author: str | None = None
    created_at: int | None = None
    key: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.body, str) or not self.body.strip():
            raise ProfileError("a message needs a body")
        if not isinstance(self.kind, str) or not _MESSAGE_KIND.fullmatch(self.kind):
            raise ProfileError(f"message kind {self.kind!r} must match {_MESSAGE_KIND.pattern}")
        if self.reply_to is not None and not _HEX64.fullmatch(self.reply_to):
            raise ProfileError("reply_to is the id of the message answered")

    @property
    def said(self) -> tuple:
        """What the author wrote: the identity of the message under its key."""
        return self.body, self.kind, self.subject, self.refs, self.reply_to

    def to_payload(self, key: str) -> dict:
        return {"body": self.body, "kind": self.kind, "subject": self.subject,
                "refs": list(self.refs), "reply_to": self.reply_to, "key": key}

    def to_dict(self) -> dict:
        return {"id": self.id, "topic": self.topic, "author": self.author,
                "created_at": self.created_at, "kind": self.kind, "subject": self.subject,
                "body": self.body, "refs": list(self.refs), "reply_to": self.reply_to,
                "key": self.key}


@dataclass(frozen=True)
class Receipt:
    """What a write came to. `id` is always the canonical event. `bytes_used` of
    `bytes_cap` is the event against the campaign event cap, reported on every post so
    a caller sees how close it runs."""
    backend: str
    topic: str
    id: str
    accepted: bool
    duplicate: bool = False
    detail: str = ""
    bytes_used: int = 0
    bytes_cap: int = MAX_EVENT_BYTES
    disposition: str | None = None
    result_ref: str | None = None

    def to_dict(self) -> dict:
        out = dict(self.__dict__)
        out["bytes_used_pct"] = round(100 * self.bytes_used / self.bytes_cap, 1)
        return out


@runtime_checkable
class ChannelBackend(Protocol):
    """The transport contract every backend keeps (file, SQLite, Nostr relay, workspace
    mailbox): the same five verbs, idempotency keys and dispositions."""
    name: str

    def post(self, topic: str, message: Message, *, key: str) -> Receipt: ...

    def watch(self, topic: str, seat: str, *, wait_s: float) -> list[Message]: ...

    def ack(self, topic: str, seat: str, msg_id: str, *, disposition: str,
            result_ref: str | None) -> Receipt: ...

    def history(self, topic: str, *, after: str | None) -> Iterator[Message]: ...

    def seal(self, topic: str) -> Receipt: ...


def _newest[T](rows: list[tuple[Event, T]]) -> tuple[Event, T] | None:
    best = None
    for row in rows:
        if best is None or supersedes(row[0], best[0]):
            best = row
    return best


class CampaignSession:
    """One key, one authenticated socket, one campaign. `rejected` collects every
    record read from the relay that was not a well-formed record of this campaign, with
    the reason: skipped, and never silently.

    A campaign encrypted with an epoch keyring (`Trust.keyring`) is given its ring:
    on connect the session fetches the epoch keys delivered to this key since it last
    looked, so it never writes under an epoch a revocation has retired."""

    def __init__(self, trust: Trust, signer: Signer, *, timeout_s: float = DEFAULT_WAIT_S,
                 clock: Clock = time.time, keyring: keyrings.KeyRing | None = None,
                 sync_keys: bool = True):
        self.trust, self.clock, self.signer, self.timeout_s = trust, clock, signer, timeout_s
        self.declared = trust
        self.keyring, self.sync_keys = keyring, sync_keys
        self.key_sync: dict | None = None
        self.relay = RelayClient(trust.relay, signer, timeout_s=timeout_s,
                                 allow_cleartext=trust.allow_cleartext, clock=clock,
                                 auth_url=trust.relay_auth_url)
        self.rejected: list[tuple[str, str]] = []
        self._blobs: BlossomClient | None = None
        self._load_ring()

    def _load_ring(self) -> None:
        keys = self.keyring.keys() if self.keyring is not None else None
        self.trust = self.declared if keys is None else self.declared.with_ring(keys)

    def connect(self) -> CampaignSession:
        self.relay.connect()
        if self.keyring is not None and self.sync_keys:
            try:
                self.sync_keyring()
            except NostrError:
                self.close()
                raise
        return self

    def sync_keyring(self) -> dict:
        """Merge the epoch keys delivered to this key, and load the ring."""
        if self.keyring is None:
            raise ProfileError("this campaign has no epoch keyring")
        self.key_sync = keyrings.sync(self.relay, self.signer, self.declared, self.keyring)
        self.rejected += [(r["id"], f"epoch keys: {r['reason']}")
                          for r in self.key_sync["rejected"]]
        self._load_ring()
        return self.key_sync

    def close(self) -> None:
        self.relay.close()

    def __enter__(self) -> CampaignSession:
        return self.connect()

    def __exit__(self, *exc_info) -> None:
        self.close()

    @property
    def pubkey(self) -> str:
        return self.relay.pubkey

    def blobs(self) -> BlossomClient:
        """The campaign's blob store: its declared origin, or the relay's own."""
        if self._blobs is None:
            self._blobs = BlossomClient(
                self.trust.blossom_origin, self.signer, server=self.trust.blossom_server,
                timeout_s=self.timeout_s, allow_cleartext=self.trust.allow_cleartext,
                clock=self.clock)
        return self._blobs

    # ------------------------------------------------- blobs under the epoch keys
    def put_sealed_blob(self, data: bytes) -> tuple[Blob, int]:
        """Upload `data` encrypted under the current epoch (NIP-44 v2, as ASCII), so a
        blob is exactly as readable as the records of its epoch. Returns the stored
        blob (its sha256 is the ciphertext's) and the epoch."""
        ring = self.trust.ring
        if ring is None:
            raise ProfileError("this campaign is not encrypted; a blob is uploaded as it is")
        ciphertext = nip44.encrypt_bytes(data, ring.conversation_key(ring.current))
        return self.blobs().upload(ciphertext.encode("ascii")), ring.current

    def open_sealed_blob(self, ciphertext: bytes) -> tuple[bytes, int]:
        """The plaintext of a blob sealed under one of the held epochs, newest tried
        first (the MAC decides), and that epoch."""
        ring = self.trust.ring
        if ring is None:
            raise ProfileError("this campaign is not encrypted; download the blob as it is")
        try:
            text = ciphertext.decode("ascii")
        except UnicodeDecodeError as exc:
            raise ProfileError("the blob is not a sealed blob (not NIP-44 ASCII)") from exc
        for epoch in ring.held():
            with contextlib.suppress(nip44.Nip44Error):
                return nip44.decrypt_bytes(text, ring.conversation_key(epoch)), epoch
        raise ProfileError(
            f"the blob does not open under any of the {len(ring.held())} epoch key(s) held "
            f"here ({sorted(ring.held())}): it was sealed in an epoch this seat was not "
            "given, or uploaded in plaintext (fetch it with --plain)")

    def get_sealed_blob(self, sha256: str, dest: str | Path) -> dict:
        """Download, verify, decrypt and write a sealed blob to `dest`, whole or not."""
        data, epoch = self.open_sealed_blob(self.blobs().download(sha256))
        dest = Path(dest)
        fd, partial = tempfile.mkstemp(dir=dest.parent, prefix=f".{dest.name}.")
        try:
            with os.fdopen(fd, "wb") as out:
                out.write(data)
            os.replace(partial, dest)
        except BaseException:
            Path(partial).unlink(missing_ok=True)
            raise
        return {"sha256": sha256, "epoch": epoch, "bytes": len(data),
                "plaintext_sha256": hashlib.sha256(data).hexdigest()}

    # ------------------------------------------------------------------ primitives
    def sign_record(self, kind: Kind, record_type: str, payload: dict, *,
                    topic: str | None = None, tags=(), created_at: int | None = None) -> Event:
        return self.relay.sign(int(kind), [*self.trust.tags(topic), *tags],
                               encode(self.trust, record_type, payload), created_at=created_at)

    def publish_record(self, event: Event, record_type: str) -> Event:
        size = event.wire_bytes
        if size > MAX_EVENT_BYTES:
            raise EventTooLarge(
                f"this {record_type} is {size:,} bytes, {100 * size / MAX_EVENT_BYTES:.0f}% "
                f"of the {MAX_EVENT_BYTES:,}-byte campaign event cap; nothing was sent. "
                "Upload the body as a blob and send its sha256")
        self.relay.publish(event)
        return event

    def publish(self, kind: Kind, record_type: str, payload: dict, *,
                topic: str | None = None, tags=()) -> Event:
        return self.publish_record(
            self.sign_record(kind, record_type, payload, topic=topic, tags=tags), record_type)

    def admit_all[T](self, events: Iterable[Event], kind: Kind, record_type: str,
                     parse: Callable[[Event, dict], T], *,
                     topic: str | None = None) -> list[tuple[Event, T]]:
        """Each event through the one receive-side boundary: the size cap, the
        campaign envelope, then the record's own shape and its tags. What fails any of
        them goes to `rejected` with the reason; the rest is returned."""
        out = []
        for event in events:
            try:
                payload = admit(event, self.trust, kind=kind, record_type=record_type,
                                topic=topic)
                out.append((event, parse(event, payload)))
            except ProfileError as exc:
                self.rejected.append((event.id, f"{record_type}: {exc}"))
        return out

    def records[T](self, kind: Kind, record_type: str, parse: Callable[[Event, dict], T], *,
                   topic: str | None = None, where: dict | None = None
                   ) -> list[tuple[Event, T]]:
        """Every stored record of one type, oldest first, admitted and parsed."""
        flt = {"kinds": [int(kind)], **self.trust.scope(topic), **(where or {})}
        return self.admit_all(self.relay.query_all(flt), kind, record_type, parse,
                              topic=topic)

    # ------------------------------------------------------------- ephemeral: liveness
    def heartbeat(self, beat: Heartbeat) -> Event:
        return self.publish(Kind.HEARTBEAT, "heartbeat", beat.to_payload())

    def watch_heartbeats(self, *, wait_s: float,
                         stop_after: int | None = None) -> list[tuple[Heartbeat, Event]]:
        """Heartbeats that arrive in the next `wait_s` seconds, returning early once
        `stop_after` of them were heard. The relay stores none, so there is no history
        to ask for."""
        deadline = time.monotonic() + wait_s
        beats: list[tuple[Heartbeat, Event]] = []
        flt = {"kinds": [int(Kind.HEARTBEAT)], **self.trust.scope()}
        with self.relay.subscribe_live(flt) as live:
            while ((stop_after is None or len(beats) < stop_after)
                   and (event := live.wait(deadline)) is not None):
                beats += [(beat, got) for got, beat in self.admit_all(
                    [event], Kind.HEARTBEAT, "heartbeat",
                    lambda _, payload: Heartbeat.from_payload(payload))]
        return beats

    # --------------------------------------------------- addressable: replaced in place
    def _heads[T](self, kind: Kind, record_type: str, parse: Callable[[dict], T],
                  name_of: Callable[[T], str], authors: Iterable[str],
                  name: str | None = None) -> list[tuple[Event, T]]:
        """Heads of one type by the keys allowed to write them. A head whose `d` tag
        does not name the record in its own payload is not a head."""
        def strict(event: Event, payload: dict) -> T:
            record = parse(payload)
            if event.values("d") != [self.trust.address(name_of(record))]:
                raise ProfileError("d tag does not name the record it carries")
            return record

        where: dict = {"authors": sorted(authors)}
        if name is not None:
            where["#d"] = [self.trust.address(name)]
        return self.records(kind, record_type, strict, where=where)

    def _replace[T](self, kind: Kind, record_type: str, record: T,
                    parse: Callable[[dict], T], name_of: Callable[[T], str],
                    guard: Callable[[T], None]) -> tuple[Event, bool]:
        """Write the new head of an addressable slot so that it wins, or refuse.

        The held head is read first: an identical one means this is a retry and nothing
        is written; otherwise `guard` raises if the write is older or conflicting. The
        new head is stamped strictly after the held one (NIP-01 gives a same-second tie
        to the lower id, which would let the older head survive). Then the head is read
        back: a relay has no conditional write, so if another writer with this key won
        the slot in between, that is reported here and not discovered later."""
        name = name_of(record)
        mine = [self.pubkey]
        held = _newest(self._heads(kind, record_type, parse, name_of, mine, name))
        if held is not None:
            if held[1] == record:
                return held[0], False
            guard(held[1])
        stamp = max(now(self.clock), held[0].created_at + 1 if held else 0)
        event = self.publish_record(
            self.sign_record(kind, record_type, record.to_payload(),
                             tags=[["d", self.trust.address(name)]], created_at=stamp),
            record_type)
        won = _newest(self._heads(kind, record_type, parse, name_of, mine, name))
        if won is None or won[0].id != event.id:
            raise StaleRecord(
                f"this {record_type} was sent, but another writer using this key holds "
                f"the slot ({won[0].id[:12] + '…' if won else 'nothing readable'}). One "
                "key should have one writer; read the head again before retrying")
        return event, True

    def put_checkpoint(self, checkpoint: Checkpoint) -> tuple[Event, bool]:
        """Publish a seat's checkpoint pointer. Returns the head's event and whether
        anything was written: an exact retry returns the event already there."""
        def forward(held: Checkpoint) -> None:
            if (checkpoint.attempt, checkpoint.seq) <= (held.attempt, held.seq):
                if checkpoint.seq == held.seq and checkpoint.attempt == held.attempt:
                    raise StaleRecord(
                        f"checkpoint {held.seq} of {held.seat} is already recorded with "
                        f"digest {held.sha256[:12]}…; a different pointer for the same "
                        "sequence is a conflict, not an update")
                raise StaleRecord(
                    f"checkpoint (attempt {checkpoint.attempt}, sequence {checkpoint.seq}) is "
                    f"behind the recorded (attempt {held.attempt}, sequence {held.seq}) of "
                    f"{held.seat}; nothing was written")
            if (checkpoint.seq == held.seq + 1 and checkpoint.parent_sha256
                    and checkpoint.parent_sha256 != held.sha256):
                raise StaleRecord(
                    f"checkpoint {checkpoint.seq} declares parent "
                    f"{checkpoint.parent_sha256[:12]}…, but the recorded checkpoint "
                    f"{held.seq} is {held.sha256[:12]}…; nothing was written")

        return self._replace(Kind.CHECKPOINT_HEAD, "checkpoint", checkpoint,
                             Checkpoint.from_payload, lambda c: c.seat, forward)

    def get_checkpoint(self, seat: str, *, author: str | None = None) -> Checkpoint | None:
        """The newest checkpoint `author` (this key by default) published for `seat`.
        A checkpoint lives under its writer's key, so another member publishing the same
        seat name writes a different slot and is never returned here."""
        newest = _newest(self._heads(Kind.CHECKPOINT_HEAD, "checkpoint",
                                     Checkpoint.from_payload, lambda c: c.seat,
                                     [author or self.pubkey], slug(seat, "seat")))
        return newest[1] if newest else None

    def put_route(self, route: Route) -> tuple[Event, bool]:
        if self.pubkey not in self.trust.leads:
            raise NotAuthorized("the Route Board is written by a lead or operator key of "
                                "this campaign; this key is neither, so nothing was sent")
        return self._replace(Kind.ROUTE_HEAD, "route", route, Route.from_payload,
                             lambda r: r.route, lambda held: None)

    def routes(self) -> list[Route]:
        """The Route Board: the newest head per route among the keys allowed to write it."""
        by_route: dict[str, list] = {}
        for row in self._heads(Kind.ROUTE_HEAD, "route", Route.from_payload,
                               lambda r: r.route, self.trust.leads):
            by_route.setdefault(row[1].route, []).append(row)
        return [_newest(by_route[name])[1] for name in sorted(by_route)]

    # ------------------------------------------- the learning loop: condition heads
    def _condition_heads(self, name: str | None = None) -> list[tuple[Event, Condition]]:
        return self._heads(Kind.CONDITION_HEAD, "condition", Condition.from_payload,
                           lambda c: c.condition, self.trust.reviewers, name)

    @staticmethod
    def _latest(rows: list[tuple[Event, Condition]]) -> tuple[Event, Condition] | None:
        """Across reviewers the furthest revision stands; a tie goes to the newer head."""
        best = None
        for row in rows:
            if (best is None or row[1].rev > best[1].rev
                    or (row[1].rev == best[1].rev and supersedes(row[0], best[0]))):
                best = row
        return best

    def condition_head(self, name: str) -> tuple[Event, Condition] | None:
        return self._latest(self._condition_heads(slug(name, "condition")))

    def conditions(self) -> list[tuple[Event, Condition]]:
        by_name: dict[str, list] = {}
        for row in self._condition_heads():
            by_name.setdefault(row[1].condition, []).append(row)
        return [self._latest(by_name[name]) for name in sorted(by_name)]

    def open_condition(self, condition: Condition) -> tuple[Event, bool]:
        """Declare an acceptance condition at revision 1. From then on only decisions
        move it."""
        if self.pubkey not in self.trust.reviewers:
            raise NotAuthorized("a condition is opened by a reviewer or operator key of "
                                "this campaign; nothing was sent")
        if condition.rev != 1 or condition.state != "open":
            raise ProfileError("a condition is opened at revision 1, open")
        standing = self.condition_head(condition.condition)
        if standing is not None and standing[1] != condition:
            raise StaleRecord(
                f"condition {condition.condition!r} already stands at revision "
                f"{standing[1].rev}; a decision moves it, opening it again does not")

        def unopened(held: Condition) -> None:
            raise StaleRecord(f"condition {held.condition!r} is already open at revision "
                              f"{held.rev}")

        return self._replace(Kind.CONDITION_HEAD, "condition", condition,
                             Condition.from_payload, lambda c: c.condition, unopened)

    # --------------------------------------------------------- regular: durable facts
    @staticmethod
    def _claim(event: Event, payload: dict) -> Claim:
        claim = Claim.from_payload(payload)
        if len(event.values("e")) > 1:
            raise ProfileError("a claim links at most one goal event")
        return claim

    def claim(self, claim: Claim, *, goal_event: str | None = None) -> Event:
        return self.publish(Kind.CLAIM, "claim", claim.to_payload(),
                            tags=[["e", goal_event]] if goal_event else [])

    def claims(self) -> list[tuple[Claim, Event]]:
        return [(claim, event) for event, claim in self.records(Kind.CLAIM, "claim", self._claim)]

    def decisions(self, *, claim_id: str | None = None,
                  authors: Iterable[str] | None = None) -> list[tuple[Decision, Event]]:
        """Reviewer rulings, oldest first. Only keys allowed to review count."""
        def parse(event: Event, payload: dict) -> Decision:
            decision = Decision.from_payload(payload)
            if event.values("e") != [decision.claim]:
                raise ProfileError("e tag does not name the claim decided")
            return decision

        where: dict = {"authors": sorted(authors or self.trust.reviewers)}
        if claim_id is not None:
            where["#e"] = [claim_id]
        return [(d, e) for e, d in self.records(Kind.DECISION, "decision", parse, where=where)]

    def decide(self, claim_id: str, *, outcome: str, reason: str, next_action: str,
               statement: str = "", reopen_if: str = "") -> tuple[Decision, Condition, bool]:
        """Rule on one claim and move its condition one revision.

        Returns the decision, the condition as it now stands, and whether this call
        found the ruling already made. It is safe to repeat: the decision is looked up
        by claim before anything is written, and a head left behind by an interrupted
        run is brought forward on the retry. A reviewer never rules on its own claim."""
        if self.pubkey not in self.trust.reviewers:
            raise NotAuthorized("a claim is decided by a reviewer or operator key of this "
                                "campaign; nothing was sent")
        found = self.records(Kind.CLAIM, "claim", self._claim, where={"ids": [claim_id]})
        if not found:
            raise ProfileError(f"no claim {claim_id[:12]}… on this campaign")
        claim_event, claim = found[0]
        if claim_event.pubkey == self.pubkey:
            raise NotAuthorized("a claim is not reviewed by the key that made it; nothing "
                                "was sent")
        standing = self.condition_head(claim.condition)
        if standing is None:
            raise ProfileError(f"condition {claim.condition!r} was never opened; a reviewer "
                               "opens it before claims against it can be decided")
        head = standing[1]
        mine = self.decisions(claim_id=claim_id, authors=[self.pubkey])
        if mine:
            decision, decision_event = mine[0]
        else:
            if claim.condition_rev != head.rev:
                raise StaleRecord(
                    f"the claim was made against revision {claim.condition_rev} of "
                    f"{claim.condition!r}, which now stands at revision {head.rev}. The "
                    "claimant submits again against what is open now; nothing was written")
            if outcome == "accepted" and claim.effect == "narrows" and not statement.strip():
                raise ProfileError("accepting a claim that narrows the condition needs the "
                                   "narrowed statement")
            decision = Decision(claim=claim_id, condition=claim.condition,
                                condition_rev=head.rev, outcome=outcome, reason=reason,
                                next_action=next_action, statement=statement,
                                reopen_if=reopen_if, candidate_digest=claim.candidate_digest)
            decision_event = self.publish(Kind.DECISION, "decision", decision.to_payload(),
                                          tags=[["e", claim_id]])
        if head.last_decision == decision_event.id:
            return decision, head, True
        if head.rev != decision.condition_rev:
            raise StaleRecord(
                f"the ruling on {claim_id[:12]}… was made at revision "
                f"{decision.condition_rev} of {claim.condition!r}, and the condition has "
                f"since moved to revision {head.rev} without it. Reconcile by hand")

        def forward(held: Condition) -> None:
            if held.rev > head.rev:
                raise StaleRecord(f"this key already holds revision {held.rev} of "
                                  f"{held.condition!r}")

        moved = head.after(claim, decision, decision_event.id)
        self._replace(Kind.CONDITION_HEAD, "condition", moved, Condition.from_payload,
                      lambda c: c.condition, forward)
        return decision, moved, bool(mine)

    def handoff(self, packet: Handoff, *, for_seat: str | None = None) -> Event:
        payload = packet.to_payload()
        if for_seat is not None:
            payload["for_seat"] = slug(for_seat, "seat")
        return self.publish(Kind.HANDOFF, "handoff", payload)

    def handoffs(self, *, for_seat: str | None = None,
                 author: str | None = None) -> list[tuple[Handoff, Event, str | None]]:
        """Handoff packets, oldest first, each with its signed event and the seat it
        names (None: nobody in particular). With `for_seat`, those for that seat or for
        nobody; with `author`, those one key signed. Any member can send a packet: a
        packet is a colleague's note, and who signed it is part of reading it."""
        def parse(_: Event, payload: dict) -> tuple[str | None, Handoff]:
            addressed = payload.pop("for_seat", None)
            if addressed is not None:
                slug(addressed, "seat")
            return addressed, Handoff.from_payload(payload)

        where = {"authors": [author]} if author else None
        return [(packet, event, addressed) for event, (addressed, packet)
                in self.records(Kind.HANDOFF, "handoff", parse, where=where)
                if for_seat is None or addressed in (None, for_seat)]

    def directives(self) -> DirectiveLedger:
        """Every directive offered on the relay, verified and ordered. Events from keys
        outside the roster are fetched too, so a forgery shows up as rejected with its
        reason instead of vanishing in a filter."""
        offered = self.relay.query_all({"kinds": [int(Kind.DIRECTIVE)], **self.trust.scope()})
        return resolve_directives(offered, self.trust)

    def directive(self, text: str, *, audience: tuple[str, ...] = (EVERY_SEAT,),
                  graph_digest: str = "", on_top_of: str | None = None) -> Event:
        """Issue the next operator directive. With directives held, `on_top_of` names
        the one this builds on; if that one has rivals for its place, this directive
        overrules them, which is how an operator settles a fork."""
        if self.pubkey not in self.trust.operator_pubkeys:
            raise NotAuthorized("only an operator key of this campaign issues directives; "
                                "nothing was sent")
        ledger = self.directives()
        overrules: tuple[str, ...] = ()
        if on_top_of is None:
            if ledger.held:
                raise ProfileError(
                    f"{len(ledger.held)} directive(s) are held: "
                    + "; ".join(f"{d.event_id[:12]}… {why}" for d, why in ledger.held)
                    + ". Name the one to build on with on_top_of")
            base = ledger.head
        else:
            held = [d for d, _ in ledger.held]
            known = {d.event_id: d for d in (*ledger.in_force, *held)}
            if on_top_of not in known:
                raise ProfileError(f"no verified directive {on_top_of[:12]}… to build on")
            base = known[on_top_of]
            overrules = tuple(sorted(d.event_id for d in held if d.event_id != base.event_id
                                     and (d.seq, d.prev) == (base.seq, base.prev)))
        directive = Directive(text=text, seq=base.seq + 1 if base else 1,
                              prev=base.event_id if base else None,
                              audience=tuple(audience), graph_digest=graph_digest,
                              overrules=overrules)
        return self.publish(Kind.DIRECTIVE, "directive", directive.to_payload())


@dataclass(frozen=True)
class _Journal:
    messages: list[Message]         # canonical, in journal order
    alias: dict[str, str]           # any physical copy's id → its canonical id
    sealed: bool


class NostrRelayChannelBackend:
    """`ChannelBackend` over a private, invite-gated Nostr relay."""
    name = "nostr-relay"

    def __init__(self, session: CampaignSession, *, deliver_own: bool = False):
        self.session, self.deliver_own = session, deliver_own

    @property
    def _trust(self) -> Trust:
        return self.session.trust

    def _key_tag(self, topic: str, key: str) -> str:
        """An opaque, exact-match handle for an idempotency key: keys are built from
        campaign, wave and task names, which stay out of relay-indexed tags."""
        scoped = "\x1f".join((self._trust.campaign, topic, key))
        return hashlib.sha256(scoped.encode()).hexdigest()

    # --------------------------------------------------------- receive-side parsers
    def _message(self, topic: str) -> Callable[[Event, dict], Message]:
        def parse(event: Event, payload: dict) -> Message:
            got = fields(payload, {"body": str, "kind": str, "key": str},
                         {"subject": str, "refs": list, "reply_to": str})
            if not got["key"]:
                raise ProfileError("empty idempotency key")
            if event.values("i") != [self._key_tag(topic, got["key"])]:
                raise ProfileError("i tag is not the digest of the message's own key")
            reply = got.get("reply_to")
            if event.values("e") != ([reply] if reply else []):
                raise ProfileError("e tag does not match reply_to")
            return Message(body=got["body"], kind=got["kind"],
                           subject=got.get("subject", ""), refs=tuple(got.get("refs", ())),
                           reply_to=reply, id=event.id, topic=topic, author=event.pubkey,
                           created_at=event.created_at, key=got["key"])
        return parse

    @staticmethod
    def _ack(event: Event, payload: dict) -> dict:
        got = fields(payload, {"seat": str, "msg_id": str, "disposition": str},
                     {"result_ref": str, "note": str})
        slug(got["seat"], "seat")
        if got["disposition"] not in DISPOSITIONS:
            raise ProfileError(f"disposition {got['disposition']!r} is not one of {DISPOSITIONS}")
        if event.values("e") != [got["msg_id"]]:
            raise ProfileError("e tag does not name the message acked")
        return got

    def _seal_ids(self, payload: dict) -> list[str]:
        got = fields(payload, {"topic": str, "count": int, "manifest_sha256": str},
                     {"ids": list})
        if "ids" in got:
            ids = got["ids"]
        else:                               # too many to list in one event: a blob holds them
            ids = self.session.blobs().download(got["manifest_sha256"]).decode().split("\n")
            ids = [i for i in ids if i]
        if (len(ids) != got["count"] or len(set(ids)) != len(ids)
                or not all(_HEX64.fullmatch(i) for i in ids)
                or hashlib.sha256("\n".join(ids).encode()).hexdigest() != got["manifest_sha256"]):
            raise ProfileError("seal manifest does not match its own count and digest")
        return ids

    def _seal(self, topic: str) -> tuple[Event, list[str]] | None:
        """The operator seal on the topic and the message ids it lists, if any. A seal
        from any other key is not one; neither is one without a manifest."""
        def parse(_: Event, payload: dict) -> list[str]:
            if payload.get("topic") != topic:
                raise ProfileError("seals another topic")
            return self._seal_ids(payload)

        seals = self.session.records(
            Kind.SEAL, "seal", parse, topic=topic,
            where={"authors": sorted(self._trust.operator_pubkeys)})
        return seals[0] if seals else None

    def _read(self, topic: str, seal: tuple[Event, list[str]] | None) -> _Journal:
        """The topic's journal. Open: one canonical message per (author, key), in
        (time, id) order. Sealed: exactly the ids the seal lists, in the order it lists
        them."""
        physical: dict[str, Message] = {}
        first: dict[tuple, Message] = {}
        alias: dict[str, str] = {}
        for _, message in self.session.records(Kind.MESSAGE, "message", self._message(topic),
                                               topic=topic):
            physical[message.id] = message
            alias[message.id] = first.setdefault((message.author, message.key), message).id
        def linked(message: Message) -> Message:
            """A reply to a discarded copy is a reply to the message it was a copy of."""
            target = alias.get(message.reply_to, message.reply_to)
            return message if target == message.reply_to else replace(message, reply_to=target)

        if seal is None:
            return _Journal([linked(m) for m in first.values()], alias, sealed=False)
        missing = [ident for ident in seal[1] if ident not in physical]
        if missing:
            raise SealBroken(
                f"topic {topic!r} was sealed with {len(seal[1])} message(s) and "
                f"{len(missing)} of them are no longer on the relay (first: "
                f"{missing[0][:12]}…). A sealed journal is not served with holes in it")
        listed = set(seal[1])
        self.session.rejected += [(ident, "message: outside the sealed journal")
                                  for ident in physical if ident not in listed]
        return _Journal([linked(physical[ident]) for ident in seal[1]], alias, sealed=True)

    def _acks(self, topic: str, where: dict) -> list[tuple[Event, dict]]:
        return self.session.records(Kind.ACK, "ack", self._ack, topic=topic, where=where)

    @staticmethod
    def _settles(topic: str, got: dict) -> bool:
        """Does this ack settle its message? On `inbox` a settlement has to say where
        the work went (handled) or why there is none (ignored, rejected); an ack that
        says neither settles nothing, whoever wrote it and with whatever client."""
        if got["disposition"] not in TERMINAL_DISPOSITIONS:
            return False
        if topic != INBOX:
            return True
        if got["disposition"] == "handled":
            return bool(got.get("result_ref"))
        return bool(got.get("result_ref") or got.get("note"))

    @staticmethod
    def _require_settlement(topic: str, disposition: str, result_ref: str | None,
                            note: str | None) -> None:
        if topic != INBOX or disposition not in TERMINAL_DISPOSITIONS:
            return
        if disposition == "handled" and not result_ref:
            raise ProfileError("a handled inbox pointer needs result_ref: the PR, commit or "
                               "issue that absorbed it")
        if disposition != "handled" and not (result_ref or note):
            raise ProfileError(f"an inbox pointer marked {disposition} needs a note or a "
                               "result_ref saying why")

    # ----------------------------------------------------------------- the protocol
    def _publish(self, topic: str, message: Message, key: str) -> Event:
        tags = [["i", self._key_tag(topic, key)]]
        if message.reply_to:
            tags.append(["e", message.reply_to])
        return self.session.publish(Kind.MESSAGE, "message", message.to_payload(key),
                                    topic=topic, tags=tags)

    def post(self, topic: str, message: Message, *, key: str) -> Receipt:
        """Publish `message` once under `key`. The receipt names the canonical event:
        if this key was used before, or another writer with this key got there first,
        that is the earlier event, and `duplicate` says so."""
        if not key:
            raise ProfileError("a post needs an idempotency key")
        if self._seal(topic) is not None:
            raise TopicSealed(f"topic {topic!r} is sealed; nothing was sent")
        mine = {"authors": [self.session.pubkey], "#i": [self._key_tag(topic, key)]}
        parse = self._message(topic)
        earlier = self.session.records(Kind.MESSAGE, "message", parse, topic=topic, where=mine)
        if earlier:
            if earlier[0][1].said != message.said:
                raise IdempotencyConflict(
                    f"key {key!r} already carries a different message on {topic!r} "
                    f"({earlier[0][0].id[:12]}…); nothing was sent")
            return Receipt(backend=self.name, topic=topic, id=earlier[0][0].id, accepted=True,
                           duplicate=True, detail="already posted under this key",
                           bytes_used=earlier[0][0].wire_bytes)
        sent = self._publish(topic, message, key)
        # a relay has no "insert if absent": read back who holds the key now
        standing = self.session.records(Kind.MESSAGE, "message", parse, topic=topic, where=mine)
        first = standing[0] if standing else (sent, message)
        if first[0].id == sent.id:
            return Receipt(backend=self.name, topic=topic, id=sent.id, accepted=True,
                           bytes_used=sent.wire_bytes)
        if first[1].said != message.said:
            raise IdempotencyConflict(
                f"key {key!r} was used at the same moment for a different message on "
                f"{topic!r}. The earlier one ({first[0].id[:12]}…) stands; this one was "
                "sent and no reader will show it. Post it again under a key of its own")
        return Receipt(backend=self.name, topic=topic, id=first[0].id, accepted=True,
                       duplicate=True, bytes_used=first[0].wire_bytes,
                       detail="another writer with this key published first; its event is "
                              "the canonical one")

    def _pending(self, topic: str, seat: str) -> list[Message]:
        journal = self._read(topic, self._seal(topic))
        done = {journal.alias.get(got["msg_id"], got["msg_id"])
                for _, got in self._acks(topic, {"authors": [self.session.pubkey]})
                if got["seat"] == seat and self._settles(topic, got)}
        return [m for m in journal.messages
                if m.id not in done and (self.deliver_own or m.author != self.session.pubkey)]

    def watch(self, topic: str, seat: str, *, wait_s: float) -> list[Message]:
        """Messages on `topic` that `seat` has not settled, oldest first. With none
        pending, waits up to `wait_s` for the next one. The live subscription opens
        before history is read, so nothing can arrive unseen between the two. Delivery
        is at least once: a message stays pending until this seat acks it."""
        slug(seat, "seat")
        deadline = time.monotonic() + wait_s
        flt = {"kinds": [int(Kind.MESSAGE)], **self._trust.scope(topic)}
        with self.session.relay.subscribe_live(flt) as live:
            pending = self._pending(topic, seat)
            while not pending and live.wait(deadline) is not None:
                pending = self._pending(topic, seat)
        return pending

    def _canonical(self, topic: str, msg_id: str) -> str:
        """The canonical id of the message `msg_id` is a copy of."""
        parse = self._message(topic)
        found = self.session.records(Kind.MESSAGE, "message", parse, topic=topic,
                                     where={"ids": [msg_id]})
        if not found:
            raise UnknownMessage(f"no message {msg_id[:12]}… on topic {topic!r}")
        message = found[0][1]
        copies = self.session.records(
            Kind.MESSAGE, "message", parse, topic=topic,
            where={"authors": [message.author], "#i": [self._key_tag(topic, message.key)]})
        return copies[0][0].id if copies else msg_id

    def ack(self, topic: str, seat: str, msg_id: str, *, disposition: str,
            result_ref: str | None = None, note: str | None = None) -> Receipt:
        """Record what `seat` did with a message. The first settlement stands: acking
        again, with whatever disposition, returns the recorded one."""
        slug(seat, "seat")
        if disposition not in DISPOSITIONS:
            raise ProfileError(f"disposition {disposition!r} must be one of {DISPOSITIONS}")
        self._require_settlement(topic, disposition, result_ref, note)
        target = self._canonical(topic, msg_id)
        mine = {"authors": [self.session.pubkey], "#e": [target]}

        def recorded() -> tuple[Event, dict] | None:
            return next(((event, got) for event, got in self._acks(topic, mine)
                         if got["seat"] == seat and self._settles(topic, got)), None)

        def receipt(event: Event, got: dict, detail: str) -> Receipt:
            return Receipt(backend=self.name, topic=topic, id=event.id, accepted=True,
                           duplicate=bool(detail), detail=detail, bytes_used=event.wire_bytes,
                           disposition=got["disposition"], result_ref=got.get("result_ref"))

        first = recorded()
        if first is not None:
            return receipt(*first, "already settled by this seat")
        payload = {"seat": seat, "msg_id": target, "disposition": disposition,
                   "result_ref": result_ref, "note": note}
        sent = self.session.publish(Kind.ACK, "ack", payload, topic=topic, tags=[["e", target]])
        if disposition in TERMINAL_DISPOSITIONS:
            first = recorded()              # two writers for one seat: the earlier stands
            if first is not None and first[0].id != sent.id:
                return receipt(*first, "another writer for this seat settled it first; "
                                       "that settlement stands")
        return receipt(sent, payload, "")

    def ack_many(self, topic: str, seat: str, msg_ids: list[str], **settlement) -> list[Receipt]:
        """`ack` for several messages. If one fails, `PartialBatch` reports what
        completed before it."""
        done: list[Receipt] = []
        for index, msg_id in enumerate(msg_ids):
            try:
                done.append(self.ack(topic, seat, msg_id, **settlement))
            except NostrError as exc:
                raise PartialBatch(done, msg_id, exc, msg_ids[index + 1:]) from exc
        return done

    def history(self, topic: str, *, after: str | None = None,
                seen: Iterable[str] = ()) -> Iterator[Message]:
        """The journal, oldest first, without consuming anything.

        `after` continues from a message the caller already has. On a sealed topic the
        journal is fixed, and that is an exact position. On an open topic it is not:
        events are ordered by their author's clock in whole seconds, so a message
        published later can sort earlier within the same second. There `after` returns
        everything from the cursor's second onward except the cursor itself and
        whatever is listed in `seen`. That can repeat a message; it never skips one
        published in or after that second. A message stamped earlier than the cursor
        by a slow clock is not found this way: for work that must not be missed, use
        `watch` and `ack`."""
        journal = self._read(topic, self._seal(topic))
        if after is None:
            return iter(journal.messages)
        after = journal.alias.get(after, after)
        position = {m.id: i for i, m in enumerate(journal.messages)}
        if after not in position:
            raise UnknownMessage(f"no message {after[:12]}… on topic {topic!r} to "
                                 "continue from")
        if journal.sealed:
            return iter(journal.messages[position[after] + 1:])
        boundary = journal.messages[position[after]].created_at
        skip = {after, *(journal.alias.get(i, i) for i in seen)}
        return iter([m for m in journal.messages
                     if m.created_at >= boundary and m.id not in skip])

    def seal(self, topic: str) -> Receipt:
        """Close the topic's journal: sign the list of the message ids in it, in order.
        Operator keys only. The list rides in the seal event when it fits the event
        cap, and in a blob named by its digest when it does not."""
        if self.session.pubkey not in self._trust.operator_pubkeys:
            raise NotAuthorized(f"only an operator key seals a topic; {topic!r} is unchanged")
        existing = self._seal(topic)
        if existing is not None:
            return Receipt(backend=self.name, topic=topic, id=existing[0].id, accepted=True,
                           duplicate=True, detail="already sealed",
                           bytes_used=existing[0].wire_bytes)
        ids = [m.id for m in self._read(topic, None).messages]
        manifest = "\n".join(ids).encode()
        payload = {"topic": topic, "count": len(ids),
                   "manifest_sha256": hashlib.sha256(manifest).hexdigest(), "ids": ids}
        event = self.session.sign_record(Kind.SEAL, "seal", payload, topic=topic)
        where = "listed in the seal"
        if event.wire_bytes > MAX_EVENT_BYTES:
            self.session.blobs().upload(manifest, content_type="text/plain")
            del payload["ids"]
            event = self.session.sign_record(Kind.SEAL, "seal", payload, topic=topic)
            where = f"listed in blob {payload['manifest_sha256'][:12]}…"
        self.session.publish_record(event, "seal")
        return Receipt(backend=self.name, topic=topic, id=event.id, accepted=True,
                       detail=f"sealed after {len(ids)} message(s), {where}",
                       bytes_used=event.wire_bytes)

    # ------------------------------------------------------------- the inbox door
    def todo(self, note: str, *, target: str, key: str, surface: str | None = None,
             doc: str | None = None, page: str | None = None, refs: tuple[str, ...] = (),
             subject: str = "") -> Receipt:
        """One pointer into `inbox`: where to look, never a copy of what is there."""
        tagged = [f"target:{target}"]
        tagged += [f"{name}:{value}" for name, value in
                   (("surface", surface), ("doc", doc), ("page", page)) if value]
        return self.post(INBOX, Message(body=note, kind="todo", subject=subject,
                                        refs=tuple(dict.fromkeys([*tagged, *refs]))), key=key)

    def triage(self, *, target: str | None = None, surface: str | None = None) -> dict:
        """Unhandled `inbox` pointers, grouped by target, with the compaction flag. A
        pointer is handled once any member settles it with a result or a reason: the
        buffer is shared."""
        journal = self._read(INBOX, self._seal(INBOX))
        settled = {journal.alias.get(got["msg_id"], got["msg_id"])
                   for _, got in self._acks(INBOX, {}) if self._settles(INBOX, got)}
        wanted = [f"target:{target}"] if target else []
        wanted += [f"surface:{surface}"] if surface else []
        open_items = [m for m in journal.messages
                      if m.id not in settled and all(ref in m.refs for ref in wanted)]
        stamp = now(self.session.clock)
        targets: dict[str, dict] = {}
        for item in open_items:
            name = next((r.split(":", 1)[1] for r in item.refs if r.startswith("target:")),
                        "(no target)")
            row = targets.setdefault(name, {"count": 0, "oldest_age_hours": 0.0})
            row["count"] += 1
            row["oldest_age_hours"] = max(row["oldest_age_hours"],
                                          round((stamp - item.created_at) / 3600, 2))
        for row in targets.values():
            row["compaction_due"] = (row["count"] >= COMPACTION_MAX_ITEMS
                                     or row["oldest_age_hours"] >= COMPACTION_MAX_AGE_HOURS)
        return {"topic": INBOX, "unhandled": [m.to_dict() for m in open_items],
                "targets": targets,
                "compaction_rule": f"due at {COMPACTION_MAX_ITEMS} unhandled items or "
                                   f"{COMPACTION_MAX_AGE_HOURS:g} hours"}

    def resolve(self, msg_ids: list[str], *, seat: str, result_ref: str | None = None,
                disposition: str = "handled", note: str | None = None) -> list[Receipt]:
        """Settle `inbox` pointers. `handled` must say where the work went: a PR, a
        commit or an issue. Nothing stays open in two places."""
        if disposition not in TERMINAL_DISPOSITIONS:
            raise ProfileError(f"resolve takes one of {TERMINAL_DISPOSITIONS}")
        self._require_settlement(INBOX, disposition, result_ref, note)
        return self.ack_many(INBOX, seat, msg_ids, disposition=disposition,
                             result_ref=result_ref, note=note)
