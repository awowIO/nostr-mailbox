"""The campaign profile: which Nostr kinds carry which campaign record, what a record
must look like, and whose signature gives one authority.

Three storage lifecycles keep the relay small (NIP-01 kind ranges):

- ephemeral (`28880`): heartbeats. Forwarded to whoever is watching, never written.
- addressable (`3888x`, one `d` tag naming the seat, route or condition): seat
  checkpoints, the Route Board and condition heads. The relay keeps the newest event
  per (kind, author, d) and drops the one it replaces, so a thousand checkpoints cost
  one row.
- regular (`888x`): claims, review decisions, handoffs, operator directives, mailbox
  messages, acks and seals. Kept, because each is a fact somebody may have to prove.

The kind numbers are the assignments proposed in the private-relay report (`8880`–
`8890`, `28880`, `38880`–`38882`), plus two this module adds in the same blocks:
`8891` for a mailbox message and `38883` for a seat checkpoint head.

A signature proves who wrote a record. It never proves the writer was allowed to.
`Trust` is the campaign's answer to "allowed": the pinned relay, the operator keys, and
the keys that may lead routes or review claims. `admit` is the one door every received
record comes through, and `verify_directive` the one an operator directive does."""
from __future__ import annotations

import json
import re
import tomllib
from dataclasses import dataclass
from enum import IntEnum
from pathlib import Path
from urllib.parse import urlsplit

from . import bech32, nip44
from .event import Event, InvalidEvent, NostrError, verify_event

SCHEMA = "cf.campaign/1"
TRUST_SCHEMA = "cf.transport/1"
TRANSPORT_FILE = "nostr.toml"           # the conventional name of a campaign's declaration
# The report's cap on one complete serialized campaign event. A body that does not fit
# belongs in a blob; the event then carries its sha256.
MAX_EVENT_BYTES = 16_384
_SLUG = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_GROUP = re.compile(r"^[A-Za-z0-9_-]{1,64}$")       # NIP-29: a-z0-9-_ group ids
EVERY_SEAT = "*"


class Kind(IntEnum):
    GOAL_REVISION = 8880
    CLAIM = 8881
    DECISION = 8882                     # the report's VerificationReceipt
    ROUTE_TRANSITION = 8883
    HANDOFF = 8884
    DIRECTIVE = 8885
    DOCS_WAVE_RECEIPT = 8886
    REVIEW_WAKE = 8887
    ACK = 8888
    SEAL = 8889
    PROMOTION = 8890
    MESSAGE = 8891
    HEARTBEAT = 28880
    GOAL_HEAD = 38880
    CONDITION_HEAD = 38881
    ROUTE_HEAD = 38882
    CHECKPOINT_HEAD = 38883


class ProfileError(NostrError):
    """A record that is not a well-formed record of this campaign."""


class DirectiveRejected(ProfileError):
    """Something offered as an operator directive that a seat must not act on."""


class EventTooLarge(ProfileError):
    """A record over the campaign event cap."""


def slug(value, what: str) -> str:
    if not isinstance(value, str) or not _SLUG.match(value):
        raise ProfileError(f"{what} {value!r} must match {_SLUG.pattern}")
    return value


def _url(value, schemes: tuple[str, ...], what: str, *, origin_only: bool):
    """A parsed URL of one of `schemes` with no credentials, query or fragment, and
    (for an origin) no path: nothing this client would silently ignore."""
    if not isinstance(value, str):
        raise ProfileError(f"{what} must be a string, got {type(value).__name__}")
    try:
        parts = urlsplit(value)
        _ = parts.port                              # reading it is what rejects a bad port
    except ValueError as exc:
        raise ProfileError(f"{what} {value!r} is not a usable URL: {exc}") from exc
    if parts.scheme not in schemes or not parts.hostname:
        raise ProfileError(f"{what} must be a {'/'.join(schemes)} URL, got {value!r}")
    if parts.username is not None or parts.password is not None:
        raise ProfileError(f"{what} must not carry credentials")
    if parts.query or parts.fragment:
        raise ProfileError(f"{what} must not carry a query or a fragment")
    if origin_only and parts.path not in ("", "/"):
        raise ProfileError(f"{what} must be an origin (scheme, host, optional port) with "
                           f"no path, got {value!r}")
    return parts


# ----------------------------------------------------------------------------- trust
@dataclass(frozen=True)
class Trust:
    """What a campaign pins before any seat dials out. Loaded from the campaign's own
    `nostr.toml`; there is no default relay and no built-in roster."""
    relay: str
    campaign: str
    operator_pubkeys: frozenset[str]
    group: str | None = None                 # NIP-29 group id; adds an `h` tag when set
    blossom: str | None = None               # a separate blob origin; the relay's if unset
    lead_pubkeys: frozenset[str] = frozenset()       # may also write the Route Board
    reviewer_pubkeys: frozenset[str] = frozenset()   # may also decide claims
    allow_cleartext: bool = False            # ws:// or http:// beyond loopback
    relay_auth_url: str | None = None        # the relay's own name for itself, if not `relay`
    campaign_key: str | None = None          # 32-byte NIP-44 v2 campaign key (64 hex or nsec)

    _KEYS = frozenset({"schema", "relay", "campaign", "operator_pubkeys", "group",
                       "blossom", "lead_pubkeys", "reviewer_pubkeys", "allow_cleartext",
                       "relay_auth_url", "campaign_key"})
    _ROSTERS = ("operator_pubkeys", "lead_pubkeys", "reviewer_pubkeys")

    def __post_init__(self) -> None:
        _url(self.relay, ("ws", "wss"), "relay", origin_only=False)
        if self.relay_auth_url is not None:
            _url(self.relay_auth_url, ("ws", "wss"), "relay_auth_url", origin_only=False)
        if self.blossom is not None:
            _url(self.blossom, ("http", "https"), "blossom", origin_only=True)
        slug(self.campaign, "campaign")
        if self.campaign_key is not None and (not isinstance(self.campaign_key, str)
                                              or not _HEX64.match(self.campaign_key)):
            raise ProfileError("campaign_key must be 64 lowercase hex characters (or nsec1…)")
        if type(self.allow_cleartext) is not bool:
            raise ProfileError(f"allow_cleartext must be true or false, got "
                               f"{self.allow_cleartext!r}: a quoted \"false\" is a string, "
                               "and a string would have switched cleartext ON")
        if self.group is not None and (not isinstance(self.group, str)
                                       or not _GROUP.match(self.group)):
            raise ProfileError(f"group {self.group!r} must match {_GROUP.pattern}")
        if not self.operator_pubkeys:
            raise ProfileError("operator_pubkeys is empty: a campaign with no operator key "
                               "has nobody who can direct or seal it")
        for roster in self._ROSTERS:
            for key in getattr(self, roster):
                if not isinstance(key, str) or not _HEX64.match(key):
                    raise ProfileError(f"{roster} key {key!r} is not 64 lowercase hex "
                                       "characters")

    @property
    def conversation_key(self) -> bytes | None:
        """The 32-byte NIP-44 v2 conversation key for this campaign, when encrypted."""
        if self.campaign_key is None:
            return None
        return nip44.campaign_conversation_key(bytes.fromhex(self.campaign_key), self.campaign)

    @classmethod
    def from_mapping(cls, raw: dict, *, source: str = "trust") -> Trust:
        unknown = sorted(set(raw) - cls._KEYS)
        if unknown:
            raise ProfileError(f"{source}: unknown keys {unknown}; known: {sorted(cls._KEYS)}")
        if raw.get("schema") != TRUST_SCHEMA:
            raise ProfileError(f"{source}: schema must be {TRUST_SCHEMA!r}")
        missing = [k for k in ("relay", "campaign", "operator_pubkeys") if k not in raw]
        if missing:
            raise ProfileError(f"{source}: missing {missing}")
        rosters = {}
        for roster in cls._ROSTERS:
            keys = raw.get(roster, [])
            if not isinstance(keys, list) or not all(isinstance(k, str) for k in keys):
                raise ProfileError(f"{source}: {roster} must be a list of npub or hex strings")
            try:
                rosters[roster] = frozenset(bech32.pubkey_hex(k) for k in keys)
            except bech32.Bech32Error as exc:
                raise ProfileError(f"{source}: {roster}: {exc}") from exc
        ck = raw.get("campaign_key")
        if ck is not None:
            if not isinstance(ck, str):
                raise ProfileError(f"{source}: campaign_key must be a 64-hex or nsec1… string")
            try:
                ck = bech32.privkey_hex(ck) if ck.startswith("nsec1") else ck.lower()
            except bech32.Bech32Error as exc:
                raise ProfileError(f"{source}: campaign_key: {exc}") from exc
        try:
            return cls(relay=raw["relay"], campaign=raw["campaign"], group=raw.get("group"),
                       blossom=raw.get("blossom"), relay_auth_url=raw.get("relay_auth_url"),
                       allow_cleartext=raw.get("allow_cleartext", False),
                       campaign_key=ck, **rosters)
        except ProfileError as exc:
            raise ProfileError(f"{source}: {exc}") from exc

    @classmethod
    def load(cls, path: str | Path) -> Trust:
        path = Path(path)
        try:
            with open(path, "rb") as fh:
                raw = tomllib.load(fh)
        except FileNotFoundError as exc:
            raise ProfileError(f"no transport declaration at {path}") from exc
        except tomllib.TOMLDecodeError as exc:
            raise ProfileError(f"{path} is not valid TOML: {exc}") from exc
        except OSError as exc:
            raise ProfileError(f"cannot read {path}: {exc}") from exc
        return cls.from_mapping(raw, source=str(path))

    # ---- who may write what
    @property
    def leads(self) -> frozenset[str]:
        """Route Board writers: every operator, and the declared leads."""
        return self.operator_pubkeys | self.lead_pubkeys

    @property
    def reviewers(self) -> frozenset[str]:
        """Who may decide a claim: every operator, and the declared reviewers."""
        return self.operator_pubkeys | self.reviewer_pubkeys

    # ---- where blobs live
    @property
    def blossom_origin(self) -> str:
        """The origin blobs are fetched from: the declared one, else the relay's own
        (the relay serves Blossom beside its WebSocket), wss→https and ws→http."""
        if self.blossom is not None:
            parts = urlsplit(self.blossom)
            return f"{parts.scheme}://{parts.netloc}"
        parts = urlsplit(self.relay)
        return f"{'https' if parts.scheme == 'wss' else 'http'}://{parts.netloc}"

    @property
    def blossom_server(self) -> str:
        """The `host[:port]` a blob authorization must name. For the relay's own
        Blossom that is the relay's public name, which is `relay_auth_url` when a seat
        dials the relay by another address."""
        if self.blossom is not None:
            return urlsplit(self.blossom).netloc
        return urlsplit(self.relay_auth_url or self.relay).netloc

    # ---- routing
    def route(self, topic: str | None = None) -> str:
        """The `t` tag value: the campaign for a typed record, `<campaign>:<topic>` for
        mailbox traffic."""
        return self.campaign if topic is None else f"{self.campaign}:{slug(topic, 'topic')}"

    def address(self, name: str) -> str:
        """The `d` tag of an addressable record. The group is part of it, so one
        campaign slug used in two groups never shares a slot."""
        scoped = f"{self.campaign}:{name}"
        return f"{self.group}:{scoped}" if self.group else scoped

    def tags(self, topic: str | None = None) -> list[list[str]]:
        tags = [["t", self.route(topic)]]
        if self.group:
            tags.append(["h", self.group])
        return tags

    def scope(self, topic: str | None = None) -> dict:
        """The filter conditions that select this campaign's records."""
        flt = {"#t": [self.route(topic)]}
        if self.group:
            flt["#h"] = [self.group]
        return flt


# -------------------------------------------------------------------------- envelope
def encode(trust: Trust, record_type: str, payload: dict) -> str:
    raw = json.dumps({**payload, "schema": SCHEMA, "type": record_type,
                      "campaign": trust.campaign},
                     sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    conv = trust.conversation_key
    return nip44.encrypt(raw, conv) if conv is not None else raw


def decode(event: Event, trust: Trust, *, kind: Kind, record_type: str,
           topic: str | None = None) -> dict:
    """The payload of a record of this campaign, or `ProfileError`."""
    if event.kind != kind:
        raise ProfileError(f"kind {event.kind} is not a {record_type} ({int(kind)})")
    if event.values("t") != [trust.route(topic)]:
        raise ProfileError(f"routing tag {event.values('t')} is not exactly "
                           f"[{trust.route(topic)!r}]")
    if event.values("h") != ([trust.group] if trust.group else []):
        raise ProfileError(f"group tag {event.values('h')} does not match the campaign's")
    conv = trust.conversation_key
    if conv is not None:
        try:
            raw = nip44.decrypt(event.content, conv)
        except nip44.Nip44Error as exc:
            raise ProfileError(f"NIP-44 v2 decryption failed: {exc}") from exc
    else:
        raw = event.content
    try:
        body = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ProfileError(f"content is not JSON: {exc}") from exc
    if not isinstance(body, dict):
        raise ProfileError("content is not a JSON object")
    for field, wanted in (("schema", SCHEMA), ("type", record_type),
                          ("campaign", trust.campaign)):
        if body.pop(field, None) != wanted:
            raise ProfileError(f"content {field} is not {wanted!r}")
    return body


def admit(event: Event, trust: Trust, *, kind: Kind, record_type: str,
          topic: str | None = None) -> dict:
    """The one receive-side door: a record over the size cap is refused before it is
    parsed, then `decode` decides whether it is this campaign's at all. Every reader
    comes through here, so the cap holds for every record type."""
    size = event.wire_bytes
    if size > MAX_EVENT_BYTES:
        raise ProfileError(f"{size:,} bytes is over the {MAX_EVENT_BYTES:,}-byte campaign "
                           "event cap")
    return decode(event, trust, kind=kind, record_type=record_type, topic=topic)


def fields(payload: dict, required: dict[str, type], optional: dict[str, type]) -> dict:
    """`payload` with exactly the declared keys and types, or `ProfileError`."""
    unknown = sorted(set(payload) - set(required) - set(optional))
    if unknown:
        raise ProfileError(f"unexpected fields {unknown}")
    out = {}
    for name in required:
        if name not in payload:
            raise ProfileError(f"missing field {name!r}")
        out[name] = payload[name]
    for name in optional:
        if payload.get(name) is not None:
            out[name] = payload[name]
    for name, value in out.items():
        kind = required.get(name) or optional[name]
        if type(value) is not kind:                 # exact: True is not an int here
            raise ProfileError(f"field {name!r} must be {kind.__name__}")
        if kind is list and not all(isinstance(item, str) for item in value):
            raise ProfileError(f"field {name!r} must be a list of strings")
    return out


def _text(value, what: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ProfileError(f"{what} is empty")
    return value


def _line(value, what: str) -> str:
    """One non-empty line: these are rendered as list items."""
    if "\n" in _text(value, what):
        raise ProfileError(f"{what} must be a single line")
    return value


def _digest(value, what: str) -> str:
    if not isinstance(value, str) or not _HEX64.match(value):
        raise ProfileError(f"{what} must be a sha256 in lowercase hex")
    return value


# --------------------------------------------------------------------------- handoff
HANDOFF_FIELDS = (
    ("original_goal", "Original goal"),
    ("open_condition", "Open condition"),
    ("evidence_and_rejected_routes", "Evidence & rejected routes"),
    ("next_action", "Next action"),
)
_HANDOFF_HEADINGS = {f"## {label}": key for key, label in HANDOFF_FIELDS}
_PROVENANCE = "<!-- handoff provenance: "


@dataclass(frozen=True)
class Handoff:
    """The four-field first-call packet a fresh or post-compaction session starts from.
    Exactly four fields, all present: a packet missing its open condition or its next
    action sends the next seat back to rereading receipts."""
    original_goal: str
    open_condition: str
    evidence_and_rejected_routes: str
    next_action: str

    def __post_init__(self) -> None:
        for key, label in HANDOFF_FIELDS:
            value = getattr(self, key)
            _text(value, f"handoff field {label!r}")
            clash = [line for line in value.splitlines()
                     if line.strip() in _HANDOFF_HEADINGS or line.startswith("<!--")]
            if clash:
                raise ProfileError(f"handoff field {label!r} carries a line that reads as a "
                                   f"field heading or a provenance line: {clash[0]!r}")

    def to_payload(self) -> dict:
        return {key: getattr(self, key) for key, _ in HANDOFF_FIELDS}

    @classmethod
    def from_payload(cls, payload: dict) -> Handoff:
        return cls(**fields(payload, {key: str for key, _ in HANDOFF_FIELDS}, {}))

    def render(self, provenance: dict[str, str] | None = None) -> str:
        """The packet as the seat reads it: the four headed sections, in order, and
        nothing else under a heading. `provenance` (who signed it, which event, for
        whom) rides above them in one comment line, beside the four fields, not in."""
        body = "\n\n".join(f"## {label}\n{getattr(self, key).strip()}"
                           for key, label in HANDOFF_FIELDS) + "\n"
        if not provenance:
            return body
        pairs = "; ".join(f"{name}={str(value).replace('--', '—')}"
                          for name, value in provenance.items())
        return f"{_PROVENANCE}{pairs} -->\n{body}"

    @classmethod
    def parse(cls, text: str) -> Handoff:
        """The inverse of `render`. The four headings must appear once each, in order;
        a provenance comment above the first is allowed and ignored."""
        sections: dict[str, list[str]] = {}
        current: str | None = None
        for line in text.splitlines():
            key = _HANDOFF_HEADINGS.get(line.strip())
            if key is not None:
                if key in sections:
                    raise ProfileError(f"handoff heading {line.strip()!r} appears twice")
                current = key
                sections[key] = []
            elif current is None:
                if line.strip() and not line.startswith(_PROVENANCE):
                    raise ProfileError("handoff text starts before its first heading")
            else:
                sections[current].append(line)
        if list(sections) != [key for key, _ in HANDOFF_FIELDS]:
            raise ProfileError("a handoff has exactly these headings, in this order: "
                               + ", ".join(label for _, label in HANDOFF_FIELDS))
        return cls(**{key: "\n".join(lines).strip() for key, lines in sections.items()})


# ---------------------------------------------- the learning loop: claim → decision
CLAIM_EFFECTS = ("closes", "narrows", "falsifies")
DECISION_OUTCOMES = ("accepted", "narrowed", "rejected")
CONDITION_STATES = ("open", "closed")


@dataclass(frozen=True)
class Claim:
    """An Obligation-Tree claim: evidence offered against one revision of one open
    condition. It names how it acts on the condition; a claim that does none of closes /
    narrows / falsifies has no place in the tree, and one with no evidence cannot be
    reviewed. Read back, a claim is a proposal until a reviewer decides it."""
    condition: str
    condition_rev: int
    effect: str
    candidate_digest: str
    evidence_refs: tuple[str, ...]
    wave: str = ""
    task: str = ""

    def __post_init__(self) -> None:
        slug(self.condition, "claim condition")
        if type(self.condition_rev) is not int or self.condition_rev < 1:
            raise ProfileError("claim condition_rev is the condition revision it was made "
                               "against, an integer from 1")
        if self.effect not in CLAIM_EFFECTS:
            raise ProfileError(f"claim effect {self.effect!r} must be one of {CLAIM_EFFECTS}")
        _digest(self.candidate_digest, "claim candidate_digest")
        if not self.evidence_refs:
            raise ProfileError("a claim needs at least one evidence reference to review")
        for ref in self.evidence_refs:
            _line(ref, "claim evidence reference")

    def to_payload(self) -> dict:
        return {"condition": self.condition, "condition_rev": self.condition_rev,
                "effect": self.effect, "candidate_digest": self.candidate_digest,
                "evidence_refs": list(self.evidence_refs), "wave": self.wave,
                "task": self.task}

    @classmethod
    def from_payload(cls, payload: dict) -> Claim:
        got = fields(payload, {"condition": str, "condition_rev": int, "effect": str,
                               "candidate_digest": str, "evidence_refs": list},
                     {"wave": str, "task": str})
        got["evidence_refs"] = tuple(got["evidence_refs"])
        return cls(**got)


@dataclass(frozen=True)
class Decision:
    """A reviewer's ruling on one claim: accepted, narrowed or rejected, with the reason.
    Durable, so the reasoning survives the condition head it then replaces. It binds the
    claim's event id, the condition revision ruled on and the candidate digest."""
    claim: str
    condition: str
    condition_rev: int
    outcome: str
    reason: str
    next_action: str
    candidate_digest: str
    statement: str = ""          # the condition as it stands after this ruling
    reopen_if: str = ""          # what would reopen a rejected route

    def __post_init__(self) -> None:
        _digest(self.claim, "decision claim id")
        slug(self.condition, "decision condition")
        if type(self.condition_rev) is not int or self.condition_rev < 1:
            raise ProfileError("decision condition_rev is an integer from 1")
        if self.outcome not in DECISION_OUTCOMES:
            raise ProfileError(f"decision outcome {self.outcome!r} must be one of "
                               f"{DECISION_OUTCOMES}")
        _line(self.reason, "decision reason")
        _text(self.next_action, "decision next_action")
        _digest(self.candidate_digest, "decision candidate_digest")
        if self.outcome == "narrowed":
            _text(self.statement, "the narrowed condition statement")
        if self.outcome == "rejected":
            _line(self.reopen_if, "the reopening condition of a rejected claim")

    def to_payload(self) -> dict:
        return dict(self.__dict__)

    @classmethod
    def from_payload(cls, payload: dict) -> Decision:
        return cls(**fields(payload, {"claim": str, "condition": str, "condition_rev": int,
                                      "outcome": str, "reason": str, "next_action": str,
                                      "candidate_digest": str},
                            {"statement": str, "reopen_if": str}))


@dataclass(frozen=True)
class Condition:
    """The head of one acceptance condition: what is still open, what evidence was
    accepted, which routes were rejected and what would reopen them, and the next
    action. Replaced in place by each decision; `rev` counts them. A four-field
    handoff is rendered straight from this, so the next seat starts from what was
    decided and not from the receipts."""
    condition: str
    rev: int
    state: str
    goal: str
    statement: str
    next_action: str
    evidence: tuple[str, ...] = ()
    rejected_routes: tuple[str, ...] = ()
    last_decision: str = ""
    last_claim: str = ""

    def __post_init__(self) -> None:
        slug(self.condition, "condition")
        if type(self.rev) is not int or self.rev < 1:
            raise ProfileError("condition rev is an integer from 1")
        if self.state not in CONDITION_STATES:
            raise ProfileError(f"condition state {self.state!r} must be one of "
                               f"{CONDITION_STATES}")
        _text(self.goal, "condition goal")
        _text(self.statement, "condition statement")
        _text(self.next_action, "condition next_action")
        for item in (*self.evidence, *self.rejected_routes):
            _line(item, "condition evidence or rejected route")
        for name in ("last_decision", "last_claim"):
            if getattr(self, name):
                _digest(getattr(self, name), f"condition {name}")

    def to_payload(self) -> dict:
        return {**self.__dict__, "evidence": list(self.evidence),
                "rejected_routes": list(self.rejected_routes)}

    @classmethod
    def from_payload(cls, payload: dict) -> Condition:
        got = fields(payload, {"condition": str, "rev": int, "state": str, "goal": str,
                               "statement": str, "next_action": str},
                     {"evidence": list, "rejected_routes": list, "last_decision": str,
                      "last_claim": str})
        got["evidence"] = tuple(got.get("evidence", ()))
        got["rejected_routes"] = tuple(got.get("rejected_routes", ()))
        return cls(**got)

    def after(self, claim: Claim, decision: Decision, decision_id: str) -> Condition:
        """This condition once `decision` on `claim` is applied: the next revision."""
        evidence, rejected = self.evidence, self.rejected_routes
        state, statement = self.state, decision.statement or self.statement
        if decision.outcome == "rejected":
            rejected = (*rejected, f"{claim.effect} via {claim.candidate_digest[:12]}…: "
                                   f"{decision.reason} (reopen if: {decision.reopen_if})")
        else:
            evidence = tuple(dict.fromkeys((*evidence, *claim.evidence_refs)))
            if decision.outcome == "accepted" and claim.effect in ("closes", "falsifies"):
                state = "closed"
        return Condition(condition=self.condition, rev=self.rev + 1, state=state,
                         goal=self.goal, statement=statement,
                         next_action=decision.next_action, evidence=evidence,
                         rejected_routes=rejected, last_decision=decision_id,
                         last_claim=decision.claim)

    def handoff(self) -> Handoff:
        """The first-call packet for whoever picks this condition up next."""
        def listed(title: str, items: tuple[str, ...]) -> str:
            return f"{title}:\n" + ("\n".join(f"- {item}" for item in items) or "- (none yet)")

        open_condition = (self.statement if self.state == "open" else
                          f"CLOSED at revision {self.rev}. It read: {self.statement}")
        return Handoff(
            original_goal=self.goal, open_condition=open_condition,
            evidence_and_rejected_routes=(listed("Accepted evidence", self.evidence) + "\n\n"
                                          + listed("Rejected routes", self.rejected_routes)),
            next_action=self.next_action)


# ----------------------------------------------------------------------- route board
ROUTE_STATES = ("scouting", "active", "parked", "falsified", "closed")


@dataclass(frozen=True)
class Route:
    """One row of the Route Board (`ROUTES`). The falsification criterion is required:
    a route nobody can say how to abandon is how a campaign fixates."""
    route: str
    state: str
    hypothesis: str
    falsification_criterion: str
    origin: str = ""
    evidence: tuple[str, ...] = ()
    obstruction: str = ""
    reopen_trigger: str = ""

    def __post_init__(self) -> None:
        slug(self.route, "route")
        if self.state not in ROUTE_STATES:
            raise ProfileError(f"route state {self.state!r} must be one of {ROUTE_STATES}")
        _text(self.hypothesis, "route hypothesis")
        _text(self.falsification_criterion, "route falsification_criterion")

    def to_payload(self) -> dict:
        return {"route": self.route, "state": self.state, "hypothesis": self.hypothesis,
                "falsification_criterion": self.falsification_criterion,
                "origin": self.origin, "evidence": list(self.evidence),
                "obstruction": self.obstruction, "reopen_trigger": self.reopen_trigger}

    @classmethod
    def from_payload(cls, payload: dict) -> Route:
        got = fields(payload, {"route": str, "state": str, "hypothesis": str,
                               "falsification_criterion": str},
                     {"origin": str, "evidence": list, "obstruction": str,
                      "reopen_trigger": str})
        got["evidence"] = tuple(got.get("evidence", ()))
        return cls(**got)


# ------------------------------------------------------------------------ checkpoint
@dataclass(frozen=True)
class Checkpoint:
    """A seat's newest checkpoint pointer. The checkpoint itself is a blob; this names
    it by digest, so the relay holds one small row per seat however long the seat runs.
    `seq` only moves forward: an older or conflicting pointer is refused at write."""
    seat: str
    seq: int
    sha256: str
    task: str = ""
    parent_sha256: str = ""
    feed_sha256: str = ""
    attempt: int = 1
    note: str = ""

    def __post_init__(self) -> None:
        slug(self.seat, "seat")
        if type(self.seq) is not int or type(self.attempt) is not int:
            raise ProfileError("checkpoint seq and attempt are integers")
        if self.seq < 0 or self.attempt < 1:
            raise ProfileError("checkpoint seq must be ≥ 0 and attempt ≥ 1")
        _digest(self.sha256, "checkpoint sha256")
        for name in ("parent_sha256", "feed_sha256"):
            if getattr(self, name):
                _digest(getattr(self, name), f"checkpoint {name}")

    def to_payload(self) -> dict:
        return {"seat": self.seat, "seq": self.seq, "sha256": self.sha256,
                "task": self.task, "parent_sha256": self.parent_sha256,
                "feed_sha256": self.feed_sha256, "attempt": self.attempt, "note": self.note}

    @classmethod
    def from_payload(cls, payload: dict) -> Checkpoint:
        return cls(**fields(payload, {"seat": str, "seq": int, "sha256": str},
                            {"task": str, "parent_sha256": str, "feed_sha256": str,
                             "attempt": int, "note": str}))


# ------------------------------------------------------------------------- heartbeat
@dataclass(frozen=True)
class Heartbeat:
    """Liveness. It grants nothing: a heartbeat cannot advance a condition or stand in
    for a work receipt, and the relay does not keep it."""
    seat: str
    status: str = "alive"
    detail: str = ""

    def __post_init__(self) -> None:
        slug(self.seat, "seat")
        slug(self.status, "heartbeat status")

    def to_payload(self) -> dict:
        return {"seat": self.seat, "status": self.status, "detail": self.detail}

    @classmethod
    def from_payload(cls, payload: dict) -> Heartbeat:
        return cls(**fields(payload, {"seat": str}, {"status": str, "detail": str}))


# ------------------------------------------------------------------------- directive
@dataclass(frozen=True)
class Directive:
    """Operator words for the campaign. `seq` and `prev` chain directives so a relay
    cannot drop one from the middle or reorder them unnoticed. `overrules` names the
    rival directives this one settles a fork against. The three trailing fields are
    filled from the signed event when a directive is read.

    Verified here means "the operator signed this", not "this is in a contract". A
    directive binds a seat once it is adopted into the `OPERATOR.md` that seat's harness
    renders (`bridge.adopt_directive`); until then it is a verified proposal."""
    text: str
    seq: int
    prev: str | None = None
    audience: tuple[str, ...] = (EVERY_SEAT,)
    graph_digest: str = ""
    overrules: tuple[str, ...] = ()
    event_id: str = ""
    operator: str = ""
    created_at: int = 0

    def __post_init__(self) -> None:
        _text(self.text, "directive text")
        if type(self.seq) is not int or self.seq < 1:
            raise ProfileError("directive seq is an integer from 1")
        if (self.seq == 1) != (self.prev is None):
            raise ProfileError("directive 1 has no predecessor; every later one names its own")
        if self.prev is not None:
            _digest(self.prev, "directive prev")
        if self.graph_digest:
            _digest(self.graph_digest, "directive graph_digest")
        for rival in self.overrules:
            _digest(rival, "directive overrules entry")
        if not self.audience:
            raise ProfileError("directive audience is empty")
        for seat in self.audience:
            if seat != EVERY_SEAT:
                slug(seat, "directive audience seat")

    def to_payload(self) -> dict:
        return {"text": self.text, "seq": self.seq, "prev": self.prev,
                "audience": list(self.audience), "graph_digest": self.graph_digest,
                "overrules": list(self.overrules)}

    @property
    def campaign_wide(self) -> bool:
        return self.audience == (EVERY_SEAT,)

    def addressed_to(self, seat: str) -> bool:
        return EVERY_SEAT in self.audience or seat in self.audience


def verify_directive(raw, trust: Trust) -> Directive:
    """The directive in `raw`, or `DirectiveRejected`.

    In order: the event id and Schnorr signature are recomputed from the raw event
    (never taken on a caller's word); the kind must be the directive kind; the signing
    key must be on the campaign's operator roster; the record must fit the campaign
    event cap, belong to this campaign and parse as a directive. A correctly signed
    event from any other key is a member talking, not an operator directing."""
    try:
        event = verify_event(raw)
    except InvalidEvent as exc:
        raise DirectiveRejected(f"not a validly signed event: {exc}") from exc
    if event.kind != Kind.DIRECTIVE:
        raise DirectiveRejected(f"kind {event.kind} is not an operator directive "
                                f"({int(Kind.DIRECTIVE)})")
    if event.pubkey not in trust.operator_pubkeys:
        raise DirectiveRejected(
            f"signed by {bech32.encode(bech32.NPUB, bytes.fromhex(event.pubkey))}, which is "
            f"not one of the {len(trust.operator_pubkeys)} operator key(s) of campaign "
            f"{trust.campaign!r}")
    try:
        payload = admit(event, trust, kind=Kind.DIRECTIVE, record_type="directive")
        got = fields(payload, {"text": str, "seq": int, "audience": list},
                     {"prev": str, "graph_digest": str, "overrules": list})
        return Directive(text=got["text"], seq=got["seq"], prev=got.get("prev"),
                         audience=tuple(got["audience"]),
                         graph_digest=got.get("graph_digest", ""),
                         overrules=tuple(got.get("overrules", ())),
                         event_id=event.id, operator=event.pubkey,
                         created_at=event.created_at)
    except DirectiveRejected:
        raise
    except ProfileError as exc:
        raise DirectiveRejected(f"signed by an operator but malformed: {exc}") from exc


@dataclass(frozen=True)
class DirectiveLedger:
    """What a set of offered directives amounts to. `in_force` is the unbroken chain
    from sequence 1. `held` waits on an operator: a gap, or two directives claiming the
    same place. `rejected` never had standing.

    One thing no ledger built from a relay's answer can show: a relay that withholds
    the newest directives returns a shorter chain that still looks complete. The
    machine that adopts directives keeps its own record of the last one adopted for
    that reason, and refuses an answer that no longer contains it."""
    in_force: tuple[Directive, ...]
    held: tuple[tuple[Directive, str], ...]
    rejected: tuple[tuple[str, str], ...]

    @property
    def head(self) -> Directive | None:
        return self.in_force[-1] if self.in_force else None

    def for_seat(self, seat: str) -> tuple[Directive, ...]:
        return tuple(d for d in self.in_force if d.addressed_to(seat))


def resolve_directives(raw_events, trust: Trust) -> DirectiveLedger:
    """Verify every offered event and order the survivors into the one chain a seat may
    treat as the operator's word. Two operator directives at the same sequence are a
    fork, and both are held. An operator settles it with the next directive: built on
    the one that stands, and naming every rival in `overrules`. A directive that merely
    continues one branch settles nothing, so two operators extending two branches
    cannot lock the chain: the explicit ruling still decides."""
    verified: dict[str, Directive] = {}
    rejected: list[tuple[str, str]] = []
    for raw in raw_events:
        shown = raw.id if isinstance(raw, Event) else (
            str(raw.get("id", "?")) if isinstance(raw, dict) else "?")
        try:
            directive = verify_directive(raw, trust)
        except DirectiveRejected as exc:
            rejected.append((shown, str(exc)))
        else:
            verified[directive.event_id] = directive
    chain: list[Directive] = []
    held: dict[str, str] = {}
    prev, seq = None, 1
    while True:
        here = [d for d in verified.values() if d.seq == seq and d.prev == prev]
        if len(here) > 1:
            rivals = {d.event_id for d in here}
            standing = [d for d in here
                        if any(n.seq == seq + 1 and n.prev == d.event_id
                               and rivals - {d.event_id} <= set(n.overrules)
                               for n in verified.values())]
            if len(standing) != 1:
                for d in here:
                    held[d.event_id] = (
                        f"competing successors: {len(here)} directives claim sequence "
                        f"{seq}; an operator settles it by issuing sequence {seq + 1} on "
                        "top of the one that stands, overruling the rest")
                break
            here = standing
        if not here:
            break
        chain.append(here[0])
        prev, seq = here[0].event_id, seq + 1
    in_force = {d.event_id for d in chain}
    for d in verified.values():
        if d.event_id in in_force or d.event_id in held:
            continue
        if d.seq < seq:
            rejected.append((d.event_id, f"sequence {d.seq} is already settled on another "
                                         "directive"))
        elif d.seq == seq:
            held[d.event_id] = (f"sequence {seq} does not follow the directive in force "
                                f"({prev[:12] + '…' if prev else 'none yet'})")
        else:
            held[d.event_id] = (f"gap: sequence {d.seq} cannot apply before sequence "
                                f"{seq} is in force")
    return DirectiveLedger(in_force=tuple(chain),
                           held=tuple((verified[i], why) for i, why in held.items()),
                           rejected=tuple(rejected))
