"""Campaign topics as NIP-29 relay-hosted groups, run by their members: no kubectl.

A topic is a group id `g` (`^[a-z0-9][a-z0-9_-]{0,63}$`, also a valid campaign topic
slug). Every record of the topic carries `["h", g]`, and the relay gates the group:
`private` (only members read `#h=g`), `restricted` (only members write it) and `closed`
(a join without an invite code waits for an admin). What each event means:

    9007 create-group  [["h",g],["private"],["restricted"],["closed"]]   any member
    9000 put-user      [["h",g],["p",pk,"member"]]                       an admin
    9001 remove-user   [["h",g],["p",pk]]                                an admin
    9005 delete-event  [["h",g],["e",id]]   (declines a join request)    an admin
    9009 create-invite [["h",g],["code",c]]                              an admin
    9021 join-request  [["h",g]] (+ ["code",c]), reason in the content   anyone

Who is an admin and who is a member is read from signed events, never taken on the
relay's word: the admins are the author of the earliest 9007 for `g` and the campaign's
operator keys; the members are the newest admin-signed 9000 or 9001 per pubkey. At one
timestamp a removal beats an addition, and each write here is stamped after the one it
follows, so a tie never decides anything this client wrote."""
from __future__ import annotations

import re
import secrets
from collections.abc import Iterable

from .event import Event, now
from .profile import ProfileError
from .relay import RelayClient

PUT_USER = 9000
REMOVE_USER = 9001
EDIT_METADATA = 9002
DELETE_EVENT = 9005
CREATE_GROUP = 9007
DELETE_GROUP = 9008
CREATE_INVITE = 9009
JOIN_REQUEST = 9021
LEAVE_REQUEST = 9022
GROUP_METADATA = 39000                  # relay-signed group state (NIP-29)
GROUP_ADMINS = 39001
GROUP_MEMBERS = 39002
# What the relay's `groups.roles.admin` lets an admin sign (relay.yaml).
ADMIN_KINDS = frozenset({PUT_USER, REMOVE_USER, EDIT_METADATA, DELETE_EVENT, DELETE_GROUP,
                         CREATE_INVITE, 9010})
RELAY_KINDS = frozenset({GROUP_METADATA, GROUP_ADMINS, GROUP_MEMBERS, 39003})
TOPIC_ID = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
FLAGS = (("private",), ("restricted",), ("closed",))


class TopicError(ProfileError):
    """A topic that does not exist, belongs to someone else, or refused this key."""


def topic_id(value) -> str:
    if not isinstance(value, str) or not TOPIC_ID.fullmatch(value):
        raise TopicError(f"topic {value!r} must match {TOPIC_ID.pattern}: a NIP-29 group id "
                         "that is also a campaign topic slug")
    return value


def _first(events: Iterable[Event]) -> Event | None:
    return min(events, key=lambda e: (e.created_at, e.id), default=None)


class Topic:
    """One NIP-29 group on one authenticated connection."""

    def __init__(self, relay: RelayClient, group: str, *,
                 operators: Iterable[str] = ()):
        self.relay, self.group = relay, topic_id(group)
        self.operators = frozenset(operators)

    @property
    def me(self) -> str:
        return self.relay.pubkey

    def _events(self, *kinds: int, **where) -> list[Event]:
        return self.relay.query_all({"kinds": sorted(kinds), "#h": [self.group], **where})

    def _publish(self, kind: int, tags: list[list[str]], content: str = "", *,
                 created_at: int | None = None) -> tuple[Event, str]:
        event = self.relay.sign(kind, [["h", self.group], *tags], content,
                                created_at=created_at)
        return event, self.relay.publish(event)

    # ------------------------------------------------------------------ who is who
    def creation(self) -> Event | None:
        """The 9007 that created the group: the earliest one, by (created_at, id)."""
        return _first(self._events(CREATE_GROUP))

    def admins(self) -> frozenset[str]:
        made = self.creation()
        return self.operators | ({made.pubkey} if made else frozenset())

    def _moderation(self, admins: frozenset[str]) -> dict[str, Event]:
        """The newest admin-signed 9000 or 9001 per pubkey."""
        newest: dict[str, tuple] = {}
        for event in self._events(PUT_USER, REMOVE_USER, authors=sorted(admins)):
            for pubkey in event.values("p"):
                rank = (event.created_at, event.kind == REMOVE_USER, event.id)
                if pubkey not in newest or rank > newest[pubkey][0]:
                    newest[pubkey] = (rank, event)
        return {pubkey: event for pubkey, (_, event) in newest.items()}

    def members(self) -> frozenset[str]:
        """Who the admins say belongs: the group's creator, and every pubkey whose
        newest admin-signed moderation event adds it."""
        admins = self.admins()
        made = self.creation()
        added = {pubkey for pubkey, event in self._moderation(admins).items()
                 if event.kind == PUT_USER}
        return frozenset(added | ({made.pubkey} if made else set()))

    # ---------------------------------------------------------------- the verbs
    def create(self) -> tuple[Event, bool]:
        """Create the group, or find this key's own creation of it. Returns the 9007
        and whether this call wrote it."""
        made = self.creation()
        if made is not None:
            if made.pubkey != self.me:
                raise TopicError(f"topic {self.group!r} already exists and was created by "
                                 f"{made.pubkey[:12]}…; pick another id or ask to join it")
            return made, False
        event, _ = self._publish(CREATE_GROUP, [list(f) for f in FLAGS])
        return event, True

    def _stamp(self, pubkey: str) -> int:
        held = self._moderation(self.admins()).get(pubkey)
        return max(now(self.relay.clock), held.created_at + 1 if held else 0)

    def put_user(self, pubkey: str) -> Event:
        return self._publish(PUT_USER, [["p", pubkey, "member"]],
                             created_at=self._stamp(pubkey))[0]

    def remove_user(self, pubkey: str) -> Event:
        return self._publish(REMOVE_USER, [["p", pubkey]], created_at=self._stamp(pubkey))[0]

    @staticmethod
    def new_code() -> str:
        return secrets.token_urlsafe(32)      # as the relay's own invite codes

    def publish_invite(self, code: str) -> Event:
        """Register a group invite code (9009): a join request carrying it is admitted
        by the relay at once. Every member can read a 9009, so the code admits to the
        group and no further; the keeper hands keys only to a proven redeemer."""
        return self._publish(CREATE_INVITE, [["code", code]])[0]

    def create_invite(self) -> str:
        code = self.new_code()
        self.publish_invite(code)
        return code

    def join(self, *, code: str | None = None, proof: str | None = None,
             reason: str = "") -> tuple[Event, str]:
        """Ask to join (9021). With a code the relay admits at once; without one the
        request waits for an admin. `proof` binds a token's code to this key (see
        `keyring.redeem_proof`). Returns the request and what the relay said."""
        tags = [["code", code]] if code else []
        tags += [["proof", proof]] if proof else []
        return self._publish(JOIN_REQUEST, tags, reason)

    def join_requests(self) -> list[Event]:
        return self._events(JOIN_REQUEST)

    def requests(self) -> list[Event]:
        """Codeless join requests still waiting: not from a member, not declined by an
        admin, oldest first, one per requester (the earliest)."""
        admins = self.admins()
        members = self.members()
        declined = {ident for event in self._events(DELETE_EVENT, authors=sorted(admins))
                    for ident in event.values("e")}
        waiting: dict[str, Event] = {}
        for event in self.join_requests():
            if (event.pubkey in members or event.id in declined or event.has_tag("code")
                    or event.pubkey in waiting):
                continue
            waiting[event.pubkey] = event
        return sorted(waiting.values(), key=lambda e: (e.created_at, e.id))

    def decline(self, request_id: str) -> Event:
        return self._publish(DELETE_EVENT, [["e", request_id]])[0]
