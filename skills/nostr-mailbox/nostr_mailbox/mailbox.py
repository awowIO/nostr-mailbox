"""Personal dropboxes: pairwise mail between members, behind a quarantine firewall, with
attachments staged to disk at 0600 and never through an agent's transcript.

Every member has a dropbox: the mail addressed to its key (`pairwise` envelopes, kind
4410, tagged `["t", "<campaign>:dropbox"]`). The relay serves an envelope only to the
key it is addressed to. What this seat then does with each one depends only on events
the mailbox owner signed (`acl`):

- **quarantined**: the sender holds no grant from the owner (or wrote outside it). It is
  never decrypted; only its outer metadata is shown.
- **pending_approval**: the sender is `human_gated`. The seal is checked, and subject,
  body and attachments are withheld from every command an agent runs. A human releases
  it with `mail approve <id>` at a terminal, which publishes the owner's own kind-8888
  ack on topic `dropbox` (seat `human-gate`, `handled`; `--decline` writes `rejected`).
- **unread / read**: released, because the sender is `trusted_auto` or a human approved.

A released attachment is downloaded, checked against the digest and size its seal
signed, and written under a stage root (`~/nostr-mailbox-files` unless
`NOSTR_MAILBOX_FILES` names another), mode 0600. Every directory on the way is opened
with `O_DIRECTORY | O_NOFOLLOW` from a pinned descriptor, so a symlink anywhere below
the home directory is refused, and the file is linked into place only if the name is
free. What an agent ever sees of a file is `{dest, bytes, sha256}` and `{path, status}`.

Local state (which mail was shown, what was staged where) is one 0600 JSON file per
identity. Nothing else here is kept off the relay."""
from __future__ import annotations

import contextlib
import errno
import hashlib
import json
import os
import secrets
import socket
import stat
import tempfile
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from . import acl, bech32, pairwise, secp256k1
from .backend import CampaignSession, NostrRelayChannelBackend
from .blossom import BlossomError
from .event import Event, dumps, now
from .identity import Signer
from .pairwise import ENVELOPE, RECEIPT, Opened, Route
from .profile import MAX_EVENT_BYTES, Kind, ProfileError

STAGE_ROOT_ENV = "NOSTR_MAILBOX_FILES"
DEFAULT_STAGE_ROOT = "~/nostr-mailbox-files"
DROPBOX = "dropbox"
GATE_SEAT = "human-gate"
WAITING = ("unread", "pending_approval", "quarantined")     # what `mail read` shows by default
RELEASED = ("unread", "read")


class MailError(ProfileError):
    """Mail that may not be sent, or a command on mail that is not in the right state."""


class StagingProblem(MailError):
    """One attachment that was not staged; recorded per attachment, never dropped."""
    status = "refused"


class StagingConflict(StagingProblem):
    status = "conflict"


class IntegrityProblem(StagingProblem):
    status = "invalid"


def _npub(pubkey: str) -> str:
    return bech32.encode(bech32.NPUB, bytes.fromhex(pubkey))


def stage_root() -> str:
    """The configured stage root, `~/…` or absolute."""
    return os.environ.get(STAGE_ROOT_ENV) or DEFAULT_STAGE_ROOT


@dataclass(frozen=True)
class Item:
    """One envelope as this seat sees it."""
    event: Event
    route: Route | None
    state: str              # unread | read | pending_approval | quarantined | invalid | rejected
    trust: str | None = None
    opened: Opened | None = None
    problem: str | None = None

    @property
    def released(self) -> bool:
        return self.state in RELEASED


class Dropbox:
    def __init__(self, session: CampaignSession, signer: Signer, *, state_path: Path,
                 user_home: Path, profile_home: Path):
        self.session, self.signer = session, signer
        self.me = signer.pubkey
        self.relay_name = session.trust.relay_auth_url or session.trust.relay
        self.state_path, self.user_home = Path(state_path), Path(user_home)
        self.profile_home = Path(profile_home)
        self._acl: dict[str, acl.AclState] = {}

    @property
    def relay(self):
        return self.session.relay

    @property
    def topic_tag(self) -> str:
        return self.session.trust.route(DROPBOX)

    # --------------------------------------------------------------- local state
    def _state(self) -> dict:
        try:
            mode = stat.S_IMODE(self.state_path.stat().st_mode)
        except FileNotFoundError:
            return {"read": [], "staged": {}}
        if mode & ~0o600:
            raise MailError(f"{self.state_path} is mode {mode:04o}; it must be 0600")
        try:
            body = json.loads(self.state_path.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            raise MailError(f"cannot read the mail state {self.state_path}: {exc}") from exc
        return {"read": list(body.get("read", [])), "staged": dict(body.get("staged", {}))}

    def _save(self, state: dict) -> None:
        self.state_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd, staged = tempfile.mkstemp(dir=self.state_path.parent, suffix=".part")
        try:
            with os.fdopen(fd, "w") as fh:
                json.dump(state, fh)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(staged, self.state_path)
        finally:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(staged)

    # ----------------------------------------------------------------------- ACL
    def acl_events(self, owner: str) -> list[Event]:
        """The ACL artifacts of `owner`'s mailbox. NIP-01 relays index single-letter
        tags only, so they are asked for the way agent-mailbox asks a standard relay:
        the owner's own grants, revokes and invites by author, claims by `#p`. A grant
        another key signs is not asked for by author, and `acl.derive` rejects one that
        arrives anyway."""
        authored = self.relay.query_all({"kinds": [acl.GRANT, acl.REVOKE, acl.INVITE],
                                         "authors": [owner]})
        addressed = self.relay.query_all({"kinds": list(acl.ACL_KINDS), "#p": [owner]})
        events = {e.id: e for e in [*authored, *addressed]}
        return [e for e in events.values() if e.values("mbx") == [owner]]

    def acl_state(self, owner: str) -> acl.AclState:
        if owner not in self._acl:
            self._acl[owner] = acl.derive(owner, self.acl_events(owner), relay=self.relay_name,
                                          at=now(self.relay.clock))
        return self._acl[owner]

    def _publish_acl(self, kind: int, tags: list[list[str]], content: str = "", *,
                     about: str | None = None) -> Event:
        """Sign and publish one of this owner's ACL artifacts, stamped strictly after
        the newest one it already wrote about the same peer: per peer the newest wins,
        so a tie must never be left to decide."""
        stamp = now(self.relay.clock)
        if about is not None:
            mine = [e for e in self.acl_events(self.me)
                    if e.pubkey == self.me and about in e.values("p")]
            stamp = max([stamp, *(e.created_at + 1 for e in mine)])
        event = self.relay.sign(kind, tags, content, created_at=stamp)
        self.relay.publish(event)
        self._acl.pop(self.me, None)
        return event

    def grant(self, peer: str, *, scope: str, parts: Iterable[str] = (),
              trust: str = acl.DEFAULT_TRUST, read_replies: bool = True,
              until: int | None = None) -> acl.Grant:
        if peer == self.me:
            raise MailError("a mailbox owner needs no grant on its own mailbox")
        tags = [["mbx", self.me], ["p", peer], *acl.terms_tags(scope, parts, trust, read_replies),
                ["relay", self.relay_name]]
        if until is not None:
            tags.append(["access_until", str(until)])
        self._publish_acl(acl.GRANT, tags, about=peer)
        held = self.acl_state(self.me).grants.get(peer)
        if held is None:
            raise MailError("the grant was published but does not read back as in force; "
                            "check the relay's clock against this machine's")
        return held

    def revoke(self, peer: str) -> Event:
        return self._publish_acl(acl.REVOKE, [["mbx", self.me], ["p", peer]], about=peer)

    def invite(self, *, scope: str, parts: Iterable[str] = (), trust: str = acl.DEFAULT_TRUST,
               read_replies: bool = True, label: str | None = None,
               until: int | None = None) -> tuple[str, Event]:
        """A one-time invite: a fresh key whose public half is published in the signed
        terms and whose secret travels in the returned `inv_…` token."""
        secret = secp256k1.generate_secret()
        tags = [["mbx", self.me], ["invite_key", secp256k1.pubkey_gen(secret).hex()],
                *acl.terms_tags(scope, parts, trust, read_replies), ["relay", self.relay_name]]
        if label:
            tags.append(["label", pairwise.sanitize_label(label)])
        if until is not None:
            tags.append(["claim_until", str(until)])
        event = self._publish_acl(acl.INVITE, tags)
        return acl.encode_invite_token(event, secret), event

    def claim(self, token: str, *, name: str = "") -> dict:
        """Claim a one-time invite. The owner's client confirms the first valid claim it
        sees; until then this key holds no grant."""
        secret, invite = acl.decode_invite_token(token)
        owner = invite.pubkey
        if owner == self.me:
            raise MailError("this is your own invite; give it to the person it is for")
        if invite.values("relay") != [self.relay_name]:
            raise MailError(f"the invite is for relay {invite.values('relay')}, not "
                            f"{self.relay_name}; nothing was claimed")
        until = acl._deadline(invite, "claim_until", "expiration")
        if until is not None and now(self.relay.clock) > until:
            raise MailError("the invite expired before it was claimed; nothing was sent")
        before = self.acl_state(owner)
        taken = before.claimed_invites.get(invite.id)
        if taken is not None and taken != self.me:
            raise MailError("the invite was already claimed and confirmed for another key; "
                            "nothing was sent")
        if taken == self.me:
            return {"invite_id": invite.id, "mailbox": _npub(owner), "state": "granted",
                    "grant": before.grants[self.me].to_dict()}
        proof = acl.claim_proof(invite.id, self.me, secret)
        claim = self.relay.sign(acl.CLAIM, [["mbx", owner], ["e", invite.id], ["p", owner],
                                            ["invite_sig", proof]],
                                dumps({"name": pairwise.sanitize_label(name)}))
        self.relay.publish(claim)
        self._acl.pop(owner, None)
        state = self.acl_state(owner)
        reason = next((why for ident, why in state.rejected if ident == claim.id), None)
        if reason is not None:
            raise MailError(f"the claim was published and does not stand: {reason}")
        return {"invite_id": invite.id, "claim_id": claim.id, "mailbox": _npub(owner),
                "state": "pending_owner_confirmation",
                "next": "the owner's client confirms the first valid claim of an invite the "
                        "next time it reads its dropbox; mail is accepted after that"}

    def settle_claims(self) -> list[acl.Grant]:
        """As the owner: confirm the first valid claim of each invite with a grant on
        the invite's terms, naming the invite. Safe to repeat: a confirmed invite has no
        pending claim."""
        state = self.acl_state(self.me)
        confirmed = []
        for invite_id, claim in sorted(state.pending_claims.items()):
            scope, parts, trust, read_replies = acl.parse_terms(state.invites[invite_id])
            self._publish_acl(acl.GRANT, [
                ["mbx", self.me], ["p", claim.pubkey],
                *acl.terms_tags(scope, parts, trust, read_replies), ["relay", self.relay_name],
                ["e", invite_id]], about=claim.pubkey)
            confirmed.append(claim.pubkey)
        return [self.acl_state(self.me).grants[pk] for pk in confirmed
                if pk in self.acl_state(self.me).grants]

    # ---------------------------------------------------------------------- send
    def _portable(self, dest: str) -> str:
        home = str(self.user_home)
        if dest.startswith("~/"):
            portable = dest
        elif dest.startswith(home + os.sep):
            portable = "~/" + dest[len(home) + 1:]
        elif os.path.isabs(dest):
            portable = dest
        else:
            raise MailError(f"--attach-file DEST {dest!r} must be absolute or start with ~/")
        if ".." in PurePosixPath(portable).parts:
            raise MailError(f"--attach-file DEST {dest!r} may not contain '..'")
        return portable

    def _upload(self, attachments: Iterable[tuple[str, str]]) -> list[dict]:
        manifest = []
        for dest, src in attachments:
            portable = self._portable(dest)
            try:
                data = Path(src).expanduser().read_bytes()
            except OSError as exc:
                raise MailError(f"--attach-file source {src}: {exc}") from exc
            if not data:
                raise MailError(f"--attach-file source {src} is empty")
            ciphertext, key = pairwise.seal_file(data)
            blob = self.session.blobs().upload(ciphertext)
            manifest.append({"dest": portable, "bytes": len(data),
                             "sha256": hashlib.sha256(data).hexdigest(),
                             "blob": blob.sha256, "key": key})
        return manifest

    def _authorize(self, route: Route) -> None:
        owner = route.owner
        grants = self.acl_state(owner).grants
        if owner == self.me:
            if not acl.can_read(owner, route.reader, author=self.me, recipient=route.reader,
                                part=route.part, thread_opener=route.opener, grants=grants):
                raise MailError(f"{_npub(route.reader)} cannot read {route.part!r} in your "
                                "mailbox under its grant; nothing was sent")
            return
        denial = acl.write_denial(owner, self.me, recipient=route.reader, part=route.part,
                                  thread_opener=route.opener, grants=grants)
        if denial:
            raise MailError(f"{denial} (mailbox {_npub(owner)}): ask its owner for "
                            "`acl grant`; nothing was sent")

    def _deliver(self, kind: int, route: Route, content: dict, *, seat: Signer | None,
                 cert: Event | None) -> Event:
        event = pairwise.wrap(kind, self.signer, route, content, created_at=now(self.relay.clock),
                              extra_tags=[["t", self.topic_tag]], seat=seat, cert=cert)
        size = event.wire_bytes
        if size > MAX_EVENT_BYTES:
            raise MailError(f"this mail is {size:,} bytes, {100 * size / MAX_EVENT_BYTES:.0f}% "
                            f"of the {MAX_EVENT_BYTES:,}-byte event cap; nothing was sent. Put "
                            "the bulk in an --attach-file")
        self.relay.publish(event)
        return event

    def send(self, *, to: str | None = None, reply_to: str | None = None, body: str = "",
             subject: str | None = None, attachments: Iterable[tuple[str, str]] = (),
             seat: Signer | None = None, cert: Event | None = None) -> dict:
        attachments = list(attachments)
        if not body.strip() and not attachments:
            raise MailError("nothing to send: give a body or an --attach-file")
        if reply_to:
            parent = self._released(reply_to)
            if parent.event.kind == RECEIPT:
                raise MailError("a receipt is not replied to")
            route = parent.route.reply(reader=parent.event.pubkey)
        else:
            if to is None or to == self.me:
                raise MailError("name the member whose dropbox this is for (--to <npub>)")
            route = Route.root(to, to, self.me)
        self._authorize(route)
        manifest = self._upload(attachments)
        event = self._deliver(ENVELOPE, route, {"v": 1, "subject": subject, "body": body,
                                                "attachments": manifest}, seat=seat, cert=cert)
        return {"id": event.id, "msg_id": route.msg, "thread": route.thread,
                "mailbox": _npub(route.owner), "to": _npub(route.reader), "part": route.part,
                "attachments": [{k: a[k] for k in ("dest", "bytes", "sha256")} for a in manifest],
                "bytes_used": event.wire_bytes, "bytes_cap": MAX_EVENT_BYTES,
                "bytes_used_pct": round(100 * event.wire_bytes / MAX_EVENT_BYTES, 1)}

    def receipt(self, ident: str, *, status: str, note: str | None = None) -> dict:
        if status not in pairwise.RECEIPT_STATUSES:
            raise MailError(f"receipt status {status!r} must be one of "
                            f"{pairwise.RECEIPT_STATUSES}")
        parent = self._released(ident)
        if parent.event.kind != ENVELOPE:
            raise MailError("a receipt acknowledges a message, not another receipt")
        route = parent.route.reply(reader=parent.event.pubkey)
        self._authorize(route)
        event = self._deliver(RECEIPT, route, {"v": 1, "status": status, "note": note,
                                               "ref": parent.route.msg}, seat=None, cert=None)
        return {"id": event.id, "acknowledged": parent.event.id, "status": status,
                "to": _npub(route.reader)}

    # ---------------------------------------------------------------------- read
    def _gates(self) -> dict[str, str]:
        """envelope id → the human gate's first ruling (handled = approved)."""
        rows = self.session.records(Kind.ACK, "ack", NostrRelayChannelBackend._ack,
                                    topic=DROPBOX, where={"authors": [self.me]})
        out: dict[str, str] = {}
        for _, got in rows:
            if got["seat"] == GATE_SEAT and got["disposition"] in ("handled", "rejected"):
                out.setdefault(got["msg_id"], got["disposition"])
        return out

    def items(self) -> list[Item]:
        self.settle_claims()
        events = self.relay.query_all({"kinds": list(pairwise.MAIL_KINDS), "#p": [self.me],
                                       "#t": [self.topic_tag]})
        gates, read = self._gates(), set(self._state()["read"])
        mine = self.acl_state(self.me).grants
        return [self._classify(e, mine, gates, read) for e in events if e.pubkey != self.me]

    def _classify(self, event: Event, mine: dict, gates: dict, read: set) -> Item:
        if event.wire_bytes > MAX_EVENT_BYTES:
            return Item(event, None, "invalid", problem="over the event cap")
        try:
            route = pairwise.route_of(event)
        except pairwise.EnvelopeError as exc:
            return Item(event, None, "invalid", problem=str(exc))
        if route.reader != self.me:
            return Item(event, route, "invalid", problem="not addressed to this key")
        grants = mine if route.owner == self.me else self.acl_state(route.owner).grants
        denial = acl.write_denial(route.owner, event.pubkey, recipient=self.me,
                                  part=route.part, thread_opener=route.opener, grants=grants)
        if denial:
            return Item(event, route, "quarantined", problem=denial)
        try:
            opened = pairwise.open_envelope(event, self.signer, route)
        except pairwise.EnvelopeError as exc:
            return Item(event, route, "invalid", problem=str(exc))
        source = grants if route.owner == self.me else mine
        tier = source[event.pubkey].trust if event.pubkey in source else acl.DEFAULT_TRUST
        if tier == "trusted_auto" or gates.get(event.id) == "handled":
            state = "read" if event.id in read else "unread"
        elif gates.get(event.id) == "rejected":
            state = "rejected"
        else:
            state = "pending_approval"
        return Item(event, route, state, trust=tier, opened=opened)

    def find(self, ident: str) -> Item:
        ident = ident.strip().lower()
        if not ident or any(c not in "0123456789abcdef" for c in ident):
            raise MailError("a mail id is a hexadecimal prefix of its envelope id")
        found = [i for i in self.items() if i.event.id.startswith(ident)]
        if not found:
            raise MailError(f"no mail {ident!r} addressed to this key; `mail read --all` "
                            "lists ids")
        if len(found) > 1:
            raise MailError(f"mail id prefix {ident!r} is ambiguous; give more characters")
        return found[0]

    def _released(self, ident: str) -> Item:
        item = self.find(ident)
        if not item.released:
            raise MailError(f"mail {item.event.id[:12]}… is {item.state}; only released mail "
                            "can be answered or acknowledged")
        return item

    def show(self, item: Item, staged: dict | None = None) -> dict:
        event, route = item.event, item.route
        out = {"id": event.id, "kind": "receipt" if event.kind == RECEIPT else "message",
               "from": {"npub": _npub(event.pubkey)}, "state": item.state,
               "trust": item.trust, "created_at": event.created_at}
        if route is not None:
            out.update({"msg_id": route.msg, "thread": route.thread,
                        "mailbox": _npub(route.owner), "part": route.part,
                        "reply_to": route.reply_to})
        if item.state in ("quarantined", "invalid"):
            out["problem"] = item.problem
        elif item.state == "pending_approval":
            out["content"] = "withheld"
            out["attachment_count"] = len(event.values("blob"))
            if event.kind == RECEIPT:           # a fixed vocabulary: safe to show
                out["status"] = item.opened.content["status"]
            out["notice"] = ("the sender is human_gated: subject, body and files are withheld "
                             "from agents. A human releases it at their own terminal with "
                             f"`nostr-mailbox mail approve {event.id[:12]}`")
        elif item.released:
            content = item.opened.content
            out["from"].update({"agent": item.opened.label, "harness": item.opened.harness})
            if event.kind == RECEIPT:
                out.update({"status": content["status"], "note": content.get("note")})
            else:
                out.update({"subject": content.get("subject"), "body": content["body"]})
                done = {s["dest"]: s for s in (staged or {}).get(event.id, [])}
                atts = [{"dest": a["dest"], "bytes": a["bytes"], "sha256": a["sha256"],
                         "staged": {k: v for k, v in done.get(a["dest"],
                                                              {"status": "not_staged"}).items()
                                    if k not in ("dest", "bytes", "sha256")}}
                        for a in content.get("attachments") or []]
                if atts:
                    out["attachments"] = atts
        return out

    def read(self, *, everything: bool = False, mark: bool = True) -> list[dict]:
        items = self.items()
        if not everything:
            items = [i for i in items if i.state in WAITING]
        state = self._state()
        for item in items:
            if (item.released and item.trust == "trusted_auto" and item.event.kind == ENVELOPE
                    and item.opened.content.get("attachments")
                    and item.event.id not in state["staged"]):
                state["staged"][item.event.id] = self._stage_all(item)
        out = [self.show(i, state["staged"]) for i in items]
        if mark:
            state["read"] = sorted(set(state["read"]) | {i.event.id for i in items
                                                         if i.state == "unread"})
        self._save(state)
        return out

    # ------------------------------------------------------------- human gate
    def review(self, ident: str) -> dict:
        """Everything a human needs to decide on one pending mail: for the human's own
        terminal only, never for an agent's output."""
        item = self.find(ident)
        if item.state != "pending_approval":
            raise MailError(f"mail {item.event.id[:12]}… is {item.state}, not pending_approval")
        content = item.opened.content
        files = []
        for att in content.get("attachments") or []:
            try:
                with self._stage_parent(att["dest"], create=False) as (target, parent):
                    exists = parent is not None and _exists(target.name, parent)
                    verdict = "exists: approve with --overwrite to replace" if exists else "new"
                    where = str(target)
            except StagingProblem as exc:
                where, verdict = att["dest"], f"refused: {exc}"
            files.append({"dest": att["dest"], "target": where, "bytes": att["bytes"],
                          "sha256": att["sha256"], "verdict": verdict})
        return {"id": item.event.id, "from": _npub(item.event.pubkey),
                "agent": item.opened.label, "harness": item.opened.harness,
                "kind": "receipt" if item.event.kind == RECEIPT else "message",
                "subject": content.get("subject"),
                "body": content.get("body", content.get("note")), "attachments": files}

    def approve(self, ident: str, *, decline: bool = False, overwrite: bool = False,
                note: str | None = None) -> dict:
        item = self.find(ident)
        if item.state != "pending_approval":
            raise MailError(f"mail {item.event.id[:12]}… is {item.state}, not pending_approval")
        self.session.publish(Kind.ACK, "ack", {
            "seat": GATE_SEAT, "msg_id": item.event.id,
            "disposition": "rejected" if decline else "handled", "result_ref": None,
            "note": note or ("declined" if decline else "approved") + " by a human at a terminal"},
            topic=DROPBOX, tags=[["e", item.event.id]])
        state = self._state()
        released = self.find(item.event.id)
        if not decline and released.event.kind == ENVELOPE and \
                released.opened.content.get("attachments"):
            state["staged"][released.event.id] = self._stage_all(released, overwrite=overwrite)
            self._save(state)
        return self.show(released, state["staged"])

    def status(self) -> dict:
        totals = dict.fromkeys(WAITING, 0)
        for item in self.items():
            if item.state in totals:
                totals[item.state] += 1
        return {"me": _npub(self.me), **totals}

    @staticmethod
    def hook_line(status: dict) -> str:
        """One line for a harness hook: counts, never content."""
        if not any(status[s] for s in WAITING):
            return "nostr-mailbox: no unread mail.\n"
        parts = [f"{status['unread']} unread"]
        if status["pending_approval"]:
            parts.append(f"{status['pending_approval']} awaiting human approval")
        if status["quarantined"]:
            parts.append(f"{status['quarantined']} quarantined")
        return f"nostr-mailbox: {', '.join(parts)}. Run: nostr-mailbox mail read\n"

    # ------------------------------------------------------------------ staging
    def _expand(self, path: str) -> Path:
        return self.user_home / path[2:] if path.startswith("~/") else Path(path)

    @contextlib.contextmanager
    def _stage_parent(self, dest: str, *, create: bool):
        """(target path, descriptor of its parent directory) for `dest`, walking every
        directory with O_DIRECTORY | O_NOFOLLOW from a pinned descriptor. The parent is
        None when it does not exist and `create` is false."""
        path = self._expand(dest)
        if not path.is_absolute() or ".." in PurePosixPath(dest).parts:
            raise StagingProblem("the destination must be absolute or under ~/, without '..'")
        root = self._expand(stage_root())
        if path == root or not path.is_relative_to(root):
            raise StagingProblem(f"the destination is outside the stage root {root}")
        base = self.user_home if path.is_relative_to(self.user_home) else Path(path.anchor)
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        try:
            profile = os.stat(self.profile_home)
        except FileNotFoundError:
            profile = None
        actual_base = base.resolve(strict=True)
        actual = actual_base / path.relative_to(base)
        if actual.is_relative_to(self.profile_home.resolve()):
            raise StagingProblem("the destination is inside the nostr-mailbox home")
        parent = _open_dir(str(actual_base), flags, None)
        try:
            for name in path.parent.relative_to(base).parts:
                try:
                    child = _open_dir(name, flags, parent)
                except FileNotFoundError:
                    if not create:
                        yield actual, None
                        return
                    with contextlib.suppress(FileExistsError):
                        os.mkdir(name, 0o700, dir_fd=parent)
                    child = _open_dir(name, flags, parent)
                os.close(parent)
                parent = child
                if profile is not None and os.path.samestat(os.fstat(parent), profile):
                    raise StagingProblem("the destination is inside the nostr-mailbox home")
            yield actual, parent
        finally:
            os.close(parent)

    def _stage_one(self, item: Item, att: dict, overwrite: bool) -> dict:
        try:
            ciphertext = self.session.blobs().download(att["blob"])
        except BlossomError as exc:
            raise IntegrityProblem(f"the attachment blob is unavailable: {exc}") from exc
        try:
            data = pairwise.open_file(ciphertext, att)
        except pairwise.EnvelopeError as exc:
            raise IntegrityProblem(str(exc)) from exc
        with self._stage_parent(att["dest"], create=True) as (target, parent):
            temporary = ".incoming-" + secrets.token_hex(16)
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600,
                         dir_fd=parent)
            try:
                with os.fdopen(fd, "wb") as fh:
                    fh.write(data)
                    fh.flush()
                    os.fchmod(fh.fileno(), 0o600)
                    os.fsync(fh.fileno())
                if overwrite:
                    os.replace(temporary, target.name, src_dir_fd=parent, dst_dir_fd=parent)
                else:
                    os.link(temporary, target.name, src_dir_fd=parent, dst_dir_fd=parent,
                            follow_symlinks=False)
            except (IsADirectoryError, FileExistsError) as exc:
                raise StagingConflict(f"{target} already exists") from exc
            finally:
                with contextlib.suppress(FileNotFoundError):
                    os.unlink(temporary, dir_fd=parent)
        return {"dest": att["dest"], "path": str(target), "bytes": len(data),
                "sha256": att["sha256"], "status": "staged", "mode": "0600"}

    def _stage_all(self, item: Item, *, overwrite: bool = False) -> list[dict]:
        results = []
        for att in item.opened.content.get("attachments") or []:
            try:
                results.append(self._stage_one(item, att, overwrite))
            except StagingProblem as exc:
                results.append({"dest": att["dest"], "bytes": att["bytes"],
                                "sha256": att["sha256"], "status": exc.status,
                                "reason": str(exc)})
        return results


def _open_dir(name: str, flags: int, parent: int | None) -> int:
    """One directory, never through a symlink. FileNotFoundError passes through."""
    try:
        return os.open(name, flags, dir_fd=parent)
    except FileNotFoundError:
        raise
    except OSError as exc:
        if exc.errno in (errno.ELOOP, errno.ENOTDIR, errno.EACCES, errno.EPERM):
            raise StagingProblem(f"the destination passes through {name!r}, a symlink or a "
                                 "directory this user cannot enter") from exc
        raise


def _exists(name: str, parent: int) -> bool:
    try:
        os.stat(name, dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError:
        return False
    return True


def seat_cert_for(person: Signer, seat: Signer, label: str, *, created_at: int) -> Event:
    """The certificate a person signs for one of its seats, on the fly: it is never
    published, only carried inside that seat's seals."""
    return pairwise.seat_certificate(person, seat.pubkey, label=label, harness=label,
                                     host=socket.gethostname(), created_at=created_at)
