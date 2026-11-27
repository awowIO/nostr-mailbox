"""Pairwise mail: the agent-mailbox double-signed envelope over NIP-44 v2 ECDH.

    4410 envelope (outer, signed by the sender's member key)
         tags    [["mbx",owner],["p",reader],["part",part],["thread",t],["msg",m],
                  ["opener",opener,nonce],["t","<campaign>:dropbox"],
                  ["reply_to",m']?, ["blob",<sha256 of ciphertext>]…]
         content NIP-44 v2 under conversation_key(sender, reader) of the JSON of:
    4412 seal (inner, signed by the sender, or by a seat it certified; never published)
         tags    [["p",reader],["mbx",owner],["part",part],["thread",t],["msg",m],
                  ["k","4410"],["reply_to",m']?,["seat_cert",<JSON of a 34410>]?]
         content {"v":1,"subject":str|null,"body":str,"attachments":[…]}
    4411 receipt: the same envelope and seal, `reply_to` the acknowledged message and
         content {"v":1,"status":"received|resolved|declined","note":str|null,"ref":m'}
    34410 seat certificate (signed by the person): [["d",seat],["p",seat],["label",…],
         ["harness",…],["host",…]]

A reader admits an envelope only when the seal repeats the envelope's routing, the
kind and the reply it answers (so a seal cannot be re-wrapped and forwarded as if its
author had written to someone else), and is signed by the envelope's author or by a
seat that author certified.

Threads are commitments, not counters: every envelope carries `["opener", pk, nonce]`
and its thread is the first 16 bytes of sha256("agent-mailbox/thread/v1" ‖ owner ‖
opener ‖ nonce ‖ part). A root is written by its opener and its message id is the
thread. So any reader can tell who opened a thread, and in which part, from the
envelope alone; no relay ordering can hand a thread to someone else.

An attachment is encrypted with its own random 32-byte key (NIP-44 v2, the key used
directly as the conversation key), uploaded as ASCII ciphertext, and listed in the
seal as {dest, bytes, sha256 (plaintext), blob (sha256 of the ciphertext), key}."""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
from dataclasses import dataclass

from . import nip44
from .event import Event, InvalidEvent, NostrError, dumps, unsigned, verify_event
from .identity import Signer, pairwise_key

ENVELOPE, RECEIPT, SEAL, SEAT_CERT = 4410, 4411, 4412, 34410
MAIL_KINDS = (ENVELOPE, RECEIPT)
RECEIPT_STATUSES = ("received", "resolved", "declined")
THREAD_DOMAIN = b"agent-mailbox/thread/v1"
PERSON = "person"                       # the label of a seal the sender signed itself
_PART = re.compile(r"^(inbox|bus|topic:[a-z0-9][a-z0-9._-]*)$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_HEX32 = re.compile(r"^[0-9a-f]{32}$")
_LABEL_BAD = re.compile(r"[^a-z0-9._-]+")


class EnvelopeError(NostrError):
    """An envelope whose routing, seal or content does not hold together."""


def sanitize_label(value: str | None) -> str:
    """Peer-controlled names shown to an agent are reduced to [a-z0-9._-]."""
    return _LABEL_BAD.sub("-", (value or "").lower()).strip("-")[:64]


def thread_id(owner: str, opener: str, part: str, nonce: str) -> str:
    raw = THREAD_DOMAIN + bytes.fromhex(owner + opener + nonce) + part.encode("ascii")
    return hashlib.sha256(raw).hexdigest()[:32]


@dataclass(frozen=True)
class Route:
    """Where an envelope sits: whose mailbox, who reads it, which part and thread."""
    owner: str
    reader: str
    part: str
    thread: str
    msg: str
    opener: str
    nonce: str
    reply_to: str | None = None

    @classmethod
    def root(cls, owner: str, reader: str, opener: str, part: str = "inbox") -> Route:
        nonce = secrets.token_hex(16)
        thread = thread_id(owner, opener, part, nonce)
        return cls(owner, reader, part, thread, thread, opener, nonce)

    def reply(self, reader: str) -> Route:
        """The next message in this thread, to `reader`, answering this one."""
        return Route(self.owner, reader, self.part, self.thread, secrets.token_hex(16),
                     self.opener, self.nonce, reply_to=self.msg)

    def tags(self) -> list[list[str]]:
        tags = [["mbx", self.owner], ["p", self.reader], ["part", self.part],
                ["thread", self.thread], ["msg", self.msg],
                ["opener", self.opener, self.nonce]]
        return tags + ([["reply_to", self.reply_to]] if self.reply_to else [])


def route_of(event: Event) -> Route:
    """The route an envelope declares, checked against its own thread commitment."""
    def one(name: str, pattern: re.Pattern) -> str:
        values = event.values(name)
        if len(values) != 1 or not pattern.match(values[0]):
            raise EnvelopeError(f"envelope tag {name!r} must appear once and be well formed")
        return values[0]

    owner, reader = one("mbx", _HEX64), one("p", _HEX64)
    part, thread, msg = one("part", _PART), one("thread", _HEX32), one("msg", _HEX32)
    replies = event.values("reply_to")
    if len(replies) > 1 or (replies and not _HEX32.match(replies[0])):
        raise EnvelopeError("an envelope answers at most one message")
    openers = [t for t in event.tags if t[0] == "opener"]
    if (len(openers) != 1 or len(openers[0]) != 3 or not _HEX64.match(openers[0][1])
            or not _HEX32.match(openers[0][2])):
        raise EnvelopeError("an envelope carries one thread commitment [opener, pk, nonce]")
    opener, nonce = openers[0][1], openers[0][2]
    if thread_id(owner, opener, part, nonce) != thread:
        raise EnvelopeError("the thread does not belong to this opener, mailbox and part")
    if not replies and (event.pubkey != opener or msg != thread):
        raise EnvelopeError("a thread's first message is written by its opener and named "
                            "by the thread id")
    return Route(owner, reader, part, thread, msg, opener, nonce,
                 replies[0] if replies else None)


# ---------------------------------------------------------------------- seats
def seat_certificate(person: Signer, seat_pubkey: str, *, label: str, harness: str,
                     host: str, created_at: int) -> Event:
    """The person's signed statement that `seat_pubkey` is one of its agent seats."""
    return person.sign_event(unsigned(SEAT_CERT, [
        ["d", seat_pubkey], ["p", seat_pubkey], ["label", sanitize_label(label)],
        ["harness", sanitize_label(harness)], ["host", sanitize_label(host)]], "", created_at))


# ------------------------------------------------------------------------ wrap
def wrap(kind: int, sender: Signer, route: Route, content: dict, *, created_at: int,
         extra_tags=(), seat: Signer | None = None, cert: Event | None = None) -> Event:
    """Seal `content` (signed by `seat`, or the sender itself) and wrap it for the
    route's reader in an envelope the sender signs."""
    if kind not in MAIL_KINDS:
        raise EnvelopeError(f"kind {kind} is not a mail kind {MAIL_KINDS}")
    if (seat is None) != (cert is None):
        raise EnvelopeError("a seat seals only with the certificate that names it")
    seal_tags = [["p", route.reader], ["mbx", route.owner], ["part", route.part],
                 ["thread", route.thread], ["msg", route.msg], ["k", str(kind)]]
    if route.reply_to:
        seal_tags.append(["reply_to", route.reply_to])
    if cert is not None:
        seal_tags.append(["seat_cert", dumps(cert.to_dict())])
    seal = (seat or sender).sign_event(unsigned(SEAL, seal_tags, dumps(content), created_at))
    payload = nip44.encrypt(dumps(seal.to_dict()), pairwise_key(sender, route.reader))
    blobs = [["blob", att["blob"]] for att in content.get("attachments") or []]
    return sender.sign_event(unsigned(kind, [*route.tags(), *extra_tags, *blobs], payload,
                                      created_at))


@dataclass(frozen=True)
class Opened:
    content: dict
    agent: str                          # the key that signed the seal
    label: str                          # PERSON, or the certified seat's label
    harness: str | None


def open_envelope(event: Event, me: Signer, route: Route) -> Opened:
    """Decrypt and check the seal of an envelope addressed to (or written by) `me`."""
    peer = route.reader if event.pubkey == me.pubkey else event.pubkey
    # Every message here is fixed text: what a sender wrote must not reach an agent
    # through an error, least of all from mail whose content is withheld.
    try:
        raw = json.loads(nip44.decrypt(event.content, pairwise_key(me, peer)))
        seal = verify_event(raw)
    except nip44.Nip44Error as exc:
        raise EnvelopeError(f"the envelope does not decrypt for this key: {exc}") from exc
    except (json.JSONDecodeError, RecursionError, InvalidEvent) as exc:
        raise EnvelopeError("the seal is not a validly signed event") from exc
    if seal.kind != SEAL:
        raise EnvelopeError("the inner event is not a seal")
    for name in ("p", "mbx", "part", "thread", "msg"):
        if seal.values(name) != event.values(name):
            raise EnvelopeError(f"the sealed {name!r} differs from the envelope: re-wrapped "
                                "or forwarded")
    if seal.values("k") != [str(event.kind)] or seal.values("reply_to") != event.values(
            "reply_to"):
        raise EnvelopeError("the sealed kind or reply differs from the envelope")
    if seal.pubkey == event.pubkey:
        label, harness = PERSON, None
    else:
        certs = seal.values("seat_cert")
        if len(certs) != 1:
            raise EnvelopeError("the seal is signed by a key that is neither the sender nor "
                                "a seat the sender certified")
        try:
            cert = verify_event(json.loads(certs[0]))
        except (json.JSONDecodeError, RecursionError, InvalidEvent) as exc:
            raise EnvelopeError("the seat certificate does not verify") from exc
        if (cert.kind != SEAT_CERT or cert.pubkey != event.pubkey
                or cert.values("d") != [seal.pubkey]):
            raise EnvelopeError("the seat certificate does not bind the sealing key to the "
                                "sender")
        label = sanitize_label((cert.values("label") or [""])[0]) or "seat"
        harness = sanitize_label((cert.values("harness") or [""])[0]) or None
    try:
        content = json.loads(seal.content)
    except (json.JSONDecodeError, RecursionError) as exc:
        raise EnvelopeError("the sealed content is not JSON") from exc
    check_content(event, content)
    return Opened(content, seal.pubkey, label, harness)


def check_content(event: Event, content) -> None:
    if not isinstance(content, dict) or type(content.get("v")) is not int or content["v"] != 1:
        raise EnvelopeError("unsupported mail content version")
    if event.kind == RECEIPT:
        if (content.get("status") not in RECEIPT_STATUSES
                or content.get("ref") != (event.values("reply_to") or [None])[0]
                or not isinstance(content.get("note"), (str, type(None)))
                or "attachments" in content):
            raise EnvelopeError("a receipt carries a known status and the ref it answers")
        return
    if (not isinstance(content.get("body"), str)
            or not isinstance(content.get("subject"), (str, type(None)))):
        raise EnvelopeError("the message body or subject has the wrong type")
    attachments = content.get("attachments", [])
    if not isinstance(attachments, list):
        raise EnvelopeError("the attachment list is not a list")
    blobs = set(event.values("blob"))
    for att in attachments:
        ok = (isinstance(att, dict) and set(att) == {"dest", "bytes", "sha256", "blob", "key"}
              and isinstance(att["dest"], str) and att["dest"] and "\x00" not in att["dest"]
              and type(att["bytes"]) is int and att["bytes"] > 0
              and all(isinstance(att[k], str) and _HEX64.match(att[k])
                      for k in ("sha256", "blob", "key")))
        if not ok or att["blob"] not in blobs:
            raise EnvelopeError("an attachment entry is malformed or names a blob the "
                                "envelope does not carry")
    if blobs != {att["blob"] for att in attachments}:
        raise EnvelopeError("the envelope carries a blob its seal does not list")


# ------------------------------------------------------------------ attachments
def seal_file(data: bytes) -> tuple[bytes, str]:
    """(ASCII ciphertext to upload, hex key) for one attachment."""
    if not data:
        raise EnvelopeError("an attachment is never empty")
    key = os.urandom(32)
    return nip44.encrypt_bytes(data, key).encode("ascii"), key.hex()


def open_file(ciphertext: bytes, att: dict) -> bytes:
    """The attachment's plaintext, checked against everything the seal signed."""
    if hashlib.sha256(ciphertext).hexdigest() != att["blob"]:
        raise EnvelopeError("the blob does not hash to the digest the seal names")
    try:
        data = nip44.decrypt_bytes(ciphertext.decode("ascii"), bytes.fromhex(att["key"]))
    except (nip44.Nip44Error, UnicodeDecodeError) as exc:
        raise EnvelopeError(f"the attachment does not decrypt: {exc}") from exc
    if len(data) != att["bytes"] or hashlib.sha256(data).hexdigest() != att["sha256"]:
        raise EnvelopeError("the decrypted attachment is not the size and digest the seal "
                            "signed")
    return data
