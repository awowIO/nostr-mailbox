"""The command line: `nostr-mailbox …`, `python -m nostr_mailbox …`, and the skill script.

Every command prints one JSON document on stdout. Exit 0 means it completed; exit 1
means it did not, with `error: …` on stderr; a command over several ids that stops
part-way prints which ids completed before it exits 1. Secrets never travel on the
command line: an invite code is read from a file, a pipe or a hidden prompt, and a key
is never printed.

A command that talks to a relay needs the campaign's transport declaration
(`--trust nostr.toml`, or `NOSTR_MAILBOX_TRUST`). There is no default relay.

Two commands write files a harness reads, and nothing else: `handoff materialize --out`
(a four-field packet) and `directive adopt --operator-file` (one entry in an
OPERATOR.md). Both can append one wake line to `--wake-file`."""
from __future__ import annotations

import argparse
import base64
import binascii
import contextlib
import functools
import getpass
import hashlib
import json
import math
import os
import shlex
import sys
import threading
from pathlib import Path

from . import bech32, bridge, secp256k1
from .backend import (
    BUS,
    DISPOSITIONS,
    INBOX,
    TERMINAL_DISPOSITIONS,
    CampaignSession,
    Message,
    NostrRelayChannelBackend,
    PartialBatch,
)
from .event import NostrError
from .identity import (
    AUTH_KIND,
    BLOSSOM_AUTH_KIND,
    DEFAULT_NAME,
    HOME_ENV,
    IdentityError,
    SignerServer,
    create_identity,
    home,
    load_identity,
)
from .profile import (
    CLAIM_EFFECTS,
    DECISION_OUTCOMES,
    EVERY_SEAT,
    ROUTE_STATES,
    Checkpoint,
    Claim,
    Condition,
    Handoff,
    Heartbeat,
    Kind,
    ProfileError,
    Route,
    Trust,
)
from .relay import (
    DEFAULT_WAIT_S,
    INVITE_CLAIM_KIND,
    INVITE_TTL,
    NCLI_CONFIG,
    PAGE_LIMIT,
    RelayAdmin,
    RelayError,
    RelayRejected,
    fetch_info,
    invite_code,
)

TRUST_ENV = "NOSTR_MAILBOX_TRUST"
IDENTITY_ENV = "NOSTR_MAILBOX_IDENTITY"
SEAT_ENV = "NOSTR_MAILBOX_SEAT"

# What a signer socket signs for each role. A seat's signer cannot be made to sign a
# directive, a seal, a Route Board row or a review decision: those kinds are simply not
# on its list.
SEAT_KINDS = frozenset({
    AUTH_KIND, INVITE_CLAIM_KIND, BLOSSOM_AUTH_KIND, int(Kind.HEARTBEAT),
    int(Kind.CHECKPOINT_HEAD), int(Kind.CLAIM), int(Kind.HANDOFF), int(Kind.ACK),
    int(Kind.MESSAGE)})
ROLE_KINDS = {
    "seat": SEAT_KINDS,
    "lead": SEAT_KINDS | {int(Kind.ROUTE_HEAD)},
    "reviewer": SEAT_KINDS | {int(Kind.DECISION), int(Kind.CONDITION_HEAD)},
    "operator": SEAT_KINDS | {int(Kind.ROUTE_HEAD), int(Kind.DECISION),
                              int(Kind.CONDITION_HEAD), int(Kind.DIRECTIVE), int(Kind.SEAL)},
}
SEAT_BLOB_VERBS = frozenset({"get", "upload"})


# --------------------------------------------------------------------------- context
def _identity(args):
    return load_identity(args.identity, base=args.home)


def _default_trust_path(args) -> Path:
    return home(args.home) / "nostr.toml"


def _default_admin_path(args) -> Path:
    return home(args.home) / "admin.json"


def _write_admin_file(path: Path, admin: RelayAdmin) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    tmp = path.with_suffix(".json.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump({"exec_prefix": admin.exec_prefix, "config": admin.config}, fh)
    os.replace(tmp, path)


def _trust(args) -> Trust:
    path = args.trust
    if not path:
        candidate = _default_trust_path(args)
        if candidate.is_file():
            path = str(candidate)
    if not path:
        raise ProfileError(f"no transport declaration: run `nostr-mailbox setup` or "
                           f"`nostr-mailbox join`, pass --trust nostr.toml, or set "
                           f"{TRUST_ENV}. There is no default relay")
    return Trust.load(path)


def _write_trust_file(path: Path, mapping: dict) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    lines = [
        f'schema = {json.dumps(mapping.get("schema", "cf.transport/1"))}',
        f'relay = {json.dumps(mapping["relay"])}',
        f'campaign = {json.dumps(mapping["campaign"])}',
        f'operator_pubkeys = {json.dumps(list(mapping["operator_pubkeys"]))}',
    ]
    for opt in ("lead_pubkeys", "reviewer_pubkeys"):
        if mapping.get(opt):
            lines.append(f"{opt} = {json.dumps(list(mapping[opt]))}")
    for scalar in ("group", "blossom", "relay_auth_url", "campaign_key"):
        if mapping.get(scalar):
            lines.append(f"{scalar} = {json.dumps(mapping[scalar])}")
    if mapping.get("allow_cleartext") is True:
        lines.append("allow_cleartext = true")
    text = "\n".join(lines) + "\n"
    Trust.from_mapping(mapping, source=str(path))
    tmp = path.with_suffix(".toml.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(text)
    os.replace(tmp, path)


def _encode_invite_token(trust: Trust, code: str) -> str:
    bundle = {
        "schema": "cf.transport/1",
        "relay": trust.relay,
        "campaign": trust.campaign,
        "operator_pubkeys": [_npub(k) for k in sorted(trust.operator_pubkeys)],
        "code": code,
    }
    if trust.lead_pubkeys:
        bundle["lead_pubkeys"] = [_npub(k) for k in sorted(trust.lead_pubkeys)]
    if trust.reviewer_pubkeys:
        bundle["reviewer_pubkeys"] = [_npub(k) for k in sorted(trust.reviewer_pubkeys)]
    for attr in ("group", "blossom", "relay_auth_url", "campaign_key"):
        val = getattr(trust, attr)
        if val:
            bundle[attr] = val
    if trust.allow_cleartext:
        bundle["allow_cleartext"] = True
    raw = json.dumps(bundle, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "nm1_" + base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _decode_invite_token(token: str) -> tuple[str, dict | None]:
    if not token.startswith("nm1_"):
        return token, None
    b64 = token[4:]
    pad = "=" * ((4 - len(b64) % 4) % 4)
    try:
        data = json.loads(base64.urlsafe_b64decode(b64 + pad).decode("utf-8"))
    except (binascii.Error, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProfileError(f"invalid nm1_ invite token: {exc}") from exc
    if not isinstance(data, dict) or not isinstance(data.get("code"), str) or not data["code"]:
        raise ProfileError("nm1_ invite token is missing `code`")
    code = data.pop("code")
    data.pop("expires_at", None)
    Trust.from_mapping(data, source="nm1_ invite token")
    return code, data


def _session(args) -> CampaignSession:
    """An unconnected session; `with` connects it and closes it."""
    signer = _identity(args).signer(timeout_s=args.timeout_seconds)
    return CampaignSession(_trust(args), signer, timeout_s=args.timeout_seconds)


def _seat(args) -> str:
    return args.seat or args.identity


def _npub(pubkey: str) -> str:
    return bech32.encode(bech32.NPUB, bytes.fromhex(pubkey))


def _with_rejected(session: CampaignSession, result: dict) -> dict:
    """Records the relay returned that were not valid records of this campaign are
    reported beside the answer, never dropped unseen."""
    if session.rejected:
        result["rejected"] = [{"id": ident, "reason": why} for ident, why in session.rejected]
    if session.relay.notices:
        result["relay_notices"] = session.relay.notices
    return result


def _content_key(*parts) -> str:
    """The idempotency key when none is given: a digest of what is being said, so
    running the same command twice says it once."""
    return hashlib.sha256(json.dumps(parts, sort_keys=True).encode()).hexdigest()


def _read_file(path: str) -> str:
    try:
        return Path(path).read_text()
    except (OSError, UnicodeDecodeError) as exc:
        raise ProfileError(f"cannot read {path}: {exc}") from exc


def _text(value: str | None) -> str:
    if value is None or value == "-":
        return sys.stdin.read()
    return value


def _directive_dict(directive) -> dict:
    return {"id": directive.event_id, "seq": directive.seq, "prev": directive.prev,
            "operator": _npub(directive.operator), "created_at": directive.created_at,
            "audience": list(directive.audience), "graph_digest": directive.graph_digest,
            "overrules": list(directive.overrules), "text": directive.text}


def _admin(args) -> RelayAdmin:
    if args.kubectl:
        kubeconfig = os.environ.get("KUBECONFIG", "").split(os.pathsep)[0].strip()
        admin = RelayAdmin.kubectl(timeout_s=args.timeout_seconds, namespace=args.namespace,
                                   pod=args.pod)
        if kubeconfig:
            admin.exec_prefix = ["kubectl", "--kubeconfig", kubeconfig,
                                 *admin.exec_prefix[1:]]
        return admin
    if args.compose:
        return RelayAdmin.compose(args.compose, timeout_s=args.timeout_seconds)
    if args.exec:
        return RelayAdmin(shlex.split(args.exec), timeout_s=args.timeout_seconds,
                          config=args.config)
    saved = _default_admin_path(args)
    if saved.is_file():
        try:
            data = json.loads(saved.read_text())
            if isinstance(data, dict) and isinstance(data.get("exec_prefix"), list):
                return RelayAdmin([str(x) for x in data["exec_prefix"]],
                                  timeout_s=args.timeout_seconds,
                                  config=str(data.get("config") or args.config))
        except (OSError, json.JSONDecodeError):
            pass
    return RelayAdmin([], timeout_s=args.timeout_seconds, config=args.config)


# -------------------------------------------------------------------------- identity
def cmd_init(args) -> dict:
    identity = create_identity(
        args.name, base=args.home, pubkey=args.pubkey,
        command=shlex.split(args.signer_command) if args.signer_command else None,
        socket_path=args.signer_socket, timeout_s=args.timeout_seconds)
    return {**identity.describe(), "created": True,
            "next": "give the npub to the operator, or redeem an invite with `relay join`"}


def cmd_id(args) -> dict:
    return load_identity(args.name, base=args.home).describe()


def cmd_signer_serve(args) -> dict:
    kinds = set(ROLE_KINDS[args.role]) | set(args.allow_kind)
    trust = Trust.load(args.trust) if args.trust else None
    relay = args.relay or (trust and (trust.relay_auth_url or trust.relay))
    blob_server = args.blossom_server or (trust and trust.blossom_server)
    signer = _identity(args).signer(timeout_s=args.timeout_seconds)
    server = SignerServer(args.socket, signer, allow_kinds=frozenset(kinds), relay=relay,
                          blossom_server=blob_server, blossom_verbs=SEAT_BLOB_VERBS,
                          read_timeout_s=args.timeout_seconds)
    server.start()
    print(json.dumps({"serving": args.socket, "npub": _identity(args).npub,
                      "role": args.role, "allow_kinds": sorted(kinds),
                      "relay_pin": relay, "blossom_pin": blob_server,
                      "blossom_verbs": sorted(SEAT_BLOB_VERBS) if blob_server else None}),
          flush=True)
    try:
        with contextlib.suppress(KeyboardInterrupt):    # Ctrl-C is how this command ends
            threading.Event().wait()
    finally:
        server.close()
    return {"stopped": args.socket}


# ---------------------------------------------------------------- relay membership
def _ensure_identity(args):
    try:
        return load_identity(args.identity, base=args.home), False
    except IdentityError:
        return create_identity(args.identity, base=args.home), True


def cmd_setup(args) -> dict:
    """One-command operator setup: creates the operator key (if missing), generates a
    32-byte NIP-44 v2 campaign_key (reusing an existing one for the same campaign), writes
    `<home>/nostr.toml` (0600), saves `<home>/admin.json` (0600) so future `invite` /
    `relay revoke` calls need no flags, and enrolls the operator key on the relay."""
    ident, created = _ensure_identity(args)
    trust_path = Path(args.trust) if args.trust else _default_trust_path(args)
    existing_ck = None
    if trust_path.is_file():
        with contextlib.suppress(ProfileError):
            prev = Trust.load(trust_path)
            if prev.campaign == args.campaign and prev.campaign_key:
                existing_ck = prev.campaign_key
    ck = None if args.no_encryption else (existing_ck or os.urandom(32).hex())
    mapping = {
        "schema": "cf.transport/1",
        "relay": args.relay,
        "campaign": args.campaign,
        "operator_pubkeys": [ident.npub],
    }
    if ck:
        mapping["campaign_key"] = ck
    _write_trust_file(trust_path, mapping)
    out = {
        "identity": ident.name,
        "npub": ident.npub,
        "identity_created": created,
        "trust_file": str(trust_path),
        "relay": args.relay,
        "campaign": args.campaign,
        "encrypted_nip44_v2": bool(ck),
    }
    if args.kubectl or args.compose or args.exec:
        admin = _admin(args)
        _write_admin_file(_default_admin_path(args), admin)
        out["enrolled_on_relay"] = admin.add_member(ident.pubkey)
    return out


def _invite_input(args) -> tuple[str, dict | None]:
    token = getattr(args, "token", None)
    if token and token != "-":
        text = token
    elif args.code_file and args.code_file != "-":
        text = _read_file(args.code_file)
    elif token == "-" or args.code_file == "-" or not sys.stdin.isatty():
        text = sys.stdin.read()
    else:
        text = getpass.getpass("One-use relay invite code or nm1_ token: ")
    text = text.strip()
    if not text:
        raise ProfileError("no invite code given")
    if text.startswith("nm1_"):
        return _decode_invite_token(text)
    if not text.startswith("{"):
        return text, None
    try:                                    # the JSON `relay invite` wrote or printed
        obj = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ProfileError(
            f"the invite looks like JSON but does not parse: {exc}") from exc
    if (isinstance(obj, dict) and isinstance(obj.get("token"), str)
            and obj["token"].startswith("nm1_")):
        return _decode_invite_token(obj["token"])
    return invite_code(obj), None


def _advertised(trust: Trust, args) -> dict:
    """What the relay claims in its NIP-11 document, or why that could not be read."""
    try:
        return fetch_info(trust.relay, timeout_s=args.timeout_seconds,
                          allow_cleartext=trust.allow_cleartext).to_dict()
    except RelayError as exc:
        return {"advertises_private": False, "unreadable": str(exc)}


def cmd_relay_join(args) -> dict:
    code, bundle = _invite_input(args)
    if bundle is not None and not args.trust:
        _write_trust_file(_default_trust_path(args), bundle)
        _ensure_identity(args)
    trust = _trust(args)
    advertised = _advertised(trust, args)
    if not advertised["advertises_private"]:
        raise ProfileError(
            f"{trust.relay} does not advertise both auth_required and membership_required "
            f"({advertised.get('unreadable') or 'its NIP-11 document says otherwise'}). An "
            "invite is not spent on a relay that does not claim to be private; nothing "
            "was sent")
    with _session(args) as session:
        answer = session.relay.join(code)
        return {"joined": trust.relay, "campaign": trust.campaign,
                "npub": _identity(args).npub, "relay_said": answer}


def cmd_relay_check(args) -> dict:
    """Four separate facts, because one green light would hide which is missing: what
    the relay claims, whether it accepted this key's proof, whether this key may read
    it, and (when the campaign names one) whether it may read the group."""
    trust = _trust(args)
    advertised = _advertised(trust, args)

    def may_read(session: CampaignSession, extra: dict) -> tuple[bool, str]:
        try:                                # an ephemeral kind: nothing stored to download
            session.relay.query({"kinds": [int(Kind.HEARTBEAT)], "limit": 1, **extra})
        except RelayRejected as exc:
            return False, exc.reason
        return True, ""

    with _session(args) as session:
        access, said = may_read(session, {})
        group = None
        if trust.group:
            allowed, why = may_read(session, {"#h": [trust.group]}) if access else (False, said)
            group = {"id": trust.group, "access": allowed, "relay_said": why}
    max_limit = advertised.get("max_limit")
    ok = advertised["advertises_private"] and access and (group is None or group["access"])
    return {"ok": ok, "relay": trust.relay, "npub": _identity(args).npub,
            "advertised": advertised, "authenticated": True,
            "relay_access": access, "relay_said": said, "group": group,
            "page_limit": PAGE_LIMIT,
            "page_limit_within_relay_max": None if max_limit is None
            else max_limit >= PAGE_LIMIT,
            "schnorr_backend": secp256k1.BACKEND,
            "note": "`advertised` is what the relay says of itself. `relay_access` is what "
                    "it did for this key. Neither shows that it turns strangers away: "
                    "run `relay check` with a key that was never enrolled and expect "
                    "relay_access false",
            "_exit": 0 if ok else 1}


def cmd_relay_invite(args) -> dict:
    """One single-use invite, in the relay's own shape. With `--bundle` (or the top-level
    `nostr-mailbox invite` alias), also includes a self-contained `token` (`nm1_...`) so a
    friend can join in one command (`nostr-mailbox join nm1_...`)."""
    admin = _admin(args)
    trust = None
    if getattr(args, "bundle", False):
        with contextlib.suppress(ProfileError):
            trust = _trust(args)
    if not args.code_file:
        print("warning: this output carries a bearer code; send it privately, or use "
              "--code-file", file=sys.stderr)
        invite = admin.create_invite(ttl=args.ttl)
        if trust is not None:
            invite = {**invite, "token": _encode_invite_token(trust, invite["code"])}
        return invite
    try:
        fd = os.open(args.code_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except OSError as exc:
        raise ProfileError(f"cannot create {args.code_file} ({exc}); no invite was "
                           "made") from exc
    try:
        invite = admin.create_invite(ttl=args.ttl)
    except NostrError:
        os.close(fd)
        Path(args.code_file).unlink()
        raise
    if trust is not None:
        invite = {**invite, "token": _encode_invite_token(trust, invite["code"])}
    with os.fdopen(fd, "w") as fh:
        json.dump(invite, fh)
    return {"invite_written": args.code_file, "mode": "0600", "max_uses": invite["max_uses"],
            "expires_at": invite["expires_at"]}


def cmd_relay_add(args) -> dict:
    pubkey = bech32.pubkey_hex(args.pubkey)
    return {"added": pubkey, "relay_said": _admin(args).add_member(pubkey)}


def cmd_relay_revoke(args) -> dict:
    pubkey = bech32.pubkey_hex(args.pubkey)
    return {"removed": pubkey, "relay_said": _admin(args).remove_member(pubkey),
            "effect": "the relay closes this key's open subscriptions and refuses what it "
                      "asks next. Its sockets may stay connected and carry nothing; no "
                      "restart is needed, and nobody else is disconnected"}


# ----------------------------------------------------------------------------- inbox
def cmd_todo(args) -> dict:
    note = _text(args.message)
    refs = tuple(args.ref)
    key = args.idempotency_key or _content_key(
        INBOX, note, args.subject, args.target, args.surface, args.doc, args.page, refs)
    with _session(args) as session:
        receipt = NostrRelayChannelBackend(session).todo(
            note, target=args.target, key=key, surface=args.surface, doc=args.doc,
            page=args.page, refs=refs, subject=args.subject)
        return _with_rejected(session, receipt.to_dict())


def cmd_triage(args) -> dict:
    with _session(args) as session:
        return _with_rejected(session, NostrRelayChannelBackend(session).triage(
            target=args.target, surface=args.surface))


def cmd_resolve(args) -> dict:
    with _session(args) as session:
        receipts = NostrRelayChannelBackend(session).resolve(
            args.msg_ids, seat=_seat(args), result_ref=args.result_ref,
            disposition=args.disposition, note=args.note)
        return _with_rejected(session, {"resolved": [r.to_dict() for r in receipts]})


# ------------------------------------------------------------------------------- bus
def cmd_post(args) -> dict:
    body = _text(args.message)
    refs = tuple(args.ref)
    key = args.idempotency_key or _content_key(
        args.topic, body, args.kind, args.subject, refs, args.reply_to)
    with _session(args) as session:
        receipt = NostrRelayChannelBackend(session).post(
            args.topic, Message(body=body, kind=args.kind, subject=args.subject, refs=refs,
                                reply_to=args.reply_to), key=key)
        return _with_rejected(session, receipt.to_dict())


def cmd_read(args) -> dict:
    with _session(args) as session:
        messages = [m for m in NostrRelayChannelBackend(session).history(
                        args.topic, after=args.after)
                    if (not args.kind or m.kind == args.kind)
                    and all(ref in m.refs for ref in args.ref)]
        return _with_rejected(session, {"topic": args.topic,
                                        "messages": [m.to_dict() for m in messages]})


def cmd_watch(args) -> dict:
    with _session(args) as session:
        seat = _seat(args)
        messages = NostrRelayChannelBackend(session).watch(args.topic, seat,
                                                           wait_s=args.wait_seconds)
        return _with_rejected(session, {
            "topic": args.topic, "seat": seat, "messages": [m.to_dict() for m in messages],
            "next": "each message stays pending for this seat until `ack` settles it"})


def cmd_ack(args) -> dict:
    with _session(args) as session:
        receipts = NostrRelayChannelBackend(session).ack_many(
            args.topic, _seat(args), args.msg_ids, disposition=args.disposition,
            result_ref=args.result_ref, note=args.note)
        return _with_rejected(session, {"acked": [r.to_dict() for r in receipts]})


def cmd_seal(args) -> dict:
    with _session(args) as session:
        return _with_rejected(session,
                              NostrRelayChannelBackend(session).seal(args.topic).to_dict())


# ------------------------------------------------------------------ campaign records
def cmd_heartbeat(args) -> dict:
    with _session(args) as session:
        event = session.heartbeat(Heartbeat(seat=_seat(args), status=args.status,
                                            detail=args.detail))
        return {"event_id": event.id, "stored_by_relay": False}


def cmd_heartbeats(args) -> dict:
    with _session(args) as session:
        beats = session.watch_heartbeats(wait_s=args.wait_seconds, stop_after=args.count)
        return _with_rejected(session, {"waited_seconds": args.wait_seconds, "heartbeats": [
            {**beat.to_payload(), "author": _npub(event.pubkey),
             "created_at": event.created_at} for beat, event in beats]})


def cmd_checkpoint_put(args) -> dict:
    checkpoint = Checkpoint(seat=_seat(args), seq=args.seq, sha256=args.sha256, task=args.task,
                            parent_sha256=args.parent_sha256, feed_sha256=args.feed_sha256,
                            attempt=args.attempt, note=args.note)
    with _session(args) as session:
        event, written = session.put_checkpoint(checkpoint)
        return {"event_id": event.id, "written": written, **checkpoint.to_payload()}


def cmd_checkpoint_get(args) -> dict:
    with _session(args) as session:
        author = bech32.pubkey_hex(args.author) if args.author else None
        found = session.get_checkpoint(_seat(args), author=author)
        return _with_rejected(session, {"seat": _seat(args),
                                        "checkpoint": found.to_payload() if found else None})


def cmd_route_put(args) -> dict:
    route = Route(route=args.route, state=args.state, hypothesis=args.hypothesis,
                  falsification_criterion=args.falsification_criterion, origin=args.origin,
                  evidence=tuple(args.evidence), obstruction=args.obstruction,
                  reopen_trigger=args.reopen_trigger)
    with _session(args) as session:
        event, written = session.put_route(route)
        return {"event_id": event.id, "written": written, **route.to_payload()}


def cmd_route_list(args) -> dict:
    with _session(args) as session:
        return _with_rejected(session, {"routes": [r.to_payload() for r in session.routes()]})


def _condition_dict(event, condition: Condition) -> dict:
    return {"event_id": event.id, "reviewer": _npub(event.pubkey),
            "created_at": event.created_at, **condition.to_payload()}


def cmd_condition_open(args) -> dict:
    condition = Condition(condition=args.condition, rev=1, state="open", goal=args.goal,
                          statement=args.statement, next_action=args.next_action)
    with _session(args) as session:
        event, written = session.open_condition(condition)
        return {"written": written, **_condition_dict(event, condition)}


def cmd_condition_list(args) -> dict:
    with _session(args) as session:
        return _with_rejected(session, {"conditions": [
            _condition_dict(event, condition) for event, condition in session.conditions()]})


def cmd_claim_put(args) -> dict:
    claim = Claim(condition=args.condition, condition_rev=args.condition_rev,
                  effect=args.effect, candidate_digest=args.candidate_digest,
                  evidence_refs=tuple(args.evidence_ref), wave=args.wave, task=args.task)
    with _session(args) as session:
        event = session.claim(claim, goal_event=args.goal_event)
        return {"event_id": event.id, "status": "proposal", "goal_event": args.goal_event,
                **claim.to_payload()}


def cmd_claim_list(args) -> dict:
    with _session(args) as session:
        decided: dict[str, list] = {}
        for decision, event in session.decisions():
            decided.setdefault(decision.claim, []).append(
                {"outcome": decision.outcome, "reason": decision.reason,
                 "decision_id": event.id, "reviewer": _npub(event.pubkey)})
        return _with_rejected(session, {"claims": [
            {"event_id": event.id, "author": _npub(event.pubkey),
             "created_at": event.created_at, "goal_event": (event.values("e") or [None])[0],
             "status": "decided" if event.id in decided else "proposal",
             "decisions": decided.get(event.id, []), **claim.to_payload()}
            for claim, event in session.claims()]})


def cmd_claim_decide(args) -> dict:
    with _session(args) as session:
        decision, condition, repeated = session.decide(
            args.claim_id, outcome=args.outcome, reason=args.reason,
            next_action=args.next_action, statement=args.statement or "",
            reopen_if=args.reopen_if or "")
        return _with_rejected(session, {
            "decision": decision.to_payload(), "already_decided": repeated,
            "condition": condition.to_payload(),
            "next": f"`handoff materialize --condition {condition.condition}` renders the "
                    "packet the next seat starts from"})


def cmd_handoff_send(args) -> dict:
    if args.file:
        packet = Handoff.parse(_text(args.file) if args.file == "-"
                               else _read_file(args.file))
    else:
        given = {"original_goal": args.original_goal, "open_condition": args.open_condition,
                 "evidence_and_rejected_routes": args.evidence, "next_action": args.next_action}
        missing = [name for name, value in given.items() if not value]
        if missing:
            raise ProfileError(f"a handoff has four fields; missing {missing}")
        packet = Handoff(**given)
    with _session(args) as session:
        event = session.handoff(packet, for_seat=args.for_seat)
        return {"event_id": event.id, "for_seat": args.for_seat, **packet.to_payload()}


def cmd_handoff_read(args):
    """Packets members sent. A packet is a colleague's note: who signed it is shown,
    and it is the reader's to weigh. The packet a reviewer's decisions produce comes
    from `handoff materialize`."""
    with _session(args) as session:
        seat = None if args.all_seats else (args.for_seat or _seat(args))
        author = bech32.pubkey_hex(args.sender) if args.sender else None
        packets = session.handoffs(for_seat=seat, author=author)
        if args.latest or args.render:
            packets = packets[-1:]
        if args.render:
            if not packets:
                raise ProfileError("no handoff packet to render")
            packet, event, addressed = packets[0]
            return packet.render({"event": event.id, "from": _npub(event.pubkey),
                                  "for-seat": addressed or "anyone"})
        return _with_rejected(session, {"for_seat": seat or "every seat", "handoffs": [
            {"event_id": event.id, "from": _npub(event.pubkey), "for_seat": addressed,
             "created_at": event.created_at, **packet.to_payload()}
            for packet, event, addressed in packets]})


def cmd_handoff_materialize(args) -> dict:
    """Render the first-call packet from a condition's reviewer-signed head into the
    file a seat starts from, and optionally wake it."""
    with _session(args) as session:
        standing = session.condition_head(args.condition)
        if standing is None:
            raise ProfileError(f"no reviewer has opened condition {args.condition!r}")
        event, condition = standing
        packet = condition.handoff()
        text = packet.render({
            "condition": condition.condition, "revision": condition.rev,
            "state": condition.state, "head": event.id, "reviewer": _npub(event.pubkey),
            "decision": condition.last_decision or "none",
            "claim": condition.last_claim or "none"})
        result = {"condition": condition.condition, "revision": condition.rev,
                  "state": condition.state, "reviewer": _npub(event.pubkey),
                  **packet.to_payload()}
        result.update(bridge.deliver_handoff(text, packet.open_condition.splitlines()[0],
                                             out=args.out, wake_file=args.wake_file))
        return _with_rejected(session, result)


def cmd_directive_send(args) -> dict:
    with _session(args) as session:
        event = session.directive(_text(args.text), audience=tuple(args.audience or [EVERY_SEAT]),
                                  graph_digest=args.graph_digest, on_top_of=args.on_top_of)
        return {"event_id": event.id, "signed_by": _identity(args).npub}


def cmd_directive_read(args) -> dict:
    """Operator directives the relay holds, verified here. Verified means the operator
    signed it. It binds a seat once it is in that seat's emitted contract."""
    with _session(args) as session:
        ledger = session.directives()
        seat = None if args.all_seats else _seat(args)
        chain = ledger.in_force if seat is None else ledger.for_seat(seat)
        result = {
            "for_seat": seat or "every seat",
            "verified_against_operator_keys": len(session.trust.operator_pubkeys),
            "verified": [_directive_dict(d) for d in chain],
            "held": [{**_directive_dict(d), "why": why} for d, why in ledger.held],
            "rejected": [{"id": ident, "why": why} for ident, why in ledger.rejected],
            "note": "`verified` is the operator's signed word, in order. It is a proposal "
                    "until it is adopted into the OPERATOR.md a seat's harness renders "
                    "(`directive adopt <id> --operator-file OPERATOR.md`); a seat acts on "
                    "its contract, not on this list"}
        if args.operator_file:
            state = bridge.adoption_state(ledger, bridge.adopted_ids(args.operator_file))
            for entry in result["verified"]:
                entry["adopted_here"] = entry["id"] in state["adopted"]
            result["adoption"] = state
        return result


def cmd_directive_adopt(args) -> dict:
    with _session(args) as session:
        return _with_rejected(session, bridge.adopt_directive(
            session, args.event_id, operator_file=args.operator_file,
            graph_digest=args.graph_digest, verify_cmd=args.verify_cmd,
            wake_file=args.wake_file))


# ----------------------------------------------------------------------------- blobs
def _blobs(args):
    trust = _trust(args)
    signer = _identity(args).signer(timeout_s=args.timeout_seconds)
    return CampaignSession(trust, signer, timeout_s=args.timeout_seconds).blobs()


def cmd_blob_put(args) -> dict:
    return _blobs(args).upload_file(args.file, content_type=args.content_type).to_dict()


def cmd_blob_get(args) -> dict:
    blob = _blobs(args).download_to(args.sha256, args.out)
    return {**blob.to_dict(), "written": args.out, "digest_verified": True}


def cmd_blob_has(args) -> dict:
    return {"sha256": args.sha256, "exists": _blobs(args).exists(args.sha256)}


# ---------------------------------------------------------------------------- parser
def _seconds(text: str) -> float:
    try:
        value = float(text)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"{text!r} is not a number of seconds") from exc
    if not math.isfinite(value) or value < 0:
        raise argparse.ArgumentTypeError(f"{text!r} must be a finite number of seconds, 0 or more")
    return value


def _patience(text: str) -> float:
    value = _seconds(text)
    if value == 0:
        raise argparse.ArgumentTypeError("a relay cannot answer in 0 seconds")
    return value


@functools.cache
def build_parser(prog: str = "nostr-mailbox") -> argparse.ArgumentParser:
    """The command tree. It reads nothing from the environment: a flag left unset is
    filled from its variable when a command runs (`_from_environment`)."""
    ap = argparse.ArgumentParser(prog=prog, description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--trust", help=f"the campaign's nostr.toml (or {TRUST_ENV})")
    ap.add_argument("--identity",
                    help=f"identity name (or {IDENTITY_ENV}; default: {DEFAULT_NAME})")
    ap.add_argument("--home", default=None, help=f"identity directory (or {HOME_ENV})")
    ap.add_argument("--timeout-seconds", type=_patience, default=DEFAULT_WAIT_S,
                    help=f"how long to wait for one relay, signer or verify-command answer "
                         f"(default {DEFAULT_WAIT_S:g})")
    sub = ap.add_subparsers(dest="command", required=True)

    def add(parent, name: str, func, text: str):
        parser = parent.add_parser(name, help=text, description=text)
        parser.set_defaults(func=func)
        return parser

    def group(name: str, text: str):
        parser = sub.add_parser(name, help=text, description=text)
        return parser.add_subparsers(dest=f"{name}_command", required=True)

    def seat(parser) -> None:
        parser.add_argument("--seat",
                            help=f"seat handle (or {SEAT_ENV}; default: the identity name)")

    def wake(parser) -> None:
        parser.add_argument("--wake-file", help="append one wake line to this file "
                                                "(a harness monitor tails it)")

    def reach(parser) -> None:
        how = parser.add_mutually_exclusive_group()
        how.add_argument("--kubectl", action="store_true",
                         help="run ncli inside the Kubernetes StatefulSet pod")
        how.add_argument("--compose", metavar="COMPOSE_FILE",
                         help="run ncli inside the self-hosted compose stack")
        how.add_argument("--exec", metavar="PREFIX",
                         help="any other command prefix that reaches ncli")
        parser.add_argument("--namespace", default="nostr-relay")
        parser.add_argument("--pod", default="nostr-relay-0")
        parser.add_argument("--config", default=NCLI_CONFIG,
                            help="relay.yaml as ncli sees it (only without --kubectl/--compose)")

    p = add(sub, "setup", cmd_setup,
            "one-command operator setup: key + NIP-44 v2 campaign_key + nostr.toml (+ relay add)")
    p.add_argument("--campaign", required=True, help="campaign slug")
    p.add_argument("--relay", required=True,
                   help="relay WebSocket URL (e.g. wss://relay.example.com)")
    p.add_argument("--no-encryption", action="store_true",
                   help="omit the NIP-44 v2 campaign_key")
    reach(p)

    p = add(sub, "invite", cmd_relay_invite,
            "mint a single-use invite (includes a self-contained nm1_ token for `join`)")
    p.set_defaults(bundle=True)
    reach(p)
    p.add_argument("--ttl", default=INVITE_TTL, help=f"invite lifetime (default {INVITE_TTL})")
    p.add_argument("--code-file", help="write the invite here (0600) instead of printing it")

    p = add(sub, "join", cmd_relay_join,
            "join in one command from an nm1_ token (auto-creates key & nostr.toml)")
    p.add_argument("token", nargs="?", help="nm1_ invite token (or '-' for stdin)")
    p.add_argument("--code-file", help="file holding the invite ('-' for stdin)")

    p = add(sub, "init", cmd_init, "generate a key (mode 0600), or register an external signer")
    p.add_argument("--name", help="identity to create (default: --identity)")
    p.add_argument("--signer-command", help="program that signs: event JSON in, signed JSON out")
    p.add_argument("--signer-socket", help="Unix socket of a `signer serve`")
    p.add_argument("--pubkey", help="npub or hex of the externally held key")
    p = add(sub, "id", cmd_id, "show an identity's npub and hex public key (never the secret)")
    p.add_argument("--name", help="identity to show (default: --identity)")

    signer = group("signer", "sign for a container seat that holds no key")
    p = add(signer, "serve", cmd_signer_serve, "serve this identity on a Unix socket (0600)")
    p.add_argument("--socket", required=True)
    p.add_argument("--role", choices=sorted(ROLE_KINDS), required=True,
                   help="which kinds the socket will sign")
    p.add_argument("--allow-kind", type=int, action="append", default=[],
                   help="one more kind to allow (repeatable)")
    p.add_argument("--relay", help="sign NIP-42 proofs for this relay URL only "
                                   "(default: the trust file's relay)")
    p.add_argument("--blossom-server", help="sign blob get/upload for this host[:port] only "
                                            "(default: the trust file's blob server)")

    relay = group("relay", "join the relay; invite, add and revoke members")
    p = add(relay, "join", cmd_relay_join, "redeem a single-use invite (NIP-43)")
    p.add_argument("token", nargs="?", help="nm1_ invite token (or '-' for stdin)")
    p.add_argument("--code-file", help="file holding the invite ('-' for stdin); a terminal "
                                       "is prompted without echo")
    add(relay, "check", cmd_relay_check,
        "what the relay advertises, and what it lets this key do; exit 1 unless all hold")
    p = add(relay, "invite", cmd_relay_invite, "create one single-use invite (operator)")
    reach(p)
    p.add_argument("--ttl", default=INVITE_TTL, help=f"invite lifetime (default {INVITE_TTL})")
    p.add_argument("--code-file", help="write the invite here (0600) instead of printing it")
    p = add(relay, "add", cmd_relay_add, "enroll a public key directly (operator)")
    reach(p)
    p.add_argument("pubkey", help="npub or hex")
    p = add(relay, "revoke", cmd_relay_revoke, "remove a member (operator)")
    reach(p)
    p.add_argument("pubkey", help="npub or hex")

    p = add(sub, "todo", cmd_todo, "drop ONE pointer into inbox")
    p.add_argument("message", nargs="?", help="the pointer ('-' or omitted: stdin)")
    p.add_argument("--target", required=True, help="repo or product slug")
    p.add_argument("--surface")
    p.add_argument("--doc")
    p.add_argument("--page")
    p.add_argument("--ref", action="append", default=[])
    p.add_argument("--subject", default="")
    p.add_argument("--idempotency-key")
    p = add(sub, "triage", cmd_triage, "unhandled inbox pointers and the compaction flag")
    p.add_argument("--target")
    p.add_argument("--surface")
    p = add(sub, "resolve", cmd_resolve, "settle inbox pointers with where the work went")
    p.add_argument("msg_ids", nargs="+")
    p.add_argument("--result-ref", help="PR, commit or issue (required for handled)")
    p.add_argument("--disposition", default="handled", choices=TERMINAL_DISPOSITIONS)
    p.add_argument("--note")
    seat(p)

    p = add(sub, "post", cmd_post, "publish to bus or a campaign topic")
    p.add_argument("topic")
    p.add_argument("message", nargs="?", help="the message ('-' or omitted: stdin)")
    p.add_argument("--kind", default="message",
                   help="handoff, finding, question, answer, claim, checkpoint, …")
    p.add_argument("--subject", default="")
    p.add_argument("--ref", action="append", default=[])
    p.add_argument("--reply-to")
    p.add_argument("--idempotency-key")
    p = add(sub, "read", cmd_read, "replay a topic's history without consuming it")
    p.add_argument("topic", nargs="?", default=BUS)
    p.add_argument("--after", help="id of a message already read: everything from its "
                                   "second onward (may repeat, never skips)")
    p.add_argument("--kind")
    p.add_argument("--ref", action="append", default=[])
    p = add(sub, "watch", cmd_watch, "this seat's unsettled messages; waits when there are none")
    p.add_argument("topic", nargs="?", default=BUS)
    seat(p)
    p.add_argument("--wait-seconds", type=_seconds, default=DEFAULT_WAIT_S)
    p = add(sub, "ack", cmd_ack, "settle messages for this seat, after acting on them")
    p.add_argument("topic")
    p.add_argument("msg_ids", nargs="+")
    seat(p)
    p.add_argument("--disposition", default="handled", choices=DISPOSITIONS)
    p.add_argument("--result-ref")
    p.add_argument("--note")
    p = add(sub, "seal", cmd_seal, "close a finished topic (operator)")
    p.add_argument("topic")

    p = add(sub, "heartbeat", cmd_heartbeat, "send one ephemeral liveness beat")
    seat(p)
    p.add_argument("--status", default="alive")
    p.add_argument("--detail", default="")
    p = add(sub, "heartbeats", cmd_heartbeats, "listen for live heartbeats")
    p.add_argument("--wait-seconds", type=_seconds, default=DEFAULT_WAIT_S)
    p.add_argument("--count", type=int, help="return as soon as this many were heard")

    checkpoint = group("checkpoint", "a seat's newest checkpoint pointer (replaced in place)")
    p = add(checkpoint, "put", cmd_checkpoint_put, "publish this seat's checkpoint pointer")
    seat(p)
    p.add_argument("--seq", type=int, required=True)
    p.add_argument("--sha256", required=True, help="digest of the checkpoint blob")
    p.add_argument("--task", default="")
    p.add_argument("--parent-sha256", default="")
    p.add_argument("--feed-sha256", default="")
    p.add_argument("--attempt", type=int, default=1)
    p.add_argument("--note", default="")
    p = add(checkpoint, "get", cmd_checkpoint_get, "read a seat's checkpoint pointer")
    seat(p)
    p.add_argument("--author", help="npub or hex of the writer (default: this identity)")

    route = group("route", "the Route Board (ROUTES), one replaceable row per route")
    p = add(route, "put", cmd_route_put, "write a route row (lead or operator)")
    p.add_argument("route")
    p.add_argument("--state", required=True, choices=ROUTE_STATES)
    p.add_argument("--hypothesis", required=True)
    p.add_argument("--falsification-criterion", required=True,
                   help="what observation would make us abandon this route")
    p.add_argument("--origin", default="")
    p.add_argument("--evidence", action="append", default=[])
    p.add_argument("--obstruction", default="")
    p.add_argument("--reopen-trigger", default="")
    add(route, "list", cmd_route_list, "the current board")

    condition = group("condition", "acceptance conditions: what is still open, and why")
    p = add(condition, "open", cmd_condition_open, "declare a condition at revision 1 (reviewer)")
    p.add_argument("condition", help="a slug claims will name")
    p.add_argument("--goal", required=True, help="the original goal it serves")
    p.add_argument("--statement", required=True, help="what must be shown")
    p.add_argument("--next-action", required=True, help="the first thing a seat should do")
    add(condition, "list", cmd_condition_list, "every condition as it now stands")

    claim = group("claim", "Obligation-Tree claims and the decisions on them")
    p = add(claim, "put", cmd_claim_put, "offer evidence against one revision of a condition")
    p.add_argument("--condition", required=True)
    p.add_argument("--condition-rev", type=int, required=True,
                   help="the revision the evidence was gathered against")
    p.add_argument("--effect", required=True, choices=CLAIM_EFFECTS)
    p.add_argument("--candidate-digest", required=True, help="sha256 of the candidate")
    p.add_argument("--evidence-ref", action="append", required=True,
                   help="where the evidence is, e.g. blob:<sha256> (repeatable)")
    p.add_argument("--wave", default="")
    p.add_argument("--task", default="")
    p.add_argument("--goal-event", help="id of the sealed goal revision")
    add(claim, "list", cmd_claim_list, "every claim, with the decisions on it")
    p = add(claim, "decide", cmd_claim_decide,
            "accept, narrow or reject a claim and move its condition (reviewer)")
    p.add_argument("claim_id")
    p.add_argument("--outcome", required=True, choices=DECISION_OUTCOMES)
    p.add_argument("--reason", required=True, help="one line: why")
    p.add_argument("--next-action", required=True, help="what the next seat does first")
    p.add_argument("--statement", help="the condition as it now reads (required to narrow)")
    p.add_argument("--reopen-if", help="what would reopen a rejected route (required to reject)")

    handoff = group("handoff", "four-field first-call handoff packets")
    p = add(handoff, "send", cmd_handoff_send, "publish a packet")
    p.add_argument("--original-goal")
    p.add_argument("--open-condition")
    p.add_argument("--evidence", help="evidence & rejected routes")
    p.add_argument("--next-action")
    p.add_argument("--file", help="a packet as four `## ` sections ('-' for stdin)")
    p.add_argument("--for-seat")
    p = add(handoff, "read", cmd_handoff_read, "packets for this seat, with who signed each")
    p.add_argument("--for-seat", help="default: this seat")
    seat(p)
    p.add_argument("--all-seats", action="store_true", help="packets for every seat")
    p.add_argument("--sender", help="only packets this npub signed")
    p.add_argument("--latest", action="store_true")
    p.add_argument("--render", action="store_true",
                   help="print the newest packet as the four headed sections")
    p = add(handoff, "materialize", cmd_handoff_materialize,
            "render a condition's packet into the file a seat starts from")
    p.add_argument("--condition", required=True)
    p.add_argument("--out", required=True,
                   help="the packet file, replaced whole (e.g. the seat's HANDOFF.md)")
    wake(p)

    directive = group("directive", "operator directives, signed, verified and adopted")
    p = add(directive, "send", cmd_directive_send, "issue the next directive (operator)")
    p.add_argument("text", nargs="?", help="the directive ('-' or omitted: stdin)")
    p.add_argument("--audience", action="append", help="seat id (repeatable; default: all)")
    p.add_argument("--graph-digest", default="")
    p.add_argument("--on-top-of", help="settle a fork: build on this directive, overruling "
                                       "its rivals")
    p = add(directive, "read", cmd_directive_read,
            "the operator's verified directives; proposals until adopted")
    seat(p)
    p.add_argument("--all-seats", action="store_true", help="every audience, not this seat's")
    p.add_argument("--operator-file", help="also say which directives this OPERATOR.md "
                                           "has adopted")
    p = add(directive, "adopt", cmd_directive_adopt,
            "append one verified, campaign-wide directive to an OPERATOR.md")
    p.add_argument("event_id")
    p.add_argument("--operator-file", required=True,
                   help="the OPERATOR.md a seat's harness renders (created if absent)")
    p.add_argument("--graph-digest", help="required when the directive names one")
    p.add_argument("--verify-cmd",
                   help="a command that checks the file before it is written: it gets the "
                        "candidate OPERATOR.md path as its last argument and the words on "
                        "stdin; non-zero refuses the adoption")
    wake(p)

    blob = group("blob", "content-addressed blobs (Blossom)")
    p = add(blob, "put", cmd_blob_put, "upload a file; prints its sha256")
    p.add_argument("file")
    p.add_argument("--content-type", default="application/octet-stream")
    p = add(blob, "get", cmd_blob_get, "download by sha256; written only if the digest matches")
    p.add_argument("sha256")
    p.add_argument("--out", required=True)
    p = add(blob, "has", cmd_blob_has, "is this blob on the server")
    p.add_argument("sha256")
    return ap


def _from_environment(args) -> None:
    """A flag wins; otherwise its environment variable; otherwise the stated default."""
    args.trust = args.trust or os.environ.get(TRUST_ENV)
    args.identity = args.identity or os.environ.get(IDENTITY_ENV) or DEFAULT_NAME
    if getattr(args, "name", "") is None:
        args.name = args.identity
    if getattr(args, "seat", "") is None:
        args.seat = os.environ.get(SEAT_ENV)


def main(argv: list[str] | None = None, *, prog: str = "nostr-mailbox") -> int:
    args = build_parser(prog).parse_args(argv)
    _from_environment(args)
    try:
        result = args.func(args)
    except PartialBatch as exc:
        print(json.dumps({
            "completed": [receipt.to_dict() for receipt in exc.completed],
            "failed": {"id": exc.failed, "error": str(exc.error)},
            "not_attempted": exc.remaining,
            "retry": "run the same command again: a completed id returns its recorded "
                     "receipt, and nothing is written twice"}, indent=2))
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except NostrError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:                  # a file or socket below our own wrappers
        print(f"error: {exc}", file=sys.stderr)
        return 1
    code = result.pop("_exit", 0) if isinstance(result, dict) else 0
    if isinstance(result, str):
        sys.stdout.write(result)
    else:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
