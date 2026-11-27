"""Witnesses for what a four-reviewer audit found: keyrings that belong to one persona,
invites that know a role, a join that commits nothing before the relay took it, an admin
reach per org, a signer pinned by the campaign this machine declares, and the file,
regex and blob hygiene underneath.

Nothing is mocked. `LoopbackRelay` is a server on a loopback socket; every command is
the real CLI, in this process or as a subprocess; every file is a real file. The one
stand-in is the relay's admin CLI: a recording program on a real subprocess boundary."""
import base64
import json
import os
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest

from nostr_mailbox import (
    BlossomClient,
    BlossomError,
    CampaignSession,
    EpochKeys,
    KeyRingError,
    LocalSigner,
    LoopbackRelay,
    Message,
    ProfileError,
    Trust,
    bech32,
    cli,
    groups,
    profile,
    secp256k1,
)
from nostr_mailbox import keyring as keyrings
from nostr_mailbox._files import write_private
from nostr_mailbox.identity import IdentityError, create_identity, load_identity
from nostr_mailbox.keyring import KeyRing

REPO = Path(__file__).resolve().parents[1]
SKILL = REPO / "skills/nostr-mailbox"
WAIT = 5.0              # the suite's convention: a witness that passes never waits this long
ENV = (cli.TRUST_ENV, cli.IDENTITY_ENV, cli.SEAT_ENV, "NOSTR_MAILBOX_HOME")


@pytest.fixture(autouse=True)
def _no_ambient_profile(monkeypatch):
    """Each witness names its home and persona; nothing comes from the caller's shell."""
    for name in ENV:
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def run(capsys):
    """The CLI in this process, as `persona` on the machine at `home`. Returns what it
    printed, parsed; with `code=1`, what it said on stderr."""
    def invoke(home: Path, persona: str, *argv, code: int = 0):
        status = cli.main(["--home", str(home), "--persona", persona, *map(str, argv)])
        out, err = capsys.readouterr()
        assert status == code, err or out
        return json.loads(out) if status == 0 else err
    return invoke


@pytest.fixture
def relay():
    with LoopbackRelay(member_claims=True) as running:
        yield running


def _keeper(run, relay, home: Path, topic: str = "wave") -> dict:
    """An operator's machine: campaign `camp` set up, enrolled, keeping `topic`."""
    made = run(home, "operator", "setup", "--relay", relay.url, "--campaign", "camp")
    relay.add_member(bech32.pubkey_hex(made["npub"]))
    run(home, "operator", "topic", "create", topic)
    return made


def _ring_file(home: Path, persona: str, topic: str = "wave") -> Path:
    return home / "keyrings" / persona / f"{topic}.json"


def _token(token: str) -> dict:
    body = token[4:]
    return json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))


def _retoken(bundle: dict) -> str:
    raw = json.dumps(bundle, sort_keys=True, separators=(",", ":")).encode()
    return "nm1_" + base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _wraps_for(relay, pubkey: str) -> list:
    return [e for e in relay.stored() if e.kind == 1059 and e.values("p") == [pubkey]]


# ============================================ 1. a keyring belongs to one persona
def test_two_personas_of_one_home_hold_two_rings_and_neither_reads_the_others(
        run, relay, tmp_path):
    """Alice and Bob share one laptop home. Alice joins topic `wave` with its whole
    history; Bob joins it `--history from-now`. Each ring is a file of its own, bound
    to its owner's key: Bob holds epoch 2 alone and cannot read what Alice can, and a
    copy of Alice's ring in Bob's place is refused, not read."""
    ops, laptop = tmp_path / "ops", tmp_path / "laptop"
    _keeper(run, relay, ops)
    run(ops, "operator", "--topic", "wave", "post", "bus", "epoch-1 finding", "--kind",
        "finding")
    joined = run(laptop, "alice", "join",
                 run(ops, "operator", "topic", "invite", "wave", "--for", "alice")["token"])
    assert joined["held_epochs"] == [1]
    invited = run(ops, "operator", "topic", "invite", "wave", "--for", "bob", "--history",
                  "from-now")
    assert invited["rotated_to"] == 2 and invited["epochs_in_token"] == [2]
    assert run(laptop, "bob", "join", invited["token"])["held_epochs"] == [2], \
        "bob is given epoch 2 alone, whatever alice's ring on this home holds"

    alice_file, bob_file = _ring_file(laptop, "alice"), _ring_file(laptop, "bob")
    assert not (laptop / "keyrings/wave.json").exists(), "no ring shared by the home"
    held = {name: json.loads(path.read_text()) for name, path in
            (("alice", alice_file), ("bob", bob_file))}
    assert sorted(held["bob"]["epochs"]) == ["2"]
    assert held["alice"]["owner"] != held["bob"]["owner"]
    for name, body in held.items():
        assert body["owner"] == load_identity(name, base=laptop).pubkey
        assert body["relay"] == relay.url
    for path in (alice_file, bob_file):
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    assert run(laptop, "alice", "topic", "sync", "wave")["topics"][0]["held_epochs"] == [1, 2]

    run(ops, "operator", "--topic", "wave", "post", "bus", "epoch-2 finding", "--kind",
        "finding")
    seen = run(laptop, "bob", "--topic", "wave", "read", "bus", "--kind", "finding")
    assert [m["body"] for m in seen["messages"]] == ["epoch-2 finding"]
    assert any("no key for epoch 1" in r["reason"] for r in seen["rejected"])
    assert sorted(m["body"] for m in run(laptop, "alice", "--topic", "wave", "read", "bus",
                                         "--kind", "finding")["messages"]) == [
        "epoch-1 finding", "epoch-2 finding"]

    # a ring is opened only for its owner, on its relay, and filled only by its owner
    trust = Trust.load(laptop / "topics/wave.toml")
    bob_file.write_bytes(alice_file.read_bytes())
    assert "keyring of another key" in run(laptop, "bob", "--topic", "wave", "read", "bus",
                                           code=1)
    with pytest.raises(KeyRingError, match="another key"):
        KeyRing.open(laptop, trust, "bob")
    elsewhere = Trust.from_mapping({**cli._mapping(trust), "relay": "wss://other.example"})
    with pytest.raises(KeyRingError, match="not on wss://other.example"):
        KeyRing.open(laptop, elsewhere, "alice")
    ring = KeyRing.open(laptop, trust, "alice")
    bob = load_identity("bob", base=laptop).signer(timeout_s=WAIT)
    with CampaignSession(trust, bob, timeout_s=WAIT, sync_keys=False) as session, \
            pytest.raises(KeyRingError, match="this session signs as"):
        keyrings.sync(session.relay, bob, trust, ring)
    assert "KeyRing('wave'" in repr(ring) and ring.epochs[1] not in repr(ring)


def test_a_ring_from_before_rings_had_owners_moves_to_its_one_identity_or_is_refused(
        run, relay, tmp_path):
    """`<home>/keyrings/<topic>.json` is where a ring lived before it had an owner. In a
    home with one identity it is that identity's: opened, bound and moved. In a home
    with two, nothing says whose it is, so it is refused with the move that settles it."""
    ops = tmp_path / "ops"
    _keeper(run, relay, ops)
    owned, legacy = _ring_file(ops, "operator"), ops / "keyrings/wave.json"

    def unown() -> None:
        body = json.loads(owned.read_text())
        del body["owner"], body["relay"]
        write_private(legacy, json.dumps(body))
        owned.unlink()

    unown()
    assert run(ops, "operator", "topic", "sync", "wave")["topics"][0]["keeper"] is True
    assert not legacy.exists() and stat.S_IMODE(owned.stat().st_mode) == 0o600
    run(ops, "operator", "--topic", "wave", "post", "bus", "still the keeper")
    assert json.loads(owned.read_text())["owner"] == load_identity(
        "operator", base=ops).pubkey, "bound to its owner by the first save"

    unown()
    run(ops, "second", "init")
    for persona in ("operator", "second"):
        refused = run(ops, persona, "topic", "sync", "wave", code=1)
        assert "holds 2 identities (operator, second)" in refused and "mv " in refused
    assert legacy.exists() and not owned.exists(), "nothing was moved on a guess"
    owned.parent.mkdir(mode=0o700, exist_ok=True)
    legacy.rename(owned)                       # the user's own word on whose it is
    assert run(ops, "operator", "topic", "sync", "wave")["topics"][0]["held_epochs"] == [1]
    with pytest.raises(KeyRingError, match="belongs to one identity"):
        KeyRing.open(ops, Trust.load(ops / "topics/wave.toml"), "nobody")


def test_a_trust_refuses_the_ring_of_another_campaign():
    """`with_ring` used to relabel any ring as its own campaign's, so the check that
    forbids it could never fire."""
    key, pub = "5a" * 32, secp256k1.pubkey_gen(bytes.fromhex("01" * 32)).hex()
    trust = Trust(relay="wss://relay.example", campaign="camp",
                  operator_pubkeys=frozenset({pub}), keyring="wave")
    with pytest.raises(ProfileError, match="epoch keys of campaign 'other'"):
        trust.with_ring(EpochKeys("other", {1: key}, 1))
    assert trust.with_ring(EpochKeys("camp", {2: key}, 2)).ring.held() == [2]


# ================================================ 2. an invite that knows a role
def test_a_write_only_member_is_given_no_key_by_token_or_rotation_and_writes_sealed_mail(
        run, relay, tmp_path):
    """Carol is invited `--role write-only`, onto a laptop home where Alice already reads
    the topic. Her token carries no epoch key, the keeper's 9000 names her role, no gift
    wrap is ever addressed to her (not at admission, not when the topic rotates), and
    Alice's ring on the same home is not hers to read. What she writes is sealed mail
    into the keeper's `topic:wave` dropbox part. Made a reader, she reads from the epoch
    current then; a reader made write-only reads no further."""
    ops, laptop, desk = tmp_path / "ops", tmp_path / "laptop", tmp_path / "dave"
    operator = _keeper(run, relay, ops)
    run(laptop, "alice", "join",
        run(ops, "operator", "topic", "invite", "wave", "--for", "alice")["token"])
    assert "write-only member is given none" in run(
        ops, "operator", "topic", "invite", "wave", "--role", "write-only", "--history",
        "from-now", code=1)
    invited = run(ops, "operator", "topic", "invite", "wave", "--for", "carol", "--role",
                  "write-only")
    carried = _token(invited["token"])
    assert (invited["role"], invited["history"], invited["epochs_in_token"]) == (
        "write-only", None, [])
    assert "epochs" not in carried and "current" not in carried and "campaign_key" not in carried
    assert carried["role"] == "write-only" and "topic:wave" in invited["role_note"]

    joined = run(laptop, "carol", "join", invited["token"])
    carol, alice = (load_identity(n, base=laptop) for n in ("carol", "alice"))
    assert (joined["role"], joined["held_epochs"], joined["introduced_on_bus"]) == (
        "write-only", [], None)
    assert json.loads(_ring_file(laptop, "carol").read_text())["epochs"] == {}
    blind = run(laptop, "carol", "--topic", "wave", "read", "bus")
    assert blind["messages"] == [] and blind["rejected"], "alice's ring here is not hers"
    assert all("holds no key" in r["reason"] for r in blind["rejected"])
    assert "write-only member is given none" in run(
        laptop, "carol", "--topic", "wave", "post", "bus", "hi", code=1)

    synced = run(ops, "operator", "topic", "sync", "wave")["topics"][0]
    assert synced["redeemed_invites"] == [carol.npub] and synced["delivered"] == {}
    assert synced["mail_part_opened"] == [carol.npub]
    put = [e for e in relay.stored() if e.kind == groups.PUT_USER
           and carol.pubkey in e.values("p")]
    assert [list(t) for e in put for t in e.tags if t[0] == "p"] == [
        ["p", carol.pubkey, "write-only"]]
    again = run(ops, "operator", "topic", "sync", "wave")["topics"][0]
    assert again["mail_part_opened"] == [] and again["delivered"] == {}, "safe to repeat"

    # the topic rotates: every reader is given the new epoch, the writer nothing
    rotated = run(ops, "operator", "topic", "invite", "wave", "--for", "dave", "--history",
                  "from-now")
    assert rotated["rotated_to"] == 2 and rotated["delivered"] == {alice.npub: [2]}
    run(desk, "dave", "join", rotated["token"])
    assert _wraps_for(relay, carol.pubkey) == [], "no key ring was ever wrapped to her"
    assert run(laptop, "carol", "topic", "sync", "wave")["topics"][0]["held_epochs"] == []

    # what she writes instead
    assert "does not cover 'inbox'" in run(
        laptop, "carol", "--topic", "wave", "mail", "send", "--to", operator["npub"],
        "to the wrong part", code=1)
    sent = run(laptop, "carol", "--topic", "wave", "mail", "send", "--to", operator["npub"],
               "--part", "topic:wave", "the retry duplicates")
    assert sent["part"] == "topic:wave"
    [mail] = run(ops, "operator", "mail", "read")["messages"]
    assert (mail["state"], mail["part"], mail["from"]["npub"]) == (
        "pending_approval", "topic:wave", carol.npub)
    assert "the retry duplicates" not in json.dumps(mail), "held at the keeper's human gate"

    # made a reader, she reads from here on; a reader made write-only reads no further
    raised = run(ops, "operator", "topic", "approve", "wave", carol.npub, "--role",
                 "read-write", "--history", "from-now")
    assert raised["rotated_to"] == 3 and raised["delivered"][carol.npub] == [3]
    assert run(laptop, "carol", "topic", "sync", "wave")["topics"][0]["held_epochs"] == [3]
    lowered = run(ops, "operator", "topic", "approve", "wave", alice.npub, "--role",
                  "write-only")
    assert lowered["rotated_to"] == 4 and alice.npub not in lowered["delivered"]
    assert lowered["delivered"][carol.npub] == [4] and lowered["mail_part_opened"] == [alice.npub]
    assert run(laptop, "alice", "topic", "sync", "wave")["topics"][0]["held_epochs"] == [1, 2, 3]
    revoked = run(ops, "operator", "topic", "revoke", "wave", alice.npub)
    assert revoked["mail_part_closed"] is True and revoked["rotated_to"] == 5
    assert "no owner-signed grant" in run(
        laptop, "alice", "--topic", "wave", "mail", "send", "--to", operator["npub"],
        "--part", "topic:wave", "after the revocation", code=1)


def test_a_token_names_its_role_and_carries_keys_exactly_when_the_role_reads():
    """The token's own shape is checked before anything is sent: a write-only token
    that carries keys, or a reader's that carries none, is not a token."""
    pub = secp256k1.pubkey_gen(bytes.fromhex("02" * 32)).hex()
    base = {"schema": "cf.transport/1", "relay": "wss://relay.example", "campaign": "camp",
            "operator_pubkeys": [pub], "group": "wave", "keyring": "wave", "code": "c",
            "topic": "wave", "group_code": "g", "redeem": "ab" * 32, "owner": pub}
    keys = {"epochs": {"1": "5a" * 32}, "current": 1}
    assert cli._decode_invite_token(_retoken({**base, **keys}))[3]["role"] == "read-write"
    assert cli._decode_invite_token(_retoken({**base, "role": "write-only"}))[3][
        "role"] == "write-only"
    for bad in ({**base, **keys, "role": "write-only"}, {**base, "role": "read-only"},
                {**base, **keys, "role": "owner"}, {**base, **keys, "keyring": "other"}):
        with pytest.raises(ProfileError, match="nm1_ topic token"):
            cli._decode_invite_token(_retoken(bad))


# ======================================= 3. nothing is trusted before the relay took it
def test_a_join_the_relay_refuses_writes_no_declaration_and_no_keyring(run, relay, tmp_path):
    """A token whose invite is not good, on a relay that is not private, or whose group
    code is spent, leaves the machine without a trust file, a topic file or a ring."""
    ops, fresh = tmp_path / "ops", tmp_path / "fresh"
    _keeper(run, relay, ops)
    root = cli._mapping(Trust.load(ops / "nostr.toml"))
    assert "already used" in run(fresh, "roland", "join",
                                 _retoken({**root, "code": "never-minted"}), code=1)
    assert not (fresh / "nostr.toml").exists() and not (fresh / "orgs").exists()

    with LoopbackRelay(membership_required=False) as open_relay:
        code = open_relay.create_invite()
        refused = run(tmp_path / "other", "roland", "join",
                      _retoken({**root, "relay": open_relay.url, "code": code}), code=1)
        assert "does not advertise both" in refused and open_relay._invites[code] == 1
    assert not (tmp_path / "other").exists(), "not a key, not a file"

    invited = run(ops, "operator", "topic", "invite", "wave", "--for", "roland")
    spent = _retoken({**_token(invited["token"]), "group_code": "not-the-code"})
    assert "invalid or used" in run(fresh, "roland", "join", spent, code=1)
    assert not (fresh / "topics").exists() and not (fresh / "keyrings").exists()
    assert not (fresh / "nostr.toml").exists()
    assert run(fresh, "roland", "join", invited["token"])["held_epochs"] == [1], \
        "and the real token still joins, once"


def test_a_token_never_replaces_a_declaration_this_machine_already_trusts(run, relay, tmp_path):
    """Mallory is a member and can mint a good invite code. Her token names this very
    campaign with herself as its operator and a campaign key of her own. Joining with it
    changes nothing this machine trusts, and says so; a token for another relay under
    the same campaign name is refused before anything is sent."""
    ops = tmp_path / "ops"
    _keeper(run, relay, ops)
    declared = (ops / "nostr.toml").read_bytes()
    mallory = LocalSigner(secp256k1.generate_secret())
    forged = {**cli._mapping(Trust.load(ops / "nostr.toml")),
              "operator_pubkeys": [bech32.encode(bech32.NPUB, bytes.fromhex(mallory.pubkey))],
              "campaign_key": "66" * 32}
    joined = run(ops, "second", "join", _retoken({**forged, "code": relay.create_invite()}))
    assert "campaign_key, operator_pubkeys differently" in joined["declaration_kept"]
    assert "66" * 32 not in json.dumps(joined), "what differs is named, never shown"
    assert (ops / "nostr.toml").read_bytes() == declared
    stored = len(relay.stored())
    moved = run(ops, "third", "join", _retoken({**forged, "relay": "wss://evil.example",
                                                "code": "x"}), code=1)
    assert "another org" in moved or "never replaces a declaration" in moved
    assert (ops / "nostr.toml").read_bytes() == declared and len(relay.stored()) == stored
    assert not (ops / "identities/third.json").exists()


def _admin_cli(tmp_path: Path, name: str) -> tuple[str, Path]:
    """Stands where `kubectl exec … --` does for one relay: records its argv, and answers
    an invite request the way ncli does."""
    log, program = tmp_path / f"{name}.log", tmp_path / f"{name}.sh"
    stamp = int(time.time())
    invite = json.dumps({"code": f"code-of-{name}", "created_at": stamp,
                         "expires_at": stamp + 7 * 24 * 3600, "max_uses": 1, "uses": 0})
    program.write_text(f'printf "%s\\n" "$*" >> "{log}"\n'
                       f"case \"$*\" in *\"invites create\"*) printf '%s' '{invite}' ;; "
                       '*) echo ok ;; esac\n')
    return f"/bin/sh {program}", log


def test_a_second_orgs_setup_keeps_the_first_orgs_admin_reach(run, tmp_path):
    """Two campaigns on two relays, set up from one home. Each keeps its own admin
    reach, and `invite --admin` for either runs that relay's admin CLI and no other."""
    home = tmp_path / "home"
    reach_a, log_a = _admin_cli(tmp_path, "relay-a")
    reach_b, log_b = _admin_cli(tmp_path, "relay-b")
    first = run(home, "operator", "setup", "--relay", "wss://a.example", "--campaign",
                "alpha", "--exec", reach_a)
    second = run(home, "operator", "setup", "--relay", "wss://b.example", "--campaign",
                 "beta", "--exec", reach_b)
    assert first["admin_file"] == str(home / "admin.json")
    assert second["admin_file"] == str(home / "orgs/beta.admin.json")
    for path, campaign, reach in ((home / "admin.json", "alpha", reach_a),
                                  (home / "orgs/beta.admin.json", "beta", reach_b)):
        saved = json.loads(path.read_text())
        assert (saved["campaign"], saved["exec_prefix"]) == (campaign, reach.split())
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    alpha = run(home, "operator", "invite", "--admin", "--for", "roland")
    beta = run(home, "operator", "--trust", second["trust_file"], "invite", "--admin")
    assert (alpha["code"], beta["code"]) == ("code-of-relay-a", "code-of-relay-b")
    assert _token(alpha["token"])["relay"] == "wss://a.example"
    assert _token(beta["token"])["relay"] == "wss://b.example"
    assert sum("invites create" in line for line in log_a.read_text().splitlines()) == 1
    assert sum("invites create" in line for line in log_b.read_text().splitlines()) == 1

    # a reach that names another campaign is another org's, and is not run
    (home / "orgs/beta.admin.json").write_bytes((home / "admin.json").read_bytes())
    refused = run(home, "operator", "--trust", second["trust_file"], "invite", "--admin",
                  code=1)
    assert "admin reach of campaign 'alpha', not 'beta'" in refused
    assert sum("invites create" in line for line in log_a.read_text().splitlines()) == 1
    (home / "orgs/beta.admin.json").unlink()
    assert "there is none at" in run(home, "operator", "--trust", second["trust_file"],
                                     "invite", "--admin", code=1)


def _serve_signer(home: Path, *argv) -> tuple[dict, str]:
    """`signer serve` as a real process: what it printed when it came up, and what it
    said on stderr. Stopped the way a person stops it."""
    short = Path(tempfile.mkdtemp(prefix="nm", dir="/tmp"))     # AF_UNIX paths are length-capped
    proc = subprocess.Popen(
        [sys.executable, "-m", "nostr_mailbox", "--home", str(home), *argv, "signer", "serve",
         "--socket", str(short / "s.sock"), "--role", "seat"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        env={**{k: v for k, v in os.environ.items() if k not in ENV}, "PYTHONPATH": str(SKILL)})
    try:
        up = json.loads(proc.stdout.readline())
    finally:
        proc.terminate()
        _, said = proc.communicate(timeout=WAIT)
    return up, said


def test_signer_serve_is_pinned_by_the_campaign_this_machine_declares(run, tmp_path):
    """After `setup`, `signer serve` with no --trust pins the relay and the blob server
    `<home>/nostr.toml` declares. With nothing declared it says, on stderr, that it is
    pinned to nothing."""
    home = tmp_path / "home"
    run(home, "default", "setup", "--relay", "wss://relay.example", "--campaign", "camp")
    up, said = _serve_signer(home)
    assert (up["relay_pin"], up["blossom_pin"]) == ("wss://relay.example", "relay.example")
    assert up["blossom_verbs"] == ["get", "upload"] and "warning" not in said
    bare = tmp_path / "bare"
    create_identity("default", base=bare)
    up, said = _serve_signer(bare)
    assert up["relay_pin"] is None and "to ANY relay" in said
    assert _serve_signer(bare, "--trust", str(home / "nostr.toml"))[0][
        "relay_pin"] == "wss://relay.example"


# ===================================================================== 6. hygiene
def test_a_wire_value_with_a_trailing_newline_is_not_well_formed(tmp_path):
    """`$` also matches before a final newline, so `.match` on an anchored pattern let
    `"wave\\n"` through as a topic id (and a file name). Every such check is a fullmatch."""
    key = "ab" * 32
    with pytest.raises(ProfileError):
        profile.slug("seat-1\n", "seat")
    with pytest.raises(ProfileError):
        groups.topic_id("wave\n")
    with pytest.raises(ProfileError):
        Message(body="hi", reply_to=key + "\n")
    with pytest.raises(ProfileError):
        Trust(relay="wss://relay.example", campaign="camp", operator_pubkeys=frozenset({key}),
              keyring="wave\n")
    with pytest.raises(ProfileError):
        EpochKeys("camp", {1: key + "\n"}, 1)
    with pytest.raises(IdentityError):
        create_identity("seat\n", base=tmp_path)
    with pytest.raises(KeyRingError):
        keyrings._epochs({"1\n": key}, "a delivery")
    assert not list(tmp_path.rglob("*")), "nothing was written under a name with a newline"


def test_a_private_file_is_never_written_through_a_planted_name_and_secrets_stay_out_of_repr(
        tmp_path):
    """The old writers opened a fixed `<name>.tmp` sibling with O_TRUNC, which follows a
    symlink planted there. The shared writer stages under a name nobody can predict,
    0600, and replaces the target whole."""
    victim, target = tmp_path / "victim.txt", tmp_path / "home/nostr.toml"
    victim.write_text("untouched")
    target.parent.mkdir()
    for planted in (target.with_suffix(".toml.tmp"), target.with_suffix(".json.tmp")):
        planted.symlink_to(victim)
    key = "5a" * 32
    pub = secp256k1.pubkey_gen(bytes.fromhex("03" * 32)).hex()
    cli._write_trust_file(target, {"schema": "cf.transport/1", "relay": "wss://relay.example",
                                   "campaign": "camp", "operator_pubkeys": [pub],
                                   "campaign_key": key})
    assert victim.read_text() == "untouched"
    assert stat.S_IMODE(target.stat().st_mode) == 0o600 and Trust.load(target).campaign_key == key
    assert sorted(p.name for p in target.parent.iterdir()) == [
        "nostr.json.tmp", "nostr.toml", "nostr.toml.tmp"], "no staging file is left behind"
    os.chmod(target, 0o644)
    write_private(target, "replaced\n")
    assert target.read_text() == "replaced\n" and stat.S_IMODE(target.stat().st_mode) == 0o600
    with pytest.raises(FileExistsError):
        write_private(target, "again\n", exclusive=True)
    assert target.read_text() == "replaced\n"

    trust = Trust(relay="wss://relay.example", campaign="camp",
                  operator_pubkeys=frozenset({pub}), campaign_key=key)
    identity = create_identity("seat", base=tmp_path / "home")
    assert key not in repr(trust) and "campaign='camp'" in repr(trust)
    assert identity.signer_spec["nsec"] not in repr(identity) and "seat" in repr(identity)


def test_a_blob_server_never_decides_how_much_this_client_reads(tmp_path):
    """A blob over the cap this client was given is refused from its declared length,
    before it is read into memory or onto disk, and the refusal names the cap."""
    with LoopbackRelay() as relay:
        signer = LocalSigner(secp256k1.generate_secret())
        relay.add_member(signer.pubkey)
        host = relay.http_url[len("http://"):]
        blob = BlossomClient(relay.http_url, signer, server=host).upload(os.urandom(2048))
        small = BlossomClient(relay.http_url, signer, server=host, max_blob_bytes=1024)
        with pytest.raises(BlossomError, match=r"declares 2,048 bytes, 200% of the 1,024-byte"):
            small.download(blob.sha256)
        dest = tmp_path / "out.bin"
        with pytest.raises(BlossomError, match=r"1,024-byte cap"):
            small.download_to(blob.sha256, dest)
        assert list(tmp_path.iterdir()) == [], "nothing landed, not even a partial file"
        exact = BlossomClient(relay.http_url, signer, server=host, max_blob_bytes=2048)
        assert len(exact.download(blob.sha256)) == 2048
        assert exact.download_to(blob.sha256, dest).size == 2048


def test_the_skill_installer_copies_through_no_symlink_and_finds_pi_where_it_is_told(tmp_path):
    """`--install` for a skill-directory harness refuses a symlinked directory anywhere
    between the harness folder and the file, as the plugin copy does, and installs for
    Pi under PI_CODING_AGENT_DIR when that is set."""
    script, agent = REPO / "scripts/sync_plugin.py", tmp_path / "pi-agent"
    env = {**os.environ, "HOME": str(tmp_path / "home"), "PI_CODING_AGENT_DIR": str(agent)}

    def install(*extra):
        return subprocess.run([sys.executable, str(script), "--install", "--harness", "pi",
                               *extra], capture_output=True, text=True, env=env, check=False)

    planned = install("--dry-run")
    assert planned.returncode == 0, planned.stderr
    assert f"-> {agent}/skills/nostr-mailbox/SKILL.md" in planned.stdout
    assert not agent.exists(), "a dry run writes nothing"
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (agent / "skills/nostr-mailbox").mkdir(parents=True)
    (agent / "skills/nostr-mailbox/nostr_mailbox").symlink_to(elsewhere)
    refused = install()
    assert refused.returncode != 0 and "refusing to copy through a symlink" in refused.stderr
    assert list(elsewhere.iterdir()) == [], "nothing was written through the link"
