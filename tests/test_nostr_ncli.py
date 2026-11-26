"""Release-qualified witnesses: the mailbox against the REAL pinned relay.

These boot the actual `ncli` executable on the checked-in `deploy/nostr-relay/relay.yaml`
(with loopback binds and a throwaway data directory added) and drive it through the
production client, admin wrapper and CLI with two disposable identities. They are what
tells the loopback relay in `test_nostr_mailbox.py` apart from the deployed one.

They need the pinned release binary, which this repository does not ship and CI does
not fetch:

    NOSTR_MAILBOX_NCLI_BIN=/path/to/ncli pytest tests/test_nostr_ncli.py -q

Without the variable every witness here is SKIPPED, and nothing else in the suite
proves agreement with ncli. The edges (Caddy, Traefik), the container image and a
cluster are not exercised here either: the relay is dialled directly."""
import hashlib
import http.client
import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit

import pytest

from nostr_mailbox import (
    BUS,
    BlossomClient,
    BlossomError,
    CampaignSession,
    Checkpoint,
    Claim,
    Condition,
    Heartbeat,
    HistoryTruncated,
    Kind,
    Message,
    NostrRelayChannelBackend,
    RelayAdmin,
    RelayAdminError,
    RelayRejected,
    Route,
    StaleRecord,
    TopicSealed,
    Trust,
    create_identity,
    fetch_info,
    relay,
)

NCLI = os.environ.get("NOSTR_MAILBOX_NCLI_BIN")
PINNED = "0.8.0-rc.54"
PUBLIC = "wss://relay.campaign.example"         # the relay's public name; never dialled
REPO = Path(__file__).resolve().parents[1]
WAIT = 10.0

pytestmark = pytest.mark.skipif(
    not NCLI, reason="needs the pinned ncli binary: set NOSTR_MAILBOX_NCLI_BIN")


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class Live:
    """One real relay for the module, and everything a witness needs to reach it."""

    def __init__(self, root: Path):
        version = subprocess.run([NCLI, "version"], capture_output=True, text=True, check=True)
        assert PINNED in version.stdout, f"not the pinned release: {version.stdout!r}"
        self.root, self.port, admin_port = root, _free_port(), _free_port()
        shipped = (REPO / "deploy/nostr-relay/relay.yaml").read_text()
        assert "port: 5500\n" in shipped
        self.config = root / "relay.yaml"       # the checked-in file, with isolated binds
        self.config.write_text(shipped.replace(
            "port: 5500\n", f"port: {self.port}\nlisten: 127.0.0.1:{self.port}\n"
                            f"admin:\n  listen: 127.0.0.1:{admin_port}\n"))
        self.env = {**os.environ, "NCLI_NIP11_URL": PUBLIC,
                    "NCLI_NIP11_PRIVKEY": hashlib.sha256(os.urandom(32)).hexdigest(),
                    "HOME": str(root / "home"),
                    "PATH": f"{Path(NCLI).resolve().parent}{os.pathsep}{os.environ['PATH']}"}
        check = subprocess.run([NCLI, "relay", "--config", str(self.config), "--check"],
                               capture_output=True, text=True, env=self.env, cwd=root)
        assert check.returncode == 0, f"ncli rejects the shipped relay.yaml: {check.stderr}"
        self.log = open(root / "relay.log", "w")           # noqa: SIM115 - closed in stop()
        self.process = subprocess.Popen([NCLI, "relay", "--config", str(self.config)],
                                        env=self.env, cwd=root, stdout=self.log,
                                        stderr=self.log)
        deadline = time.monotonic() + WAIT
        while True:
            assert self.process.poll() is None, (root / "relay.log").read_text()[-2000:]
            try:
                socket.create_connection(("127.0.0.1", self.port), 0.05).close()
                break
            except OSError:
                assert time.monotonic() < deadline, "the relay never opened its port"
        self.url = f"ws://127.0.0.1:{self.port}"
        self.admin = RelayAdmin(["env", f"PATH={self.env['PATH']}", f"HOME={self.env['HOME']}",
                                 f"NCLI_NIP11_URL={PUBLIC}",
                                 f"NCLI_NIP11_PRIVKEY={self.env['NCLI_NIP11_PRIVKEY']}"],
                                config=str(self.config), timeout_s=WAIT)
        self.ids = root / "ids"
        self.alice, self.bob, self.carol = (
            create_identity(name, base=self.ids) for name in ("alice", "bob", "carol"))
        self.trust = Trust(relay=self.url, relay_auth_url=PUBLIC, campaign="live",
                           operator_pubkeys=frozenset({self.alice.pubkey}))
        self.trust_file = root / "nostr.toml"
        self.trust_file.write_text(
            f'schema = "cf.transport/1"\nrelay = "{self.url}"\nrelay_auth_url = "{PUBLIC}"\n'
            f'campaign = "live"\noperator_pubkeys = ["{self.alice.npub}"]\n')
        self.admin.add_member(self.alice.pubkey)

    def session(self, identity, **trust_changes) -> CampaignSession:
        trust = Trust(**{**self.trust.__dict__, **trust_changes})
        return CampaignSession(trust, identity.signer(timeout_s=WAIT), timeout_s=WAIT)

    def cli(self, identity: str, *argv: str) -> subprocess.CompletedProcess:
        """The skill script, as an agent runs it: a real process, no shared state."""
        script = REPO / "skills/nostr-mailbox/scripts/nostr_mailbox.py"
        return subprocess.run(
            [sys.executable, "-I", "-S", str(script), "--trust", str(self.trust_file),
             "--home", str(self.ids), "--identity", identity, "--timeout-seconds", str(WAIT),
             *argv], capture_output=True, text=True, timeout=60)

    def stop(self) -> None:
        self.process.terminate()
        self.process.wait(timeout=WAIT)
        self.log.close()


@pytest.fixture(scope="module")
def live(tmp_path_factory):
    running = Live(tmp_path_factory.mktemp("ncli"))
    yield running
    running.stop()


def test_the_shipped_config_is_private_and_a_stranger_is_turned_away(live):
    info = fetch_info(live.url, timeout_s=WAIT)
    assert info.auth_required and info.membership_required and info.advertises_private
    assert info.max_limit >= relay.PAGE_LIMIT, "the relay must serve a full client page"

    with live.session(live.bob) as stranger:              # authenticates, is not enrolled
        with pytest.raises(RelayRejected) as refused:
            stranger.relay.query({"kinds": [int(Kind.MESSAGE)], "limit": 1})
        assert refused.value.prefix == "restricted"
        with pytest.raises(RelayRejected):
            NostrRelayChannelBackend(stranger).post(BUS, Message(body="let me in"), key="k")
    stranger_check = live.cli("bob", "relay", "check")
    report = json.loads(stranger_check.stdout)
    assert stranger_check.returncode == 1 and report["ok"] is False
    assert report["authenticated"] and not report["relay_access"]
    assert report["advertised"]["advertises_private"], "the claim and the refusal are separate"

    member_check = live.cli("alice", "relay", "check")
    assert member_check.returncode == 0, member_check.stderr
    assert json.loads(member_check.stdout)["relay_access"] is True


def test_an_invite_from_the_real_admin_cli_admits_one_key_once(live):
    invite = live.admin.create_invite()
    assert set(invite) >= {"code", "created_at", "expires_at", "max_uses", "uses"}
    assert (invite["max_uses"], invite["uses"]) == (1, 0)
    assert invite["expires_at"] - invite["created_at"] == 7 * 24 * 3600, "the 168h TTL"
    code_file = live.root / "bob.invite"
    code_file.write_text(json.dumps(invite))
    code_file.chmod(0o600)

    joined = live.cli("bob", "relay", "join", "--code-file", str(code_file))
    assert joined.returncode == 0, joined.stderr
    assert invite["code"] not in joined.stdout + joined.stderr
    assert json.loads(live.cli("bob", "relay", "check").stdout)["ok"] is True

    reused = live.cli("carol", "relay", "join", "--code-file", str(code_file))
    assert reused.returncode == 1 and "refused the invite claim" in reused.stderr
    assert json.loads(live.cli("carol", "relay", "check").stdout)["relay_access"] is False


def test_the_mailbox_round_trips_and_live_reads_stay_small(live, monkeypatch):
    with live.session(live.alice) as a, live.session(live.bob) as b:
        sender, reader = NostrRelayChannelBackend(a), NostrRelayChannelBackend(b)
        body = 'unicode Ω, <html> & "quotes" \\ \u2028 \t and a control \x01 char'
        base, older = int(time.time()) - 60, []     # each message gets a second of its own
        a.relay.clock = lambda: base - 1
        first = sender.post(BUS, Message(body=body, kind="handoff", subject="s"), key="one")
        retry = sender.post(BUS, Message(body=body, kind="handoff", subject="s"), key="one")
        assert retry.duplicate and retry.id == first.id
        for n in range(4):
            a.relay.clock = lambda n=n: base + n
            older.append(sender.post(BUS, Message(body=f"backlog {n}"), key=f"b{n}").id)
        a.relay.clock = time.time

        assert body in [m.body for m in reader.history(BUS)], "serialization agrees byte for byte"
        pending = reader.watch(BUS, "bob", wait_s=0)
        assert sorted(m.id for m in pending) == sorted([first.id, *older])

        # a live subscription must not replay the topic: on this relay `limit: 0` does
        flt = {"kinds": [int(Kind.MESSAGE)], **b.trust.scope(BUS)}
        assert len(b.relay.query({**flt, "limit": 0})) == 5, "0 means no limit here"
        counted = b.relay.subscribe({**flt, "limit": relay.LIVE_LIMIT})
        assert len(counted.stored()) == relay.LIVE_LIMIT
        counted.close()
        with b.relay.subscribe_live(flt) as tail:
            fresh = sender.post(BUS, Message(body="arrives live"), key="live")
            assert tail.wait(time.monotonic() + WAIT).id == fresh.id

        # bounded pages against the real `until` and `limit`: six messages, two a page
        monkeypatch.setattr(relay, "PAGE_LIMIT", 2)
        assert [m.id for m in reader.history(BUS)] == [first.id, *older, fresh.id]
        # and the one case paging by second cannot cross is reported, not papered over
        a.relay.clock = lambda: base - 100
        crowd = [sender._publish("crowded", Message(body=f"c{n}"), f"c{n}") for n in range(3)]
        a.relay.clock = time.time
        assert len({event.created_at for event in crowd}) == 1
        with pytest.raises(HistoryTruncated, match="inside the single second"):
            list(reader.history("crowded"))
        monkeypatch.undo()
        assert len(list(reader.history("crowded"))) == 3

        for message in reader.watch(BUS, "bob", wait_s=0):
            reader.ack(BUS, "bob", message.id, disposition="handled", result_ref="pr#1")
        assert reader.watch(BUS, "bob", wait_s=0) == []
        assert a.rejected == [] and b.rejected == []


def test_same_second_messages_survive_a_cursor_and_a_seal_freezes_the_journal(live):
    with live.session(live.alice) as a, live.session(live.bob) as b:
        sender, reader = NostrRelayChannelBackend(a), NostrRelayChannelBackend(b)
        topic = "wave-1"
        ids = [sender.post(topic, Message(body=f"m{n}"), key=f"k{n}").id for n in range(6)]
        seen = [m.id for m in reader.history(topic)]
        assert sorted(seen) == sorted(ids)
        for cursor in ids:                  # whatever the cursor, nothing published at or
            got = {m.id for m in reader.history(topic, after=cursor)}      # after it is lost
            later = set(seen[seen.index(cursor) + 1:])
            assert later <= got and cursor not in got

        sealed = sender.seal(topic)
        assert sealed.detail == "sealed after 6 message(s), listed in the seal"
        with pytest.raises(TopicSealed):
            reader.post(topic, Message(body="too late"), key="late")
        reader._publish(topic, Message(body="written past the seal"), "rogue")
        assert [m.id for m in reader.history(topic)] == seen, "the manifest is the journal"
        assert [m.id for m in reader.history(topic, after=seen[2])] == seen[3:], "exact when sealed"
        assert any("outside the sealed journal" in why for _, why in b.rejected)

        empty = sender.seal("wave-empty")
        assert empty.detail.startswith("sealed after 0 message(s)")
        assert list(reader.history("wave-empty")) == []


def test_heads_only_move_forward_and_liveness_is_not_stored(live):
    with live.session(live.alice) as a, live.session(live.bob) as b:
        digest = [hashlib.sha256(bytes([n])).hexdigest() for n in range(3)]
        _, written = b.put_checkpoint(Checkpoint(seat="bob", seq=11, sha256=digest[0]))
        assert written
        b.put_checkpoint(Checkpoint(seat="bob", seq=12, sha256=digest[1]))
        with pytest.raises(StaleRecord, match="behind the recorded"):
            b.put_checkpoint(Checkpoint(seat="bob", seq=11, sha256=digest[0]))     # a late retry
        assert b.put_checkpoint(Checkpoint(seat="bob", seq=12, sha256=digest[1]))[1] is False
        assert a.get_checkpoint("bob", author=live.bob.pubkey).seq == 12

        row = dict(hypothesis="h", falsification_criterion="f")
        a.put_route(Route(route="cache-key", state="scouting", **row))
        a.put_route(Route(route="cache-key", state="falsified", **row))
        assert [(r.route, r.state) for r in b.routes()] == [("cache-key", "falsified")]

        flt = {"kinds": [int(Kind.HEARTBEAT)], **a.trust.scope()}
        with a.relay.subscribe_live(flt) as tail:
            beat = b.heartbeat(Heartbeat(seat="bob", detail="tick"))
            assert tail.wait(time.monotonic() + WAIT).id == beat.id
        assert a.relay.query({**flt, "limit": 5}) == [], "an ephemeral event is never stored"


def test_private_blobs_through_the_production_client(live, tmp_path):
    with live.session(live.alice) as a:
        blobs = a.blobs()
        assert blobs.server == urlsplit(PUBLIC).netloc, "the public host is what gets signed"
        data = os.urandom(70_000)
        digest = hashlib.sha256(data).hexdigest()
        source = tmp_path / "fixture.bin"
        source.write_bytes(data)
        blob = blobs.upload_file(source)
        assert blob.sha256 == digest and blob.size == len(data)
        assert blob.url == f"https://{urlsplit(PUBLIC).netloc}/media/{digest}.bin"
        assert blobs.exists(digest) and blobs.download(digest) == data
        assert blobs.download_to(digest, tmp_path / "back.bin").size == len(data)
        assert (tmp_path / "back.bin").read_bytes() == data

        def get(path: str, authorization: str | None) -> int:
            conn = http.client.HTTPConnection("127.0.0.1", live.port, timeout=WAIT)
            conn.request("GET", path, headers={"Authorization": authorization}
                         if authorization else {})
            status = conn.getresponse().status
            conn.close()
            return status

        published = urlsplit(blob.url).path                  # the descriptor's own path
        assert get(published, blobs._authorization("get", digest)) == 200
        assert get(f"/{digest}", blobs._authorization("get", digest)) == 200
        assert get(published, None) == 401, "an anonymous read is refused"
        elsewhere = BlossomClient(blobs.origin, a.signer, server="another.host", timeout_s=WAIT)
        with pytest.raises(BlossomError, match="403"):
            elsewhere.download(digest)
    stranger = BlossomClient(f"http://127.0.0.1:{live.port}", live.carol.signer(timeout_s=WAIT),
                             server=urlsplit(PUBLIC).netloc, timeout_s=WAIT)
    with pytest.raises(BlossomError, match="403"):
        stranger.download(digest)
    with pytest.raises(BlossomError, match="403"):
        stranger.upload(b"spam")


def test_a_reviewed_claim_and_an_operator_directive_round_trip(live):
    with live.session(live.alice) as reviewer, live.session(live.bob) as seat:
        reviewer.open_condition(Condition(
            condition="ac-3", rev=1, state="open", goal="Make retries idempotent.",
            statement="A retry after a lost OK creates nothing new.",
            next_action="Reproduce the duplicate on main."))
        claim = seat.claim(Claim(condition="ac-3", condition_rev=1, effect="closes",
                                 candidate_digest="cd" * 32, evidence_refs=("blob:" + "ef" * 32,)))
        decision, head, repeated = reviewer.decide(
            claim.id, outcome="accepted", reason="fixture f1 passes on the candidate",
            next_action="Open the PR.")
        assert (decision.outcome, head.rev, head.state) == ("accepted", 2, "closed")
        assert repeated is False
        assert reviewer.decide(claim.id, outcome="accepted", reason="again",
                               next_action="x")[2] is True, "a retried ruling writes nothing"
        assert seat.condition_head("ac-3")[1] == head

        reviewer.directive("Freeze the candidate digest.")
        reviewer.directive("Seat bob: rerun the baseline.", audience=("bob",))
        ledger = seat.directives()
        assert [d.seq for d in ledger.in_force] == [1, 2] and not ledger.held


def test_revoking_a_member_closes_its_subscriptions_on_the_open_socket(live):
    live.admin.add_member(live.carol.pubkey)
    with live.session(live.carol) as carol:
        flt = {"kinds": [int(Kind.MESSAGE)], **carol.trust.scope(BUS)}
        tail = carol.relay.subscribe_live(flt)
        live.admin.remove_member(live.carol.pubkey)
        with pytest.raises(RelayRejected, match="membership revoked"):
            tail.wait(time.monotonic() + WAIT)
        with pytest.raises(RelayRejected):                  # same socket, still open
            carol.relay.query({**flt, "limit": 1})
    with pytest.raises(RelayAdminError, match="exited"):    # the admin CLI's own refusal
        live.admin.add_member("not-a-pubkey")
