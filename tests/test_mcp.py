"""Witnesses for `nostr-mailbox mcp`: the six tools over JSON-RPC 2.0, against a relay
that really runs.

Nothing is mocked. `LoopbackRelay` is a server on a loopback TCP socket speaking the
same NIP-01/29/42/43 and Blossom a deployed relay does. Every tool call below travels
the wire: a JSON-RPC request through `serve_stdio`, its reply parsed back. Each machine
is its own home directory, and every file a tool writes is a real file."""
import hashlib
import io
import json
import os
import socket
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from nostr_mailbox import LoopbackRelay, Trust, bech32, cli, mcp
from nostr_mailbox.keyring import KeyRing
from nostr_mailbox.relay import MAX_MESSAGE_BYTES

SKILL = Path(__file__).resolve().parents[1] / "skills/nostr-mailbox"
WAIT = 5.0              # the suite's convention: a witness that passes never waits this long
ENV = (cli.TRUST_ENV, cli.IDENTITY_ENV, cli.SEAT_ENV, "NOSTR_MAILBOX_HOME")


@pytest.fixture(autouse=True)
def _no_ambient_profile(monkeypatch):
    """Each witness names its home and persona; nothing comes from the caller's shell."""
    for name in ENV:
        monkeypatch.delenv(name, raising=False)


def _framed(message: dict) -> bytes:
    data = json.dumps(message).encode()
    return b"Content-Length: %d\r\n\r\n" % len(data) + data


def _replies(data: bytes) -> list:
    """Every message a server wrote, newline-delimited or Content-Length framed."""
    stream, out = io.BytesIO(data), []
    while line := stream.readline():
        if line.lower().startswith(b"content-length:"):
            length = int(line.split(b":", 1)[1])
            assert stream.readline() == b"\r\n"
            out.append(json.loads(stream.read(length)))
        else:
            out.append(json.loads(line))
    return out


def _wire(home: Path, server_persona: str, name: str, arguments: dict) -> dict:
    """One tools/call, sent as a JSON line through serve_stdio (a server started as
    `server_persona`; a `persona` argument overrides it): the reply as it came."""
    request = {"jsonrpc": "2.0", "id": 7, "method": "tools/call",
               "params": {"name": name, "arguments": arguments}}
    written = io.BytesIO()
    mcp.serve_stdio(io.BytesIO(json.dumps(request).encode() + b"\n"), written,
                    home_dir=home, default_persona=server_persona)
    [reply] = _replies(written.getvalue())
    assert reply["id"] == 7
    return reply


def _tool(home: Path, server_persona: str, name: str, **arguments) -> dict:
    reply = _wire(home, server_persona, name, arguments)
    assert "error" not in reply, reply
    result = reply["result"]
    assert result["isError"] is False, result["content"][0]["text"]
    assert json.loads(result["content"][0]["text"]) == result["structuredContent"]
    return result["structuredContent"]


def _refused(home: Path, server_persona: str, name: str, **arguments) -> str:
    """What the server said when it refused: a tool error, or a JSON-RPC error."""
    reply = _wire(home, server_persona, name, arguments)
    if "error" in reply:
        return reply["error"]["message"]
    assert reply["result"]["isError"] is True, reply
    return reply["result"]["content"][0]["text"]


@pytest.fixture
def cli_run(capsys):
    """The CLI in this process, as `persona` on the machine at `home`."""
    def run(home: Path, persona: str, *argv) -> dict:
        status = cli.main(["--home", str(home), "--persona", persona, *map(str, argv)])
        out, err = capsys.readouterr()
        assert status == 0, err or out
        return json.loads(out)
    return run


def _setup(cli_run, relay, home: Path, persona: str, campaign: str) -> dict:
    made = cli_run(home, persona, "setup", "--relay", relay.url, "--campaign", campaign)
    relay.add_member(bech32.pubkey_hex(made["npub"]))
    return made


def test_six_tools_carry_a_channel_from_invite_to_revocation(cli_run, tmp_path):
    """The operator's machine keeps topic `wave`. Roland, a second persona on a laptop
    that already has one, joins from a https-style join link minted with a role, posts a
    finding with an encrypted attachment, and files a claim; the operator watches, acks,
    replays, runs the board, and revokes him. A third persona of that laptop, invited
    write-only, is given no key and can neither read nor post. Every call is a JSON-RPC
    message."""
    with LoopbackRelay(member_claims=True) as relay:
        ops, laptop = tmp_path / "operator-machine", tmp_path / "laptop"
        _setup(cli_run, relay, ops, "operator", "camp")
        cli_run(ops, "operator", "topic", "create", "wave")

        listed = _tool(ops, "operator", "mailbox_list")
        assert listed["default_org"] == "camp" and listed["active_persona"] == "operator"
        [org] = listed["orgs"]
        assert org["registry_file"] == str(ops / "orgs/camp.toml")
        assert stat.S_IMODE((ops / "orgs/camp.toml").stat().st_mode) == 0o600
        assert (org["declaration"], org["default"], org["channels"]) == (
            str(ops / "nostr.toml"), True, ["wave"])
        assert org["personas"] == [{"name": "operator", "roles": ["operator"]}]
        assert listed["channels"] == [{"name": "wave", "campaign": "camp", "relay": relay.url,
                                       "keyring": "wave", "held_epochs": [1],
                                       "current_epoch": 1, "keeper": True}]
        assert [(k["name"], k["channel"]) for k in listed["keyrings"]] == [("wave", "wave")]

        # an invite with a role: recorded beside the invite, and a reader's carries keys
        invited = _tool(ops, "operator", "mailbox_invite", target="wave", role="read-only",
                        recipient="roland")
        assert invited["role"] == "read-only" and invited["epochs_in_token"] == [1]
        assert "does not stop it writing" in invited["role_note"]
        assert invited["join_url"] == "http" + relay.url[2:] + "/join/#" + invited["token"]
        assert "bearer_secret" in invited
        [recorded] = KeyRing.open(ops, Trust.load(ops / "topics/wave.toml"),
                                  "operator").registry["invites"].values()
        assert (recorded["role"], recorded["for"]) == ("read-only", "roland")

        # roland: a second persona on a machine that already has one, joining by the link
        cli_run(laptop, "laptop", "init")
        joined = _tool(laptop, "laptop", "mailbox_join", persona="roland",
                       token_or_url=invited["join_url"], as_member="roland")
        assert (joined["topic"], joined["held_epochs"], joined["member"]) == ("wave", [1],
                                                                              "roland")
        assert joined["org_file"] == str(laptop / "orgs/camp.toml")
        seen = _tool(laptop, "roland", "mailbox_list")
        assert [p["name"] for p in seen["personas"]] == ["laptop", "roland"]
        roland_npub = seen["personas"][1]["npub"]
        [org] = seen["orgs"]
        assert (org["campaign"], org["declaration"], org["default"]) == ("camp", None, False), \
            "a topic token carries no campaign_key, so it never becomes the org's declaration"
        assert org["personas"] == [{"name": "roland", "roles": ["member"]}]
        assert [(c["name"], c["keeper"], c["held_epochs"]) for c in seen["channels"]] == [
            ("wave", False, [1])]

        # a write-only invite carries no key. On the same laptop its holder's ring is its
        # own and empty beside roland's, so it reads nothing and cannot post here
        drop = _tool(ops, "operator", "mailbox_invite", target="wave", role="write-only",
                     recipient="vendor")
        assert drop["epochs_in_token"] == [] and "given none" in drop["role_note"]
        assert "write-only member is given none" in _refused(
            ops, "operator", "mailbox_invite", target="wave", role="write-only",
            history="from-now")
        vendor = _tool(laptop, "laptop", "mailbox_join", persona="vendor",
                       token_or_url=drop["token"])
        assert (vendor["role"], vendor["held_epochs"]) == ("write-only", [])
        mine = _tool(laptop, "vendor", "mailbox_list")
        assert [(c["name"], c["held_epochs"]) for c in mine["channels"]] == [("wave", [])]
        assert [k["name"] for k in mine["keyrings"]] == ["wave"], "its own, not roland's"
        assert "write-only member is given none" in _refused(
            laptop, "vendor", "mailbox_post", channel="wave", body="cannot")

        # a finding with an attachment; a body that looks like a flag stays a body
        fixture = tmp_path / "trace.json"
        fixture.write_bytes(b'{"lost_ok": "replayed twice"}')
        posted = _tool(laptop, "roland", "mailbox_post", channel="wave",
                       body="--reply-to=forged", kind="finding", files=[str(fixture)])
        [attached] = posted["attachments"]
        assert attached["plaintext_sha256"] == hashlib.sha256(fixture.read_bytes()).hexdigest()
        assert attached["sha256"] != attached["plaintext_sha256"] and attached["epoch"] == 1
        assert b"replayed twice" not in relay.blossom.blobs[attached["sha256"]]

        pending = _tool(ops, "operator", "mailbox_watch", channel="wave")["messages"]
        [finding] = [m for m in pending if m["kind"] == "finding"]
        assert (finding["body"], finding["reply_to"], finding["refs"]) == (
            "--reply-to=forged", None, [attached["ref"]])
        assert any(m["subject"] == "member-joined:roland" for m in pending)
        settled = _tool(ops, "operator", "mailbox_watch", channel="wave", ack_id=finding["id"],
                        result_ref="PR#7")
        assert [(a["disposition"], a["result_ref"]) for a in settled["acked"]] == [
            ("handled", "PR#7")]
        assert finding["id"] not in {m["id"] for m in settled["messages"]}, "settled: not again"
        replay = _tool(ops, "operator", "mailbox_watch", channel="wave", history=True,
                       kind="finding")
        assert [m["id"] for m in replay["messages"]] == [finding["id"]], "history keeps it"
        got = cli_run(ops, "operator", "--topic", "wave", "blob", "get", attached["sha256"],
                      "--out", tmp_path / "got.json")
        assert got["sealed"] and (tmp_path / "got.json").read_bytes() == fixture.read_bytes()

        # the board: a route, a condition, roland's claim on it, the operator's ruling
        def board(home, persona, action, **params):
            return _tool(home, persona, "mailbox_board", channel="wave", action=action,
                         params=params)

        board(ops, "operator", "route_put", route="retry-dedupe", state="active",
              hypothesis="-k: a dash-led hypothesis", evidence=["fixture f1"],
              falsification_criterion="a retry creates a second record")
        assert [(r["route"], r["hypothesis"], r["evidence"]) for r in board(
            ops, "operator", "route_list")["routes"]] == [
            ("retry-dedupe", "-k: a dash-led hypothesis", ["fixture f1"])]
        board(ops, "operator", "condition_open", condition="ac-1",
              goal="Make retries idempotent.", next_action="Reproduce it.",
              statement="A retry after a lost OK creates nothing new.")
        claim = board(laptop, "roland", "claim_put", condition="ac-1", condition_rev=1,
                      effect="closes", candidate_digest=attached["plaintext_sha256"],
                      evidence_ref=[attached["ref"]])
        ruled = board(ops, "operator", "claim_decide", claim_id=claim["event_id"],
                      outcome="accepted", reason="the fixture replays once",
                      next_action="Merge it.")
        assert ruled["decision"]["outcome"] == "accepted"
        assert ruled["condition"]["state"] == "closed"

        # what the server refuses, and why
        assert "holds no channel 'wavee'" in _refused(ops, "operator", "mailbox_post",
                                                      channel="wavee", body="typo")
        blobs = len(relay.blossom.blobs)
        assert "message kind" in _refused(ops, "operator", "mailbox_post", channel="wave",
                                          body="x", kind="Not A Kind", files=[str(fixture)])
        assert len(relay.blossom.blobs) == blobs, "refused before any file was uploaded"
        assert "unknown: ['falsification']" in _refused(
            ops, "operator", "mailbox_board", channel="wave", action="route_put",
            params={"route": "r", "state": "active", "hypothesis": "h",
                    "falsification": "f"})
        assert "needs params ['next_action']" in _refused(
            ops, "operator", "mailbox_board", channel="wave", action="condition_open",
            params={"condition": "ac-2", "goal": "g", "statement": "s"})

        # revoke: the topic rotates past him, and the relay stops serving it to him
        revoked = board(ops, "operator", "revoke", member=roland_npub)
        assert revoked["rotated_to"] == 2 and roland_npub not in revoked["delivered"]
        assert _tool(laptop, "roland", "mailbox_watch", channel="wave",
                     history=True)["messages"] == []


def test_a_second_org_joins_beside_the_first_and_each_bus_stays_reachable(cli_run, tmp_path):
    """Sam joins org alpha, then org beta. Beta's declaration goes beside alpha's, never
    over it (alpha's campaign_key would be lost), the registry lists both, and `org`
    reaches each one's bus."""
    with LoopbackRelay(member_claims=True) as relay:
        alpha, beta, laptop = (tmp_path / name for name in ("alpha", "beta", "laptop"))
        _setup(cli_run, relay, alpha, "alice", "alpha")
        _setup(cli_run, relay, beta, "bob", "beta")

        first = _tool(alpha, "alice", "mailbox_invite", target="alpha", scope="org",
                      recipient="sam")
        assert first["member"] == "sam" and first["join_url"].endswith("/join/#" + first["token"])
        console_link = f"http{relay.url[2:]}/#join={first['token']}&topic=alpha"
        assert _tool(laptop, "sam", "mailbox_join", token_or_url=console_link)[
            "trust_file"] == str(laptop / "nostr.toml"), "the web console's link form joins too"
        alpha_declared = (laptop / "nostr.toml").read_text()

        second = _tool(beta, "bob", "mailbox_invite", target="beta", scope="org")
        joined = _tool(laptop, "sam", "mailbox_join", token_or_url=second["join_url"])
        assert joined["trust_file"] == str(laptop / "orgs/beta/nostr.toml")
        assert "--trust" in joined["next"]
        assert (laptop / "nostr.toml").read_text() == alpha_declared, "alpha is kept whole"
        listed = _tool(laptop, "sam", "mailbox_list")
        assert {o["campaign"]: (o["default"], o["declaration"], o["personas"])
                for o in listed["orgs"]} == {
            "alpha": (True, str(laptop / "nostr.toml"), [{"name": "sam", "roles": ["member"]}]),
            "beta": (False, str(laptop / "orgs/beta/nostr.toml"),
                     [{"name": "sam", "roles": ["member"]}])}

        _tool(laptop, "sam", "mailbox_post", channel="bus", org="beta", body="hello beta")
        _tool(laptop, "sam", "mailbox_post", channel="bus", body="hello alpha")
        assert [m["body"] for m in _tool(beta, "bob", "mailbox_watch", channel="bus")[
            "messages"]] == ["hello beta"]
        heard = _tool(alpha, "alice", "mailbox_watch", channel="bus")["messages"]
        assert sorted((m["subject"], m["body"]) for m in heard) == [
            ("", "hello alpha"),
            ("member-joined:sam", f"sam joined campaign alpha ({listed['personas'][0]['npub']})")
        ], "alpha hears sam's introduction (its invite named him) and nothing of beta"
        assert "no declaration of org 'gamma'" in _refused(
            laptop, "sam", "mailbox_post", channel="bus", org="gamma", body="nobody")
        assert "role and history apply to channel invites" in _refused(
            alpha, "alice", "mailbox_invite", target="alpha", scope="org", role="read-only")


def test_serve_stdio_answers_line_and_content_length_json_rpc_and_guards_its_streams(
        tmp_path, capsys):
    """Requests in both framings, a notification, a batch, garbage, an unknown method and
    tool, and a tool call that would have read stdin: each gets the reply it is owed, in
    its own framing, and nothing but protocol reaches stdout."""
    def line(message: dict) -> bytes:
        return json.dumps(message).encode() + b"\n"

    def call(req_id, name, arguments):
        return {"jsonrpc": "2.0", "id": req_id, "method": "tools/call",
                "params": {"name": name, "arguments": arguments}}

    stream = b"".join([
        line({"jsonrpc": "2.0", "id": 1, "method": "initialize",
              "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                         "clientInfo": {"name": "witness", "version": "0"}}}),
        line({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        _framed({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
        b"{this is not json\n",
        _framed(call(3, "mailbox_post", {"channel": "bus", "body": "-"})),
        line(call(4, "mailbox_list", {"persona": "scout"})),
        line([{"jsonrpc": "2.0", "id": 5, "method": "ping"},
              {"jsonrpc": "2.0", "method": "notifications/cancelled"}]),
        line({"jsonrpc": "2.0", "id": 6, "method": "resources/list"}),
        line(call(8, "mailbox_teleport", {})),
        line(call(9, "mailbox_watch", {"channel": "bus", "wait_seconds": -1})),
    ])
    written = io.BytesIO()
    assert mcp.serve_stdio(io.BytesIO(stream), written, home_dir=tmp_path) == 0
    init, tools, garbage, stdin_read, listed, batch, unknown, no_tool, negative = _replies(
        written.getvalue())
    assert (tools["id"], stdin_read["id"]) == (2, 3)
    assert written.getvalue().count(b"Content-Length:") == 2, "framed in, framed out"

    assert init["result"]["protocolVersion"] == "2024-11-05"
    assert init["result"]["serverInfo"]["name"] == "nostr-mailbox"
    assert sorted(t["name"] for t in tools["result"]["tools"]) == sorted(mcp.HANDLERS)
    assert garbage["id"] is None and garbage["error"]["code"] == -32700
    assert stdin_read["result"]["isError"] is True
    assert "stdin carries the MCP protocol" in stdin_read["result"]["content"][0]["text"]
    assert listed["result"]["structuredContent"]["active_persona"] == "scout", \
        "the stream after the refused stdin read was not consumed"
    assert batch == [{"jsonrpc": "2.0", "id": 5, "result": {}}], "a notification owes nothing"
    assert unknown["error"]["code"] == -32601
    assert no_tool["error"]["code"] == -32602 and "mailbox_teleport" in no_tool["error"]["message"]
    assert negative["error"]["code"] == -32602
    assert capsys.readouterr().out == ""


def test_the_mcp_subcommand_serves_over_real_pipes(tmp_path):
    """`python -m nostr_mailbox --persona scout mcp`: the real command on real pipes. Its
    stdout holds the protocol and nothing else, and it exits 0 when stdin closes."""
    cli.main(["--home", str(tmp_path), "--persona", "scout", "init"])
    requests = (_framed({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                         "params": {"protocolVersion": "2025-06-18"}})
                + _framed({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                           "params": {"name": "mailbox_list", "arguments": {}}}))
    env = {k: v for k, v in os.environ.items() if k not in ENV}
    done = subprocess.run(
        [sys.executable, "-m", "nostr_mailbox", "--home", str(tmp_path), "--persona", "scout",
         "mcp"], input=requests, capture_output=True, timeout=WAIT,
        env={**env, "PYTHONPATH": str(SKILL)})
    assert done.returncode == 0, done.stderr.decode()
    init, listed = _replies(done.stdout)
    assert init["result"]["protocolVersion"] == "2025-06-18"
    seen = listed["result"]["structuredContent"]
    assert seen["active_persona"] == "scout"
    assert [p["name"] for p in seen["personas"]] == ["scout"]


def test_mailbox_watch_checks_every_argument_before_its_ack_is_written(cli_run, tmp_path):
    """An ack_id rides with a watch or a history read. Whatever either command refuses
    (a history filter without history, an infinite wait, a wait with history, an `after`
    the journal lacks) refuses the whole call before the ack is written: the message
    stays pending, and the same ack then settles it once."""
    with LoopbackRelay(member_claims=True) as relay:
        ops = tmp_path / "ops"
        _setup(cli_run, relay, ops, "operator", "camp")
        relay.add_member(bech32.pubkey_hex(cli_run(ops, "worker", "init")["npub"]))
        _tool(ops, "worker", "mailbox_post", channel="bus", body="work")

        def pending() -> list[str]:
            return [m["id"] for m in _tool(ops, "operator", "mailbox_watch",
                                           channel="bus")["messages"]]

        [work] = pending()
        ack = {"channel": "bus", "ack_id": work, "result_ref": "PR#1"}
        for refused, said in [({"kind": "finding"}, "filter the history"),
                              ({"wait_seconds": float("inf")}, "finite number of seconds"),
                              ({"history": True, "wait_seconds": 1}, "history answers at once"),
                              ({"history": True, "after": "0" * 64}, "to continue from")]:
            assert said in _refused(ops, "operator", "mailbox_watch", **ack, **refused)
            assert pending() == [work], f"{refused} settled nothing"
        settled = _tool(ops, "operator", "mailbox_watch", **ack)
        assert [a["result_ref"] for a in settled["acked"]] == ["PR#1"]
        assert settled["messages"] == [] and pending() == []


def test_serve_stdio_tells_a_frame_cut_short_from_a_clean_end_of_input(tmp_path):
    """A clean end of input between messages returns 0. Input that ends inside a
    frame's headers or before its Content-Length bytes arrived, and a frame whose length
    cannot be read, are answered -32700 in Content-Length framing and return 1; nothing
    after such a frame is read."""
    def served(data: bytes) -> tuple[int, bytes]:
        written = io.BytesIO()
        return mcp.serve_stdio(io.BytesIO(data), written, home_dir=tmp_path), written.getvalue()

    ping = _framed({"jsonrpc": "2.0", "id": 1, "method": "ping"})
    body = len(ping) - ping.index(b"\r\n\r\n") - 4
    status, written = served(ping + b"\r\n\n")
    assert (status, _replies(written)) == (0, [{"jsonrpc": "2.0", "id": 1, "result": {}}])
    later = json.dumps({"jsonrpc": "2.0", "id": 2, "method": "ping"}).encode() + b"\n"
    for data, said in [
            (ping + ping[:-5], f"the input ended {body - 5:,} bytes into a {body:,}-byte message"),
            (ping + b"Content-Length: 40\r\n", "the input ended inside a frame's headers"),
            (ping + b"Content-Length: many\r\n\r\n" + later,
             "a framed message without a readable Content-Length")]:
        status, written = served(data)
        assert status == 1, said
        answered, refused = _replies(written)
        assert answered["id"] == 1 and refused["error"] == {"code": -32700, "message": said}
        assert written.count(b"Content-Length:") == 2, "framed as the frame was"


def test_a_frame_over_the_cap_is_refused_unread_and_ends_the_session(tmp_path):
    """`nostr-mailbox mcp` on real pipes, its stdin left open: a Content-Length over the
    frame cap, a line that does not end within it, and a header block that does not end
    within it are each answered -32700 at once, with the size, the cap and the share of
    it used. The server reads nothing it refused and exits 1 without waiting for more."""
    cap = mcp.MAX_FRAME_BYTES
    assert cap == MAX_MESSAGE_BYTES
    header = b"Content-Length: 2\r\nX-Pad: "
    cases = [(b"Content-Length: %d\r\n\r\n" % (4 * cap), True,
              f"a {4 * cap:,}-byte message, 400% of the {cap:,}-byte frame cap"),
             (b"x" * (cap + 1), False,
              f"a line of more than {cap:,} bytes, over 100% of the {cap:,}-byte frame cap"),
             (header + b"a" * (cap + 1 - len(header)), True,
              f"a header block of more than {cap:,} bytes, over 100% of the {cap:,}-byte")]
    env = {**{k: v for k, v in os.environ.items() if k not in ENV}, "PYTHONPATH": str(SKILL)}
    for sent, framed, said in cases:
        with subprocess.Popen([sys.executable, "-m", "nostr_mailbox", "--home", str(tmp_path),
                               "mcp"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, env=env) as server:
            server.stdin.write(sent)
            server.stdin.flush()
            try:
                status = server.wait(timeout=WAIT)          # stdin is still open
            except subprocess.TimeoutExpired:
                server.kill()
                raise
            written, err = server.stdout.read(), server.stderr.read().decode()
        assert status == 1 and "the MCP session ended on a frame it could not read" in err
        [reply] = _replies(written)
        assert reply["error"]["code"] == -32700 and said in reply["error"]["message"]
        assert "refused unread, and the session ends" in reply["error"]["message"]
        assert written.startswith(b"Content-Length:") is framed


def test_the_mcp_subcommand_forwards_trust_topic_and_timeout_seconds(cli_run, tmp_path):
    """`nostr-mailbox --trust T --timeout-seconds N mcp` and `--topic wave mcp`, on real
    pipes. With --trust, `bus` with no org is the bus T declares (here another
    machine's org, beta), not nostr.toml's alpha; with --topic it is topic wave, where
    the board acts too. A call naming an org acts on that org's own bus and inherits
    neither. --timeout-seconds bounds every command: one against a relay that never
    answers fails inside it. mailbox_list says what `bus` means."""
    with LoopbackRelay(member_claims=True) as relay, \
            socket.create_server(("127.0.0.1", 0)) as silent:
        machine, elsewhere = tmp_path / "machine", tmp_path / "elsewhere"
        _setup(cli_run, relay, machine, "operator", "alpha")
        cli_run(machine, "operator", "topic", "create", "wave")
        _setup(cli_run, relay, elsewhere, "bob", "beta")
        beta = elsewhere / "nostr.toml"
        cli_run(machine, "operator", "--trust", machine / "quiet.toml", "setup", "--relay",
                f"ws://127.0.0.1:{silent.getsockname()[1]}", "--campaign", "quiet")
        patience = WAIT / 10            # the 25-second default would overrun WAIT
        env = {**{k: v for k, v in os.environ.items() if k not in ENV},
               "PYTHONPATH": str(SKILL)}

        def serve(*flags, calls) -> list[dict]:
            requests = b"".join(_framed({"jsonrpc": "2.0", "id": i, "method": "tools/call",
                                         "params": {"name": name, "arguments": arguments}})
                                for i, (name, arguments) in enumerate(calls, 1))
            done = subprocess.run(
                [sys.executable, "-m", "nostr_mailbox", "--home", str(machine), "--persona",
                 "operator", *map(str, flags), "mcp"], input=requests, capture_output=True,
                timeout=WAIT, env=env)
            assert done.returncode == 0, done.stderr.decode()
            return [reply["result"] for reply in _replies(done.stdout)]

        def bodies(home: Path, persona: str, *scope) -> list[str]:
            return [m["body"] for m in cli_run(home, persona, *scope, "read")["messages"]]

        listed, posted, aside, stalled = serve(
            "--trust", beta, "--timeout-seconds", patience, calls=[
                ("mailbox_list", {}),
                ("mailbox_post", {"channel": "bus", "body": "to beta"}),
                ("mailbox_post", {"channel": "bus", "org": "alpha", "body": "to alpha"}),
                ("mailbox_watch", {"channel": "bus", "org": "quiet"})])
        seen = listed["structuredContent"]
        assert seen["bus"] == {"topic": None, "campaign": "beta", "declaration": str(beta)}
        assert (seen["default_org"], seen["timeout_seconds"]) == ("beta", patience)
        assert {o["campaign"]: (o["default"], o["declaration"]) for o in seen["orgs"]} == {
            "alpha": (False, str(machine / "nostr.toml")), "beta": (True, str(beta)),
            "quiet": (False, str(machine / "quiet.toml"))}
        assert posted["isError"] is False and aside["isError"] is False
        assert stalled["isError"] is True and "deadline" in stalled["content"][0]["text"]
        assert bodies(elsewhere, "bob") == ["to beta"]
        assert bodies(machine, "operator") == ["to alpha"]

        listed, posted, routed, aside = serve("--topic", "wave", calls=[
            ("mailbox_list", {}),
            ("mailbox_post", {"channel": "bus", "body": "in wave"}),
            ("mailbox_board", {"action": "route_put", "params": {
                "route": "r1", "state": "active", "hypothesis": "h",
                "falsification_criterion": "f"}}),
            ("mailbox_post", {"channel": "bus", "org": "alpha", "body": "alpha's own"})])
        assert listed["structuredContent"]["bus"] == {
            "topic": "wave", "campaign": "alpha",
            "declaration": str(machine / "topics/wave.toml")}
        assert not any(r["isError"] for r in (posted, routed, aside))
        assert bodies(machine, "operator", "--topic", "wave") == ["in wave"]
        assert sorted(bodies(machine, "operator")) == ["alpha's own", "to alpha"], \
            "one second orders nothing in the journal"
        assert [r["route"] for r in cli_run(machine, "operator", "--topic", "wave", "route",
                                            "list")["routes"]] == ["r1"]
        assert cli_run(machine, "operator", "route", "list")["routes"] == []
