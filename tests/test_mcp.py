"""Witnesses for `nostr-mailbox mcp`: the six tools over JSON-RPC 2.0, against a relay
that really runs.

Nothing is mocked. `LoopbackRelay` is a server on a loopback TCP socket speaking the
same NIP-01/29/42/43 and Blossom a deployed relay does. Every tool call below travels
the wire: a JSON-RPC request through `serve_stdio`, or over real HTTP to a server on a
loopback port (`mcp_http`, the console), its reply parsed back. Each machine is its own
home directory, and every file a tool writes is a real file. The Claude Desktop entry is
written by the real installer and launched the way an MCP stdio client launches it.

What these witnesses cannot show: ChatGPT, Claude.ai and Claude Desktop themselves. The
OpenAPI document is held to what a GPT Action imports (OpenAPI 3.1, an operationId and a
short description per operation, a bearer scheme or, under a magic URL, none); the OAuth
sign-in is driven here as the MCP authorization spec has a client drive it (a 401, RFC
9728 and 8414 discovery, RFC 7591 registration, a consent form posted as a browser posts
it, PKCE S256); the import and the click in a real client need that client."""
import base64
import hashlib
import html
import http.client
import io
import json
import os
import re
import secrets
import shutil
import signal
import socket
import stat
import subprocess
import sys
import threading
import time
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit

import pytest

from nostr_mailbox import LoopbackRelay, Trust, bech32, cli, mcp, mcp_http, ui
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


# ================================================================== MCP over HTTP
BEARER = "witness-bearer-0123456789abcdefghijklmnopqrstuvwxyzABCDEF"
STREAMABLE = {"Accept": "application/json, text/event-stream"}


def _http(url: str, method: str, path: str, body=None, *, token: str | None = BEARER,
          headers: dict | None = None) -> tuple[int, http.client.HTTPResponse, bytes]:
    """One request to a server on loopback, on its own connection: status, response, body."""
    parts = urlsplit(url)
    conn = http.client.HTTPConnection(parts.hostname, parts.port, timeout=WAIT)
    sent = {**({"Authorization": f"Bearer {token}"} if token else {}), **(headers or {})}
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        sent.setdefault("Content-Type", "application/json")
    try:
        conn.request(method, path, body=data, headers=sent)
        response = conn.getresponse()
        payload = response.read()
    finally:
        conn.close()
    return response.status, response, payload


def _rpc(url: str, message, *, session: str | None = None, token: str | None = BEARER,
         headers: dict | None = None) -> tuple[int, http.client.HTTPResponse, object]:
    sent = {**STREAMABLE, **({mcp_http.SESSION_HEADER: session} if session else {}),
            **(headers or {})}
    status, response, payload = _http(url, "POST", "/mcp", message, token=token, headers=sent)
    return status, response, json.loads(payload) if payload else None


def _call(name: str, arguments: dict, req_id: int = 7) -> dict:
    return {"jsonrpc": "2.0", "id": req_id, "method": "tools/call",
            "params": {"name": name, "arguments": arguments}}


def _event(stream) -> dict:
    """The next server-sent event on `stream` (a comment-only one as `comment`)."""
    fields: dict = {}
    while (line := stream.readline()) not in (b"\n", b""):
        text = line.decode().rstrip("\n")
        if text.startswith(":"):
            fields["comment"] = text[1:].strip()
            continue
        name, _, value = text.partition(": ")
        fields[name] = f"{fields[name]}\n{value}" if name in fields else value
    return fields


def _open_stream(url: str, path: str, headers: dict):
    parts = urlsplit(url)
    conn = http.client.HTTPConnection(parts.hostname, parts.port, timeout=WAIT)
    conn.request("GET", path, headers={"Authorization": f"Bearer {BEARER}",
                                       "Accept": "text/event-stream", **headers})
    return conn, conn.getresponse()


def _bodies(cli_run, home: Path, persona: str, topic: str) -> list[str]:
    return [m["body"] for m in cli_run(home, persona, "--topic", topic, "read")["messages"]]


def test_streamable_http_carries_the_tools_with_sessions_a_bearer_and_cors(cli_run, tmp_path):
    """`POST /mcp` with a real relay behind it: initialize opens a session, a notification
    is answered 202, tools/list offers no file argument, a post lands in the topic, a batch
    and an SSE-only client are each answered. Without the bearer, with a foreign Origin,
    an unknown version or session, or an oversized body, nothing runs. `GET /mcp` holds a
    stream open until `DELETE /mcp` closes its session."""
    with LoopbackRelay(member_claims=True) as relay:
        ops = tmp_path / "ops"
        _setup(cli_run, relay, ops, "operator", "camp")
        cli_run(ops, "operator", "topic", "create", "wave")
        with mcp_http.McpServer(token=BEARER, port=0, home_dir=ops, default_persona="operator",
                                timeout_seconds=WAIT, quiet=True) as server:
            url = server.url
            init = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
                    "params": {"protocolVersion": "2025-11-25", "capabilities": {},
                               "clientInfo": {"name": "witness", "version": "0"}}}
            for token, said in [(None, "missing"), ("guess", "wrong")]:
                status, response, body = _rpc(url, init, token=token)
                assert status == 401 and "missing or wrong bearer token" in body["error"], said
                assert response.getheader("WWW-Authenticate") == (
                    f'Bearer resource_metadata="{url}/.well-known/oauth-protected-resource"'), \
                    "a 401 names where an MCP client learns to sign in"
                assert "sign in by OAuth" in body["error"]
            assert server.routes.sessions() == 0, "a refused initialize opens nothing"

            status, response, opened = _rpc(url, init)
            sid = response.getheader(mcp_http.SESSION_HEADER)
            assert status == 200 and sid and opened["result"]["protocolVersion"] == "2025-11-25"
            assert response.getheader("Content-Type").startswith("application/json")
            versioned = {mcp_http.VERSION_HEADER: "2025-11-25"}
            status, _, body = _rpc(url, {"jsonrpc": "2.0", "method": "notifications/initialized"},
                                   session=sid, headers=versioned)
            assert (status, body) == (202, None)

            _, _, listed = _rpc(url, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
                                session=sid, headers=versioned)
            offered = {t["name"]: t["inputSchema"]["properties"] for t in listed["result"]["tools"]}
            assert sorted(offered) == sorted(mcp.HANDLERS)
            assert "files" not in offered["mailbox_post"], "no file on this machine is offered"
            assert "code_file" not in offered["mailbox_invite"]

            _, _, posted = _rpc(url, _call("mailbox_post", {"channel": "wave",
                                                            "body": "over streamable http"}),
                                session=sid)
            assert posted["result"]["isError"] is False
            assert posted["result"]["structuredContent"]["channel"] == "wave"
            assert _bodies(cli_run, ops, "operator", "wave") == ["over streamable http"]
            secret = tmp_path / "id_ed25519"
            secret.write_text("a key an HTTP client must not upload")
            _, _, refused = _rpc(url, _call("mailbox_post", {"channel": "wave", "body": "x",
                                                             "files": [str(secret)]}),
                                 session=sid)
            assert refused["error"]["code"] == -32602
            assert "names a file on the server's machine" in refused["error"]["message"]
            assert len(relay.blossom.blobs) == 0, "nothing was uploaded"

            _, _, batch = _rpc(url, [{"jsonrpc": "2.0", "id": 3, "method": "ping"},
                                     {"jsonrpc": "2.0", "method": "notifications/cancelled"},
                                     _call("mailbox_list", {}, 4)], session=sid)
            assert [r["id"] for r in batch] == [3, 4]
            assert batch[1]["result"]["structuredContent"]["active_persona"] == "operator"

            status, response, raw = _http(url, "POST", "/mcp",
                                          {"jsonrpc": "2.0", "id": 5, "method": "ping"},
                                          headers={"Accept": "text/event-stream",
                                                   mcp_http.SESSION_HEADER: sid})
            assert status == 200 and response.getheader("Content-Type").startswith(
                "text/event-stream")
            event = _event(io.BytesIO(raw))
            assert event["event"] == "message" and json.loads(event["data"]) == {
                "jsonrpc": "2.0", "id": 5, "result": {}}

            status, _, body = _rpc(url, {"jsonrpc": "2.0", "id": 6, "method": "ping"},
                                   session=sid, headers={mcp_http.VERSION_HEADER: "1999-01-01"})
            assert status == 400 and "is not one this server speaks" in body["error"]["message"]
            status, _, body = _rpc(url, {"jsonrpc": "2.0", "id": 6, "method": "ping"},
                                   session="never-opened")
            assert status == 404 and body["error"]["code"] == -32001
            status, _, body = _rpc(url, {"jsonrpc": "2.0", "id": 6, "method": "ping"})
            assert status == 200 and body["result"] == {}, "no session named: served as is"

            # CORS: a loopback origin (a local inspector) is answered, another site is not
            local = {"Origin": "http://localhost:6274"}
            status, response, _ = _http(url, "OPTIONS", "/mcp", token=None, headers={
                **local, "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "authorization, content-type, mcp-session-id"})
            assert status == 204
            assert response.getheader("Access-Control-Allow-Origin") == local["Origin"]
            assert response.getheader("Access-Control-Allow-Methods") == \
                "GET, POST, DELETE, OPTIONS"
            allowed = {h.strip() for h in response.getheader(
                "Access-Control-Allow-Headers").split(",")}
            assert {"Authorization", "Content-Type", "Accept", "Mcp-Session-Id"} <= allowed
            assert response.getheader("Access-Control-Expose-Headers") == "Mcp-Session-Id"
            status, response, _ = _rpc(url, {"jsonrpc": "2.0", "id": 8, "method": "ping"},
                                       headers=local)
            assert status == 200 and response.getheader("Access-Control-Allow-Origin") == \
                local["Origin"]
            status, _, body = _rpc(url, _call("mailbox_post", {"channel": "wave", "body": "no"}),
                                   headers={"Origin": "https://evil.example"})
            assert status == 403 and "another site is not served" in body["error"]
            assert _bodies(cli_run, ops, "operator", "wave") == ["over streamable http"]

            # a body over the frame cap is refused from its declared length, unread
            parts = urlsplit(url)
            conn = http.client.HTTPConnection(parts.hostname, parts.port, timeout=WAIT)
            conn.putrequest("POST", "/mcp")
            for name, value in {"Authorization": f"Bearer {BEARER}",
                                "Content-Type": "application/json",
                                "Content-Length": str(4 * mcp.MAX_FRAME_BYTES)}.items():
                conn.putheader(name, value)
            conn.endheaders()
            response = conn.getresponse()
            said = json.loads(response.read())["error"]["message"]
            conn.close()
            assert response.status == 413
            assert f"400% of the {mcp.MAX_FRAME_BYTES:,}-byte cap" in said and "unread" in said

            # GET /mcp holds a stream for the session; DELETE /mcp ends both
            conn, stream = _open_stream(url, "/mcp", {mcp_http.SESSION_HEADER: sid})
            assert stream.status == 200 and stream.getheader(mcp_http.SESSION_HEADER) == sid
            assert _event(stream)["comment"].startswith("ready")
            status, _, raw = _http(url, "DELETE", "/mcp", headers={mcp_http.SESSION_HEADER: sid})
            assert status == 200 and json.loads(raw) == {"closed": sid}
            assert stream.read() == b"", "the stream ended when its session closed"
            conn.close()
            status, _, body = _rpc(url, {"jsonrpc": "2.0", "id": 9, "method": "ping"},
                                   session=sid)
            assert status == 404, "a closed session is not served again"
            assert _http(url, "GET", "/mcp", headers={"Accept": "application/json"})[0] == 406


def test_the_sse_transport_answers_on_the_stream_and_in_the_body(cli_run, tmp_path):
    """MCP 2024-11-05: `GET /sse` names its `/messages` endpoint first. Every request
    posted there is answered both in the response body and as an `event: message` on the
    stream, a post landing on the real relay; a notification is answered 202 and puts
    nothing on the stream. When the client leaves, its session ends with it."""
    with LoopbackRelay(member_claims=True) as relay:
        ops = tmp_path / "ops"
        _setup(cli_run, relay, ops, "operator", "camp")
        cli_run(ops, "operator", "topic", "create", "wave")
        with mcp_http.McpServer(token=BEARER, port=0, home_dir=ops, default_persona="operator",
                                timeout_seconds=WAIT, quiet=True) as server:
            url = server.url
            assert _http(url, "GET", "/sse", token=None)[0] == 401
            conn, stream = _open_stream(url, "/sse", {})
            assert stream.getheader("Content-Type").startswith("text/event-stream")
            endpoint = _event(stream)
            assert endpoint["event"] == "endpoint"
            assert endpoint["data"].startswith("/messages?session_id=")
            sid = endpoint["data"].split("=", 1)[1]

            def message(body) -> tuple[int, object]:
                status, _, raw = _http(url, "POST", endpoint["data"], body)
                return status, json.loads(raw) if raw else None

            status, opened = message({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                                      "params": {"protocolVersion": "2024-11-05"}})
            assert status == 200 and opened["result"]["protocolVersion"] == "2024-11-05"
            pushed = _event(stream)
            assert pushed["event"] == "message" and json.loads(pushed["data"]) == opened
            assert message({"jsonrpc": "2.0", "method": "notifications/initialized"}) == (202, None)

            status, posted = message(_call("mailbox_post", {"channel": "wave",
                                                            "body": "over http+sse"}, 2))
            assert status == 200 and posted["result"]["isError"] is False
            pushed = _event(stream)
            assert json.loads(pushed["data"]) == posted, "the notification put nothing between"
            assert _bodies(cli_run, ops, "operator", "wave") == ["over http+sse"]

            status, _, raw = _http(url, "POST", "/messages?session_id=never-opened",
                                   {"jsonrpc": "2.0", "id": 3, "method": "ping"})
            assert status == 404 and json.loads(raw)["error"]["code"] == -32001
            status, _, raw = _http(url, "POST", "/messages",
                                   {"jsonrpc": "2.0", "id": 3, "method": "ping"})
            assert status == 400 and "names its session" in json.loads(raw)["error"]["message"]
            status, _, raw = _http(url, "POST", "/mcp", {"jsonrpc": "2.0", "id": 3,
                                                         "method": "ping"},
                                   headers={mcp_http.SESSION_HEADER: sid})
            assert status == 404, "an SSE session is not a Streamable HTTP one"

            assert server.routes.sessions() == 1
            stream.close()
            conn.close()
            deadline = time.monotonic() + WAIT          # the server learns it at once; the
            while server.routes.sessions() and time.monotonic() < deadline:   # test waits
                time.sleep(0.01)                        # only for its own thread to see it
            assert server.routes.sessions() == 0, "the session ended with its stream"
            assert message({"jsonrpc": "2.0", "id": 4, "method": "ping"})[0] == 404


def test_openapi_describes_each_tool_and_its_route_runs_it(cli_run, tmp_path):
    """`GET /openapi.json` (no bearer: ChatGPT imports it by URL) is an OpenAPI 3.1
    document with one operation per tool and a bearer scheme, its server the origin the
    request reached. `POST /tools/<tool>` runs the tool on the real relay and answers what
    it says, or a status and why."""
    with LoopbackRelay(member_claims=True) as relay:
        ops = tmp_path / "ops"
        _setup(cli_run, relay, ops, "operator", "camp")
        cli_run(ops, "operator", "topic", "create", "wave")
        with mcp_http.McpServer(token=BEARER, port=0, home_dir=ops, default_persona="operator",
                                timeout_seconds=WAIT, quiet=True) as server:
            url = server.url
            status, _, raw = _http(url, "GET", "/openapi.json", token=None)
            doc = json.loads(raw)
            assert status == 200 and doc["openapi"] == "3.1.0"
            assert doc["servers"] == [{"url": url}]
            assert doc["components"]["securitySchemes"]["bearerAuth"] == {
                **doc["components"]["securitySchemes"]["bearerAuth"],
                "type": "http", "scheme": "bearer"}
            assert doc["security"] == [{"bearerAuth": []}]
            assert sorted(doc["paths"]) == sorted(f"/tools/{n}" for n in mcp.HANDLERS)
            for name in mcp.HANDLERS:
                operation = doc["paths"][f"/tools/{name}"]["post"]
                assert operation["operationId"] == name and operation["summary"]
                assert len(operation["description"]) <= \
                    mcp_http.GPT_OPERATION_DESCRIPTION_CHARS
                schema = operation["requestBody"]["content"]["application/json"]["schema"]
                assert schema["type"] == "object"
                assert {"200", "400", "401", "422"} <= set(operation["responses"])
            assert "files" not in doc["paths"]["/tools/mailbox_post"]["post"]["requestBody"][
                "content"]["application/json"]["schema"]["properties"]
            proxied = json.loads(_http(url, "GET", "/openapi.json", token=None, headers={
                "X-Forwarded-Proto": "https", "X-Forwarded-Host": "mcp.example.org"})[2])
            assert proxied["servers"] == [{"url": "https://mcp.example.org"}]

            assert _http(url, "POST", "/tools/mailbox_list", {}, token=None)[0] == 401
            status, _, raw = _http(url, "POST", "/tools/mailbox_list", {})
            assert status == 200 and json.loads(raw)["active_persona"] == "operator"
            status, _, raw = _http(url, "POST", "/tools/mailbox_list",
                                   headers={"Content-Length": "0"})
            assert status == 200, "a tool without arguments takes an empty body"

            status, _, raw = _http(url, "POST", "/tools/mailbox_post",
                                   {"channel": "wave", "body": "from a GPT action"})
            assert status == 200 and json.loads(raw)["channel"] == "wave"
            assert _bodies(cli_run, ops, "operator", "wave") == ["from a GPT action"]
            status, _, raw = _http(url, "POST", "/tools/mailbox_watch",
                                   {"channel": "wave", "history": True})
            assert [m["body"] for m in json.loads(raw)["messages"]] == ["from a GPT action"]

            for body, want, said in [
                    ({"channel": "wavee", "body": "typo"}, 422, "holds no channel 'wavee'"),
                    ({"channel": "wave"}, 400, "needs ['body']"),
                    ({"channel": "wave", "body": "x", "files": ["/etc/hosts"]}, 400,
                     "names a file on the server's machine")]:
                status, _, raw = _http(url, "POST", "/tools/mailbox_post", body)
                assert status == want and said in json.loads(raw)["error"], body
            status, _, raw = _http(url, "POST", "/tools/mailbox_teleport", {})
            assert status == 404 and "mailbox_teleport" in json.loads(raw)["error"]
            assert _http(url, "GET", "/tools/mailbox_list")[0] == 405
            status, _, raw = _http(url, "POST", "/tools/mailbox_list",
                                   headers={"Content-Type": "text/plain", "Content-Length": "2"})
            assert status == 415 and "send JSON" in json.loads(raw)["error"]


def test_mcp_http_prints_its_bearer_keeps_it_0600_and_serves_until_ctrl_c(tmp_path):
    """`nostr-mailbox mcp --http 127.0.0.1:0`, a real process: one JSON line names the
    URL and the bearer header, the token it made is 0600 in the home and the same on the
    next start, and Ctrl-C stops it with exit 0. `--no-auth` serves loopback only, to a
    Host naming loopback; a bind beyond loopback without a bearer, a token file others can
    read, and an HTTP flag without HTTP each exit 1."""
    env = {**{k: v for k, v in os.environ.items() if k not in ENV}, "PYTHONPATH": str(SKILL)}
    home = tmp_path / "home"

    def start(*flags, at: Path = home) -> tuple[subprocess.Popen, dict]:
        proc = subprocess.Popen([sys.executable, "-m", "nostr_mailbox", "--home", str(at),
                                 "--persona", "scout", "mcp", *flags], env=env,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        line = proc.stdout.readline()
        assert line, proc.stderr.read()
        return proc, json.loads(line)

    def stop(proc: subprocess.Popen) -> dict:
        proc.send_signal(signal.SIGINT)
        out, err = proc.communicate(timeout=WAIT)
        assert proc.returncode == 0, err
        return json.loads(out)

    proc, up = start("--http", "127.0.0.1:0")
    try:
        token = (home / "mcp.token").read_text().strip()
        assert stat.S_IMODE((home / "mcp.token").stat().st_mode) == 0o600
        assert (up["token_file"], up["header"], up["persona"]) == (
            str(home / "mcp.token"), f"Authorization: Bearer {token}", "scout")
        assert up["mcp"] == up["serving"] + "/mcp" and up["auth"] == "bearer"
        assert list(up)[:2] == ["magic_mcp_url", "magic_openapi_url"], "the one URL comes first"
        assert up["magic_mcp_url"] == f"{up['serving']}/mcp/s/{token}"
        assert up["magic_openapi_url"] == up["magic_mcp_url"] + "/openapi.json"
        status, _, body = _http(up["serving"], "POST", urlsplit(up["magic_mcp_url"]).path,
                                {"jsonrpc": "2.0", "id": 1, "method": "ping"}, token=None,
                                headers=STREAMABLE)
        assert (status, json.loads(body)["result"]) == (200, {}), "it serves with no header"
        assert up["claude_code"].startswith(f"claude mcp add --transport http nostr-mailbox "
                                            f"{up['mcp']} --header")
        status, response, body = _rpc(up["serving"], {"jsonrpc": "2.0", "id": 1,
                                                      "method": "initialize", "params": {}},
                                      token=token)
        assert status == 200 and response.getheader(mcp_http.SESSION_HEADER)
        assert body["result"]["protocolVersion"] == mcp.PROTOCOL_VERSIONS[0]
    finally:
        stopped = stop(proc)
    assert stopped == {"stopped": up["serving"]}
    proc, again = start("--port", "0")
    stop(proc)
    assert again["header"] == up["header"], "the bearer is kept, not made anew"

    bare = tmp_path / "bare"
    proc, up = start("--http", "127.0.0.1:0", "--no-auth", at=bare)
    try:
        assert up["auth"].startswith("none") and up["header"] is None
        assert up["magic_mcp_url"] == up["serving"] + "/mcp", "no bearer: the plain URL"
        assert not (bare / "mcp.token").exists(), "--no-auth makes no token"
        port = urlsplit(up["serving"]).port
        status, _, body = _rpc(up["serving"], {"jsonrpc": "2.0", "id": 1, "method": "ping"},
                               token=None)
        assert (status, body["result"]) == (200, {})
        status, _, body = _rpc(up["serving"], {"jsonrpc": "2.0", "id": 1, "method": "ping"},
                               token=None, headers={"Host": f"rebound.example:{port}"})
        assert status == 403 and "another name" in body["error"]
    finally:
        stop(proc)

    loose = tmp_path / "loose.token"
    loose.write_text("a-token-others-can-read\n")
    os.chmod(loose, 0o644)
    for flags, said in [(["--http", "0.0.0.0:0", "--no-auth"], "not a loopback address"),
                        (["--http", "127.0.0.1:0", "--token-file", str(loose)], "must be 0600"),
                        (["--token", "abc"], "stdio has none"),
                        (["--http", "7000", "--bind", "127.0.0.1:7001"], "give one"),
                        (["--http", "127.0.0.1:7000", "--port", "7001"], "two ports")]:
        done = subprocess.run([sys.executable, "-m", "nostr_mailbox", "--home", str(bare),
                               "mcp", *flags], env=env, capture_output=True, text=True,
                              timeout=WAIT, stdin=subprocess.DEVNULL)
        assert done.returncode == 1 and said in done.stderr, (flags, done.stderr)
    assert not (bare / "mcp.token").exists()


def test_the_console_serves_the_same_mcp_routes_at_its_own_mcp(cli_run, tmp_path):
    """While `nostr-mailbox ui` runs, `<console>/mcp` is an MCP server: it asks for the
    home's bearer (made 0600 at start), never the page's token, keeps the console's Host
    rule, and runs as the persona X-NM-Persona names, else as the console's default. A
    post through it lands on the real relay; `/api/state` says where it is."""
    with LoopbackRelay(member_claims=True) as relay:
        ops = tmp_path / "ops"
        _setup(cli_run, relay, ops, "operator", "camp")
        cli_run(ops, "operator", "topic", "create", "wave")
        cli_run(ops, "scout", "init")
        console = ui.Console(base=ops, identity="operator", timeout_s=WAIT, quiet=True)
        with ui.ConsoleServer(console, port=0) as server:
            url = server.url
            token = (ops / "mcp.token").read_text().strip()
            assert stat.S_IMODE((ops / "mcp.token").stat().st_mode) == 0o600
            assert _rpc(url, {"jsonrpc": "2.0", "id": 1, "method": "ping"},
                        token=console.token)[0] == 401, "the page's token is not the bearer"
            port = urlsplit(url).port
            status, _, body = _rpc(url, {"jsonrpc": "2.0", "id": 1, "method": "ping"},
                                   token=token, headers={"Host": f"rebound.example:{port}"})
            assert status == 403

            _, _, listed = _rpc(url, _call("mailbox_list", {}), token=token)
            assert listed["result"]["structuredContent"]["active_persona"] == "operator"
            _, _, listed = _rpc(url, _call("mailbox_list", {}), token=token,
                                headers={ui.PERSONA_HEADER: "scout"})
            assert listed["result"]["structuredContent"]["active_persona"] == "scout"
            status, _, body = _rpc(url, _call("mailbox_list", {}), token=token,
                                   headers={ui.PERSONA_HEADER: "Not A Name"})
            assert status == 400 and "must match" in body["error"]

            _, _, posted = _rpc(url, _call("mailbox_post", {"channel": "wave",
                                                            "body": "through the console"}),
                                token=token)
            assert posted["result"]["isError"] is False
            assert _bodies(cli_run, ops, "operator", "wave") == ["through the console"]
            status, _, raw = _http(url, "POST", "/tools/mailbox_list", {}, token=token)
            assert status == 200 and json.loads(raw)["active_persona"] == "operator"
            assert json.loads(_http(url, "GET", "/openapi.json", token=None)[2])[
                "servers"] == [{"url": url}]

            parts = urlsplit(url)
            conn = http.client.HTTPConnection(parts.hostname, parts.port, timeout=WAIT)
            conn.request("GET", "/api/state", headers={ui.TOKEN_HEADER: console.token})
            state = json.loads(conn.getresponse().read())
            conn.close()
            assert state["mcp"] == {"path": "/mcp", "sse": "/sse", "openapi": "/openapi.json",
                                    "tools": "/tools/", "auth": "bearer",
                                    "token_file": str(ops / "mcp.token")}
            status, response, _ = _http(url, "OPTIONS", "/api/state", token=None,
                                        headers={"Origin": "http://localhost:6274"})
            assert status == 404 and response.getheader("Access-Control-Allow-Origin") is None, \
                "the console's own API still answers no CORS"


def test_two_agents_on_one_http_server_talk_while_a_watch_waits(cli_run, tmp_path):
    """Two agents connected to one HTTP MCP server talk in real time. Agent A's
    `mailbox_watch` on `wave` waits up to 10 s as alice; once its subscription is open,
    and 200 ms later, agent B posts there as bob, another persona of the same home. B's
    post is not queued behind A's wait: both calls answer in under 2.5 s, and A's watch
    wakes with B's message. While the calls overlap, stdout is the process's stderr;
    once both are done, it is stdout again."""
    with LoopbackRelay(member_claims=True) as relay:
        ops, laptop = tmp_path / "ops", tmp_path / "laptop"
        _setup(cli_run, relay, ops, "operator", "camp")
        cli_run(ops, "operator", "topic", "create", "wave")
        for persona in ("alice", "bob"):          # no --for: a join then announces nothing
            cli_run(laptop, persona, "join",
                    cli_run(ops, "operator", "topic", "invite", "wave")["token"])
        assert cli_run(laptop, "alice", "--topic", "wave", "watch", "bus", "--wait-seconds",
                       "0")["messages"] == [], "nothing is pending: A's watch has to wait"
        stdout = sys.stdout
        with mcp_http.McpServer(token=BEARER, port=0, home_dir=laptop, default_persona="alice",
                                timeout_seconds=WAIT, quiet=True) as server:
            answered: dict = {}

            def call(key: str, name: str, arguments: dict) -> None:
                began = time.monotonic()
                try:
                    status, _, body = _rpc(server.url, _call(name, arguments))
                except TimeoutError:        # no answer within the connection's WAIT
                    answered[key] = None
                    return
                answered[key] = (status, body, time.monotonic() - began)

            listening = relay.subscriptions()
            watcher = threading.Thread(target=call, args=(
                "watch", "mailbox_watch", {"channel": "wave", "wait_seconds": 10,
                                           "persona": "alice"}))
            watcher.start()
            deadline = time.monotonic() + WAIT
            while relay.subscriptions() == listening:       # A is listening on the relay
                assert time.monotonic() < deadline, "the watch never subscribed"
                time.sleep(0)
            time.sleep(0.2)
            poster = threading.Thread(target=call, args=(
                "post", "mailbox_post", {"channel": "wave", "body": "hello", "persona": "bob"}))
            poster.start()
            poster.join(WAIT)
            watcher.join(WAIT)
            assert not poster.is_alive() and not watcher.is_alive()

        assert answered["post"] is not None, f"the post had no answer in {WAIT} s: it was " \
                                             "held behind the watch"
        assert answered["watch"] is not None, f"the watch had no answer in {WAIT} s"
        (post_status, posted, post_took), (watch_status, watched, watch_took) = (
            answered["post"], answered["watch"])
        assert (post_status, watch_status) == (200, 200)
        assert posted["result"]["isError"] is False, posted
        assert post_took < 2.5, f"the post waited {post_took:.2f} s behind the watch"
        assert watch_took < 2.5, f"the watch took {watch_took:.2f} s: it woke on the timeout"
        heard = watched["result"]["structuredContent"]["messages"]
        assert [(m["id"], m["body"]) for m in heard] == [
            (posted["result"]["structuredContent"]["id"], "hello")], "A heard B"
        assert sys.stdout is stdout, "the last call to finish put stdout back"


CALLBACK = "https://chat.example.org/connector/oauth/callback"
PING = {"jsonrpc": "2.0", "id": 1, "method": "ping"}


def _pkce() -> tuple[str, str]:
    """A PKCE verifier and its S256 challenge (RFC 7636 §4.1, §4.2)."""
    verifier = secrets.token_urlsafe(48)
    digest = hashlib.sha256(verifier.encode()).digest()
    return verifier, base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def _form_post(url: str, path: str, fields: dict, *, headers: dict | None = None):
    """A form post, as a browser sends one (or an OAuth client its token request)."""
    parts = urlsplit(url)
    conn = http.client.HTTPConnection(parts.hostname, parts.port, timeout=WAIT)
    try:
        conn.request("POST", path, body=urlencode(fields).encode(), headers={
            "Content-Type": "application/x-www-form-urlencoded", **(headers or {})})
        response = conn.getresponse()
        payload = response.read()
    finally:
        conn.close()
    return response.status, response, payload


def _hidden(page: bytes) -> dict:
    """The hidden fields of the consent form, as a browser posts them back."""
    return {name: html.unescape(value) for name, value in re.findall(
        r'<input type="hidden" name="([^"]+)" value="([^"]*)">', page.decode())}


def _register(url: str, **metadata) -> dict:
    status, _, raw = _http(url, "POST", "/oauth/register",
                           {"client_name": "Witness GPT", "redirect_uris": [CALLBACK],
                            **metadata}, token=None)
    assert status == 201, raw
    return json.loads(raw)


def _consent(url: str, client: dict, challenge: str, *, headers: dict | None = None,
             persona: str | None = None) -> dict:
    """GET the card, then click Authorize on it: the query the client's callback gets."""
    asked = {"client_id": client["client_id"], "redirect_uri": CALLBACK,
             "response_type": "code", "state": "st-1", "code_challenge": challenge,
             "code_challenge_method": "S256", "resource": url + "/mcp"}
    status, _, page = _http(url, "GET", "/oauth/authorize?" + urlencode(asked), token=None,
                            headers=headers)
    assert status == 200 and b'name="owner_token"' not in page, page
    picked = {"persona": persona} if persona else {}
    status, response, _ = _form_post(url, "/oauth/authorize", {
        **_hidden(page), **picked, "decision": "approve"}, headers={"Origin": url,
                                                                    **(headers or {})})
    assert status == 302
    back = urlsplit(response.getheader("Location"))
    assert f"{back.scheme}://{back.netloc}{back.path}" == CALLBACK
    return dict(parse_qsl(back.query))


def _token(url: str, **fields) -> tuple[int, dict]:
    status, _, raw = _form_post(url, "/oauth/token", fields)
    return status, json.loads(raw)


def test_oauth_signs_a_client_in_with_pkce_and_its_token_acts_as_one_persona(cli_run,
                                                                           tmp_path):
    """A client handed only `<server>/mcp` signs itself in, as the MCP authorization spec
    has it: the 401 names the resource metadata (RFC 9728), that names this server as
    its authorization server (RFC 8414), the client registers itself (RFC 7591) and
    sends its user to the consent card. The person running the server proves it once
    with its token (or its magic URL); a session cookie makes every later consent one
    click, and the card alone (its CSRF token, its own origin) can answer. The code is
    bound to its PKCE challenge and spent by its first use. The access token reaches
    every route as the persona picked, and only as it; a refresh rotates both tokens;
    the grant, kept as digests in a 0600 file, outlives the server and is honored by
    another server of the same home; a code used twice revokes it."""
    with LoopbackRelay(member_claims=True) as relay:
        ops = tmp_path / "ops"
        _setup(cli_run, relay, ops, "operator", "camp")
        cli_run(ops, "operator", "topic", "create", "wave")
        cli_run(ops, "scout", "init")
        with mcp_http.McpServer(token=BEARER, port=0, home_dir=ops, default_persona="operator",
                                timeout_seconds=WAIT, quiet=True) as server:
            url = server.url
            # discovery, from nothing but the 401
            status, response, _ = _rpc(url, PING, token=None)
            assert status == 401
            found = re.fullmatch(r'Bearer resource_metadata="([^"]+)"',
                                 response.getheader("WWW-Authenticate"))
            assert found and found.group(1) == f"{url}/.well-known/oauth-protected-resource"
            resource = json.loads(_http(url, "GET", urlsplit(found.group(1)).path,
                                        token=None)[2])
            assert resource == {"resource": url + "/mcp", "authorization_servers": [url],
                                "bearer_methods_supported": ["header", "query"],
                                "resource_name": "Nostr Mailbox"}
            assert json.loads(_http(url, "GET", "/.well-known/oauth-protected-resource/mcp",
                                    token=None)[2]) == resource
            meta = json.loads(_http(url, "GET", "/.well-known/oauth-authorization-server",
                                    token=None)[2])
            assert {k: meta[k] for k in ("issuer", "authorization_endpoint", "token_endpoint",
                                         "registration_endpoint")} == {
                "issuer": url, "authorization_endpoint": url + "/oauth/authorize",
                "token_endpoint": url + "/oauth/token",
                "registration_endpoint": url + "/oauth/register"}
            assert (meta["response_types_supported"], meta["grant_types_supported"],
                    meta["code_challenge_methods_supported"],
                    meta["token_endpoint_auth_methods_supported"]) == (
                ["code"], ["authorization_code", "refresh_token"], ["S256", "plain"],
                ["none", "client_secret_post", "client_secret_basic"])
            assert json.loads(_http(url, "GET", "/.well-known/openid-configuration",
                                    token=None)[2]) == meta

            # registration: open, and nothing of it is kept
            client = _register(url)
            assert {k: client[k] for k in ("client_name", "redirect_uris", "grant_types",
                                           "response_types", "token_endpoint_auth_method")} == {
                "client_name": "Witness GPT", "redirect_uris": [CALLBACK],
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"], "token_endpoint_auth_method": "none"}
            assert "client_secret" not in client
            store = ops / "mcp-oauth.json"
            assert stat.S_IMODE(store.stat().st_mode) == 0o600
            assert json.loads(store.read_text())["grants"] == {}, "a registration keeps nothing"
            for uris, said in [(["http://evil.example/cb"], "neither https nor http on a loop"),
                               (["https://chat.example.org/cb#x"], "fragment"),
                               ([], "non-empty list")]:
                status, _, raw = _http(url, "POST", "/oauth/register", {"redirect_uris": uris},
                                       token=None)
                assert status == 400, uris
                assert json.loads(raw)["error"] == "invalid_redirect_uri"
                assert said in json.loads(raw)["error_description"]

            # the consent card: before the owner proves it, one field and no persona names
            verifier, challenge = _pkce()
            asked = {"client_id": client["client_id"], "redirect_uri": CALLBACK,
                     "response_type": "code", "state": "st-1", "code_challenge": challenge,
                     "code_challenge_method": "S256"}
            status, response, page = _http(url, "GET", "/oauth/authorize?" + urlencode(asked),
                                           token=None)
            assert status == 200 and page.startswith(b"<!doctype html>")
            assert b"Authorize <code>Witness GPT</code> to connect to Nostr Mailbox" in page
            assert "frame-ancestors 'none'" in response.getheader("Content-Security-Policy")
            assert b'name="owner_token"' in page and b"scout" not in page
            fields = _hidden(page)
            for extra, headers, said in [
                    ({"owner_token": BEARER}, {"Origin": "https://evil.example"}, b"another site"),
                    ({"owner_token": BEARER}, {"Sec-Fetch-Site": "cross-site"}, b"cross-site"),
                    ({"owner_token": BEARER, "csrf": "forged"}, {}, b"CSRF"),
                    ({"owner_token": "guess"}, {}, b"not this server&#x27;s token")]:
                status, response, body = _form_post(url, "/oauth/authorize",
                                                    {**fields, **extra}, headers=headers)
                assert status == 403 and said in body, (extra, headers, body[:300])
                assert response.getheader("Set-Cookie") is None
            status, _, page = _http(url, "GET", "/oauth/authorize?" + urlencode(
                {**asked, "redirect_uri": "https://evil.example/cb"}), token=None)
            assert status == 400 and b"not one this client registered" in page, \
                "a redirect URI never registered is not redirected to"

            # the magic URL proves it too; then the card names the personas
            status, response, page = _form_post(url, "/oauth/authorize", {
                **fields, "owner_token": mcp_http.capability_url(url, BEARER)})
            assert status == 200 and b'<option value="scout">scout</option>' in page
            assert b'<option value="operator" selected>operator (default)</option>' in page
            set_cookie = response.getheader("Set-Cookie")
            assert "HttpOnly" in set_cookie and "SameSite=Lax" in set_cookie
            assert "Path=/oauth" in set_cookie
            owner = {"Cookie": set_cookie.split(";")[0]}
            forged = {k: v for k, v in fields.items() if k != "step"}
            status, _, body = _form_post(url, "/oauth/authorize", {
                **forged, "persona": "operator", "decision": "approve"}, headers=owner)
            assert status == 403 and b"CSRF" in body, \
                "the cookie and a token anyone can load approve nothing: the card's is the owner's"
            cancelled = _form_post(url, "/oauth/authorize", {**_hidden(page),
                                                             "decision": "deny"})[1]
            assert dict(parse_qsl(urlsplit(cancelled.getheader("Location")).query))[
                "error"] == "access_denied"

            # with the cookie, one click; the code is spent by its first use, right or wrong
            got = _consent(url, client, challenge, headers=owner, persona="scout")
            assert (got["state"], got["iss"]) == ("st-1", url) and got["code"].startswith("nmo_")
            exchange = {"grant_type": "authorization_code", "code": got["code"],
                        "redirect_uri": CALLBACK, "client_id": client["client_id"]}
            status, refused = _token(url, **exchange, code_verifier=_pkce()[0])
            assert (status, refused["error"]) == (400, "invalid_grant")
            assert "does not match the code_challenge" in refused["error_description"]
            status, refused = _token(url, **exchange, code_verifier=verifier)
            assert (status, refused["error"]) == (400, "invalid_grant"), "spent when it failed"
            got = _consent(url, client, challenge, headers=owner, persona="scout")
            exchange["code"] = got["code"]
            status, issued = _token(url, **exchange, code_verifier=verifier)
            assert status == 200, issued
            assert (issued["token_type"], issued["expires_in"]) == ("Bearer", 2592000)
            assert issued["access_token"].startswith("nma_") and issued["refresh_token"]

            # the token: every route, as scout alone
            access = issued["access_token"]
            _, _, listed = _rpc(url, _call("mailbox_list", {}), token=access)
            assert listed["result"]["structuredContent"]["active_persona"] == "scout"
            _, _, other = _rpc(url, _call("mailbox_list", {"persona": "operator"}), token=access)
            assert other["result"]["isError"] is True
            assert "granted persona 'scout'" in other["result"]["content"][0]["text"]
            status, _, raw = _http(url, "POST", "/tools/mailbox_list", {"persona": "operator"},
                                   token=access)
            assert status == 403 and "acts as it alone" in json.loads(raw)["error"]
            status, _, raw = _http(url, "POST", "/tools/mailbox_list", {}, token=access)
            assert status == 200 and json.loads(raw)["active_persona"] == "scout"
            status, _, _ = _http(url, "POST", "/mcp?" + urlencode({"access_token": access}),
                                 PING, token=None, headers=STREAMABLE)
            assert status == 200, "RFC 6750 §2.3: the bearer in the query"
            status, _, raw = _http(url, "POST", urlsplit(mcp_http.capability_url(
                url, access)).path + "/tools/mailbox_list", {}, token=None)
            assert status == 200 and json.loads(raw)["active_persona"] == "scout"
            init = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
            sid = _rpc(url, init, token=access)[1].getheader(mcp_http.SESSION_HEADER)
            assert _rpc(url, PING, session=sid, token=access)[0] == 200
            assert _rpc(url, PING, session=sid)[0] == 404, \
                "a session answers the bearer that opened it alone"
            kept = store.read_text()
            [grant] = json.loads(kept)["grants"].values()
            assert (grant["persona"], grant["client_name"]) == ("scout", "Witness GPT")
            assert access not in kept and issued["refresh_token"] not in kept, "digests only"

            # a refresh rotates both tokens
            refresh = {"grant_type": "refresh_token", "client_id": client["client_id"]}
            status, again = _token(url, **refresh, refresh_token=issued["refresh_token"])
            assert status == 200 and again["access_token"] != access
            assert _rpc(url, PING, token=access)[0] == 401, "the old access token stops"
            status, refused = _token(url, **refresh, refresh_token=issued["refresh_token"])
            assert (status, refused["error"]) == (400, "invalid_grant")

            # another server of this home (the console beside `mcp --http`) honors it
            with mcp_http.McpServer(token=BEARER, port=0, home_dir=ops,
                                    default_persona="operator", timeout_seconds=WAIT,
                                    quiet=True) as beside:
                _, _, listed = _rpc(beside.url, _call("mailbox_list", {}),
                                    token=again["access_token"])
                assert listed["result"]["structuredContent"]["active_persona"] == "scout"

            # a code used twice revokes what it was exchanged for
            status, refused = _token(url, **exchange, code_verifier=verifier)
            assert (status, refused["error"]) == (400, "invalid_grant")
            assert _rpc(url, PING, token=again["access_token"])[0] == 401
            assert json.loads(store.read_text())["grants"] == {}

            # a client registered with a secret must send it
            secret = _register(url, token_endpoint_auth_method="client_secret_basic")
            assert secret["client_secret"] and secret["client_secret_expires_at"] == 0
            status, refused = _token(url, grant_type="authorization_code", code="nmo_x",
                                     client_id=secret["client_id"])
            assert (status, refused["error"]) == (401, "invalid_client")
            basic = base64.b64encode(
                f"{secret['client_id']}:{secret['client_secret']}".encode()).decode()
            status, _, raw = _form_post(url, "/oauth/token", {
                "grant_type": "authorization_code", "code": "nmo_x"},
                headers={"Authorization": f"Basic {basic}"})
            assert (status, json.loads(raw)["error"]) == (400, "invalid_grant"), "authenticated"


def test_one_magic_url_carries_the_whole_server_with_no_auth_settings(cli_run, tmp_path,
                                                                      capsys):
    """`/mcp/s/<token>` is the server under the bearer in its path, for a client that
    takes one URL and no auth settings: Streamable HTTP at the URL itself, HTTP+SSE whose
    endpoint event stays under it, `POST <url>/tools/<tool>`, and an OpenAPI document
    whose server is that URL and which asks for no authentication (a GPT Action imports
    it with Authentication: None). No request sends an Authorization header. A wrong
    token in the path runs nothing, and the server's log never names the token."""
    with LoopbackRelay(member_claims=True) as relay:
        ops = tmp_path / "ops"
        _setup(cli_run, relay, ops, "operator", "camp")
        cli_run(ops, "operator", "topic", "create", "wave")
        with mcp_http.McpServer(token=BEARER, port=0, home_dir=ops, default_persona="operator",
                                timeout_seconds=WAIT, quiet=False) as server:
            url = server.url
            magic = mcp_http.capability_url(url, BEARER)
            assert magic == f"{url}/mcp/s/{BEARER}"
            prefix = urlsplit(magic).path
            init = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
                    "params": {"protocolVersion": "2025-11-25"}}
            status, response, _ = _http(url, "POST", prefix, init, token=None, headers=STREAMABLE)
            assert status == 200 and response.getheader(mcp_http.SESSION_HEADER)
            status, _, raw = _http(url, "POST", prefix, _call("mailbox_post", {
                "channel": "wave", "body": "by the magic url"}), token=None, headers=STREAMABLE)
            assert status == 200 and json.loads(raw)["result"]["isError"] is False
            assert _bodies(cli_run, ops, "operator", "wave") == ["by the magic url"]

            status, _, raw = _http(url, "GET", prefix + "/openapi.json", token=None)
            doc = json.loads(raw)
            assert status == 200 and doc["servers"] == [{"url": magic}]
            assert doc["security"] == [] and "securitySchemes" not in doc["components"]
            assert not any("401" in op["post"]["responses"] for op in doc["paths"].values())
            status, _, raw = _http(url, "POST", prefix + "/tools/mailbox_list", {}, token=None)
            assert status == 200 and json.loads(raw)["active_persona"] == "operator"

            parts = urlsplit(url)
            conn = http.client.HTTPConnection(parts.hostname, parts.port, timeout=WAIT)
            conn.request("GET", prefix + "/sse", headers={"Accept": "text/event-stream"})
            stream = conn.getresponse()
            endpoint = _event(stream)
            assert endpoint["event"] == "endpoint"
            assert endpoint["data"].startswith(prefix + "/messages?session_id=")
            status, _, raw = _http(url, "POST", endpoint["data"],
                                   {"jsonrpc": "2.0", "id": 4, "method": "ping"}, token=None)
            assert status == 200 and json.loads(raw)["id"] == 4
            assert json.loads(_event(stream)["data"])["id"] == 4, "answered on the stream too"
            conn.close()

            status, _, raw = _http(url, "POST", "/mcp/s/guess/tools/mailbox_post",
                                   {"channel": "wave", "body": "no"}, token=None)
            assert status == 401 and "neither this server's" in json.loads(raw)["error"]
            assert _http(url, "GET", prefix + "/elsewhere", token=None)[0] == 404
            status, response, _ = _http(url, "OPTIONS", prefix, token=None, headers={
                "Origin": "http://localhost:6274", "Access-Control-Request-Method": "POST"})
            assert status == 204, "a browser client's preflight carries no token"
        logged = capsys.readouterr().err
        assert "/mcp/s/<redacted>/tools/mailbox_list" in logged
        assert BEARER not in logged and "guess" not in logged, "no token is ever logged"
        assert mcp_http.redact("GET /mcp?access_token=nma_x&y=1") == \
            "GET /mcp?access_token=<redacted>&y=1"


def test_the_console_pairs_with_one_url_and_signs_oauth_clients_in_in_one_click(cli_run,
                                                                               tmp_path):
    """Pair Coding Agent asks `/api/pair` (the page's token) for the one URL an MCP
    client is handed: `magic_mcp_url` first, then its OpenAPI document, then the plain
    `/mcp`. That URL serves with no header. A client given the plain URL signs in by
    OAuth, and here the consent card is one click from the start: this console answers
    its own loopback Host alone, as it does for its signing page."""
    with LoopbackRelay(member_claims=True) as relay:
        ops = tmp_path / "ops"
        _setup(cli_run, relay, ops, "operator", "camp")
        cli_run(ops, "scout", "init")
        console = ui.Console(base=ops, identity="operator", timeout_s=WAIT, quiet=True)
        with ui.ConsoleServer(console, port=0) as server:
            url = server.url
            token = (ops / "mcp.token").read_text().strip()
            parts = urlsplit(url)
            asked = []
            for headers in ({ui.TOKEN_HEADER: console.token}, {}):
                conn = http.client.HTTPConnection(parts.hostname, parts.port, timeout=WAIT)
                conn.request("GET", "/api/pair", headers=headers)
                response = conn.getresponse()
                asked.append((response.status, json.loads(response.read())))
                conn.close()
            (status, pair), (refused, _) = asked
            assert status == 200 and refused == 403, "the page's token is asked"
            assert list(pair)[:3] == ["magic_mcp_url", "magic_openapi_url", "mcp_url"]
            assert pair["magic_mcp_url"] == mcp_http.capability_url(url, token)
            assert pair["magic_openapi_url"] == pair["magic_mcp_url"] + "/openapi.json"
            assert pair["mcp_url"] == url + "/mcp"
            status, _, raw = _http(url, "POST", urlsplit(pair["magic_mcp_url"]).path
                                   + "/tools/mailbox_list", {}, token=None)
            assert status == 200 and json.loads(raw)["active_persona"] == "operator"

            client = _register(url)
            verifier, challenge = _pkce()
            got = _consent(url, client, challenge, persona="scout")
            status, issued = _token(url, grant_type="authorization_code", code=got["code"],
                                    redirect_uri=CALLBACK, client_id=client["client_id"],
                                    code_verifier=verifier)
            assert status == 200, issued
            _, _, listed = _rpc(url, _call("mailbox_list", {}), token=issued["access_token"])
            assert listed["result"]["structuredContent"]["active_persona"] == "scout"
            assert (ops / "mcp-oauth.json").is_file()


# ====================================================== Claude Desktop, installed
SYNC = Path(__file__).resolve().parents[1] / "scripts/sync_plugin.py"


def test_the_installer_merges_claude_desktop_and_the_entry_it_writes_launches(cli_run,
                                                                              tmp_path):
    """`sync_plugin.py --install --harness claude-desktop` merges one entry into an
    existing claude_desktop_config.json: every other key and server kept, its mode kept,
    no staging file left. The entry, launched the way an MCP stdio client launches it (its
    command, args and env alone), acts as this machine's default persona: a channel the
    terminal CLI created is open to it, its keyring the same file, with no invite. The
    profile variables set in the installing shell go along; the seat does not. Running
    again changes nothing; a dry run writes nothing; a config that is not JSON, or a
    symlink, is refused and left as it is. A full --install finds Claude Desktop by its
    folder."""
    fake_home = tmp_path / "home"
    config = tmp_path / "Claude/claude_desktop_config.json"
    config.parent.mkdir()
    before = {"globalShortcut": "Ctrl+Space",
              "mcpServers": {"other": {"command": "other-server", "args": ["--flag"]}}}
    config.write_text(json.dumps(before, indent=2))
    os.chmod(config, 0o640)
    env = {**{k: v for k, v in os.environ.items() if k not in ENV}, "HOME": str(fake_home)}

    def install(*extra, at: Path = config, environ: dict = env):
        return subprocess.run([sys.executable, str(SYNC), "--install", "--claude-desktop-config",
                               str(at), *extra], capture_output=True, text=True, env=environ,
                              check=False)

    planned = install("--harness", "claude-desktop", "--dry-run")
    assert planned.returncode == 0, planned.stderr
    assert f"merge mcpServers.nostr-mailbox into {config}" in planned.stdout
    assert json.loads(config.read_text()) == before, "a dry run writes nothing"

    done = install("--harness", "claude-desktop")
    assert done.returncode == 0, done.stderr
    merged = json.loads(config.read_text())
    binary = fake_home / ".local/bin/nostr-mailbox"
    entry = merged["mcpServers"]["nostr-mailbox"]
    assert entry == {"command": str(binary), "args": ["mcp"],
                     "env": {"PATH": os.environ["PATH"]}}, "no --persona: the machine's own"
    assert {k: v for k, v in merged.items() if k != "mcpServers"} == {
        "globalShortcut": "Ctrl+Space"}
    assert merged["mcpServers"]["other"] == before["mcpServers"]["other"]
    assert list(merged["mcpServers"]) == ["other", "nostr-mailbox"]
    assert stat.S_IMODE(config.stat().st_mode) == 0o640
    assert sorted(p.name for p in config.parent.iterdir()) == [config.name]

    # launched as Claude Desktop launches it: nothing of this shell but its default set.
    # The terminal CLI, as the default persona of the default home, keeps channel wave
    ops = fake_home / ".config/nostr-mailbox"
    with LoopbackRelay(member_claims=True) as relay:
        _setup(cli_run, relay, ops, "default", "camp")
        cli_run(ops, "default", "topic", "create", "wave")
        launched = subprocess.run(
            [entry["command"], *entry["args"]],
            input=json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                              "params": {"protocolVersion": "2025-06-18"}}) + "\n"
            + json.dumps(_call("mailbox_list", {}, 2)) + "\n"
            + json.dumps(_call("mailbox_post", {"channel": "wave", "body": "from desktop"},
                               3)) + "\n",
            capture_output=True, text=True, timeout=WAIT,
            env={"HOME": str(fake_home), **entry["env"]})
        assert launched.returncode == 0, launched.stderr
        init, listed, posted = _replies(launched.stdout.encode())
        assert init["result"]["serverInfo"]["name"] == "nostr-mailbox"
        seen = listed["result"]["structuredContent"]
        assert (seen["home"], seen["active_persona"]) == (str(ops), "default")
        assert [(c["name"], c["held_epochs"], c["keeper"]) for c in seen["channels"]] == [
            ("wave", [1], True)], "the terminal's own channel and keyring, with no invite"
        assert posted["result"]["isError"] is False, posted
        assert _bodies(cli_run, ops, "default", "wave") == ["from desktop"]

    # the installing shell's profile goes along (a desktop app passes none of it on)
    profiled = tmp_path / "profiled/claude_desktop_config.json"
    profiled.parent.mkdir()
    shell = {**env, "NOSTR_MAILBOX_HOME": str(tmp_path / "elsewhere"),
             "NOSTR_MAILBOX_IDENTITY": "alice", "NOSTR_MAILBOX_SEAT": "reviewer-3"}
    done = install("--harness", "claude-desktop", at=profiled, environ=shell)
    assert done.returncode == 0, done.stderr
    assert json.loads(profiled.read_text())["mcpServers"]["nostr-mailbox"]["env"] == {
        "PATH": os.environ["PATH"], "NOSTR_MAILBOX_HOME": str(tmp_path / "elsewhere"),
        "NOSTR_MAILBOX_IDENTITY": "alice"}, "a seat is one agent's queue, not the machine's"

    again = install("--harness", "claude-desktop")
    assert again.returncode == 0 and "unchanged" in again.stdout

    broken = tmp_path / "broken/claude_desktop_config.json"
    broken.parent.mkdir()
    broken.write_text('{"mcpServers": {')
    refused = install("--harness", "claude-desktop", at=broken)
    assert refused.returncode != 0 and "is not JSON" in refused.stderr
    assert broken.read_text() == '{"mcpServers": {'
    linked = tmp_path / "linked/claude_desktop_config.json"
    linked.parent.mkdir()
    linked.symlink_to(config)
    refused = install("--harness", "claude-desktop", at=linked)
    assert refused.returncode != 0 and "refusing to write through the symlink" in refused.stderr

    # a full --install: with no other harness on PATH or under HOME, it finds this one
    found = tmp_path / "found/claude_desktop_config.json"
    found.parent.mkdir()
    bare_path = os.pathsep.join([str(Path(sys.executable).parent), "/usr/bin", "/bin"])
    assert not any(shutil.which(h, path=bare_path) for h in ("claude", "codex", "agy", "pi",
                                                              "opencode"))
    detected = install(at=found, environ={**env, "PATH": bare_path})
    assert detected.returncode == 0, detected.stderr
    assert json.loads(found.read_text())["mcpServers"]["nostr-mailbox"]["env"] == {
        "PATH": bare_path}
