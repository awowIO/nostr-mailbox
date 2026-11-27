"""Witnesses for the Visual Web Console: the protocol engine inside `web/index.html`, and
the workstation bridge `ui.py` that serves it.

Nothing here is mocked. The engine is lifted verbatim out of the page and run under
Node.js (tests/web_ui_harness.mjs); it talks to `LoopbackRelay` over a real WebSocket,
and to the bridge over real HTTP, exactly as a browser tab does. The bridge is a real
server on a loopback port, signing with a real 0600 identity file. The one stand-in is
the relay's admin CLI for `/api/invite`: a recording program on a real subprocess
boundary, as in test_nostr_mailbox.py. That `ncli` itself mints such invites is
witnessed by test_nostr_ncli.py against the real binary.

What these witnesses cannot show: how the page draws in a real browser. The engine and
the bridge are what decide every byte on the wire, and both run here; the DOM layer is
held to parse, to be self-contained and to keep the full-width rule."""
import base64
import hashlib
import hmac
import http.client
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlsplit

import pytest

from nostr_mailbox import (
    CampaignSession,
    Claim,
    Condition,
    Decision,
    LocalSigner,
    LoopbackRelay,
    Message,
    NostrRelayChannelBackend,
    Trust,
    backend,
    bech32,
    blossom,
    cli,
    nip44,
    secp256k1,
    ui,
)
from nostr_mailbox import event as event_mod
from nostr_mailbox import relay as relay_mod
from nostr_mailbox.event import dumps, sign_with_secret, unsigned, verify_event
from nostr_mailbox.identity import create_identity
from nostr_mailbox.profile import MAX_EVENT_BYTES, Kind, encode

REPO = Path(__file__).resolve().parents[1]
SKILL = REPO / "skills/nostr-mailbox"
PAGE = SKILL / "nostr_mailbox/web/index.html"
HARNESS = Path(__file__).with_name("web_ui_harness.mjs")
NODE = shutil.which("node")
needs_node = pytest.mark.skipif(
    NODE is None, reason="the page's engine runs under Node.js here; install node to witness it")
WAIT = 5.0                      # generous: a witness that passes never waits this long


def _secret(n: int) -> bytes:
    return hashlib.sha256(f"web-ui-test-key-{n}".encode()).digest()


FRIEND_SK, NEWCOMER_SK, STRANGER_SK, PEER_SK = (_secret(n) for n in range(1, 5))


def _pub(secret: bytes) -> str:
    return secp256k1.pubkey_gen(secret).hex()


def _npub(pubkey: str) -> str:
    return bech32.encode(bech32.NPUB, bytes.fromhex(pubkey))


def _engine_source() -> str:
    match = re.search(r'<script id="nm-engine">(.*?)</script>', PAGE.read_text(), re.S)
    assert match, "web/index.html carries its engine in <script id=\"nm-engine\">"
    return match.group(1)


@pytest.fixture(scope="session")
def node(tmp_path_factory):
    """Run one harness request: the engine exactly as the page holds it, under Node."""
    if NODE is None:
        pytest.skip("node is not installed")
    engine = tmp_path_factory.mktemp("engine") / "engine.js"
    engine.write_text(_engine_source())

    def run(request: dict) -> dict:
        done = subprocess.run([NODE, str(HARNESS), str(engine)], input=json.dumps(request),
                              capture_output=True, text=True, check=False)
        assert done.returncode == 0, f"the engine failed:\n{done.stderr}"
        return json.loads(done.stdout)
    return run


@pytest.fixture
def relay():
    # The real clock: the page stamps its events and NIP-42 proofs with Date.now().
    with LoopbackRelay() as running:
        yield running


def _next_second() -> None:
    """Membership changes and messages are ordered by whole seconds (NIP-01); a witness
    that needs one strictly after the other waits for the clock to tick, no longer."""
    start = int(time.time())
    while int(time.time()) == start:
        time.sleep(0.01)


@pytest.fixture
def workstation(tmp_path, relay):
    """The operator's machine: a 0600 key, a nostr.toml with a campaign_key, enrolled on
    the relay, and `nostr-mailbox ui` serving on a free loopback port."""
    home = tmp_path / "op-home"
    ident = create_identity("default", base=home)
    relay.add_member(ident.pubkey)
    key = os.urandom(32).hex()
    cli._write_trust_file(home / "nostr.toml", {
        "schema": "cf.transport/1", "relay": relay.url, "campaign": "camp",
        "operator_pubkeys": [ident.npub], "campaign_key": key})
    console = ui.Console(base=home, timeout_s=WAIT, quiet=True)
    with ui.ConsoleServer(console, port=0) as server:
        yield SimpleNamespace(
            home=home, ident=ident, pubkey=ident.pubkey, campaign_key=key, console=console,
            server=server, url=server.url, token=console.token,
            secret=bech32.decode(bech32.NSEC, ident.signer_spec["nsec"]),
            trust={"schema": "cf.transport/1", "relay": relay.url, "campaign": "camp",
                   "operator_pubkeys": [ident.pubkey], "campaign_key": key})


def call(ws, method: str, path: str, body=None, *, token: str | None = "default",
         host: str | None = None, headers: dict | None = None, raw: bytes | None = None,
         want: int = 200):
    """One request to the bridge; returns the parsed answer (or bytes) after checking the
    status."""
    parts = urlsplit(ws.url)
    conn = http.client.HTTPConnection(parts.hostname, parts.port, timeout=WAIT)
    sent = {"Host": host or parts.netloc, **(headers or {})}
    if token is not None:
        sent[ui.TOKEN_HEADER] = ws.token if token == "default" else token
    data = raw
    if body is not None:
        data = json.dumps(body).encode()
        sent.setdefault("Content-Type", "application/json")
    try:
        conn.request(method, path, body=data, headers=sent)
        response = conn.getresponse()
        payload = response.read()
    finally:
        conn.close()
    assert response.status == want, f"{method} {path} -> {response.status}: {payload[:400]!r}"
    kind = response.getheader("Content-Type") or ""
    return json.loads(payload) if kind.startswith("application/json") else (payload, response)


def _cli_env() -> dict:
    """The environment a real CLI process gets here: this checkout's package, and none of
    the caller's own NOSTR_MAILBOX_* settings."""
    return {**{k: v for k, v in os.environ.items() if not k.startswith("NOSTR_MAILBOX_")},
            "PYTHONPATH": str(SKILL)}


def _session(ws, *, trust: Trust | None = None) -> ui.TopicSession:
    signer = LocalSigner(ws.secret)
    return ui.TopicSession(trust or Trust.load(ws.home / "nostr.toml"), signer,
                           timeout_s=WAIT)


# =============================================================== the page itself
def test_the_page_is_one_self_contained_full_width_html_file():
    """One file that runs from the relay's origin or from loopback with nothing fetched:
    no external URL, no script or stylesheet by reference, no font or CDN. Full width:
    the page wrapper spans the viewport behind fluid gutters, and no declaration caps a
    width with a fixed length."""
    page = PAGE.read_text()
    assert page.startswith("<!doctype html>\n<html lang=\"en\"")
    for needed in ('<meta charset="utf-8">',
                   '<meta name="viewport" content="width=device-width, initial-scale=1">',
                   "<title>nostr-mailbox · Web Console</title>", "<body>", "</html>",
                   '<meta name="nm-bridge" content="">'):
        assert needed in page, needed
    assert re.findall(r"https?://|wss?://[a-z0-9]", page, re.I) == [], "no external URL"
    assert not re.search(r"<script[^>]+\bsrc=|<link[^>]+stylesheet", page, re.I)
    assert not re.search(r"""(?:src|href)\s*=\s*["']//""", page), "no protocol-relative URL"
    style = re.search(r"<style>(.*?)</style>", page, re.S).group(1)
    assert not re.search(r"@import|url\(|@font-face", style), "no font, image or sheet fetched"
    assert re.search(r"\.page \{[^}]*width: 100%; max-width: none; "
                     r"padding-inline: clamp\(20px, 4vw, 64px\);", style)
    caps = re.findall(r"max-width\s*:\s*([^;}\n]+)", style)
    assert caps and all(value.strip() in ("none", "100%") for value in caps), caps
    assert "@media (max-width" not in style, "breakpoints use range syntax, never a max-width"
    for light in ("--paper: #faf9f6", "--stone: #f0eee9", "--ink: #16181d", "--hair: #d8d5ce",
                  "--teal: #3f5e63", "--sage: #4a6b53", "--amber: #78683a",
                  "--terracotta: #35547a", "--plum: #6d4c5c"):
        assert light in style, light
    assert '[data-theme="dark"]' in style and "--paper: #14171c" in style
    assert "● Ancient Sound" in page and "☀ Paper Light" in page
    assert not re.search(r"""\son(?:click|load|error|submit|change|input|mouse\w*|key\w*)=["']""",
                         page, re.I), "no inline handlers: the bridge's CSP admits two scripts"
    assert "javascript:" not in page.lower()


@needs_node
def test_both_scripts_parse_and_the_bridge_admits_exactly_them(tmp_path, workstation):
    """The served page carries this run's token and a CSP naming its two inline scripts
    by sha256, so nothing else could run in it."""
    page, response = call(workstation, "GET", "/", token=None)
    text = page.decode()
    scripts = re.findall(r"<script(?:\s[^>]*)?>(.*?)</script>", text, re.S)
    assert len(scripts) == 2
    for n, body in enumerate(scripts):
        path = tmp_path / f"script{n}.js"
        path.write_text(body)
        checked = subprocess.run([NODE, "--check", str(path)], capture_output=True, text=True)
        assert checked.returncode == 0, checked.stderr
    csp = response.getheader("Content-Security-Policy")
    for body in scripts:
        digest = base64.b64encode(hashlib.sha256(body.encode()).digest()).decode()
        assert f"'sha256-{digest}'" in csp
    assert "unsafe-inline" not in csp.split("script-src")[1].split(";")[0]
    assert "frame-ancestors 'none'" in csp and response.getheader("Cache-Control") == "no-store"
    assert f'<meta name="nm-bridge" content="{workstation.token}">' in text


# ============================================================ engine vs Python
BIP340_VECTOR_1 = ("b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfef",
                   "243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89",
                   "0000000000000000000000000000000000000000000000000000000000000001",
                   "6896bd60eeae296db48a229ff71dfe071bde413e6d43f917dc8dcf8c78de3341"
                   "8906d11ac976abccb20b091292bff4ea897efcb639ea871cfa95f6de339e4b0a")
# The published NIP-44 v2 vector: sec1 = 1, sec2 = 2, nonce = 1, plaintext "a".
NIP44_CONV = "c41c775356fd92eadc63ff5a0dc1da211b268cbea22316767095b2871ea1412d"
NIP44_PAYLOAD = ("AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABee0G5VSK0/9YypIObAtDKfYEAjD35uVk"
                 "HyB0F4DwrcNaCXlCWZKaArsGrY6M9wnuTMxWfp1RTN9Xga8no+kF5Vsb")


@needs_node
def test_the_engine_crypto_agrees_with_the_python_package_and_the_published_vectors(node):
    """SHA-256, HMAC, HKDF, ChaCha20, BIP-340 keys and signatures, ECDH, NIP-44 v2 (both
    conversation keys, padding, the extended length prefix, MAC refusal), bech32 and the
    NIP-01 event id: the page's JavaScript against secp256k1.py and nip44.py on random
    inputs, and against the published vectors."""
    rnd = os.urandom
    keys = [rnd(32) for _ in range(6)]
    one, two = (1).to_bytes(32, "big"), (2).to_bytes(32, "big")
    keys += [one, two]
    msgs = [b"", b"abc", rnd(55), rnd(56), rnd(64), rnd(1000)]
    plains = [b"a", rnd(31), rnd(32), rnd(33), rnd(300), rnd(70_000)]
    convs = [rnd(32) for _ in plains]
    nonces = [rnd(32) for _ in plains]
    payloads = [nip44.encrypt_bytes(p, k) for p, k in zip(plains, convs, strict=True)]
    sigs = [(k, rnd(32), rnd(32)) for k in keys[:4]]
    events = [sign_with_secret(unsigned(8891, [["t", "camp:bus"], ["e", "ü" * 3]],
                                        "naïve   \"quoted\"\n\ttabs", 1_800_000_000),
                               keys[0]).to_dict()]
    forged = dict(events[0], content="altered")
    request = {
        "scenario": "crypto",
        "sha256": [m.hex() for m in msgs],
        "hmac": [[rnd(n).hex(), m.hex()] for n, m in zip((16, 64, 65, 200, 32, 1), msgs,
                                                         strict=True)],
        "hkdf": [[rnd(16).hex(), rnd(32).hex(), rnd(32).hex(), 76], ["", rnd(32).hex(), "", 32]],
        "chacha": [[rnd(32).hex(), rnd(12).hex(), rnd(n).hex()] for n in (1, 63, 64, 65, 1000)],
        "pubkey": [k.hex() for k in keys],
        "sign": [[k.hex(), m.hex(), a.hex()] for k, m, a in sigs] + [list(BIP340_VECTOR_1[:3])],
        "verify": [], "ecdh": [[keys[i].hex(), secp256k1.pubkey_gen(keys[i + 1]).hex()]
                               for i in range(4)],
        "conv": [[one.hex(), secp256k1.pubkey_gen(two).hex()],
                 *[[keys[i].hex(), secp256k1.pubkey_gen(keys[i + 1]).hex()] for i in range(3)]],
        "campaign": [[k.hex(), name] for k, name in zip(convs, ("camp", "café-ops", "a.b_c-d",
                                                                 "x", "y", "z"), strict=True)],
        "padded": [1, 32, 33, 64, 65, 100, 256, 257, 1000, 65535, 65536, 100_000],
        "encrypt": [[k.hex(), n.hex(), p.hex()] for k, n, p in zip(convs, nonces, plains,
                                                                    strict=True)]
        + [[NIP44_CONV, (1).to_bytes(32, "big").hex(), b"a".hex()]],
        "decrypt": [[k.hex(), p] for k, p in zip(convs, payloads, strict=True)],
        "tampered": [[convs[0].hex(), payloads[0][:-4] + ("AAAA" if payloads[0][-4:] != "AAAA"
                                                           else "BBBB")],
                     [convs[1].hex(), payloads[0]]],
        "npub": [secp256k1.pubkey_gen(k).hex() for k in keys],
        "nsec": [k.hex() for k in keys[:3]],
        "bech_back": [bech32.encode("npub", secp256k1.pubkey_gen(k)) for k in keys[:3]]
        + [bech32.encode("nsec", k) for k in keys[:3]],
        "event_id": [{k: v for k, v in e.items() if k in ("pubkey", "created_at", "kind",
                                                           "tags", "content")} for e in events],
        "verify_event": [events[0], forged],
    }
    for k, m, a in sigs:
        sig = secp256k1.schnorr_sign(m, k, a)
        pk = secp256k1.pubkey_gen(k).hex()
        request["verify"] += [[pk, m.hex(), sig.hex()],
                              [pk, m.hex(), (sig[:-1] + bytes([sig[-1] ^ 1])).hex()]]
    got = node(request)
    assert got["sha256"] == [hashlib.sha256(m).hexdigest() for m in msgs]
    assert got["hmac"] == [hmac.new(bytes.fromhex(k), bytes.fromhex(m), "sha256").hexdigest()
                           for k, m in request["hmac"]]
    assert got["hkdf"] == [nip44.hkdf_expand(nip44.hkdf_extract(bytes.fromhex(i), bytes.fromhex(s)),
                                             bytes.fromhex(info), n).hex()
                           for s, i, info, n in request["hkdf"]]
    assert got["chacha"] == [nip44.chacha20(*(bytes.fromhex(v) for v in c)).hex()
                             for c in request["chacha"]]
    assert got["pubkey"] == [secp256k1.pubkey_gen(k).hex() for k in keys]
    assert got["sign"][:4] == [secp256k1.schnorr_sign(m, k, a).hex() for k, m, a in sigs], \
        "BIP-340 is deterministic given aux: the page signs byte for byte as Python does"
    assert got["sign"][4] == BIP340_VECTOR_1[3]
    assert got["verify"] == [True, False] * 4
    assert got["ecdh"] == [nip44.ecdh_x(bytes.fromhex(a), bytes.fromhex(b)).hex()
                           for a, b in request["ecdh"]]
    assert got["conv"][0] == NIP44_CONV
    assert got["conv"] == [nip44.conversation_key(bytes.fromhex(a), bytes.fromhex(b)).hex()
                           for a, b in request["conv"]]
    assert got["campaign"] == [nip44.campaign_conversation_key(bytes.fromhex(k), n).hex()
                               for k, n in request["campaign"]]
    assert got["padded"] == [nip44.calc_padded_len(n) for n in request["padded"]]
    assert got["encrypt"][:-1] == [nip44.encrypt_bytes(p, k, n) for k, n, p
                                   in zip(convs, nonces, plains, strict=True)]
    assert got["encrypt"][-1] == NIP44_PAYLOAD
    assert got["decrypt"] == [p.hex() for p in plains], "including the 70,000-byte extended prefix"
    assert all("invalid MAC" in why or "base64" in why for why in got["tampered"]), got["tampered"]
    assert got["npub"] == [bech32.encode("npub", secp256k1.pubkey_gen(k)) for k in keys]
    assert got["nsec"] == [bech32.encode("nsec", k) for k in keys[:3]]
    assert got["bech_back"] == [secp256k1.pubkey_gen(k).hex() for k in keys[:3]] + \
        [k.hex() for k in keys[:3]]
    assert got["event_id"] == [events[0]["id"]]
    assert got["verify_event"][0] == "ok" and "not the hash" in got["verify_event"][1]


@needs_node
def test_the_engine_writes_records_keys_and_files_the_way_the_cli_does(node, relay, tmp_path):
    """The campaign envelope round-trips both ways under the same campaign_key; the
    page's idempotency key, nostr.toml text, condition transition and four-field
    HANDOFF.md are the CLI's, byte for byte; an nm1_ token the CLI mints decodes."""
    key = os.urandom(32).hex()
    operator = LocalSigner(_secret(9))
    trust = Trust(relay=relay.url, campaign="camp", operator_pubkeys=frozenset({operator.pubkey}),
                  campaign_key=key)
    payload = {"body": "héllo ✓", "kind": "finding", "subject": "", "refs": ["issue:1"],
               "reply_to": None, "key": "k1"}
    python_event = sign_with_secret(unsigned(
        8891, [*trust.tags("bus"), ["i", hashlib.sha256(b"camp\x1fbus\x1fk1").hexdigest()]],
        encode(trust, "message", payload), 1_800_000_000), _secret(9)).to_dict()
    condition = {"condition": "ac-3", "rev": 2, "state": "open", "goal": "Make retries idempotent.",
                 "statement": "A retry after a lost OK creates nothing new.",
                 "next_action": "Reproduce it on main.", "evidence": ["blob:" + "ab" * 32],
                 "rejected_routes": ["closes via 0123456789ab…: flaky (reopen if: green twice)"],
                 "last_decision": "cd" * 32, "last_claim": "ef" * 32}
    claim = {"condition": "ac-3", "condition_rev": 2, "effect": "closes",
             "candidate_digest": "12" * 32, "evidence_refs": ["ci:run/7", "blob:" + "ab" * 32],
             "wave": "", "task": ""}
    decision = {"claim": "34" * 32, "condition": "ac-3", "condition_rev": 2, "outcome": "accepted",
                "reason": "fixture f1 passes", "next_action": "Open the PR.",
                "candidate_digest": "12" * 32, "statement": "", "reopen_if": ""}
    provenance = {"condition": "ac-3", "revision": 2, "state": "open", "head": "aa" * 32,
                  "reviewer": _npub(operator.pubkey), "decision": "a--b", "claim": "none"}
    toml_map = {"schema": "cf.transport/1", "relay": relay.url, "campaign": "camp",
                "operator_pubkeys": [_npub(operator.pubkey)], "group": "retry",
                "campaign_key": key, "reviewer_pubkeys": [_npub(_pub(FRIEND_SK))]}
    parts = [["bus", "ü body", "message", "", ["a"], None], ["inbox", "x", "", "web", None,
                                                             None, None, []]]
    token = cli._encode_invite_token(trust, "bearer-code", member="roland")
    # the topic token the CLI's `topic invite` mints (the protocol slice's wire): the trust
    # names the topic as group and keyring, and the keys travel only in "epochs"
    epoch_key = os.urandom(32).hex()
    topic_bundle = {"schema": "cf.transport/1", "relay": relay.url, "campaign": "camp",
                    "operator_pubkeys": [_npub(operator.pubkey)], "group": "retry",
                    "keyring": "retry", "topic": "retry", "group_code": "nip29-code",
                    "epochs": {"1": epoch_key}, "current": 1, "owner": operator.pubkey,
                    "member": "roland", "code": "relay-code"}
    topic_token = "nm1_" + base64.urlsafe_b64encode(json.dumps(topic_bundle).encode()).rstrip(
        b"=").decode()
    got = node({"scenario": "records", "payload": payload, "python_events": [python_event],
                "trust": {"schema": "cf.transport/1", "relay": relay.url, "campaign": "camp",
                          "operator_pubkeys": [operator.pubkey], "campaign_key": key},
                "condition": condition, "claim": claim, "decision": decision,
                "decision_id": "56" * 32, "provenance": provenance, "toml": toml_map,
                "content_keys": parts, "token": token, "topic_token": topic_token})
    assert got["decoded"] == [{k: v for k, v in payload.items()}]
    # the page's ciphertext opens under Python's conversation key, to the same envelope
    opened = json.loads(nip44.decrypt(got["encoded"], trust.conversation_key))
    assert opened == {**payload, "schema": "cf.campaign/1", "type": "message", "campaign": "camp"}
    assert got["content_keys"] == [cli._content_key(*p) for p in parts]
    cli._write_trust_file(tmp_path / "nostr.toml", toml_map)
    assert got["toml"] == (tmp_path / "nostr.toml").read_text()
    python_condition = Condition.from_payload(condition)
    assert got["handoff"] == python_condition.handoff().render(provenance)
    moved = python_condition.after(Claim.from_payload(claim), Decision.from_payload(decision),
                                   "56" * 32)
    assert got["after"] == moved.to_payload()
    assert got["token"] == {"code": "bearer-code", "member": "roland", "relay": relay.url,
                            "campaign": "camp", "operators": [operator.pubkey],
                            "campaign_key": key}
    assert got["topic_token"] == {
        "code": "relay-code", "member": "roland", "group": "retry", "keyring": "retry",
        "campaign_key": None, "extras": {"topic": "retry", "group_code": "nip29-code",
                                         "epochs": {"1": epoch_key}, "current": 1,
                                         "owner": operator.pubkey}}
    assert got["constants"] == {
        "MAX_EVENT_BYTES": MAX_EVENT_BYTES, "PAGE_LIMIT": relay_mod.PAGE_LIMIT,
        "LIVE_LIMIT": relay_mod.LIVE_LIMIT, "DEFAULT_WAIT_S": event_mod.DEFAULT_WAIT_S,
        "AUTH_TTL_S": blossom.AUTH_TTL_S, "COMPACTION_MAX_ITEMS": backend.COMPACTION_MAX_ITEMS,
        "COMPACTION_MAX_AGE_HOURS": backend.COMPACTION_MAX_AGE_HOURS,
        "EXTENDED_PREFIX_THRESHOLD": nip44.EXTENDED_PREFIX_THRESHOLD}
    for kind in Kind:
        assert got["kinds"][kind.name] == int(kind), kind
    assert (got["kinds"]["AUTH"], got["kinds"]["BLOSSOM_AUTH"], got["kinds"]["INVITE_CLAIM"],
            got["kinds"]["KEYRING"], got["kinds"]["GIFT_WRAP"]) == (
        ui.AUTH_KIND, ui.BLOSSOM_AUTH_KIND, ui.INVITE_CLAIM_KIND, ui.KEYRING_KIND, ui.GIFT_WRAP)


# ============================================================== bridge: the door
def test_the_bridge_listens_on_loopback_only_and_turns_away_foreign_requests(workstation):
    """Every API call needs this run's token and this console's Host; a write needs JSON
    and, when it names one, this console's Origin. A non-loopback bind is refused."""
    with pytest.raises(ui.Refused, match="not a loopback address"):
        ui.ConsoleServer(workstation.console, host="0.0.0.0", port=0)
    assert "missing or wrong" in call(workstation, "GET", "/api/state", token=None,
                                      want=403)["error"]
    assert "missing or wrong" in call(workstation, "GET", "/api/state", token="guess",
                                      want=403)["error"]
    rebound = call(workstation, "GET", "/api/state", host="evil.example:80", want=403)
    assert "is not this console" in rebound["error"]
    page = call(workstation, "GET", "/", token=None, host="evil.example", want=403)
    assert "Host" in page["error"]
    crossed = call(workstation, "POST", "/api/sign", {"event": {}},
                   headers={"Origin": "https://evil.example"}, want=403)
    assert "Origin" in crossed["error"]
    sited = call(workstation, "POST", "/api/sign", {"event": {}},
                 headers={"Sec-Fetch-Site": "cross-site"}, want=403)
    assert "cross-site" in sited["error"]
    form = call(workstation, "POST", "/api/sign", raw=b"event=1",
                headers={"Content-Type": "application/x-www-form-urlencoded"}, want=400)
    assert "send JSON" in form["error"]
    padded = b"{" + b" " * (ui.MAX_REQUEST_BYTES + 1) + b"}"
    big = call(workstation, "POST", "/api/post", raw=padded,
               headers={"Content-Type": "application/json"}, want=400)
    assert "at most" in big["error"]
    state = call(workstation, "GET", "/api/state")
    assert state["identity"]["pubkey"] == workstation.pubkey and "nsec" not in json.dumps(state)
    assert state["trust"]["campaign_key"] == workstation.campaign_key
    assert state["role"] == "operator" and state["capabilities"] == {
        "nip44": True, "invite": False, "join": False}


def test_the_bridge_signs_inside_the_signer_policy_and_opens_nip44(workstation, relay):
    """/api/sign is SignerServer's policy: allowed kinds for this key's role, NIP-42 for
    the pinned relay only, Blossom for the campaign's server only. /api/nip44 is the
    NIP-07 pair on the 0600 key."""
    stamp = int(time.time())
    ok = call(workstation, "POST", "/api/sign", {"event": {
        "created_at": stamp, "kind": 22242, "tags": [["relay", relay.url], ["challenge", "c"]],
        "content": ""}})["event"]
    assert verify_event(ok).pubkey == workstation.pubkey
    wrong = call(workstation, "POST", "/api/sign", {"event": {
        "created_at": stamp, "kind": 22242, "tags": [["relay", "wss://elsewhere.example"]],
        "content": ""}}, want=403)
    assert "authenticates to" in wrong["error"]
    blob = call(workstation, "POST", "/api/sign", {"event": {
        "created_at": stamp, "kind": 24242, "tags": [["t", "delete"], ["server",
                                                                     urlsplit(relay.url).netloc]],
        "content": ""}}, want=403)
    assert "blob verbs" in blob["error"]
    outside = call(workstation, "POST", "/api/sign", {"event": {
        "created_at": stamp, "kind": 1, "tags": [], "content": "a public note"}}, want=403)
    assert "allow list" in outside["error"]
    for kind in (9007, 1059, 13, 4410, int(Kind.DIRECTIVE), int(Kind.SEAL)):    # operator role
        signed = call(workstation, "POST", "/api/sign", {"event": {
            "created_at": stamp, "kind": kind, "tags": [], "content": ""}})["event"]
        assert signed["kind"] == kind
    peer = _pub(FRIEND_SK)
    sealed = call(workstation, "POST", "/api/nip44", {"op": "encrypt", "peer": _npub(peer),
                                                      "plaintext": "for you"})["result"]
    conv = nip44.conversation_key(FRIEND_SK, bytes.fromhex(workstation.pubkey))
    assert nip44.decrypt(sealed, conv) == "for you"
    back = nip44.encrypt("and back", conv)
    assert call(workstation, "POST", "/api/nip44", {"op": "decrypt", "peer": peer,
                                                    "payload": back})["result"] == "and back"
    assert "invalid MAC" in call(workstation, "POST", "/api/nip44", {
        "op": "decrypt", "peer": _pub(STRANGER_SK), "payload": back}, want=400)["error"]


def test_bridge_post_ack_and_blobs_keep_the_cli_semantics(workstation, relay):
    """/api/post and /api/ack are the backend's verbs: the CLI's content key (so posting
    twice says it once), the first settlement stands, an inbox pointer is settled only
    with where the work went. Blobs go up and come back through the bridge, digest-checked."""
    first = call(workstation, "POST", "/api/post", {"topic": "bus", "body": "Taking retry.py",
                                                    "kind": "handoff", "refs": ["issue:42"]})
    again = call(workstation, "POST", "/api/post", {"topic": "bus", "body": "Taking retry.py",
                                                    "kind": "handoff", "refs": ["issue:42"]})
    assert first["accepted"] and not first["duplicate"] and first["epoch"] == 1
    assert again["duplicate"] and again["id"] == first["id"]
    assert first["bytes_used"] < MAX_EVENT_BYTES and first["bytes_used_pct"] > 0
    stored = next(e for e in relay.stored() if e.id == first["id"])
    assert stored.values("epoch") == ["1"] and "Taking" not in stored.content
    todo = call(workstation, "POST", "/api/post", {"topic": "inbox", "body": "Look at wave-7",
                                                   "target": "webapp", "doc": "wave-7"})
    assert "handled inbox pointer needs result_ref" in call(
        workstation, "POST", "/api/ack", {"topic": "inbox", "msg_id": todo["id"]},
        want=400)["error"]
    settled = call(workstation, "POST", "/api/ack", {"topic": "inbox", "msg_id": todo["id"],
                                                     "result_ref": "webapp#44"})
    assert settled["acked"][0]["disposition"] == "handled"
    with _session(workstation) as session:
        triage = NostrRelayChannelBackend(session).triage()
        assert triage["unhandled"] == [], "the CLI sees the pointer settled"
        history = [m.body for m in NostrRelayChannelBackend(session).history("bus")]
        assert history == ["Taking retry.py"]
    data = b'{"completed_units": ["s1"]}'
    put = call(workstation, "POST", "/api/blob", raw=data,
               headers={"Content-Type": "application/json"})
    assert put["sha256"] == hashlib.sha256(data).hexdigest()
    body, response = call(workstation, "GET", f"/api/blob/{put['sha256']}")
    assert body == data and response.getheader("X-Digest-Verified") == "sha256"
    relay.blossom.blobs[put["sha256"]] = b"swapped"
    assert "hashing to" in call(workstation, "GET", f"/api/blob/{put['sha256']}",
                                want=502)["error"]


# ===================================================== topics, epochs, history
def _topic_trust(ws, topic: str, epoch: int) -> Trust:
    with _session(ws) as session:
        desk = ui.TopicDesk(session, ws.secret)
        scoped, _ = desk.scope_trust(desk.state(topic), epoch)
    return scoped


@needs_node
def test_python_epoch_history_reaches_the_browser_through_a_gift_wrapped_key_ring(
        node, workstation, relay):
    """The operator writes epoch-1 history through the bridge (a finding, an inbox
    pointer, a condition and a claim, and one record the unchanged CLI wrote with no epoch
    tag at all), then grants a friend Full History. The friend, in the page's engine with a
    fresh key, redeems an invite, opens the kind 1059 key ring and replays all of it, every
    signature verified, every record decrypted with epoch 1."""
    friend = _pub(FRIEND_SK)
    created = call(workstation, "POST", "/api/topic/create", {"topic": "retry",
                                                              "name": "Retry idempotency"})
    assert created["epoch"] == 1
    finding = call(workstation, "POST", "/api/post", {
        "group": "retry", "topic": "bus", "body": "epoch-1 finding: the retry duplicates",
        "kind": "finding"})
    assert (finding["epoch"], finding["group"]) == (1, "retry")
    call(workstation, "POST", "/api/post", {"group": "retry", "topic": "inbox",
                                            "body": "Look at wave-7", "target": "webapp"})
    scoped = _topic_trust(workstation, "retry", 1)
    with CampaignSession(scoped, LocalSigner(workstation.secret), timeout_s=WAIT) as plain:
        NostrRelayChannelBackend(plain).post("bus", Message(body="written by the old CLI"),
                                             key="old-cli")      # no epoch tag at all
        condition = Condition(condition="ac-3", rev=1, state="open",
                              goal="Make retries idempotent.",
                              statement="A retry after a lost OK creates nothing new.",
                              next_action="Reproduce it on main.")
        plain.open_condition(condition)
        plain.claim(Claim(condition="ac-3", condition_rev=1, effect="closes",
                          candidate_digest="12" * 32, evidence_refs=("ci:run/7",)))
    untagged = [e for e in relay.stored() if e.kind == 8891 and not e.values("epoch")]
    assert len(untagged) == 1
    # Pair Coding Agent: the exported nostr.toml lets the unchanged CLI read the topic
    exported = call(workstation, "POST", "/api/topic/export", {"topic": "retry"})
    path = Path(exported["trust_file"])
    assert (exported["epoch"], path.name, oct(path.stat().st_mode & 0o777)) == (
        1, "retry-epoch-1.toml", "0o600")
    assert (Trust.load(path).group, Trust.load(path).campaign_key) == ("retry", scoped.campaign_key)
    agent = subprocess.run(
        [sys.executable, "-m", "nostr_mailbox", "--trust", str(path), "--home",
         str(workstation.home), "read", "bus"], capture_output=True, text=True,
        env=_cli_env(), check=False)
    assert agent.returncode == 0, agent.stderr
    assert {m["body"] for m in json.loads(agent.stdout)["messages"]} == {
        "epoch-1 finding: the retry duplicates", "written by the old CLI"}
    grant = call(workstation, "POST", "/api/topic/grant", {
        "topic": "retry", "member": _npub(friend), "mode": "full_history"})
    assert grant["epochs"] == [1] and len(grant["wraps"]) == 1
    wrap = next(e for e in relay.stored() if e.id == grant["wraps"][0])
    assert wrap.kind == 1059 and wrap.values("p") == [friend]
    assert scoped.campaign_key not in wrap.content and "retry" not in wrap.content

    code = relay.create_invite()
    got = node({"scenario": "session", "secret": FRIEND_SK.hex(), "trust": workstation.trust,
                "timeout_s": WAIT, "join": code, "topics": ["retry"]})
    assert got["joined"] == "info: welcome" and friend in relay.members
    assert got["keyrings"] == [{"topic": "retry", "epochs": [1], "granter": workstation.pubkey,
                                "mode": "full_history", "wrap": grant["wraps"][0]}]
    seen = got["scopes"]["retry"]
    assert seen["epochs"] == [1] and seen["members"] == sorted([workstation.pubkey, friend])
    bus = {m["body"]: m["epoch"] for m in seen["topics"]["bus"]["messages"]}
    assert bus == {"epoch-1 finding: the retry duplicates": 1, "written by the old CLI": 1}
    assert seen["triage"] == {"webapp": {"count": 1, "compaction_due": False}}
    assert seen["conditions"][0]["condition"] == "ac-3"
    assert seen["conditions"][0]["handoff"] == condition.handoff().render()
    assert [(c["condition"], c["epoch"]) for c in seen["claims"]] == [("ac-3", 1)]
    assert seen["rejected"] == [] and seen["quarantine"] == []


@needs_node
def test_forward_only_and_revoke_rotate_the_epoch_and_the_gate_holds_late_writes(
        node, workstation, relay):
    """Forward-Only rotates the topic to epoch 2 and hands the newcomer epoch 2 alone:
    epoch-1 history stays sealed to them. The full-history friend follows the rotation.
    A revoke (9001) rotates to epoch 3 without the friend; a message the friend writes
    with the old key after that is held at the human gate, and the operator's page
    (signing through the bridge, its key never leaving the 0600 file) releases it."""
    friend, newcomer = _pub(FRIEND_SK), _pub(NEWCOMER_SK)
    for pk in (friend, newcomer):
        relay.add_member(pk)
    call(workstation, "POST", "/api/topic/create", {"topic": "retry"})
    call(workstation, "POST", "/api/post", {"group": "retry", "topic": "bus",
                                            "body": "before the newcomer"})
    call(workstation, "POST", "/api/topic/grant", {"topic": "retry", "member": friend,
                                                   "mode": "full_history"})
    rotated = call(workstation, "POST", "/api/topic/grant", {"topic": "retry", "member": newcomer,
                                                             "mode": "forward_only"})
    assert rotated["epoch"] == 2 and set(rotated["recipients"]) == {
        _npub(workstation.pubkey), _npub(friend), _npub(newcomer)}
    after = call(workstation, "POST", "/api/post", {"group": "retry", "topic": "bus",
                                                    "body": "after the newcomer"})
    assert after["epoch"] == 2

    late = node({"scenario": "session", "secret": NEWCOMER_SK.hex(), "trust": workstation.trust,
                 "timeout_s": WAIT, "topics": ["retry"]})["scopes"]["retry"]
    assert late["epochs"] == [2]
    assert [m["body"] for m in late["topics"]["bus"]["messages"]] == ["after the newcomer"]
    assert [r["code"] for r in late["rejected"]] == ["epoch"], "epoch 1 stays sealed to them"
    assert "epoch 1 key is not held" in late["rejected"][0]["reason"]

    mine = node({"scenario": "session", "secret": FRIEND_SK.hex(), "trust": workstation.trust,
                 "timeout_s": WAIT, "topics": ["retry"],
                 "ops": [{"op": "post", "scope": "retry", "topic": "bus",
                          "body": "friend, in epoch 2"},
                         {"op": "ack", "scope": "retry", "topic": "bus", "seat": "friend",
                          "msg": after["id"], "disposition": "handled",
                          "result_ref": "webapp#41"}]})
    assert [op.get("error") for op in mine["ops"]] == [None, None]
    assert mine["ops"][0]["ok"]["epoch"] == 2
    seen = mine["scopes"]["retry"]
    assert seen["epochs"] == [1, 2]
    assert sorted((m["body"], m["epoch"]) for m in seen["topics"]["bus"]["messages"]) == [
        ("after the newcomer", 2), ("before the newcomer", 1), ("friend, in epoch 2", 2)]
    with _session(workstation, trust=_topic_trust(workstation, "retry", 2)) as session:
        session.enter(session.trust, 2)
        bodies = [m.body for m in NostrRelayChannelBackend(session).history("bus")]
        assert sorted(bodies) == ["after the newcomer", "friend, in epoch 2"], \
            "Python reads what the page wrote in epoch 2"
        acks = session.records(Kind.ACK, "ack", lambda e, p: p, topic="bus")
        assert [(p["seat"], p["msg_id"], p["result_ref"]) for _, p in acks] == [
            ("friend", after["id"], "webapp#41")]

    _next_second()
    revoked = call(workstation, "POST", "/api/topic/revoke", {"topic": "retry", "member": friend})
    assert revoked["epoch"] == 3 and _npub(friend) not in revoked["recipients"]
    _next_second()
    call(workstation, "POST", "/api/post", {"group": "retry", "topic": "bus",
                                            "body": "epoch 3, without the friend"})
    _next_second()
    gone = node({"scenario": "session", "secret": FRIEND_SK.hex(), "trust": workstation.trust,
                 "timeout_s": WAIT, "topics": ["retry"],
                 "ops": [{"op": "post_in_epoch", "scope": "retry", "topic": "bus", "epoch": 2,
                          "body": "still here, with the old key"}]})
    seen = gone["scopes"]["retry"]
    assert seen["epochs"] == [1, 2] and friend not in seen["members"]
    assert any("epoch 3 key is not held" in r["reason"] for r in seen["rejected"])
    bridge = {"base": workstation.url, "token": workstation.token}
    operator = node({"scenario": "session", "bridge": bridge, "trust": workstation.trust,
                     "timeout_s": WAIT, "topics": ["retry"]})
    assert operator["me"] == workstation.pubkey
    held = operator["scopes"]["retry"]["quarantine"]
    assert [(q["body"], q["why"], q["ruling"]) for q in held] == [
        ("still here, with the old key", "written after this key was revoked", None)]
    released = node({"scenario": "session", "bridge": bridge, "trust": workstation.trust,
                     "timeout_s": WAIT, "topics": ["retry"],
                     "ops": [{"op": "gate", "scope": "retry", "topic": "bus",
                              "msg": held[0]["id"], "approve": True}]})
    assert released["ops"][0].get("error") is None
    view = released["scopes"]["retry"]
    assert view["quarantine"] == []
    released_flags = {m["body"]: m["released"] for m in view["topics"]["bus"]["messages"]}
    assert released_flags["still here, with the old key"] is True
    assert released_flags["epoch 3, without the friend"] is False
    gate = [a for a in view["topics"]["bus"]["acks"] if a["seat"] == "human-gate"]
    assert gate == [{"msg_id": held[0]["id"], "seat": "human-gate", "disposition": "handled",
                     "author": workstation.pubkey, "result_ref": None, "epoch": 2}], \
        "the ruling is written in the epoch of the message it rules on"


@needs_node
def test_a_topic_made_in_the_browser_is_read_and_answered_by_python(node, workstation, relay):
    """The page creates a topic (9007 + a key ring wrapped to itself), posts, and grants
    the operator full history. Python opens the page's gift wrap, reads the page's
    message, and answers; the page reads the answer."""
    relay.add_member(_pub(FRIEND_SK))
    made = node({"scenario": "session", "secret": FRIEND_SK.hex(), "trust": workstation.trust,
                 "timeout_s": WAIT, "topics": ["js-topic"],
                 "ops": [{"op": "create", "topic": "js-topic", "name": "Made in the page"},
                         {"op": "post", "scope": "js-topic", "topic": "bus",
                          "body": "hello from the page", "kind": "question"},
                         {"op": "grant", "scope": "js-topic", "member": workstation.pubkey,
                          "mode": "full_history"},
                         {"op": "create", "topic": "js-topic"}]})
    assert [op.get("error") for op in made["ops"][:3]] == [None, None, None]
    assert "already exists" in made["ops"][3]["error"]
    topics = call(workstation, "GET", "/api/topics")["topics"]
    assert [(t["topic"], t["name"], t["epochs"], t["creator"]) for t in topics] == [
        ("js-topic", "Made in the page", [1], _npub(_pub(FRIEND_SK)))]
    with _session(workstation) as session:
        desk = ui.TopicDesk(session, workstation.secret)
        state = desk.state("js-topic")
        assert not [k for k in state.epochs.values() if k in json.dumps(topics)], \
            "/api/topics never hands an epoch key to the page"
        session.enter(*desk.scope_trust(state))
        channel = NostrRelayChannelBackend(session)
        question = next(iter(channel.history("bus")))
        assert (question.body, question.kind) == ("hello from the page", "question")
        channel.post("bus", Message(body="answered by Python", kind="answer",
                                    reply_to=question.id), key="answer-1")
    read = node({"scenario": "session", "secret": FRIEND_SK.hex(), "trust": workstation.trust,
                 "timeout_s": WAIT, "topics": ["js-topic"]})
    bus = read["scopes"]["js-topic"]["topics"]["bus"]["messages"]
    assert {(m["body"], m["author"]) for m in bus} == {
        ("hello from the page", _pub(FRIEND_SK)), ("answered by Python", workstation.pubkey)}


@needs_node
def test_join_requests_are_approved_with_a_history_choice_or_declined(node, workstation, relay):
    """A member who only holds the topic link asks with kind 9021; the admin sees the
    pending request in the page and approves Forward-Only, or declines (9005) and the
    request leaves the list. A key ring from a key that is not the topic's admin is
    never used."""
    friend, stranger = _pub(FRIEND_SK), _pub(STRANGER_SK)
    for pk in (friend, stranger):
        relay.add_member(pk)
    call(workstation, "POST", "/api/topic/create", {"topic": "ops"})
    for secret, why in ((FRIEND_SK, "reviewing the fix"), (STRANGER_SK, "curious")):
        asked = node({"scenario": "session", "secret": secret.hex(), "trust": workstation.trust,
                      "timeout_s": WAIT, "topics": ["ops"],
                      "ops": [{"op": "request", "topic": "ops", "reason": why}]})
        assert asked["scopes"]["ops"]["nokey"] is True
    bridge = {"base": workstation.url, "token": workstation.token}
    pending = node({"scenario": "session", "bridge": bridge, "trust": workstation.trust,
                    "timeout_s": WAIT, "topics": ["ops"]})["scopes"]["ops"]["requests"]
    assert {(r["pubkey"], r["reason"]) for r in pending} == {(friend, "reviewing the fix"),
                                                             (stranger, "curious")}
    declined = next(r["id"] for r in pending if r["pubkey"] == stranger)
    ruled = node({"scenario": "session", "bridge": bridge, "trust": workstation.trust,
                  "timeout_s": WAIT, "topics": ["ops"],
                  "ops": [{"op": "grant", "scope": "ops", "member": friend,
                           "mode": "forward_only"},
                          {"op": "decline", "scope": "ops", "request": declined}]})
    assert [op.get("error") for op in ruled["ops"]] == [None, None]
    assert ruled["ops"][0]["ok"]["epoch"] == 2
    assert ruled["scopes"]["ops"]["requests"] == [], "approved and declined both leave the list"
    # a key ring sent by a member who is not the topic's admin opens, and is not used
    trust = Trust.load(workstation.home / "nostr.toml")
    with ui.TopicSession(trust, LocalSigner(STRANGER_SK), timeout_s=WAIT) as rogue_session:
        rogue = ui.gift_wrap(rogue_session, STRANGER_SK, friend, ui.KEYRING_KIND,
                             [["h", "ops"], ["t", "camp"]],
                             ui.keyring_content("camp", "ops", "ops", {9: "77" * 32}, 9, "rotate"))
        rogue_session.relay.publish(rogue)
    friend_view = node({"scenario": "session", "secret": FRIEND_SK.hex(),
                        "trust": workstation.trust, "timeout_s": WAIT, "topics": ["ops"]})
    assert {(k["granter"], tuple(k["epochs"])) for k in friend_view["keyrings"]} == {
        (workstation.pubkey, (2,)), (stranger, (9,))}
    assert friend_view["scopes"]["ops"]["epochs"] == [2], "only the admin's ring counts"


@needs_node
def test_the_bridge_mints_an_invite_the_browser_engine_redeems(node, workstation, relay, tmp_path):
    """/api/invite runs the relay admin saved in admin.json and returns an nm1_ token and
    a web link that keeps it in the URL fragment. The page's engine redeems that very
    token on the relay (NIP-43) with a key of its own."""
    assert "no " in call(workstation, "POST", "/api/invite", {}, want=409)["error"]
    code = relay.create_invite()
    stamp = int(time.time())
    admin = tmp_path / "ncli.sh"           # stands where `kubectl exec … --` does
    admin.write_text("printf '%s' '" + json.dumps({
        "code": code, "created_at": stamp, "expires_at": stamp + 7 * 24 * 3600,
        "max_uses": 1, "uses": 0}) + "'\n")
    (workstation.home / "admin.json").write_text(json.dumps({"exec_prefix": ["/bin/sh",
                                                                             str(admin)]}))
    minted = call(workstation, "POST", "/api/invite", {"member": "roland", "topic": "retry"})
    assert minted["token"].startswith("nm1_") and minted["max_uses"] == 1
    host = urlsplit(relay.url).netloc
    assert minted["web_link"] == f"http://{host}/#join={minted['token']}&topic=retry"
    joined = node({"scenario": "session", "secret": NEWCOMER_SK.hex(),
                   "trust": workstation.trust, "timeout_s": WAIT,
                   "join": cli._decode_invite_token(minted["token"])[0], "topics": []})
    assert joined["joined"] == "info: welcome" and _pub(NEWCOMER_SK) in relay.members


def test_the_bridge_joins_a_fresh_workstation_from_a_token(tmp_path, relay):
    """A workstation with no campaign joins from the page: the key is created 0600, the
    nostr.toml written, the invite redeemed, and the bridge starts serving that campaign.
    It refuses to join over an existing campaign."""
    operator = LocalSigner(_secret(9))
    relay.add_member(operator.pubkey)
    trust = Trust(relay=relay.url, campaign="camp", operator_pubkeys=frozenset({operator.pubkey}),
                  campaign_key=os.urandom(32).hex())
    token = cli._encode_invite_token(trust, relay.create_invite(), member="roland")
    console = ui.Console(base=tmp_path / "fresh", timeout_s=WAIT, quiet=True)
    with ui.ConsoleServer(console, port=0) as server:
        ws = SimpleNamespace(url=server.url, token=console.token)
        state = call(ws, "GET", "/api/state")
        assert state["identity"] is None and state["trust"] is None
        assert state["capabilities"]["join"] is True
        joined = call(ws, "POST", "/api/join", {"token": token, "member": "roland"})
        assert joined["campaign"] == "camp" and joined["member"] == "roland"
        assert "installed" not in joined, "the page never installs plugins"
        state = call(ws, "GET", "/api/state")
        assert state["trust"]["campaign_key"] == trust.campaign_key
        assert state["identity"]["pubkey"] in relay.members
        key_file = tmp_path / "fresh/identities/default.json"
        assert oct(key_file.stat().st_mode & 0o777) == "0o600"
        assert "already has a campaign" in call(ws, "POST", "/api/join", {"token": token},
                                                want=403)["error"]


# ================================================================== mailboxes
def _py_mail(sender_sk: bytes, owner: str, part: str, body: str, campaign: str) -> dict:
    """A kind 4410 envelope built straight from the agent-mailbox wire description, with
    Python's own primitives: the cross-check for the page's `buildMail` / `openMail`."""
    sender = secp256k1.pubkey_gen(sender_sk).hex()
    nonce = os.urandom(16).hex()
    thread = hashlib.sha256(b"agent-mailbox/thread/v1" + bytes.fromhex(owner)
                            + bytes.fromhex(sender) + bytes.fromhex(nonce)
                            + part.encode("ascii")).digest()[:16].hex()
    route = [["mbx", owner], ["p", owner], ["part", part], ["thread", thread], ["msg", thread]]
    seal = sign_with_secret(unsigned(4412, [*route, ["k", "4410"]], json.dumps(
        {"v": 1, "subject": "from Python", "body": body, "attachments": []}),
        int(time.time())), sender_sk)
    conv = nip44.conversation_key(sender_sk, bytes.fromhex(owner))
    return sign_with_secret(unsigned(4410, [*route, ["t", f"{campaign}:dropbox"],
                                            ["opener", sender, nonce]],
                                     nip44.encrypt(dumps(seal.to_dict()), conv),
                                     int(time.time())), sender_sk).to_dict()


@needs_node
def test_mailbox_envelopes_interoperate_and_ungranted_mail_stays_sealed(node, workstation, relay):
    """The kind 4410 envelope: Python seals one, the page opens it and checks its thread
    commitment; the page seals one, Python opens it. In the owner's mailbox, mail from a
    key with no grant is held and never decrypted; mail under a human_gated grant is
    held for preview until the owner's human-gate ack releases it."""
    owner, peer = _pub(FRIEND_SK), _pub(PEER_SK)
    good = _py_mail(PEER_SK, owner, "inbox", "sealed in Python", "camp")
    bent = dict(good, tags=[t if t[0] != "thread" else ["thread", "00" * 16] for t in good["tags"]])
    bent = sign_with_secret(unsigned(4410, bent["tags"], bent["content"], bent["created_at"]),
                            PEER_SK).to_dict()
    got = node({"scenario": "mail", "secret": FRIEND_SK.hex(), "envelopes": [good, bent],
                "owner": peer, "campaign": "camp", "body": "sealed in the page",
                "commit": {"owner": owner, "opener": peer, "nonce": "ab" * 16, "part": "inbox"}})
    assert got["opened"][0] == {"ok": True, "signed_by": peer, "thread": good["tags"][3][1],
                                "body": {"v": 1, "subject": "from Python",
                                         "body": "sealed in Python", "attachments": []}}
    assert not got["opened"][1]["ok"] and "commitment" in got["opened"][1]["error"]
    assert got["commit"] == hashlib.sha256(
        b"agent-mailbox/thread/v1" + bytes.fromhex(owner) + bytes.fromhex(peer)
        + bytes.fromhex("ab" * 16) + b"inbox").digest()[:16].hex()
    made = verify_event(got["made"])
    seal = verify_event(json.loads(nip44.decrypt(
        made.content, nip44.conversation_key(PEER_SK, bytes.fromhex(owner)))))
    assert (seal.kind, json.loads(seal.content)["body"]) == (4412, "sealed in the page")
    assert seal.values("k") == ["4410"] and made.values("msg") == made.values("thread")

    for pk in (owner, peer, _pub(STRANGER_SK)):
        relay.add_member(pk)
    trust = workstation.trust
    node({"scenario": "session", "secret": FRIEND_SK.hex(), "trust": trust, "timeout_s": WAIT,
          "ops": [{"op": "mail_grant", "peer": peer, "trust": "human_gated"}]})
    for secret, words in ((PEER_SK, "granted, gated"), (STRANGER_SK, "no grant at all")):
        sent = node({"scenario": "session", "secret": secret.hex(), "trust": trust,
                     "timeout_s": WAIT, "ops": [{"op": "mail", "owner": owner, "body": words,
                                                 "subject": "hi"}]})
        assert sent["ops"][0].get("error") is None
    box = node({"scenario": "session", "secret": FRIEND_SK.hex(), "trust": trust,
                "timeout_s": WAIT, "root": True, "mailbox": True})["mailbox"]
    assert box["items"] == []
    held = {m["from"]: m for m in box["held"]}
    assert held[_pub(STRANGER_SK)]["body"] is None and not held[_pub(STRANGER_SK)]["granted"]
    assert held[peer]["body"]["body"] == "granted, gated" and held[peer]["granted"]
    released = node({"scenario": "session", "secret": FRIEND_SK.hex(), "trust": trust,
                     "timeout_s": WAIT, "root": True, "mailbox": True,
                     "ops": [{"op": "mail_gate", "msg": held[peer]["id"], "approve": True}]})
    assert released["ops"][0].get("error") is None
    box = released["mailbox"]
    assert [(m["body"]["body"], m["released"]) for m in box["items"]] == [("granted, gated", True)]
    assert [m["from"] for m in box["held"]] == [_pub(STRANGER_SK)]
    ack = released["scopes"][""]["topics"]["dropbox"]["acks"]
    assert ack == [{"msg_id": held[peer]["id"], "seat": "human-gate", "disposition": "handled",
                    "author": owner, "result_ref": None, "epoch": 1}]
    answered = node({"scenario": "session", "secret": FRIEND_SK.hex(), "trust": trust,
                     "timeout_s": WAIT, "root": True,
                     "ops": [{"op": "receipt", "msg": held[peer]["id"], "status": "resolved"},
                             {"op": "reply", "msg": held[peer]["id"], "body": "thanks"}]})
    assert [op.get("error") for op in answered["ops"]] == [None, None]
    seen = node({"scenario": "session", "secret": PEER_SK.hex(), "trust": trust,
                 "timeout_s": WAIT, "root": True, "mailbox": True})["mailbox"]
    assert [m["body"]["status"] for m in seen["receipts"]] == ["resolved"]
    replies = [m for m in seen["items"] if not m["outgoing"]]
    assert [(m["body"]["body"], m["thread"]) for m in replies] == [
        ("thanks", held[peer]["thread"])], "a reply stays in the opener's thread"


# ===================================================================== the CLI
def test_nostr_mailbox_ui_serves_the_console_and_refuses_a_public_bind(workstation):
    """`nostr-mailbox ui` (the real CLI, a real process) prints one JSON line when it is
    up, serves the page, and stops on Ctrl-C. A non-loopback --host exits 1."""
    env = _cli_env()
    base = [sys.executable, "-m", "nostr_mailbox", "--home", str(workstation.home), "ui"]
    refused = subprocess.run([*base, "--host", "0.0.0.0", "--port", "0"], env=env,
                             capture_output=True, text=True, timeout=WAIT)
    assert refused.returncode == 1 and "not a loopback address" in refused.stderr
    proc = subprocess.Popen([*base, "--port", "0"], env=env, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True)
    try:
        up = json.loads(proc.stdout.readline())
        assert up["npub"] == workstation.ident.npub and up["campaign"] == "camp"
        parts = urlsplit(up["serving"])
        conn = http.client.HTTPConnection(parts.hostname, parts.port, timeout=WAIT)
        conn.request("GET", "/")
        response = conn.getresponse()
        page = response.read().decode()
        conn.close()
        assert response.status == 200 and "nostr-mailbox · Web Console" in page
        assert re.search(r'<meta name="nm-bridge" content="[A-Za-z0-9_-]{43}">', page)
    finally:
        proc.send_signal(signal.SIGINT)
        stdout, stderr = proc.communicate(timeout=WAIT)
    assert proc.returncode == 0, stderr
    assert json.loads(stdout)["stopped"] == up["serving"]
