"""Witnesses for the Visual Web Console: the protocol engine inside `web/index.html`, and
the workstation bridge `ui.py` that serves it.

Nothing here is mocked. The engine is lifted verbatim out of the page and run under
Node.js (tests/web_ui_harness.mjs); it talks to `LoopbackRelay` over a real WebSocket,
and to the bridge over real HTTP, exactly as a browser tab does. The bridge is a real
server on a loopback port, signing with a real 0600 identity file. The one stand-in is
the relay's admin CLI for `/api/invite`: a recording program on a real subprocess
boundary, as in test_nostr_mailbox.py. That `ncli` itself mints such invites is
witnessed by test_nostr_ncli.py against the real binary.

The standalone sign-in and lock witnesses drive headless Chromium against the same
loopback relay, through the actual forms, session storage and WebSocket."""
import base64
import hashlib
import hmac
import http.client
import json
import os
import re
import shlex
import shutil
import signal
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlsplit
from urllib.request import urlopen

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
    loopback,
    nip44,
    secp256k1,
    ui,
    ws,
)
from nostr_mailbox import event as event_mod
from nostr_mailbox import relay as relay_mod
from nostr_mailbox.event import dumps, sign_with_secret, unsigned, verify_event
from nostr_mailbox.identity import create_identity, load_identity
from nostr_mailbox.profile import MAX_EVENT_BYTES, EpochKeys, Kind, decrypt_record, encode

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
# The AWOW.io design system crosswire.sh's console is drawn in: its light tokens, and
# the dark ones under both the ◐ toggle and the system's preference.
LIGHT = {"bg": "#faf9f6", "panel": "#faf9f6", "ink": "#16181d", "muted": "#5a5d64",
         "line": "#e4e1da", "soft": "#f0eee9", "accent": "#35547a", "green": "#4a6b53",
         "red": "#8c3843", "amber": "#78683a", "head": "#f0eee9", "hover": "#e8eef0",
         "shadow": "0 16px 70px #16181d1f", "violet": "#6d4c5c",
         "paper": "#faf9f6", "stone": "#f0eee9", "rule": "#e4e1da", "rule-strong": "#c9c4b9",
         "teal": "#3f5e63", "terracotta": "#35547a", "terracotta-ink": "#263f5d",
         "sage": "#4a6b53", "ancient-bg": "#14171c", "ancient-surface": "#1c2027",
         "ancient-ink": "#e8eaed", "ancient-rule": "#2b313a"}
DARK = {"bg": "#14171c", "panel": "#1c2027", "ink": "#e8eaed", "muted": "#a9b0bc",
        "line": "#2b313a", "soft": "#222730", "accent": "#8fa8c4", "green": "#8fae95",
        "red": "#e08b94", "amber": "#b8ab84", "head": "#1c2027", "hover": "#252c37",
        "shadow": "0 16px 70px #0008", "violet": "#b89aa8"}


def test_the_page_is_one_self_contained_full_width_html_file():
    """One file that runs from the relay's origin or from loopback with nothing fetched:
    no external URL, no script or stylesheet by reference, no font or CDN. Full width:
    the page wrapper and `main` span the viewport behind fluid gutters, and no
    declaration caps a width with a fixed length. Drawn in the AWOW.io design
    system: its tokens in both themes, its type, a 61px header with the crosswire.sh
    wordmark, and a ◐ toggle that flips <html data-theme>."""
    page = PAGE.read_text()
    assert page.startswith("<!doctype html>\n<html lang=\"en\"")
    for needed in ('<meta charset="utf-8">',
                   '<meta name="viewport" content="width=device-width, initial-scale=1">',
                   "<title>nostr-mailbox · Web Console</title>", "<body>", "</html>",
                   '<meta name="nm-bridge" content="">',
                   'href="https://github.com/awowIO/crosswire"',
                   'href="https://maywe.email"',
                   'https://newsletter.awow.io/v1/subscribe'):
        assert needed in page, needed
    # The only absolute URLs: the two repositories, MayWe (its site, its subscribe endpoint and
    # the two origins its publishable keys belong to), and crosswire.sh's own addresses.
    assert set(re.findall(r"(?:https?|wss?)://[a-z0-9./_-]+", page, re.I)) == {
        "https://github.com/awowIO/crosswire", "https://github.com/awowIO/nostr-relay-deploy",
        "https://maywe.email",
        "https://newsletter.awow.io/v1/subscribe", "https://docs.awow.io",
        "https://crosswire.sh", "https://crosswire.sh/join/", "wss://crosswire.sh"}
    assert not re.search(r"<script[^>]+\bsrc=|<link[^>]+stylesheet", page, re.I)
    assert not re.search(r"""(?:src|href)\s*=\s*["']//""", page), "no protocol-relative URL"
    style = re.search(r"<style>(.*?)</style>", page, re.S).group(1)
    assert not re.search(r"@import|url\(|@font-face", style), "no font, image or sheet fetched"
    assert re.search(r"\.page \{[^}]*width: 100%; max-width: none; "
                     r"padding-inline: clamp\(20px, 3vw, 48px\);", style)
    assert re.search(r"(?m)^main \{[^}]*width: 100%; max-width: none;", style)
    caps = re.findall(r"max-width\s*:\s*([^;}\n]+)", style)
    assert caps and all(value.strip() in ("none", "100%") for value in caps), caps
    assert "@media (max-width" not in style, "breakpoints use range syntax, never a max-width"
    flat = re.sub(r"\s+", "", style)
    for selector, tokens in ((":root", LIGHT), (':root[data-theme="dark"]', DARK),
                             ('@media(prefers-color-scheme:dark){:root:not([data-theme="light"])',
                              DARK)):
        block = re.search(re.escape(selector) + r"\{([^}]*)\}", flat)
        assert block, selector
        held = set(block.group(1).split(";"))
        for name, value in tokens.items():
            assert f"--{name}:{value.replace(' ', '')}" in held, (selector, name)
    assert ('font: 13px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif'
            in style)
    assert "ui-monospace, SFMono-Regular, Consolas, monospace" in style
    assert "font-variant-numeric: tabular-nums" in style
    assert re.search(r"\.top \{[^}]*height: 61px;[^}]*border-bottom: 1px solid var\(--line\);"
                     r"[^}]*background: var\(--panel\);", style)
    assert '<span class="mark" aria-hidden="true">⨉</span> crosswire.sh</a>' in page
    assert '<button id="theme"' in page and 'aria-label="Switch color theme">◐</button>' in page
    assert "document.documentElement.dataset.theme = next" in page
    assert not re.search(r"""\son(?:click|load|error|submit|change|input|mouse\w*|key\w*)=["']""",
                         page, re.I), "no inline handlers: the bridge's CSP admits two scripts"
    assert "javascript:" not in page.lower()


def test_readme_and_console_maps_share_the_same_artwork():
    def artwork(source):
        # A standalone SVG has its own namespace and theme. The drawing is shared.
        return [(node.tag.split("}")[-1], node.attrib, (node.text or "").strip())
                for node in ET.fromstring(source).iter() if not node.tag.endswith("style")]

    maps = re.findall(r'<div class="diagram-box"[^>]*>(<svg\b.*?</svg>)', PAGE.read_text(), re.S)
    for drawing, name in zip(maps, ("enrollment-flow", "architecture-map"), strict=True):
        assert artwork(drawing) == artwork((REPO / "docs" / f"{name}.svg").read_text())


def test_the_page_links_its_repository_and_asks_for_invites_on_maywe():
    """The header and the footer link the repository, the footer MayWe. The entry column
    offers sign-in or single-click admission with a token or join link, followed by a
    waitlist request to MayWe's public subscribe with the publishable key of the origin
    it runs on, a honeypot, an optional use case in `details`, and a confirmation banner.

    What this cannot show: that MayWe takes the request. No test here posts to MayWe,
    as each request mails a real confirmation; the field names are read off its
    subscribe route (newsletter app/routes/subscribe.py)."""
    page = PAGE.read_text()
    repo = ('<a class="btn tiny ghost" href="https://github.com/awowIO/crosswire" '
            'target="_blank" rel="noopener noreferrer"')
    header = re.search(r'<header class="top page">.*?</header>', page, re.S).group(0)
    assert repo in header and "GitHub · awowIO/crosswire ↗</a>" in header
    footer = re.search(r'<footer class="foot page">.*?</footer>', page, re.S).group(0)
    assert '<a href="https://github.com/awowIO/crosswire"' in footer
    assert '<a href="https://maywe.email"' in footer
    assert "01 · Already invited — Open your room" in page
    assert "02 · Request an invite — Waitlist via MayWe" in page
    assert page.count('placeholder="nm1_… or https://crosswire.sh/join/#nm1_…"') == 2
    card = re.search(r"function mayweInviteCard\(\) \{.*?\n  \}\n", page, re.S).group(0)
    for needed in ('<form data-form="maywe-invite"', 'name="email" type="email" required',
                   'name="note" maxlength="500"', 'name="website" tabindex="-1"',
                   'role="status"', "Request Invite →"):
        assert needed in card, needed
    keys = re.search(r"const MAYWE_KEYS = Object\.freeze\(\{(.*?)\}\);", page, re.S).group(1)
    assert re.findall(r"'([^']+)': '([^']+)'", keys) == [
        ("https://crosswire.sh", "pk_G-LEI15eUfTnYhGyV2hMHvRsxMsJwkM4r-wgj3jS2jI"),
        ("https://docs.awow.io", "pk_6ZNZP0jBeKTpu22jfUQfQ6Dhcu6faq7iSzeEJsMMy78")]
    send = re.search(r"async 'maywe-invite'\(f, el\) \{.*?\n    \},\n", page, re.S).group(0)
    for needed in ("new URLSearchParams({ key, email, source: 'crosswire:invite-request', "
                   "website: f.website || '' })",
                   "body.set('details', JSON.stringify({ use_case: note }))",
                   "fetch(MAYWE_SUBSCRIBE_URL, { method: 'POST', body })",
                   "S.mayweSent = email"):
        assert needed in send, needed


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
        orig_tags = scoped.tags
        object.__setattr__(scoped, "tags",
                           lambda topic=None: [t for t in orig_tags(topic) if t[0] != "epoch"])
        NostrRelayChannelBackend(plain).post("bus", Message(body="written by the old CLI"),
                                             key="old-cli")      # no epoch tag at all
        object.__setattr__(scoped, "tags", orig_tags)
        condition = Condition(condition="ac-3", rev=1, state="open",
                              goal="Make retries idempotent.",
                              statement="A retry after a lost OK creates nothing new.",
                              next_action="Reproduce it on main.")
        plain.open_condition(condition)
        plain.claim(Claim(condition="ac-3", condition_rev=1, effect="closes",
                          candidate_digest="12" * 32, evidence_refs=("ci:run/7",)))
    untagged = [e for e in relay.stored() if e.kind == 8891 and not e.values("epoch")]
    assert len(untagged) == 1
    # Pair Coding Agent: the topic's declaration and this persona's own keyring let the
    # unchanged CLI read the topic, with the command prefix the bridge names
    exported = call(workstation, "POST", "/api/topic/export", {"topic": "retry"})
    path, ring = Path(exported["trust_file"]), Path(exported["keyring"])
    assert (exported["epoch"], exported["epochs"]) == (1, [1])
    assert path == workstation.home / "topics/retry.toml"
    assert ring == workstation.home / "keyrings/default/retry.json"
    assert oct(path.stat().st_mode & 0o777) == oct(ring.stat().st_mode & 0o777) == "0o600"
    declared = Trust.load(path)
    assert (declared.group, declared.keyring, declared.campaign_key) == ("retry", "retry", None)
    assert json.loads(ring.read_text())["epochs"] == {"1": scoped.campaign_key}
    assert exported["cli"] == shlex.join(["nostr-mailbox", "--home", str(workstation.home),
                                          "--topic", "retry"])
    agent = subprocess.run(
        [sys.executable, "-m", "nostr_mailbox", *shlex.split(exported["cli"])[1:], "read",
         "bus"], capture_output=True, text=True, env=_cli_env(), check=False)
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
    # Even if a relay did not enforce NIP-29 private/restricted after 9001, the client's
    # second gate holds: epoch 3 is undecryptable to friend, and friend's write with the
    # old epoch-2 key is quarantined until the operator approves it.
    if "retry" in relay.groups:
        relay.groups["retry"].private = relay.groups["retry"].restricted = False
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
    assert "campaign_key" not in cli._decode_invite_token(minted["token"])[1], \
        "an invite that names a topic declares the topic, not the campaign's key"
    whole = call(workstation, "POST", "/api/invite", {"member": "roland"})
    assert cli._decode_invite_token(whole["token"])[1]["campaign_key"] == workstation.campaign_key
    joined = node({"scenario": "session", "secret": NEWCOMER_SK.hex(),
                   "trust": workstation.trust, "timeout_s": WAIT,
                   "join": cli._decode_invite_token(minted["token"])[0], "topics": []})
    assert joined["joined"] == "info: welcome" and _pub(NEWCOMER_SK) in relay.members


@needs_node
def test_a_member_mints_an_invite_in_the_browser_that_the_cli_reads_and_a_newcomer_redeems(
        node, tmp_path):
    """Standalone, any admitted member mints a campaign invite in the tab: one NIP-43
    request (kind 28935) on its own socket, wrapped in the very nm1_ token and /join/
    link the CLI writes for that campaign and code. A newcomer's engine redeems it once.
    A relay with memberClaims off answers with nothing, and the tab says why."""
    key = os.urandom(32).hex()
    with LoopbackRelay(member_claims=True) as claims:
        claims.add_member(_pub(FRIEND_SK))
        trust = {"schema": "cf.transport/1", "relay": claims.url, "campaign": "camp",
                 "operator_pubkeys": [_npub(_pub(PEER_SK))], "campaign_key": key}
        got = _page_engine(tmp_path, MINT_IN_TAB, {
            "trust": trust, "secret": FRIEND_SK.hex(), "member": "roland", "timeout_s": WAIT})
        code = got["invite"]["code"]
        assert got["invite"]["issued_by"] == claims.pubkey and "28935" in got["invite"]["via"]
        declared = Trust.from_mapping(trust)
        assert got["token"] == cli._encode_invite_token(declared, code, member="roland")
        assert got["join_url"] == cli._join_url(declared, got["token"])
        assert cli._decode_invite_token(got["token"])[:3] == (code, trust, "roland")
        joined = node({"scenario": "session", "secret": NEWCOMER_SK.hex(), "trust": trust,
                       "timeout_s": WAIT, "join": code, "topics": []})
        assert joined["joined"] == "info: welcome" and _pub(NEWCOMER_SK) in claims.members
    with LoopbackRelay() as no_claims:
        no_claims.add_member(_pub(FRIEND_SK))
        refused = _page_engine(tmp_path, MINT_IN_TAB, {
            "trust": {**trust, "relay": no_claims.url}, "secret": FRIEND_SK.hex(),
            "member": None, "timeout_s": WAIT})
        assert "memberClaims is off" in refused["error"]


def test_the_bridge_joins_a_fresh_workstation_from_a_token(tmp_path, relay):
    """A workstation with no campaign joins from the page: the key is created 0600, the
    nostr.toml written, the invite redeemed, and the bridge starts serving that campaign.
    Then a second persona joins that same campaign from a fresh token, leaving nostr.toml
    byte for byte as it was; a token for another campaign is refused before anything is
    sent or written."""
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
        assert joined["persona"] == "default"
        toml = (tmp_path / "fresh/nostr.toml").read_bytes()
        again = call(ws, "POST", "/api/join", {"token": token})
        assert again["relay_said"].startswith("duplicate"), "a member spends nothing"
        call(ws, "POST", "/api/persona", {"name": "alice-work", "create": True})
        second = call(ws, "POST", "/api/join", {
            "token": cli._encode_invite_token(trust, relay.create_invite()), "member": "alice"})
        alice = call(ws, "GET", "/api/state")["identity"]["pubkey"]
        assert second["persona"] == "alice-work" and alice in relay.members
        assert (tmp_path / "fresh/nostr.toml").read_bytes() == toml
        other = Trust(relay=relay.url, campaign="elsewhere",
                      operator_pubkeys=frozenset({operator.pubkey}))
        stored = len(relay.stored())
        refused = call(ws, "POST", "/api/join", {
            "token": cli._encode_invite_token(other, relay.create_invite())}, want=403)
        assert "already has campaign 'camp'" in refused["error"]
        assert "'elsewhere'" in refused["error"] and len(relay.stored()) == stored
        assert (tmp_path / "fresh/nostr.toml").read_bytes() == toml


# ================================================= personas, invite links and roles
def _page_engine(tmp_path, fn: str, data):
    """One call into the page's engine under Node: `fn` is a JavaScript function of
    (NM, input), run on the engine exactly as the page holds it, and awaited. The process
    exits once the answer is written, whatever sockets the engine left open."""
    engine, runner = tmp_path / "engine-fn.js", tmp_path / "engine-fn.mjs"
    engine.write_text(_engine_source())
    runner.write_text(
        "import fs from 'node:fs';\n"
        "new Function(fs.readFileSync(process.argv[2], 'utf8'))();\n"
        "const input = JSON.parse(fs.readFileSync(0, 'utf8'));\n"
        f"const out = await ({fn})(globalThis.NM, input);\n"
        "process.stdout.write(JSON.stringify(out), () => process.exit(0));\n")
    done = subprocess.run([NODE, str(runner), str(engine)], input=json.dumps(data),
                          capture_output=True, text=True, check=False)
    assert done.returncode == 0, f"the engine failed:\n{done.stderr}"
    return json.loads(done.stdout)


READ_LINKS = """(NM, input) => input.map((frag) => {
  try { const link = NM.parseLink(frag);
        if (!link.join) return link;
        return { ...link, campaign: NM.decodeInviteToken(link.join).trust.campaign }; }
  catch (e) { return { error: e.message }; } })"""


MINT_IN_TAB = """async (NM, c) => {
  const trust = NM.makeTrust(c.trust);
  const relay = new NM.RelayClient(trust.relay, new NM.KeySigner(NM.unhex(c.secret)),
                                   { authUrl: trust.relay, timeoutS: c.timeout_s });
  await relay.connect();
  try { const invite = await relay.requestInvite();
        const token = NM.encodeInviteToken(trust, invite.code, c.member);
        return { invite, token, join_url: NM.joinUrl(trust, token) }; }
  catch (e) { if (!(e instanceof NM.NMError)) throw e; return { error: e.message }; } }"""

READ_INPUT = """(NM, input) => input.map((typed) => {
  try { return NM.readInviteInput(typed); } catch (e) { return { error: e.message }; } })"""


@needs_node
def test_the_invite_box_takes_a_bare_token_or_a_join_link(tmp_path, workstation):
    """The console's invite box (the `redeem` form and `bridge-join` action) takes a bare
    nm1_ token or a full join link, and reads from a link the same token the CLI's
    `join <link>` does, with the link's topic, role and ticket. A link with no token, or
    a token that does not decode, is refused there and then."""
    token = cli._encode_invite_token(Trust.load(workstation.home / "nostr.toml"),
                                     "bearer-code", member="roland")
    links = [f"https://crosswire.sh/join/#{token}",
             f"https://crosswire.sh/join/#{token}&topic=retry&role=read-only&ticket=t-1",
             f"http://127.0.0.1:7890/#join={token}&topic=retry"]
    got = _page_engine(tmp_path, READ_INPUT, [
        token, f"  {token}\n", *links, "https://crosswire.sh/join/", "nm1_bm90LWpzb24",
        "#invite=relay-code"])
    assert got[:5] == [
        {"join": token}, {"join": token}, {"join": token},
        {"join": token, "topic": "retry", "role": "read-only", "ticket": "t-1"},
        {"join": token, "topic": "retry"}]
    assert [cli._token_from_link(link) for link in links] == [token] * 3
    assert "nm1_" in got[5]["error"] and "invalid nm1_ invite token" in got[6]["error"]
    assert "nm1_" in got[7]["error"]


@needs_node
def test_join_links_open_the_console_and_the_engine_reads_every_link_form(tmp_path,
                                                                          workstation):
    """`/join` and `/join/` serve the very page `/` does, with this run's token and CSP,
    to this console's Host only. The engine reads a token from `#nm1_…`, `#nm1_…&topic=…`
    and `#join=nm1_…`, takes only the keys it knows, and refuses a link that names an
    unknown role or a topic that is not a topic id. Its roles are the bridge's."""
    page, _ = call(workstation, "GET", "/", token=None)
    for path in ("/join", "/join/"):
        served, response = call(workstation, "GET", path, token=None)
        assert served == page and response.getheader("Content-Type").startswith("text/html")
        assert response.getheader("Content-Security-Policy") == workstation.console.csp
        assert f'content="{workstation.token}"'.encode() in served
        assert "Host" in call(workstation, "GET", path, token=None, host="evil.example",
                              want=403)["error"]
    trust = Trust.load(workstation.home / "nostr.toml")
    token = cli._encode_invite_token(trust, "bearer-code", member="roland")
    got = _page_engine(tmp_path, READ_LINKS, [
        f"#{token}", f"{token}&topic=retry&role=read-only&ticket=t-1",
        f"#join={token}&topic=retry&ticket=t-2&extra=dropped", "#invite=relay-code",
        f"#{token}&role=owner", f"#join={token}&topic=Not_A_Topic", "#join=nope"])
    assert got[:4] == [
        {"join": token, "campaign": "camp"},
        {"join": token, "topic": "retry", "role": "read-only", "ticket": "t-1",
         "campaign": "camp"},
        {"join": token, "topic": "retry", "ticket": "t-2", "campaign": "camp"},
        {"invite": "relay-code"}]
    assert "role owner" in got[4]["error"] and "not a topic id" in got[5]["error"]
    assert "nm1_" in got[6]["error"]
    assert _page_engine(tmp_path, "(NM) => NM.ROLES", None) == list(ui.ROLES)


def test_personas_are_listed_switched_and_created_and_a_request_keeps_its_own(workstation,
                                                                            relay):
    """Every identity file is a persona in /api/state, an unusable one listed with the
    reason. /api/persona switches who the bridge signs as and creates a fresh 0600 key
    on request, never over one that exists. A request runs as the persona it began with,
    whatever a switch did meanwhile."""
    alice = create_identity("alice-work", base=workstation.home)
    broken = workstation.home / "identities/broken.json"
    broken.write_text("{}")
    broken.chmod(0o644)
    state = call(workstation, "GET", "/api/state")
    listed = {p["name"]: p for p in state["personas"]}
    assert sorted(listed) == ["alice-work", "broken", "default"]
    assert state["active_persona"] == "default" and listed["default"]["active"]
    assert listed["alice-work"]["pubkey"] == alice.pubkey and "error" not in listed["alice-work"]
    assert "0600" in listed["broken"]["error"] and "nsec" not in json.dumps(state)
    started = workstation.console.pinned()
    switched = call(workstation, "POST", "/api/persona", {"name": "alice-work"})
    assert switched["active_persona"] == switched["seat"] == "alice-work"
    assert switched["identity"]["pubkey"] == alice.pubkey
    assert started.need_identity().pubkey == workstation.pubkey, \
        "a request that began as default finishes as default"
    signed = call(workstation, "POST", "/api/sign", {"event": {
        "created_at": int(time.time()), "kind": 22242,
        "tags": [["relay", relay.url], ["challenge", "c"]], "content": ""}})["event"]
    assert verify_event(signed).pubkey == alice.pubkey
    made = call(workstation, "POST", "/api/persona", {"name": "alice-personal", "create": True})
    key_file = workstation.home / "identities/alice-personal.json"
    assert made["active_persona"] == "alice-personal" and oct(key_file.stat().st_mode & 0o777) \
        == "0o600"
    assert made["identity"]["pubkey"] not in (alice.pubkey, workstation.pubkey)
    assert "already exists" in call(workstation, "POST", "/api/persona", {
        "name": "alice-work", "create": True}, want=400)["error"]
    assert "no identity 'ghost'" in call(workstation, "POST", "/api/persona",
                                         {"name": "ghost"}, want=400)["error"]
    assert "must match" in call(workstation, "POST", "/api/persona", {"name": "Bad Name",
                                                                      "create": True},
                                want=400)["error"]
    assert call(workstation, "GET", "/api/state")["active_persona"] == "alice-personal"
    back = call(workstation, "POST", "/api/persona", {"name": "default"})
    assert back["identity"]["pubkey"] == workstation.pubkey and back["role"] == "operator"


def _admin_cli(ws, relay, tmp_path):
    """admin.json pointing at a recording program on a real subprocess boundary, as
    `kubectl exec … ncli` would be; each `mint()` arms it with a fresh real relay code.
    Returns (mint, runs): `runs()` counts the times the admin was run."""
    code_file, log = tmp_path / "next-invite.json", tmp_path / "admin-runs.log"
    admin = tmp_path / "ncli.sh"
    admin.write_text(f"echo run >> '{log}'\ncat '{code_file}'\n")
    (ws.home / "admin.json").write_text(json.dumps({"exec_prefix": ["/bin/sh", str(admin)]}))

    def mint() -> str:
        code, stamp = relay.create_invite(), int(time.time())
        code_file.write_text(json.dumps({"code": code, "created_at": stamp,
                                         "expires_at": stamp + 7 * 24 * 3600, "max_uses": 1,
                                         "uses": 0}))
        return code

    def runs() -> int:
        return len(log.read_text().splitlines()) if log.exists() else 0
    return mint, runs


def _ask(ws, secret: bytes, topic: str, ticket: str | None, reason: str = "via the link"):
    """The newcomer's join request as the page's `requestAccess` writes it: kind 9021
    with `h`, and the link's ticket."""
    with _session(ws) as plain:
        trust = plain.trust
    with ui.TopicSession(trust, LocalSigner(secret), timeout_s=WAIT) as session:
        tags = [["h", topic], *([["ticket", ticket]] if ticket else [])]
        event = session.relay.sign(ui.JOIN_REQUEST, tags, reason)
        session.relay.publish(event)
    return event.id


def _ticket(join_url: str) -> str:
    return dict(part.split("=", 1) for part in urlsplit(join_url).fragment.split("&")[1:])[
        "ticket"]


@needs_node
def test_a_topic_invite_carries_a_role_and_a_join_link_and_admits_only_its_presenter(
        tmp_path, workstation, relay):
    """/api/topics/<group>/invite mints only for an admin of a topic that exists, and
    refuses a role it does not know, before the relay's admin is run. It returns the nm1_
    token, a 1-click join link (the console's /join/ page with the token, topic, role and
    ticket in the fragment) and records only the ticket's digest, 0600. The engine reads
    that very link. Admission by ticket grants the minted terms to the one key that
    presented it, once; a ticket the workstation did not mint, other terms, or a ticket
    two keys present admit nobody."""
    mint, runs = _admin_cli(workstation, relay, tmp_path)
    call(workstation, "POST", "/api/topic/create", {"topic": "retry"})
    assert "role 'owner'" in call(workstation, "POST", "/api/topics/retry/invite",
                                  {"role": "owner"}, want=400)["error"]
    assert "create it first" in call(workstation, "POST", "/api/topics/nowhere/invite", {},
                                     want=400)["error"]
    bystander = create_identity("bystander", base=workstation.home)
    relay.add_member(bystander.pubkey)
    call(workstation, "POST", "/api/persona", {"name": "bystander"})
    assert "only an admin" in call(workstation, "POST", "/api/topics/retry/invite", {},
                                   want=403)["error"]
    call(workstation, "POST", "/api/persona", {"name": "default"})
    assert runs() == 0, "nothing is minted for a refused invite"

    mint()
    minted = call(workstation, "POST", "/api/topics/retry/invite",
                  {"role": "read-only", "history": "full_history", "member": "roland"})
    token, ticket = minted["token"], _ticket(minted["join_url"])
    assert (minted["role"], minted["history"], minted["topic"], runs()) == (
        "read-only", "full_history", "retry", 1)
    assert minted["join_url"] == (f"http://{ui.DEFAULT_HOST}:{ui.DEFAULT_PORT}/join/#{token}"
                                  f"&topic=retry&role=read-only&ticket={ticket}")
    assert cli._decode_invite_token(token)[2] == "roland", "the CLI joins with it as well"
    declared = cli._decode_invite_token(token)[1]
    assert "campaign_key" not in declared, "a topic invite never carries the campaign's key"
    assert (declared["group"], declared["keyring"]) == ("retry", "retry")
    book = workstation.home / "invites/retry.json"
    assert oct(book.stat().st_mode & 0o777) == "0o600" and ticket not in book.read_text()
    listed = call(workstation, "GET", "/api/invites")["topics"]["retry"]
    assert [(t["ticket_sha256"], t["role"], t["member"], t["admitted"]) for t in listed] == [
        (ui.ticket_digest(ticket), "read-only", "roland", None)]
    assert ticket not in json.dumps(listed)
    read = _page_engine(tmp_path, READ_LINKS, ["#" + urlsplit(minted["join_url"]).fragment])
    assert read == [{"join": token, "topic": "retry", "role": "read-only", "ticket": ticket,
                     "campaign": "camp"}]

    friend, stranger, peer = _pub(FRIEND_SK), _pub(STRANGER_SK), _pub(PEER_SK)
    relay.add_member(stranger)
    relay.add_member(peer)
    with ui.TopicSession(Trust.load(workstation.home / "nostr.toml"), LocalSigner(FRIEND_SK),
                         timeout_s=WAIT) as newcomer:
        assert newcomer.relay.join(cli._decode_invite_token(token)[0]) == "info: welcome"
    _ask(workstation, FRIEND_SK, "retry", ticket)
    _ask(workstation, STRANGER_SK, "retry", "a-ticket-nobody-minted")
    assert "minted no such ticket" in call(workstation, "POST", "/api/topic/grant", {
        "topic": "retry", "member": stranger, "ticket": "a-ticket-nobody-minted"},
        want=403)["error"]
    assert "no pending join request" in call(workstation, "POST", "/api/topic/grant", {
        "topic": "retry", "member": peer, "ticket": ticket}, want=403)["error"]
    assert "minted for role 'read-only'" in call(workstation, "POST", "/api/topic/grant", {
        "topic": "retry", "member": friend, "ticket": ticket, "role": "read-write"},
        want=403)["error"]
    admitted = call(workstation, "POST", "/api/topic/grant", {
        "topic": "retry", "member": _npub(friend), "ticket": ticket})
    assert (admitted["role"], admitted["mode"], admitted["epochs"], admitted["ticket"]) == (
        "read-only", "full_history", [1], "admitted")
    put = next(e for e in relay.stored() if e.id == admitted["put_user"])
    assert [list(t) for t in put.tags if t[0] == "p"] == [["p", friend, "read-only"]]
    assert "already admitted" in call(workstation, "POST", "/api/topic/grant", {
        "topic": "retry", "member": friend, "ticket": ticket}, want=403)["error"]
    assert call(workstation, "GET", "/api/invites")["topics"]["retry"][0]["admitted"] == friend

    mint()
    shared = _ticket(call(workstation, "POST", "/api/topics/retry/invite",
                          {"role": "read-write"})["join_url"])
    for secret in (PEER_SK, STRANGER_SK):
        _ask(workstation, secret, "retry", shared)
    assert "2 keys present this ticket" in call(workstation, "POST", "/api/topic/grant", {
        "topic": "retry", "member": peer, "ticket": shared}, want=403)["error"]
    topics = call(workstation, "GET", "/api/topics")["topics"]
    assert topics[0]["roles"] == {_npub(workstation.pubkey): "read-write",
                                  _npub(friend): "read-only"}
    assert {r["ticket"] for r in topics[0]["requests"]} == {shared, "a-ticket-nobody-minted"}


@needs_node
def test_read_only_writes_are_held_and_write_only_members_write_sealed_mail_without_a_key(
        node, tmp_path, workstation, relay):
    """A read-only member, admitted by ticket, replays the topic's history; what it posts
    is held at every console's human gate. A write-only member gets no key ring, not on
    admission and not when the topic rotates; it writes sealed mail into the admin's
    `topic:retry` dropbox part, which the admin's gate holds for preview. Downgrading a reader
    to write-only rotates the topic without it. The bridge's state says which topics a
    coding agent on this workstation holds an epoch of."""
    mint, _ = _admin_cli(workstation, relay, tmp_path)
    friend, newcomer, peer = _pub(FRIEND_SK), _pub(NEWCOMER_SK), _pub(PEER_SK)
    for pk in (friend, newcomer, peer):
        relay.add_member(pk)
    call(workstation, "POST", "/api/topic/create", {"topic": "retry"})
    call(workstation, "POST", "/api/post", {"group": "retry", "topic": "bus",
                                            "body": "epoch-1 history"})
    tickets = {}
    for secret, role in ((FRIEND_SK, "read-only"), (NEWCOMER_SK, "write-only")):
        mint()
        tickets[role] = _ticket(call(workstation, "POST", "/api/topics/retry/invite",
                                     {"role": role})["join_url"])
        _ask(workstation, secret, "retry", tickets[role])
    reader = call(workstation, "POST", "/api/topic/grant", {
        "topic": "retry", "member": friend, "ticket": tickets["read-only"]})
    writer = call(workstation, "POST", "/api/topic/grant", {
        "topic": "retry", "member": newcomer, "ticket": tickets["write-only"]})
    assert (reader["role"], len(reader["wraps"])) == ("read-only", 1)
    assert (writer["role"], writer["mode"], "wraps" in writer) == ("write-only", None, False)
    assert writer["mailbox"] == {"owner": _npub(workstation.pubkey), "part": "topic:retry",
                                 "scope": "topic_scoped", "trust": "human_gated"}

    _next_second()
    posted = node({"scenario": "session", "secret": FRIEND_SK.hex(), "trust": workstation.trust,
                   "timeout_s": WAIT, "topics": ["retry"],
                   "ops": [{"op": "post", "scope": "retry", "topic": "bus",
                            "body": "a read-only member's note"}]})
    assert posted["ops"][0].get("error") is None, "the relay takes it: roles are not its job"
    seen = posted["scopes"]["retry"]
    assert [m["body"] for m in seen["topics"]["bus"]["messages"]] == ["epoch-1 history"]
    assert [(q["body"], q["why"]) for q in seen["quarantine"]] == [
        ("a read-only member's note", "written by a read-only member")]
    bridge = {"base": workstation.url, "token": workstation.token}
    admin_view = node({"scenario": "session", "bridge": bridge, "trust": workstation.trust,
                       "timeout_s": WAIT, "topics": ["retry"], "root": True, "mailbox": True})
    assert [q["why"] for q in admin_view["scopes"]["retry"]["quarantine"]] == [
        "written by a read-only member"]

    wrote = node({"scenario": "session", "secret": NEWCOMER_SK.hex(), "trust": workstation.trust,
                  "timeout_s": WAIT, "topics": ["retry"],
                  "ops": [{"op": "mail", "owner": workstation.pubkey, "part": "topic:retry",
                           "subject": "status", "body": "wave 7 is green"}]})
    assert wrote["ops"][0].get("error") is None and wrote["keyrings"] == []
    assert wrote["scopes"]["retry"]["nokey"] is True
    assert newcomer in wrote["scopes"]["retry"]["members"]
    box = node({"scenario": "session", "bridge": bridge, "trust": workstation.trust,
                "timeout_s": WAIT, "root": True, "mailbox": True})["mailbox"]
    held = [m for m in box["held"] if m["from"] == newcomer]
    assert [(m["part"], m["granted"], m["body"]["body"]) for m in held] == [
        ("topic:retry", True, "wave 7 is green")]
    assert {"peer": newcomer, "active": True, "trust": "human_gated", "scope": "topic_scoped",
            "parts": ["topic:retry"]} in box["grants"]

    rotated = call(workstation, "POST", "/api/topic/grant", {
        "topic": "retry", "member": peer, "mode": "forward_only", "role": "read-write"})
    assert rotated["epoch"] == 2 and _npub(newcomer) not in rotated["recipients"]
    assert _npub(friend) in rotated["recipients"]
    _next_second()
    downgraded = call(workstation, "POST", "/api/topic/grant", {
        "topic": "retry", "member": friend, "role": "write-only"})
    assert downgraded["epoch"] == 3 and _npub(friend) not in downgraded["recipients"]
    after = node({"scenario": "session", "secret": NEWCOMER_SK.hex(), "trust": workstation.trust,
                  "timeout_s": WAIT, "topics": ["retry"]})
    assert after["keyrings"] == [], "no rotation ever reached the write-only key"

    assert call(workstation, "GET", "/api/state")["exports"] == {}
    call(workstation, "POST", "/api/topic/export", {"topic": "retry"})
    state = call(workstation, "GET", "/api/state")
    assert (state["exports"], state["export_errors"]) == ({"retry": [1, 2, 3]}, {}), \
        "every epoch this key holds, each under its own number"


PAGE_GRANTS = """async (NM, c) => {
  const trust = NM.makeTrust(c.trust), signer = new NM.KeySigner(NM.unhex(c.secret));
  const relay = new NM.RelayClient(trust.relay, signer,
                                   { authUrl: trust.relay, timeoutS: c.timeout_s });
  await relay.connect();
  const desk = new NM.Desk(trust, signer, relay);
  const scope = async () => {
    const { keyrings } = await desk.inbox();
    const events = await relay.queryAll({ '#h': [c.topic] });
    return NM.topicScope(trust, c.topic, events, keyrings, relay.pubkey);
  };
  await desk.createTopic(c.topic, c.topic);
  const reader = await desk.grant(await scope(), c.reader, 'full_history', 'read-only');
  const writer = await desk.grant(await scope(), c.writer, 'full_history', 'write-only');
  const late = await desk.grant(await scope(), c.late, 'forward_only', 'read-write');
  let refused = null;
  try { await desk.grant(await scope(), c.late, 'full_history', 'owner'); }
  catch (e) { refused = e.message; }
  const roster = (await scope()).roster;
  relay.close();
  return { reader, writer, late, refused, roles: roster.roles };
}"""


@needs_node
def test_roles_the_page_grants_read_the_same_in_python(tmp_path, workstation, relay):
    """The page, as a topic's admin with its own key, grants read-only, write-only and
    read-write. Python reads the same roster and roles from the relay; the write-only key
    gets no key ring, not even when the page rotates the topic, and a topic_scoped grant
    into the admin's `topic:<id>` part instead. A role the page does not know is refused."""
    admin, reader, writer, late = (_pub(k) for k in (FRIEND_SK, PEER_SK, NEWCOMER_SK,
                                                     STRANGER_SK))
    for pk in (admin, reader, writer, late):
        relay.add_member(pk)
    got = _page_engine(tmp_path, PAGE_GRANTS, {
        "trust": workstation.trust, "secret": FRIEND_SK.hex(), "timeout_s": WAIT,
        "topic": "js-roles", "reader": reader, "writer": writer, "late": late})
    assert (got["reader"]["role"], got["reader"]["epochs"]) == ("read-only", [1])
    assert got["writer"]["role"] == "write-only" and "wraps" not in got["writer"]
    assert got["writer"]["mailbox"]["part"] == "topic:js-roles"
    assert got["late"]["epoch"] == 2 and writer not in got["late"]["recipients"]
    assert set(got["late"]["recipients"]) == {admin, reader, late}
    assert "role owner" in got["refused"]
    trust = Trust.load(workstation.home / "nostr.toml")
    with ui.TopicSession(trust, LocalSigner(FRIEND_SK), timeout_s=WAIT) as session:
        state = ui.TopicDesk(session, FRIEND_SK).state("js-roles")
    assert state.roles == got["roles"] == {admin: "read-write", reader: "read-only",
                                           writer: "write-only", late: "read-write"}
    wraps_to_writer = [e for e in relay.stored() if e.kind == ui.GIFT_WRAP
                       and e.values("p") == [writer]]
    assert wraps_to_writer == []
    grant = [e for e in relay.stored() if e.kind == 4420 and e.pubkey == admin]
    assert [(g.values("p"), g.values("scope"), g.values("part"), g.values("trust"))
            for g in grant] == [([writer], ["topic_scoped"], ["topic:js-roles"],
                                 ["human_gated"])]


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


# ============================================ sealed topic blobs and per-tab personas
UNOPENED = "it was sealed in an epoch this seat was not given, or uploaded in plaintext"


def _epoch_toml(ws, topic: str, epoch: int, path: Path) -> Path:
    """The declaration of one epoch of a topic, as the unchanged CLI reads it."""
    scoped = _topic_trust(ws, topic, epoch)
    cli._write_trust_file(path, {
        "schema": "cf.transport/1", "relay": scoped.relay, "campaign": scoped.campaign,
        "group": scoped.group,
        "operator_pubkeys": [_npub(k) for k in sorted(scoped.operator_pubkeys)],
        "campaign_key": scoped.campaign_key})
    return path


def _blob_cli(ws, toml: Path, *argv: str) -> dict:
    done = subprocess.run([sys.executable, "-m", "nostr_mailbox", "--trust", str(toml),
                           "--home", str(ws.home), "blob", *argv],
                          capture_output=True, text=True, env=_cli_env(), check=False)
    assert done.returncode == 0, done.stderr
    return json.loads(done.stdout)


def test_the_bridge_seals_topic_blobs_and_opens_them_with_every_epoch_like_the_cli(
        workstation, relay, tmp_path):
    """Inside a topic the bridge seals a blob under the current epoch, as `blob put`
    does, and the real CLI and a CampaignSession open it; a blob the real CLI sealed
    opens through the bridge. After a rotation the bridge still holds every epoch: the
    epoch-1 blob opens, a new one is sealed in epoch 2. A plaintext blob does not open in
    the topic, in the CLI's words, and comes back as stored from /api/blob only. A
    swapped blob is discarded on its digest before anything is opened."""
    ws = workstation
    call(ws, "POST", "/api/topic/create", {"topic": "retry"})
    data = b"retry log: s1 ran twice\n"
    put = call(ws, "POST", "/api/topics/retry/blob", raw=data,
               headers={"Content-Type": "text/plain"})
    assert (put["sealed"], put["epoch"], put["bytes"]) == (True, 1, len(data))
    assert put["plaintext_sha256"] == hashlib.sha256(data).hexdigest() != put["sha256"]
    stored = relay.blossom.blobs[put["sha256"]]
    assert stored.isascii() and b"retry" not in stored, "the blob server holds ciphertext"
    with CampaignSession(_topic_trust(ws, "retry", 1), LocalSigner(ws.secret),
                         timeout_s=WAIT) as session:
        assert session.open_sealed_blob(stored) == (data, 1)

    epoch1 = _epoch_toml(ws, "retry", 1, tmp_path / "retry-epoch-1.toml")
    fixture = tmp_path / "fixture.bin"
    fixture.write_bytes(os.urandom(300))
    sealed = _blob_cli(ws, epoch1, "put", "--encrypt", str(fixture))
    assert (sealed["sealed"], sealed["epoch"]) == (True, 1)
    body, response = call(ws, "GET", f"/api/topics/retry/blob/{sealed['sha256']}")
    assert body == fixture.read_bytes()
    assert (response.getheader("X-NM-Epoch"), response.getheader("X-Digest-Verified")) == (
        "1", "sha256")

    relay.add_member(_pub(NEWCOMER_SK))
    assert call(ws, "POST", "/api/topic/grant", {"topic": "retry", "member": _pub(NEWCOMER_SK),
                                                "mode": "forward_only"})["epoch"] == 2
    body, response = call(ws, "GET", f"/api/topics/retry/blob/{put['sha256']}")
    assert (body, response.getheader("X-NM-Epoch")) == (data, "1"), "epoch 1 is still held"
    later = call(ws, "POST", "/api/topics/retry/blob", raw=b"after the rotation")
    assert later["epoch"] == 2
    got = _blob_cli(ws, _epoch_toml(ws, "retry", 2, tmp_path / "retry-epoch-2.toml"), "get",
                    later["sha256"], "--encrypt", "--out", str(tmp_path / "later.bin"))
    assert got["sealed"] and (tmp_path / "later.bin").read_bytes() == b"after the rotation", \
        "the CLI opens it with the epoch-2 key (its one-key declaration numbers it 1)"

    plain = call(ws, "POST", "/api/blob", raw=b"left in plaintext")
    assert plain["sha256"] == hashlib.sha256(b"left in plaintext").hexdigest()
    assert relay.blossom.blobs[plain["sha256"]] == b"left in plaintext", "the root stays as is"
    refused = call(ws, "GET", f"/api/topics/retry/blob/{plain['sha256']}", want=400)
    assert refused["type"] == "Unopened" and UNOPENED in refused["error"]
    assert "[1, 2]" in refused["error"]
    as_stored, _ = call(ws, "GET", f"/api/blob/{plain['sha256']}")
    assert as_stored == b"left in plaintext"
    assert "holds no key" in call(ws, "POST", "/api/topics/elsewhere/blob", raw=b"x",
                                  want=400)["error"]
    relay.blossom.blobs[put["sha256"]] = b"swapped"
    assert "hashing to" in call(ws, "GET", f"/api/topics/retry/blob/{put['sha256']}",
                                want=502)["error"]


@needs_node
def test_the_page_seals_and_opens_topic_blobs_like_the_cli_in_both_modes(node, workstation,
                                                                         relay):
    """Standalone, the page's engine holding the topic's key ring opens a blob Python
    sealed, and seals one Python and the bridge open; a root-campaign blob goes up as it
    is. A blob no held epoch opens is refused in the CLI's words and comes back as stored
    only when asked; a swapped one is discarded on its digest. In bridge mode the same
    engine calls are sealed and opened by the bridge, with every epoch it holds."""
    ws, friend = workstation, _pub(FRIEND_SK)
    relay.add_member(friend)
    call(ws, "POST", "/api/topic/create", {"topic": "retry"})
    call(ws, "POST", "/api/topic/grant", {"topic": "retry", "member": friend,
                                          "mode": "full_history"})
    from_python, from_page = os.urandom(500), os.urandom(300)
    epoch1 = _topic_trust(ws, "retry", 1)
    with CampaignSession(epoch1, LocalSigner(ws.secret), timeout_s=WAIT) as session:
        python_blob, _ = session.put_sealed_blob(from_python)
    plain = call(ws, "POST", "/api/blob", raw=b"left in plaintext")["sha256"]

    standalone = {"scenario": "session", "secret": FRIEND_SK.hex(), "trust": ws.trust,
                  "timeout_s": WAIT, "root": True, "topics": ["retry"]}
    got = node({**standalone, "ops": [
        {"op": "blob_get", "scope": "retry", "sha256": python_blob.sha256},
        {"op": "blob_put", "scope": "retry", "data": from_page.hex()},
        {"op": "blob_put", "scope": "", "data": b"root notes".hex(), "type": "text/plain"},
        {"op": "blob_get", "scope": "retry", "sha256": plain},
        {"op": "blob_get", "scope": "retry", "sha256": plain, "as_stored": True}]})
    opened, sealed, rooted, refused, as_stored = got["ops"]
    assert opened["ok"] == {"data": from_python.hex(), "sealed": True, "epoch": 1}
    page_blob = sealed["ok"]
    assert (page_blob["sealed"], page_blob["epoch"], page_blob["bytes"]) == (True, 1, 300)
    assert page_blob["plaintext_sha256"] == hashlib.sha256(from_page).hexdigest()
    with CampaignSession(epoch1, LocalSigner(ws.secret), timeout_s=WAIT) as session:
        assert session.open_sealed_blob(relay.blossom.blobs[page_blob["sha256"]]) == (
            from_page, 1)
    body, _ = call(ws, "GET", f"/api/topics/retry/blob/{page_blob['sha256']}")
    assert body == from_page
    assert rooted["ok"]["sha256"] == hashlib.sha256(b"root notes").hexdigest()
    assert relay.blossom.blobs[rooted["ok"]["sha256"]] == b"root notes"
    assert refused["code"] == "Unopened" and UNOPENED in refused["error"]
    assert as_stored["ok"] == {"data": b"left in plaintext".hex(), "sealed": False,
                               "epoch": None}

    bridge = {"base": ws.url, "token": ws.token, "persona": "default"}
    via = node({"scenario": "session", "bridge": bridge, "trust": ws.trust, "timeout_s": WAIT,
                "topics": ["retry"], "ops": [
                    {"op": "blob_put", "scope": "retry", "data": b"through the bridge".hex()},
                    {"op": "blob_get", "scope": "retry", "sha256": page_blob["sha256"]},
                    {"op": "blob_get", "scope": "retry", "sha256": plain},
                    {"op": "blob_get", "scope": "retry", "sha256": plain, "as_stored": True}]})
    up, back, refused, as_stored = via["ops"]
    assert (up["ok"]["sealed"], up["ok"]["epoch"]) == (True, 1)
    with CampaignSession(epoch1, LocalSigner(ws.secret), timeout_s=WAIT) as session:
        assert session.open_sealed_blob(relay.blossom.blobs[up["ok"]["sha256"]]) == (
            b"through the bridge", 1)
    assert back["ok"] == {"data": from_page.hex(), "sealed": True, "epoch": 1}
    assert refused["code"] == "Unopened" and UNOPENED in refused["error"]
    assert as_stored["ok"]["data"] == b"left in plaintext".hex()

    relay.blossom.blobs[python_blob.sha256] = b"swapped"
    swapped = node({**standalone, "ops": [{"op": "blob_get", "scope": "retry",
                                           "sha256": python_blob.sha256}]})["ops"][0]
    assert swapped["code"] == "digest" and "hashing to" in swapped["error"]


@needs_node
def test_each_tab_acts_as_the_persona_it_shows_whatever_another_tab_switches_to(
        node, workstation, relay):
    """Two tabs over real HTTP, each naming its persona on every request. Both open as
    the console's default. Tab B switches to alice-work; tab A's next sign, NIP-44 and
    post, and the page's engine in tab A (NIP-42 and a post through BridgeSigner), still
    run as default, while tab B and a freshly opened tab, which names none, run as
    alice-work. A name that is not an identity name is refused; one with no identity
    fails as a missing identity does."""
    ws = workstation
    alice = create_identity("alice-work", base=ws.home)
    relay.add_member(alice.pubkey)
    opened = call(ws, "GET", "/api/state")
    assert opened["active_persona"] == "default"
    tab_a = tab_b = {ui.PERSONA_HEADER: opened["active_persona"]}
    switched = call(ws, "POST", "/api/persona", {"name": "alice-work"}, headers=tab_b)
    tab_b = {ui.PERSONA_HEADER: switched["active_persona"]}
    assert switched["identity"]["pubkey"] == alice.pubkey
    still = call(ws, "GET", "/api/state", headers=tab_a)
    assert (still["active_persona"], still["identity"]["pubkey"]) == ("default", ws.pubkey)
    assert call(ws, "GET", "/api/state")["active_persona"] == "alice-work", \
        "a fresh tab starts from the default the switch set"

    def signer(headers: dict | None) -> str:
        auth = {"created_at": int(time.time()), "kind": 22242,
                "tags": [["relay", relay.url], ["challenge", "c"]], "content": ""}
        return verify_event(call(ws, "POST", "/api/sign", {"event": auth},
                                 headers=headers)["event"]).pubkey
    assert (signer(tab_a), signer(tab_b), signer(None)) == (ws.pubkey, alice.pubkey,
                                                            alice.pubkey)
    sealed = call(ws, "POST", "/api/nip44", {"op": "encrypt", "peer": _pub(PEER_SK),
                                             "plaintext": "from tab A"}, headers=tab_a)
    assert nip44.decrypt(sealed["result"], nip44.conversation_key(
        PEER_SK, bytes.fromhex(ws.pubkey))) == "from tab A"
    posted = call(ws, "POST", "/api/post", {"topic": "bus", "body": "tab A, still default"},
                  headers=tab_a)
    assert next(e for e in relay.stored() if e.id == posted["id"]).pubkey == ws.pubkey

    page = node({"scenario": "session", "trust": ws.trust, "timeout_s": WAIT, "root": True,
                 "bridge": {"base": ws.url, "token": ws.token, "persona": "default"},
                 "ops": [{"op": "post", "scope": "", "topic": "bus",
                          "body": "the engine in tab A"}]})
    assert page["me"] == ws.pubkey and page["ops"][0].get("error") is None
    assert next(e for e in relay.stored()
                if e.id == page["ops"][0]["ok"]["id"]).pubkey == ws.pubkey

    assert "must match" in call(ws, "GET", "/api/state",
                                headers={ui.PERSONA_HEADER: "Bad Name"}, want=400)["error"]
    assert "no identity 'ghost'" in call(ws, "POST", "/api/post", {"body": "x"},
                                         headers={ui.PERSONA_HEADER: "ghost"},
                                         want=409)["error"]


# ======================== topic invites without the campaign key; the agent at epoch N
def _cli(prefix: str, *argv) -> dict:
    """The real CLI, as a coding agent runs it from the prefix the bridge named."""
    done = subprocess.run([sys.executable, "-m", "nostr_mailbox", *shlex.split(prefix)[1:],
                           *argv], capture_output=True, text=True, env=_cli_env(), check=False)
    assert done.returncode == 0, done.stderr
    return json.loads(done.stdout)


def test_a_topic_invitee_never_holds_the_campaign_key_and_works_inside_its_topic(
        tmp_path, workstation, relay):
    """The console's topic invite declares the topic and nothing of the campaign's own
    key. A newcomer who joins a fresh workstation from it holds a declaration with no
    `campaign_key`: before an admin admits them the console refuses to write (never in
    plaintext), afterwards everything they post goes into the topic under its epoch key,
    and the campaign's own bus stays closed to them."""
    mint, _ = _admin_cli(workstation, relay, tmp_path)
    call(workstation, "POST", "/api/topic/create", {"topic": "retry"})
    call(workstation, "POST", "/api/post", {"topic": "bus", "body": "for the whole campaign"})
    mint()
    minted = call(workstation, "POST", "/api/topics/retry/invite", {"history": "full_history"})
    carried = base64.urlsafe_b64decode(minted["token"][4:] + "=" * (-len(minted["token"]) % 4))
    assert workstation.campaign_key.encode() not in carried and b"campaign_key" not in carried

    console = ui.Console(base=tmp_path / "newcomer", timeout_s=WAIT, quiet=True)
    with ui.ConsoleServer(console, port=0) as server:
        theirs = SimpleNamespace(url=server.url, token=console.token)
        call(theirs, "POST", "/api/join", {"token": minted["token"]})
        state = call(theirs, "GET", "/api/state")
        assert (state["trust"]["campaign_key"], state["trust"]["keyring"],
                state["trust"]["group"]) == (None, "retry", "retry")
        assert "campaign_key" not in (tmp_path / "newcomer/nostr.toml").read_text()
        ident = load_identity("default", base=tmp_path / "newcomer")
        assert ident.pubkey in relay.members
        early = call(theirs, "POST", "/api/post", {"topic": "bus", "body": "too soon"}, want=400)
        assert "holds no key" in early["error"], "no key yet: refused, never sent in plaintext"

        _ask(workstation, bech32.decode(bech32.NSEC, ident.signer_spec["nsec"]), "retry",
             _ticket(minted["join_url"]))
        call(workstation, "POST", "/api/topic/grant", {
            "topic": "retry", "member": ident.pubkey, "ticket": _ticket(minted["join_url"])})
        posted = call(theirs, "POST", "/api/post", {"topic": "bus", "body": "inside the topic"})
        assert (posted["group"], posted["epoch"]) == ("retry", 1)
        stored = next(e for e in relay.stored() if e.id == posted["id"])
        assert stored.values("h") == ["retry"] and "inside the topic" not in stored.content
        # with the CLI, on the declaration the join wrote: the topic, and nothing of the root
        seen = _cli(shlex.join(["nostr-mailbox", "--home", str(tmp_path / "newcomer")]),
                    "read", "bus")
        assert [m["body"] for m in seen["messages"]] == ["inside the topic"]
        assert "for the whole campaign" not in json.dumps(seen)


def test_pair_coding_agent_hands_the_cli_a_topic_at_its_true_epoch_and_it_follows_rotations(
        workstation, relay):
    """The topic stands at epoch 2 when it is paired. The CLI agent holds epochs 1 and 2
    under their own numbers and writes under 2 (the old export handed it K2 as a
    `campaign_key`, so it wrote K2-ciphertext tagged epoch 1, which no reader opens).
    When the topic rotates again the agent fetches epoch 3 itself: no fresh export. The
    prefix the bridge names carries --home, --persona and --trust when they are not the
    CLI's own defaults."""
    friend = _pub(FRIEND_SK)
    relay.add_member(friend)
    call(workstation, "POST", "/api/topic/create", {"topic": "retry"})
    call(workstation, "POST", "/api/post", {"group": "retry", "topic": "bus",
                                            "body": "written in epoch 1"})
    _next_second()
    assert call(workstation, "POST", "/api/topic/grant", {
        "topic": "retry", "member": friend, "mode": "forward_only"})["epoch"] == 2
    exported = call(workstation, "POST", "/api/topic/export", {"topic": "retry"})
    assert (exported["epoch"], exported["epochs"]) == (2, [1, 2])

    said = _cli(exported["cli"], "post", "bus", "from the agent, epoch 2", "--kind", "finding")
    stored = next(e for e in relay.stored() if e.id == said["id"])
    assert stored.values("epoch") == ["2"], "written under the topic's own current epoch"
    key2 = _topic_trust(workstation, "retry", 2).campaign_key
    assert "from the agent, epoch 2" in decrypt_record(stored, EpochKeys("camp", {2: key2}, 2))
    assert {m["body"] for m in _cli(exported["cli"], "read", "bus")["messages"]} == {
        "written in epoch 1", "from the agent, epoch 2"}
    with _session(workstation) as session:
        console_view = workstation.console.enter_scope(session, "retry")
        assert console_view is not None
        assert "from the agent, epoch 2" in [
            m.body for m in NostrRelayChannelBackend(session).history("bus")], \
            "and the console reads what the agent wrote"

    _next_second()
    assert call(workstation, "POST", "/api/topic/revoke", {"topic": "retry",
                                                            "member": friend})["epoch"] == 3
    later = _cli(exported["cli"], "post", "bus", "from the agent, epoch 3", "--kind", "finding")
    assert next(e for e in relay.stored() if e.id == later["id"]).values("epoch") == ["3"]
    assert _cli(exported["cli"], "topic", "sync", "retry")["topics"][0]["held_epochs"] == [
        1, 2, 3]
    assert call(workstation, "GET", "/api/state")["exports"] == {"retry": [1, 2, 3]}

    # the prefix names what is not the CLI's own default, quoted for a shell
    home = workstation.home
    assert call(workstation, "GET", "/api/state")["cli"] == shlex.join(
        ["nostr-mailbox", "--home", str(home)])
    create_identity("alice work".replace(" ", "-"), base=home)
    as_alice = call(workstation, "GET", "/api/state",
                    headers={ui.PERSONA_HEADER: "alice-work"})["cli"]
    assert as_alice == shlex.join(["nostr-mailbox", "--home", str(home), "--persona",
                                   "alice-work"])
    elsewhere = home / "other trust.toml"
    elsewhere.write_bytes((home / "nostr.toml").read_bytes())
    assert ui.Console(base=home, trust_path=elsewhere, quiet=True).state()["cli"] == shlex.join(
        ["nostr-mailbox", "--home", str(home), "--trust", str(elsewhere)])


class ConsoleRelay(LoopbackRelay):
    """Serve the unmodified standalone HTML alongside the relay's real NIP-11 and WS."""

    def _http(self, sock, request):
        if (request.path in ("/", "/join/") and
                relay_mod.NIP11_ACCEPT not in request.headers.get("accept", "")):
            loopback._respond(sock, 200, PAGE.read_bytes(), content_type="text/html; charset=utf-8")
        else:
            super()._http(sock, request)


def _until(read):
    deadline = time.monotonic() + 12
    while time.monotonic() < deadline:
        if value := read():
            return value
        time.sleep(0.05)
    pytest.fail("timed out waiting for " + str(read))


@contextmanager
def _browser(tmp_path, page_url):
    """Chromium's DevTools socket, using the package's stdlib WebSocket client."""
    chrome = next((p for p in (shutil.which("chromium"), shutil.which("chromium-browser"),
                               shutil.which("google-chrome"),
                               "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
                   if p and Path(p).is_file()), None)
    if chrome is None:
        pytest.skip("Chromium is needed for the browser admission witness")
    profile = tmp_path / "chromium"
    with subprocess.Popen([chrome, "--headless", "--disable-gpu", "--no-first-run",
                           "--no-default-browser-check", "--disable-background-networking",
                           "--remote-debugging-port=0", f"--user-data-dir={profile}", page_url],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) as browser:
        try:
            port_file = profile / "DevToolsActivePort"
            _until(port_file.is_file)
            port = port_file.read_text().splitlines()[0]
            with urlopen(f"http://127.0.0.1:{port}/json/list", timeout=WAIT) as res:
                target = next(t for t in json.load(res) if t["type"] == "page")
            sock = ws.connect(target["webSocketDebuggerUrl"], timeout_s=WAIT)
            try:
                def command(method, params):
                    sock.send_text(json.dumps({"id": 1, "method": method, "params": params}))
                    while True:
                        answer = json.loads(sock.recv_text(time.monotonic() + WAIT))
                        if answer.get("id") == 1:
                            break
                    return answer["result"]

                command("Page.setDownloadBehavior", {"behavior": "allow",
                                                     "downloadPath": str(tmp_path)})
                def evaluate(js):
                    result = command("Runtime.evaluate", {"expression": js, "returnByValue": True,
                                                          "userGesture": True})
                    assert "exceptionDetails" not in result, result.get("exceptionDetails")
                    return result["result"].get("value")
                _until(lambda: evaluate("!!document.querySelector('[data-act=chapter]')"))
                yield evaluate
            finally:
                sock.close()
        finally:
            browser.terminate()


def test_public_harness_switcher_and_docs_chapters(tmp_path):
    with ConsoleRelay() as relay, _browser(tmp_path, relay.http_url) as js:
        assert js("document.querySelector('.landing h1').textContent") == (
            "One encrypted wire for your coding agents and teammates across machines.")
        assert js("[...document.querySelectorAll('.overview strong')].map(s=>s.textContent)") == [
            "wss://crosswire.sh", "NIP-44 v2", "3 roles", "7 clients"]
        assert js("document.querySelector('.quickstart h2').textContent") == (
            "Try It Now — Install & Join in 2 Commands")
        assert not js("document.querySelector('.returning').open")
        js("document.querySelector('[name=handle]').value='alice'")
        harnesses = js("[...document.querySelectorAll('[data-act=harness]')].map(b=>b.textContent)")
        assert harnesses == ["Claude Code", "Codex", "CLI (uv)", "Claude Desktop", "ChatGPT",
                             "Antigravity", "Cursor"]
        prompts = set()
        for harness in harnesses:
            js(f"document.querySelector('[data-act=harness][data-id={json.dumps(harness)}]').click()")
            prompt = js("document.querySelector('#agent-prompt').textContent")
            assert "awowIO/crosswire" in prompt and "ask me for my nm1_ invite" in prompt
            prompts.add(prompt)
            shown = js("document.querySelector('.terminal code').textContent")
            assert js("document.querySelector('.terminal [data-act=copy]').dataset.text") == shown
            install, join = shown.splitlines()
            assert "github.com/awowIO/crosswire" in install and "crosswire join" in join
        assert len(prompts) == len(harnesses)
        trust = Trust.from_mapping({"schema": "cf.transport/1", "relay": relay.url,
                                    "campaign": "camp", "operator_pubkeys": [_npub(_pub(PEER_SK))]})
        token = cli._encode_invite_token(trust, relay.create_invite(), member=None)
        join_url = relay.http_url + "/join/#" + token
        js("const box = document.querySelector('[name=token]'); box.value=" + json.dumps(join_url) +
           ";box.dispatchEvent(new Event('input', {bubbles:true}))")
        js("document.querySelector('[data-id=Codex]').click()")
        assert token in js("document.querySelector('#agent-prompt').textContent")
        assert js("document.querySelector('#prompt-invite').value") == join_url
        js("const draft = document.querySelector('#prompt-invite'); draft.value='';"
           "draft.dispatchEvent(new Event('input', {bubbles:true}))")
        assert not js("document.querySelector('[name=token]').value")
        assert token not in js("document.querySelector('#agent-prompt').textContent")
        specimen = "document.querySelector('.specimen [role=tabpanel]').innerText"
        bus = js(specimen)
        assert all(text in bus for text in ("@alice", "alice/claude-code", "@bob/codex",
                                           "Acknowledged", "✓ signed · E2 · NIP-44 v2"))
        js("document.querySelector('[data-act=specimen][data-id=handoff]').click()")
        assert js("[...document.querySelectorAll('.specimen dt')].map(d=>d.textContent)") == [
            "Original goal", "Open condition", "Evidence & rejected routes", "Next action"]
        js("document.activeElement.dispatchEvent(new KeyboardEvent('keydown', "
           "{key:'ArrowRight', bubbles:true}))")
        assert js("document.activeElement.textContent") == "Write-Only Dropbox"
        assert "Sealed to Alice’s dropbox" in js(specimen)
        assert js("document.querySelector('[name=handle]').value") == "alice"
        assert js("document.querySelectorAll('.previews article').length") == 3
        chapters = [
            ("modes", ["Two Modes on One Relay", "Persona-First", "Org Workspaces"]),
            ("permissions", ["3-Gate ACL Primitives", "POOL <user>/agents",
                             "Concrete Permission Matrix", "#partners-only", "#external-intake"]),
            ("architecture", ["Enrollment & Cross-Pool Encryption Flow",
                              "Physical Architecture Map: Clients vs. Wire vs. Relay Disk"]),
            ("reference", ["CLI Quickstart", "mailbox_board", "GitHub Pages", "Kubernetes",
                           "Multi-Agent Campaign Blueprints"]),
        ]
        for chapter, phrases in chapters:
            js(f"document.querySelector('.previews [data-id={chapter}]').click()")
            active = js("document.querySelector('.chapters [aria-current=page]').dataset.id")
            assert active == chapter
            assert all(p in js("document.querySelector('main').innerText") for p in phrases)
            assert not js("!!document.querySelector('.shell, [data-act=pair], [data-act=lock]')")
            if chapter == "architecture":
                assert js("Array.from(document.querySelectorAll('main svg'), s=>s.getAttribute("
                          "'viewBox'))") == ["0 0 1120 320"] * 2
                sizes = js("Array.from(document.querySelectorAll('main svg'), s => "
                           "[s.clientWidth, s.clientHeight])")
                assert sizes[0] == sizes[1] and sizes[0][1] > 0
                js("document.querySelector('#theme').click()")
                assert js("document.querySelectorAll('main svg[role=img] title').length") == 2
            if chapter == "reference":
                assert js("document.querySelectorAll('main table td code').length") == 6
            js("document.querySelector('.chapters [data-id=switchboard]').click()")
        assert js("!!document.querySelector('[data-form=redeem]')")


def test_browser_redeems_once_backs_up_locks_and_rechecks_membership(tmp_path):
    with ConsoleRelay() as relay:
        trust = Trust.from_mapping({"schema": "cf.transport/1", "relay": relay.url,
                                    "campaign": "camp", "operator_pubkeys": [_npub(_pub(PEER_SK))],
                                    "campaign_key": os.urandom(32).hex()})
        token = cli._encode_invite_token(trust, relay.create_invite(), member=None)
        with _browser(tmp_path, relay.http_url + "/join/#" + token) as js:
            assert not js("location.hash")
            assert js("document.querySelector('[name=token]').value") == token
            assert token in js("document.querySelector('#agent-prompt').textContent")
            assert not js("!!document.querySelector('.shell, [data-act=lock]')")
            js("document.querySelector('[name=handle]').value='alice';"
               "document.querySelector('[data-form=redeem] button').click()")
            _until(lambda: js("!!document.querySelector('.shell')"))
            assert len(relay.members) == 1
            backup = js("document.querySelector('.backup button').textContent")
            assert backup == "Back up your nsec1… key"
            js("document.querySelector('.backup button').click()")
            backup_file = _until(lambda: next(tmp_path.glob("crosswire-*.nsec.txt"), None))
            nsec = backup_file.read_text().strip()
            member = _pub(bech32.decode(bech32.NSEC, nsec))
            assert member in relay.members
            message = next(e for e in relay.stored() if e.kind == int(Kind.MESSAGE))
            assert message.pubkey == member and "alice joined" not in message.content
            assert "alice joined" in js("document.querySelector('.shell').innerText")
            js("document.querySelector('[data-id=permissions]').click()")
            assert js("!!document.querySelector('main table')")
            assert js("!!document.querySelector('[data-act=lock]')")
            js("document.querySelector('[data-act=lock]').click()")
            _until(lambda: js("!!document.querySelector('[data-form=redeem]')"))
            for store in ("localStorage", "sessionStorage"):
                assert not js(f"{store}.getItem('nm.console.v1')")
            assert not js("!!document.querySelector('.shell, [data-act=lock], [data-act=pair]')")
            # The consumed invite cannot admit a second generated identity, even as a pasted URL.
            js("document.querySelector('[name=token]').value=" +
               json.dumps(relay.http_url + "/join/#" + token) + ";"
               "document.querySelector('[data-form=redeem] button').click()")
            _until(lambda: js("!!document.querySelector('[role=alert]')"))
            assert relay.members == {member} and not js("!!document.querySelector('.shell')")

            def returning(key):
                for name, val in (("nsec", key), ("relay", relay.url), ("campaign", "camp")):
                    js(f"document.querySelector('[name={name}]').value={json.dumps(val)}")
                js("document.querySelector('[data-form=sign-in]').requestSubmit()")

            returning(bech32.encode(bech32.NSEC, STRANGER_SK))
            _until(lambda: js("document.querySelector('.errors').innerText.includes('membership')"))
            assert not js("!!document.querySelector('.shell, [data-act=pair], [data-act=lock]')")
            returning(nsec)
            _until(lambda: js("!!document.querySelector('.shell')"))
            assert "alice joined" in js("document.querySelector('.shell').innerText")
            relay.remove_member(member)
            _until(lambda: js("!!document.querySelector('[data-form=sign-in]')"))
            assert not js("!!document.querySelector('.shell, [data-act=lock], [data-act=pair]')")


def test_browser_rejects_a_relay_without_membership_before_spending_an_invite(tmp_path):
    with ConsoleRelay(membership_required=False) as relay, _browser(tmp_path, relay.http_url) as js:
        trust = Trust.from_mapping({"schema": "cf.transport/1", "relay": relay.url,
                                    "campaign": "camp", "operator_pubkeys": [_npub(_pub(PEER_SK))]})
        token = cli._encode_invite_token(trust, relay.create_invite(), member=None)
        js("document.querySelector('[name=token]').value=" + json.dumps(token) +
           ";document.querySelector('[data-form=redeem]').requestSubmit()")
        _until(lambda: js("document.querySelector('.errors').innerText"
                          ".includes('membership_required')"))
        assert not relay.members and not js("!!document.querySelector('.shell, [data-act=lock]')")


def test_extension_sign_in_waits_for_the_authenticated_membership_read(tmp_path):
    """Hold the real relay's answer at the gate. Even with AUTH accepted, no room,
    pair button or key backup is drawn until the protected subscription reaches EOSE."""
    from threading import Event

    checking, release = Event(), Event()

    class SlowMembership(ConsoleRelay):
        def _req(self, connection, sub_id, filters):
            if filters == [{"kinds": [int(Kind.HEARTBEAT)], "limit": 1}]:
                assert connection.pubkey == _pub(FRIEND_SK)
                checking.set()
                if not release.wait(12):
                    return
            super()._req(connection, sub_id, filters)

    with SlowMembership() as relay, _browser(tmp_path, relay.http_url) as js:
        relay.add_member(_pub(FRIEND_SK))
        js("window.nostr = new NM.KeySigner(NM.unhex(" + json.dumps(FRIEND_SK.hex()) + "))")
        js("document.querySelector('[data-act=harness]').click();"
           "document.querySelector('.returning').open=true")
        js("document.querySelector('[name=relay]').value=" + json.dumps(relay.url))
        js("document.querySelector('[data-act=nip07]').click()")
        try:
            assert checking.wait(WAIT)
            assert not js("!!document.querySelector('.shell, .backup, [data-act=pair],"
                          " [data-act=lock], [data-form=invite]')")
        finally:
            release.set()
        _until(lambda: js("!!document.querySelector('.shell')"))
        assert js("document.querySelector('.side').innerText.includes('@me/inbox')")
        assert not js("!!document.querySelector('.backup, [data-act=show-nsec]')")


def test_workstation_console_checks_its_relay_and_stays_locked_after_sign_out(
        tmp_path, workstation, relay):
    info = call(workstation, "GET", "/api/relay-info")
    assert info["advertises_private"] and info["self_pubkey"] == relay.pubkey
    with _browser(tmp_path, workstation.url) as js:
        assert not js("!!document.querySelector('.shell, [data-act=pair]')")
        js("document.querySelector('[data-act=reconnect]').click()")
        _until(lambda: js("!!document.querySelector('.shell')"))
        js("document.querySelector('[data-act=lock]').click()")
        _until(lambda: js("!!document.querySelector('[data-act=reconnect]')"))
        relay.remove_member(workstation.pubkey)
        js("document.querySelector('[data-act=reconnect]').click()")
        _until(lambda: js("document.querySelector('.errors').innerText.includes('membership')"))
        assert not js("!!document.querySelector('.shell, [data-act=pair], [data-act=lock]')")


def test_spent_claim_retry_still_requires_membership_on_the_current_socket(tmp_path):
    class RevokeAfterClaim(ConsoleRelay):
        def _claim(self, event):
            ok, reason = super()._claim(event)
            if ok:
                self.remove_member(event.pubkey)
            return ok, reason

    with RevokeAfterClaim() as relay, _browser(tmp_path, relay.http_url) as js:
        trust = Trust.from_mapping({"schema": "cf.transport/1", "relay": relay.url,
                                    "campaign": "camp", "operator_pubkeys": [_npub(_pub(PEER_SK))]})
        token = cli._encode_invite_token(trust, relay.create_invite(), member=None)
        js("document.querySelector('[name=token]').value=" + json.dumps(token))
        submit = "document.querySelector('[data-form=redeem]').requestSubmit()"
        js(submit)
        _until(lambda: js("document.querySelector('.errors').innerText.includes('membership')"))
        assert not js("!!document.querySelector('.shell, .backup, [data-act=lock]')")
        pk = js("JSON.parse(sessionStorage.getItem('nm.console.v1')).pubkey")
        assert pk and pk not in relay.members
        relay.add_member(pk)
        js(submit)
        _until(lambda: js("!!document.querySelector('.shell')"))
        assert js("!!document.querySelector('.backup')") and relay.members == {pk}
