"""OAuth 2.1 for the HTTP MCP routes (the MCP authorization spec, 2025-06-18 and later):
a client handed nothing but `<origin>/mcp` (ChatGPT, Claude.ai, Claude Desktop, Claude
Code) signs itself in, and the person running the server approves it in one click.

- A request to `/mcp`, `/sse`, `/messages` or `/tools/*` without a bearer is answered
  401 with `WWW-Authenticate: Bearer resource_metadata="<origin>/.well-known/
  oauth-protected-resource"` (RFC 9728), which names this origin as its authorization
  server. `/.well-known/oauth-authorization-server` (RFC 8414; also served as
  `/.well-known/openid-configuration`) names the endpoints below.
- `POST /oauth/register` (RFC 7591) is open and keeps nothing: a client id is the
  client's metadata signed with this home's OAuth key, so anyone may register and no file
  grows by it. A client that asks for `client_secret_post` or `client_secret_basic` gets
  a secret derived the same way; any other is a public client (`none`).
- `GET /oauth/authorize` shows the consent card. `POST /oauth/authorize` is refused from
  another site, and carries the card's CSRF token: a MAC over the very request it
  approves and the owner's proof, rendered to the proven owner alone, so a form posted
  from elsewhere approves nothing, cookie or no cookie. On Authorize it redirects to the
  client's registered `redirect_uri` with a single-use
  code bound to the client, that `redirect_uri`, the PKCE challenge and the persona
  picked. A `redirect_uri` is https, or http on a loopback host (any port on loopback,
  RFC 8252 §7.3); nothing else is registered.
- `POST /oauth/token` exchanges a code (PKCE `S256` or `plain` checked; a code is
  consumed by its first use, right or wrong, and a second use revokes the grant it made)
  or rotates a refresh token. The access token is accepted wherever the server's bearer
  is, and acts as the persona picked on the consent card, and only as it.

Who approves. A consent hands a client the run of a persona, so the card asks the
person running the server to prove it once per browser session: the server's own token
(`<home>/mcp.token`) or the magic URL that carries it, after which a session cookie
(HttpOnly, SameSite=Lax, Path=/oauth) makes every later consent one click. The console
passes `owner_trusted`: it is loopback only, gated on its own Host, and serves its whole
signing page to the same browsers, so its card is one click from the start.

What is kept. `<home>/mcp-oauth.json`, 0600: this home's OAuth key and one record per
grant (client, persona, the sha256 of its current access and refresh tokens), changed
under an flock of `<home>/mcp-oauth.json.lock` that every server of the home takes.
Codes live in memory for their lifetime. Delete a grant from the file to revoke it; delete the file
to revoke every grant and every registered client id."""
from __future__ import annotations

import base64
import binascii
import contextlib
import hashlib
import hmac
import html
import ipaddress
import json
import os
import re
import secrets
import stat
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import unquote_plus, urlencode, urlsplit

from ._files import write_private
from .errors import NostrError
from .profile import ProfileError, slug

OAUTH_FILE = "mcp-oauth.json"
SCHEMA = "nostr-mailbox.oauth/1"
# The `expires_in` this server's contract names for an access token: 30 days. A refresh
# token has no lifetime of its own; it lasts until it is used (and replaced) or revoked.
ACCESS_TOKEN_LIFETIME_S = 2_592_000
# RFC 6749 §4.1.2: "A maximum authorization code lifetime of 10 minutes is RECOMMENDED."
CODE_LIFETIME_S = 600
OWNER_COOKIE = "nm_mcp_owner"
AUTHORIZE, TOKEN, REGISTER = "/oauth/authorize", "/oauth/token", "/oauth/register"
WELL_KNOWN_RESOURCE = "/.well-known/oauth-protected-resource"
WELL_KNOWN_SERVER = "/.well-known/oauth-authorization-server"
WELL_KNOWN_OPENID = "/.well-known/openid-configuration"
GRANT_TYPES = ("authorization_code", "refresh_token")
AUTH_METHODS = ("none", "client_secret_post", "client_secret_basic")
CHALLENGE_METHODS = ("S256", "plain")
# The parameters of an authorization request, as the consent form carries them back.
_REQUEST = ("client_id", "redirect_uri", "response_type", "state", "code_challenge",
            "code_challenge_method", "resource", "scope")
# RFC 7636 §4.1 and §4.2: a verifier, and a challenge, are 43 to 128 unreserved characters.
_PKCE = re.compile(r"[A-Za-z0-9\-._~]{43,128}")
ACCESS_PREFIX, REFRESH_PREFIX, CLIENT_PREFIX, CODE_PREFIX = "nma_", "nmr_", "nmc_", "nmo_"


class OAuthError(NostrError):
    """A request an OAuth endpoint refuses: `error` is its RFC 6749 / 7591 code."""

    def __init__(self, error: str, description: str, *, status: int = 400,
                 headers: dict | None = None):
        super().__init__(description)
        self.error, self.status, self.headers = error, status, headers or {}


class OAuthStoreError(NostrError):
    """`<home>/mcp-oauth.json` cannot be used as it is."""


@dataclass
class Answer:
    """One answer of the consent route: a page, or a redirect to the client."""
    status: int
    body: bytes = b""
    content_type: str | None = None
    headers: dict = field(default_factory=dict)


# ------------------------------------------------------------------- small pieces
def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def _loopback(host: str | None) -> bool:
    if host is None:
        return False
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def redirect_problem(uri) -> str | None:
    """Why `uri` cannot be a redirect URI here, or None: https to a host, or http to a
    loopback host; no fragment (RFC 6749 §3.1.2) and no credentials."""
    if not isinstance(uri, str) or not uri:
        return "a redirect URI is a non-empty string"
    try:
        parts = urlsplit(uri)
        host = parts.hostname
        parts.port                          # noqa: B018 (raises on a port that is no number)
    except ValueError:
        return f"{uri!r} is not a URL"
    if "#" in uri:
        return f"{uri!r} carries a fragment, which a redirect URI may not (RFC 6749 §3.1.2)"
    if "@" in parts.netloc or parts.username is not None or parts.password is not None:
        return f"{uri!r} carries credentials"
    if "\\" in uri or any(ord(c) < 0x21 or ord(c) == 0x7f for c in uri):
        # a browser reads `\` as `/`: `http://evil.example\@localhost/` is evil.example's
        return f"{uri!r} holds a backslash, a space or a control character"
    if parts.scheme == "https" and host:
        return None
    if parts.scheme == "http" and _loopback(host):
        return None
    return (f"{uri!r} is neither https nor http on a loopback host (127.0.0.1, [::1], "
            "localhost): a code is never sent anywhere else")


def _same_redirect(registered: str, asked: str) -> bool:
    """Whether `asked` is `registered`: exactly, or on loopback with another port
    (RFC 8252 §7.3: a native app's loopback port is picked when it runs). `asked` has
    passed `redirect_problem`, so its netloc is a host and a port, nothing else."""
    if asked == registered:
        return True
    mine, theirs = urlsplit(registered), urlsplit(asked)
    host = theirs.netloc.rsplit(":", 1)[0] if theirs.port is not None else theirs.netloc
    return (mine.scheme == "http" and _loopback(mine.hostname)
            and (theirs.scheme, host, theirs.path, theirs.query)
            == (mine.scheme, mine.netloc.rsplit(":", 1)[0] if mine.port is not None
                else mine.netloc, mine.path, mine.query))


def single(parsed: dict[str, list[str]]) -> dict[str, str]:
    """A parsed query or form as one value per name. RFC 6749 §3.1: a parameter sent
    more than once is refused."""
    twice = sorted(name for name, values in parsed.items() if len(values) > 1)
    if twice:
        raise OAuthError("invalid_request", f"parameters sent more than once: {twice}")
    return {name: values[0] for name, values in parsed.items()}


def _cookies(header: str | None) -> dict[str, str]:
    out = {}
    for part in (header or "").split(";"):
        name, eq, value = part.strip().partition("=")
        if eq:
            out.setdefault(name, value)
    return out


# ------------------------------------------------------------------- the server
class OAuth:
    """The authorization server of one home's HTTP MCP routes. `bearer` is the server's
    own token, the owner's proof on the consent card; `owner_trusted` skips that proof
    (the console). Safe to use from several threads."""

    def __init__(self, path: str | Path, *, bearer: str, owner_trusted: bool = False,
                 clock: Callable[[], float] = time.time):
        self.path, self._bearer, self.owner_trusted = Path(path), bearer, owner_trusted
        self._clock = clock
        self._lock = threading.Lock()
        self._held: tuple[tuple[int, int] | None, dict] | None = None
        self._codes: dict[str, dict] = {}           # sha256(code) -> what it was bound to
        self._spent: dict[str, tuple[str, float]] = {}  # sha256(code) -> (grant id, expiry)

    # ---- the file
    def _read(self) -> dict:
        try:
            mode = stat.S_IMODE(self.path.stat().st_mode)
        except FileNotFoundError:
            return {"schema": SCHEMA, "key": None, "grants": {}}
        if mode & 0o077:
            raise OAuthStoreError(f"{self.path} is mode {mode:04o}; it holds this server's "
                                  f"OAuth key and grants and must be 0600 (chmod 600 "
                                  f"{self.path})")
        try:
            body = json.loads(self.path.read_text())
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise OAuthStoreError(f"cannot read {self.path}: {exc}") from exc
        if not isinstance(body, dict) or body.get("schema") != SCHEMA or not isinstance(
                body.get("grants"), dict):
            raise OAuthStoreError(f"{self.path} is not a {SCHEMA} file")
        return body

    def _stamp(self) -> tuple[int, int, int] | None:
        """What tells one version of the file from the next: `write_private` replaces
        it, so its inode changes even when its size and mtime do not."""
        try:
            held = self.path.stat()
        except FileNotFoundError:
            return None
        return held.st_ino, held.st_mtime_ns, held.st_size

    @contextlib.contextmanager
    def _writing(self):
        """The file to change, read afresh and held: this instance's threads queue on
        `_lock` (taken by the caller), and every other server of this home (the console
        beside `mcp --http`) on an flock of `<file>.lock`, so no grant written by one is
        lost to another's write."""
        # POSIX only, as write_private's fchmod is
        import fcntl

        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd = os.open(self.path.with_name(self.path.name + ".lock"),
                     os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            self._held = None
            yield self._current()
        finally:
            os.close(fd)                    # and with it the flock

    def _current(self) -> dict:
        """The file as it is now: read again only when it changed (another server of
        this home, the console or `mcp --http`, may have written it)."""
        stamp = self._stamp()
        if self._held is None or self._held[0] != stamp:
            self._held = (stamp, self._read())
        return self._held[1]

    def _write(self, body: dict) -> None:
        write_private(self.path, json.dumps(body, indent=2, sort_keys=True) + "\n")
        self._held = (self._stamp(), body)

    def _key(self) -> bytes:
        with self._lock:
            body = self._current()
            if body.get("key") is None:
                with self._writing() as body:
                    if body.get("key") is None:
                        body = {**body, "key": secrets.token_hex(32)}
                        self._write(body)
            return bytes.fromhex(body["key"])

    def _mac(self, purpose: str, text: str) -> str:
        return _b64(hmac.new(self._key(), f"{purpose}\0{text}".encode(), hashlib.sha256).digest())

    # ---- metadata
    @staticmethod
    def protected_resource(origin: str, resource_path: str) -> dict:
        """RFC 9728: the resource at `origin` + `resource_path` and who authorizes it."""
        return {"resource": origin + resource_path, "authorization_servers": [origin],
                "bearer_methods_supported": ["header", "query"],
                "resource_name": "Nostr Mailbox"}

    @staticmethod
    def metadata(origin: str) -> dict:
        """RFC 8414 authorization server metadata, the issuer being `origin`."""
        return {"issuer": origin,
                "authorization_endpoint": origin + AUTHORIZE,
                "token_endpoint": origin + TOKEN,
                "registration_endpoint": origin + REGISTER,
                "response_types_supported": ["code"],
                "response_modes_supported": ["query"],
                "grant_types_supported": list(GRANT_TYPES),
                "code_challenge_methods_supported": list(CHALLENGE_METHODS),
                "token_endpoint_auth_methods_supported": list(AUTH_METHODS),
                "authorization_response_iss_parameter_supported": True}

    # ---- clients (RFC 7591), kept by no one
    def register(self, body: dict) -> dict:
        uris = body.get("redirect_uris")
        if not isinstance(uris, list) or not uris:
            raise OAuthError("invalid_redirect_uri", "redirect_uris is a non-empty list")
        for uri in uris:
            problem = redirect_problem(uri)
            if problem:
                raise OAuthError("invalid_redirect_uri", problem)
        for name, allowed in (("grant_types", GRANT_TYPES), ("response_types", ("code",))):
            asked = body.get(name)
            if asked is not None and (not isinstance(asked, list)
                                      or not all(isinstance(one, str) for one in asked)
                                      or not set(asked) <= set(allowed)):
                raise OAuthError("invalid_client_metadata",
                                 f"{name} {asked!r}: this server offers {list(allowed)}")
        method = body.get("token_endpoint_auth_method", "none")
        if method not in AUTH_METHODS:
            raise OAuthError("invalid_client_metadata", f"token_endpoint_auth_method "
                             f"{method!r}: this server offers {list(AUTH_METHODS)}")
        name = body.get("client_name")
        if name is not None and not isinstance(name, str):
            raise OAuthError("invalid_client_metadata", "client_name is a string")
        issued = int(self._clock())
        meta = {"n": name or "An MCP client", "r": uris, "a": method, "t": issued}
        packed = _b64(json.dumps(meta, separators=(",", ":"), sort_keys=True).encode())
        client_id = f"{CLIENT_PREFIX}{packed}.{self._mac('client', packed)}"
        out = {"client_id": client_id, "client_id_issued_at": issued,
               "client_name": meta["n"], "redirect_uris": uris,
               "grant_types": list(GRANT_TYPES), "response_types": ["code"],
               "token_endpoint_auth_method": method}
        if method != "none":
            out.update(client_secret=self._mac("secret", client_id), client_secret_expires_at=0)
        return out

    def client(self, client_id) -> dict | None:
        """The metadata `client_id` carries, or None when this home did not sign it."""
        if not isinstance(client_id, str) or not client_id.startswith(CLIENT_PREFIX):
            return None
        packed, _, mac = client_id[len(CLIENT_PREFIX):].partition(".")
        if not hmac.compare_digest(mac.encode(), self._mac("client", packed).encode()):
            return None
        try:
            meta = json.loads(_unb64(packed))
        except (binascii.Error, ValueError, UnicodeDecodeError):
            return None
        return meta if isinstance(meta, dict) else None

    # ---- the owner
    def _owner_value(self) -> str:
        return self._mac("owner", _sha256(self._bearer))

    def owner(self, cookie_header: str | None) -> bool:
        """Whether this request comes from the person running the server."""
        if self.owner_trusted:
            return True
        given = _cookies(cookie_header).get(OWNER_COOKIE)
        return given is not None and hmac.compare_digest(given.encode(),
                                                         self._owner_value().encode())

    def _proves_owner(self, text: str) -> bool:
        """The server's token, or a pasted magic URL `…/mcp/s/<token>…` that carries it."""
        text = (text or "").strip()
        if "/mcp/s/" in text:
            text = text.split("/mcp/s/", 1)[1].split("/", 1)[0].split("?", 1)[0]
        text = text.removeprefix("Bearer ").strip()
        return bool(text) and hmac.compare_digest(text.encode(), self._bearer.encode())

    def _owner_cookie(self, *, secure: bool) -> str:
        return (f"{OWNER_COOKIE}={self._owner_value()}; Path=/oauth; HttpOnly; SameSite=Lax"
                + ("; Secure" if secure else ""))

    # ---- the consent card
    def _csrf(self, request: dict, *, owned: bool) -> str:
        """The CSRF token of a form answering `request`. The owner's step carries one
        bound to the request alone (anyone may load that page, and it asks for the
        token). The card carries one bound to the request and to the owner's proof: it
        is rendered to the proven owner alone, so a form posted from anywhere else, with
        or without the owner's cookie, cannot carry it."""
        said = json.dumps([request.get(k) for k in _REQUEST])
        return self._mac("csrf-owner", f"{said}\0{self._owner_value()}") if owned else \
            self._mac("csrf", said)

    def _checked(self, request: dict) -> tuple[dict, str]:
        """The client and redirect URI a request names. One that names no client of
        this home, or a redirect URI not registered for it, is answered on this page:
        nothing is sent to an address that was never registered (RFC 6749 §4.1.2.1)."""
        meta = self.client(request.get("client_id"))
        if meta is None:
            raise OAuthError("invalid_client", "this server registered no such client: the "
                             "client registers again at " + REGISTER)
        asked = request.get("redirect_uri")
        if asked is None:
            if len(meta["r"]) != 1:
                raise OAuthError("invalid_request", "the client registered several redirect "
                                 "URIs, and the request names none of them")
            return meta, meta["r"][0]
        problem = redirect_problem(asked)
        if problem:
            raise OAuthError("invalid_request", f"redirect_uri: {problem}")
        if not any(_same_redirect(registered, asked) for registered in meta["r"]):
            raise OAuthError("invalid_request", f"redirect_uri {asked!r} is not one this "
                             "client registered")
        return meta, asked

    def _pkce_problem(self, request: dict) -> tuple[str, str] | None:
        if request.get("response_type") != "code":
            return ("unsupported_response_type",
                    f"response_type {request.get('response_type')!r}: this server answers "
                    "'code' only")
        challenge = request.get("code_challenge")
        if not challenge:
            return "invalid_request", "PKCE is required: send a code_challenge (S256)"
        if request.get("code_challenge_method", "plain") not in CHALLENGE_METHODS:
            return "invalid_request", (f"code_challenge_method must be one of "
                                       f"{list(CHALLENGE_METHODS)}")
        if not _PKCE.fullmatch(challenge):
            return "invalid_request", "a code_challenge is 43 to 128 unreserved characters"
        return None

    @staticmethod
    def _to_client(redirect: str, params: dict) -> Answer:
        joined = "&" if urlsplit(redirect).query else "?"
        return Answer(302, headers={"Location": redirect + joined + urlencode(params)})

    def authorize(self, request: dict, *, origin: str, personas: list[str], default: str,
                  owner: bool, form: dict | None = None, secure: bool = False) -> Answer:
        """`GET /oauth/authorize` (`form` None): the consent card for `request`.
        `POST /oauth/authorize` (`form`, the request carried back with its CSRF token,
        and either `step=owner` with the owner's token or `decision` approve or deny)."""
        try:
            meta, redirect = self._checked(request)
        except OAuthError as exc:
            return self._page(400, error=f"This sign-in cannot continue: {exc}")
        back = {k: v for k, v in (("state", request.get("state")), ("iss", origin)) if v}
        problem = self._pkce_problem(request)
        if problem:
            return self._to_client(redirect, {"error": problem[0],
                                              "error_description": problem[1], **back})
        card = {"name": meta["n"], "redirect": redirect, "origin": origin,
                "fields": {k: request[k] for k in _REQUEST if request.get(k) is not None},
                "personas": personas, "default": default}
        mine, anyone = self._csrf(request, owned=True), self._csrf(request, owned=False)
        if form is None:
            return self._page(200, **card, owner=owner, csrf=mine if owner else anyone)
        if form.get("step") == "owner":
            if not hmac.compare_digest((form.get("csrf") or "").encode(), anyone.encode()):
                return self._forged()
            if not owner and not self._proves_owner(form.get("owner_token", "")):
                return self._page(403, **card, owner=False, csrf=anyone,
                                  error="That is not this server's token. Paste the token "
                                        "in its mcp.token, or the magic URL it printed.")
            page = self._page(200, **card, owner=True, csrf=mine)   # proven: now the card
            if not self.owner_trusted:
                page.headers["Set-Cookie"] = self._owner_cookie(secure=secure)
            return page
        if not hmac.compare_digest((form.get("csrf") or "").encode(), mine.encode()):
            return self._forged()
        if form.get("decision") == "deny":
            return self._to_client(redirect, {"error": "access_denied",
                                              "error_description": "the owner declined",
                                              **back})
        if form.get("decision") != "approve":
            return self._page(400, **card, owner=True, csrf=mine,
                              error="Choose Authorize or Cancel.")
        persona = (form.get("new_persona") or "").strip() or form.get("persona") or default
        try:
            slug(persona, "persona")
        except ProfileError as exc:
            return self._page(400, **card, owner=True, csrf=mine, error=str(exc))
        code = CODE_PREFIX + secrets.token_urlsafe(32)
        now = self._clock()
        with self._lock:
            for spent in [k for k, v in self._codes.items() if v["expires"] <= now]:
                del self._codes[spent]
            for spent in [k for k, (_, expires) in self._spent.items() if expires <= now]:
                del self._spent[spent]
            self._codes[_sha256(code)] = {
                "client_id": request["client_id"], "client_name": meta["n"],
                "redirect_uri": redirect, "asked_redirect": "redirect_uri" in request,
                "challenge": request["code_challenge"],
                "method": request.get("code_challenge_method", "plain"),
                "persona": persona, "resource": request.get("resource"),
                "scope": request.get("scope"), "expires": now + CODE_LIFETIME_S}
        return self._to_client(redirect, {"code": code, **back})

    def _forged(self) -> Answer:
        return self._page(403, error="This form is not one this server showed its owner (its "
                                     "CSRF token does not match). Start the sign-in again "
                                     "from the app.")

    def _page(self, status: int, *, error: str | None = None, owner: bool = True,
              name: str | None = None, **card) -> Answer:
        return Answer(status, consent_page(name=name, owner=owner, error=error, **card).encode(),
                      "text/html; charset=utf-8",
                      {"Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; "
                                                  "frame-ancestors 'none'; base-uri 'none'",
                       # same-origin, never no-referrer: under no-referrer a browser
                       # sends the card's form post with `Origin: null`, which is refused
                       "X-Frame-Options": "DENY", "Referrer-Policy": "same-origin"})

    # ---- tokens
    def _client_of(self, form: dict, authorization: str | None) -> tuple[str, dict]:
        """The client a token request authenticates as (RFC 6749 §2.3.1)."""
        basic_id = basic_secret = None
        scheme, _, credentials = (authorization or "").partition(" ")
        if scheme.lower() == "basic":
            try:
                pair = base64.b64decode(credentials.strip(), validate=True).decode()
            except (binascii.Error, UnicodeDecodeError) as exc:
                raise OAuthError("invalid_client", "unreadable Basic credentials", status=401,
                                 headers={"WWW-Authenticate": 'Basic realm="oauth"'}) from exc
            basic_id, _, basic_secret = (unquote_plus(p) for p in pair.partition(":"))
        client_id = basic_id or form.get("client_id")
        meta = self.client(client_id)
        if meta is None:
            raise OAuthError("invalid_client", "this server registered no such client", status=401)
        if meta["a"] != "none":
            given = basic_secret if basic_id else form.get("client_secret")
            if not given or not hmac.compare_digest(given.encode(),
                                                    self._mac("secret", client_id).encode()):
                raise OAuthError("invalid_client", "the client secret is missing or wrong",
                                 status=401)
        return client_id, meta

    def token(self, form: dict, authorization: str | None = None) -> dict:
        """`POST /oauth/token`: a code for tokens, or a refresh token for new ones."""
        kind = form.get("grant_type")
        if kind not in GRANT_TYPES:
            raise OAuthError("unsupported_grant_type",
                             f"grant_type {kind!r}: this server offers {list(GRANT_TYPES)}")
        client_id, _ = self._client_of(form, authorization)
        if kind == "authorization_code":
            return self._exchange(form, client_id)
        return self._refresh(form, client_id)

    def _exchange(self, form: dict, client_id: str) -> dict:
        """The code's grant, made once. The code is spent by its first use, right or
        wrong, and the whole exchange holds the lock: a replay arriving meanwhile finds
        the grant this one made, and revokes it (RFC 6749 §4.1.2)."""
        digest = _sha256(form.get("code") or "")
        with self._lock:
            bound = self._codes.pop(digest, None)
            if bound is None:
                spent = self._spent.pop(digest, None)
                if spent is not None and spent[0]:
                    with self._writing():
                        self._revoke(spent[0])
                raise OAuthError("invalid_grant", "the code is unknown, used or expired")
            self._spent[digest] = ("", bound["expires"])     # spent, and made nothing yet
            if bound["expires"] <= self._clock():
                raise OAuthError("invalid_grant", "the code expired")
            if bound["client_id"] != client_id:
                raise OAuthError("invalid_grant", "the code was issued to another client")
            if form.get("redirect_uri", bound["redirect_uri"]) != bound["redirect_uri"] or (
                    bound["asked_redirect"] and "redirect_uri" not in form):
                raise OAuthError("invalid_grant", "redirect_uri is not the one the code was "
                                                  "issued for")
            verifier = form.get("code_verifier") or ""
            if not _PKCE.fullmatch(verifier):
                raise OAuthError("invalid_grant", "a code_verifier is 43 to 128 unreserved "
                                                  "characters (RFC 7636 §4.1)")
            made = (_b64(hashlib.sha256(verifier.encode()).digest())
                    if bound["method"] == "S256" else verifier)
            if not hmac.compare_digest(made.encode(), bound["challenge"].encode()):
                raise OAuthError("invalid_grant", "the code_verifier does not match the "
                                                  "code_challenge; the code is spent")
            grant_id = secrets.token_hex(16)
            record = {"client_id": client_id, "client_name": bound["client_name"],
                      "persona": bound["persona"], "redirect_uri": bound["redirect_uri"],
                      "resource": bound["resource"], "scope": bound["scope"],
                      "created_at": int(self._clock())}
            self._spent[digest] = (grant_id, bound["expires"])
            with self._writing():
                return self._issue(grant_id, record)

    def _refresh(self, form: dict, client_id: str) -> dict:
        digest = _sha256(form.get("refresh_token") or "")
        with self._lock, self._writing() as body:   # one rotation per token, on any server
            grants = body["grants"]
            found = next((gid for gid, g in grants.items()
                          if hmac.compare_digest(g["refresh_sha256"], digest)), None)
            if found is None:
                raise OAuthError("invalid_grant", "the refresh token is unknown, replaced or "
                                                  "revoked")
            if grants[found]["client_id"] != client_id:
                raise OAuthError("invalid_grant", "the refresh token was issued to another "
                                                  "client")
            return self._issue(found, dict(grants[found]))

    def _issue(self, grant_id: str, record: dict) -> dict:
        """New access and refresh tokens for `grant_id` (`_lock` and `_writing` held):
        the previous pair stops working."""
        access = ACCESS_PREFIX + secrets.token_urlsafe(32)
        refresh = REFRESH_PREFIX + secrets.token_urlsafe(32)
        record.update(access_sha256=_sha256(access), refresh_sha256=_sha256(refresh),
                      access_expires_at=int(self._clock()) + ACCESS_TOKEN_LIFETIME_S)
        body = self._current()
        self._write({**body, "grants": {**body["grants"], grant_id: record}})
        out = {"access_token": access, "token_type": "Bearer",
               "expires_in": ACCESS_TOKEN_LIFETIME_S, "refresh_token": refresh}
        if record.get("scope"):
            out["scope"] = record["scope"]
        return out

    def _revoke(self, grant_id: str) -> None:
        """Forget `grant_id` (`_lock` and `_writing` held)."""
        body = self._current()
        if grant_id in body["grants"]:
            self._write({**body, "grants": {k: v for k, v in body["grants"].items()
                                            if k != grant_id}})

    def grant_for(self, token: str) -> tuple[str, str] | None:
        """The grant an access token belongs to and the persona it acts as, or None
        when it is none of this home's live ones."""
        if not token.startswith(ACCESS_PREFIX):
            return None
        digest, now = _sha256(token), self._clock()
        with self._lock:
            grants = self._current()["grants"]
        for grant_id, record in grants.items():
            if hmac.compare_digest(record.get("access_sha256", ""), digest):
                return (grant_id, record["persona"]) if record["access_expires_at"] > now \
                    else None
        return None


# ------------------------------------------------------------------- the page
_STYLE = """
:root{--bg:#f4f5f8;--card:#fff;--ink:#15171b;--muted:#596270;--line:#d8dce3;--field:#fff;
--accent:#4f3bd9;--accent-ink:#fff;--bad:#a3260f;--bad-bg:#fdece7;--chip:#eef0f4}
@media (prefers-color-scheme:dark){:root{--bg:#0e1014;--card:#161920;--ink:#e7e9ee;--muted:#9aa3b0;
--line:#2a2f3a;--field:#0f1217;--accent:#8f7dff;--accent-ink:#0e1014;--bad:#ff9a80;--bad-bg:#2a1712;
--chip:#20242d}}
*{box-sizing:border-box}
html,body{margin:0}
body{min-height:100vh;background:var(--bg);color:var(--ink);display:flex;align-items:center;
font:16px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{width:100%;max-width:none;padding:clamp(20px,4vw,64px)}
.card{width:100%;background:var(--card);border:1px solid var(--line);border-radius:18px;
padding:clamp(20px,3.2vw,44px);display:grid;gap:clamp(20px,3vw,40px);
grid-template-columns:repeat(auto-fit,minmax(min(100%,24rem),1fr))}
.brand{font-size:.8rem;letter-spacing:.08em;text-transform:uppercase;color:var(--muted);
margin:0 0 10px}
h1{font-size:clamp(1.35rem,2.6vw,2.1rem);line-height:1.2;margin:0 0 14px}
h1 code{font:inherit;color:var(--accent)}
p{margin:0 0 12px;color:var(--muted)}
dl{display:grid;grid-template-columns:max-content 1fr;gap:8px 16px;margin:18px 0 0}
dt{color:var(--muted)}dd{margin:0;overflow-wrap:anywhere}
dd code{background:var(--chip);border-radius:6px;padding:1px 6px;font-size:.92em}
form{display:flex;flex-direction:column;gap:16px;align-self:center}
label{font-weight:600;display:block;margin-bottom:6px}
select,input{width:100%;font:inherit;color:var(--ink);background:var(--field);
border:1px solid var(--line);border-radius:10px;padding:12px 14px}
details summary{cursor:pointer;color:var(--muted)}details input{margin-top:10px}
.persona{background:var(--chip);border-radius:10px;padding:12px 14px;font-weight:600}
.go{width:100%;font:inherit;font-size:1.15rem;font-weight:700;padding:16px;border:0;
border-radius:12px;background:var(--accent);color:var(--accent-ink);cursor:pointer}
.go:hover{filter:brightness(1.08)}
.no{background:none;border:1px solid var(--line);color:var(--muted);font:inherit;padding:12px;
border-radius:12px;cursor:pointer}
.bad{background:var(--bad-bg);color:var(--bad);border-radius:10px;padding:12px 14px;margin:0}
.small{font-size:.88rem}
"""


def consent_page(*, name: str | None, owner: bool, error: str | None, redirect: str = "",
                 origin: str = "", fields: dict | None = None, csrf: str = "",
                 personas: list[str] | None = None, default: str = "") -> str:
    """The consent card: who asks, where it returns, as which persona; or, before the
    owner has proven themselves in this browser, the one field that proves it. With no
    `name`, only `error` (a request that names no client of this home)."""
    esc = html.escape
    alert = f'<p class="bad" role="alert">{esc(error)}</p>' if error else ""
    if name is None:
        title, body = "Sign-in cannot continue", f"<section><p class=brand>Nostr Mailbox</p>" \
            f"<h1>This sign-in cannot continue</h1>{alert}<p>Start again from the app that " \
            "sent you here.</p></section>"
        return _document(title, body)
    hidden = "".join(f'<input type="hidden" name="{esc(k)}" value="{esc(v)}">'
                     for k, v in {**(fields or {}), "csrf": csrf}.items())
    where = urlsplit(redirect)
    about = (f"<section><p class=brand>Nostr Mailbox</p>"
             f"<h1>Authorize <code>{esc(name)}</code> to connect to Nostr Mailbox</h1>"
             "<p>It will use this server's mailbox tools (list, invite, join, post, watch and "
             "the board) as the persona you choose, and only as it, until you revoke it.</p>"
             f"<dl><dt>App</dt><dd>{esc(name)}</dd>"
             f"<dt>Returns to</dt><dd><code>{esc(where.scheme)}://{esc(where.netloc)}</code></dd>"
             f"<dt>Server</dt><dd><code>{esc(origin)}</code></dd></dl></section>")
    if not owner:
        form = (f'<form method="post" action="{AUTHORIZE}">{hidden}'
                '<input type="hidden" name="step" value="owner">'
                '<div><label for="owner_token">Prove you run this server</label>'
                '<input id="owner_token" name="owner_token" type="password" autocomplete="off" '
                'required placeholder="its token, or the magic URL it printed" autofocus></div>'
                f'{alert}<button class="go" type="submit">Continue</button>'
                '<p class="small">Asked once per browser session: the token is in the '
                "server's mcp.token, and the magic URL (…/mcp/s/…) carries it. A page anyone "
                "can reach must not hand out your mailbox, so the first sign-in asks.</p>"
                "</form>")
        return _document(f"Authorize {name} · Nostr Mailbox", about + form)
    names = list(dict.fromkeys([default, *(personas or [])]))
    if len(names) == 1:
        pick = (f'<div><label>Persona</label><div class="persona">{esc(names[0])}</div>'
                f'<input type="hidden" name="persona" value="{esc(names[0])}"></div>')
    else:
        options = "".join(f'<option value="{esc(n)}"{" selected" if n == default else ""}>'
                          f'{esc(n)}{" (default)" if n == default else ""}</option>'
                          for n in names)
        pick = (f'<div><label for="persona">Persona</label>'
                f'<select id="persona" name="persona">{options}</select></div>')
    form = (f'<form method="post" action="{AUTHORIZE}">{hidden}{pick}'
            '<details><summary>Use a new persona instead</summary>'
            '<input name="new_persona" placeholder="e.g. chatgpt" '
            'pattern="[a-z0-9][a-z0-9._\\-]{0,63}" '
            'autocomplete="off" aria-label="New persona name"></details>'
            f'{alert}<button class="go" type="submit" name="decision" value="approve" autofocus>'
            'Authorize</button>'
            '<button class="no" type="submit" name="decision" value="deny">Cancel</button>'
            "</form>")
    return _document(f"Authorize {name} · Nostr Mailbox", about + form)


def _document(title: str, inner: str) -> str:
    return ("<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n"
            "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
            "<meta name=\"color-scheme\" content=\"light dark\">\n"
            f"<title>{html.escape(title)}</title>\n<style>{_STYLE}</style>\n</head>\n"
            f"<body>\n<main><div class=\"card\">{inner}</div></main>\n</body>\n</html>\n")


__all__ = ["ACCESS_TOKEN_LIFETIME_S", "CODE_LIFETIME_S", "OAUTH_FILE", "OAuth", "OAuthError",
           "OAuthStoreError", "consent_page", "redirect_problem", "single"]
