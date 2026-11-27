"""`nostr-mailbox mcp --http`: the six MCP tools over HTTP. `nostr-mailbox ui` serves the
same routes beside its console.

Three wires carry the JSON-RPC 2.0 that `mcp.handle_rpc` answers on stdio:

- Streamable HTTP (MCP 2025-03-26 and later). `POST /mcp` takes one message or a batch
  and answers `application/json`, or `text/event-stream` when the client accepts only
  that. A notification or a response alone is answered 202. `initialize` opens a session
  and names it in `Mcp-Session-Id`. A request naming a session this server does not hold
  (closed, or never opened) is answered 404, and one naming none is served without a
  session. `GET /mcp` (Accept: text/event-stream) holds a stream open; this server sends
  nothing on it unasked, so it carries one comment and stays open until the client
  leaves or `DELETE /mcp` closes its session.
- HTTP+SSE (MCP 2024-11-05). `GET /sse` opens a session and its stream, whose first
  event names `/messages?session_id=<sid>`. Each `POST` there is answered on that stream
  as `event: message`, and in the response body too, for a client that reads either.
- OpenAPI 3.1 (ChatGPT Custom GPT Actions). `GET /openapi.json` describes
  `POST /tools/<tool>`: the body is the tool's arguments, the answer what the tool says,
  or `{"error", "type"}` with a 4xx or 5xx status.

Who may call. Every route but `/openapi.json` and the CORS preflight needs
`Authorization: Bearer <token>`. The token is `<home>/mcp.token` (0600, made on first
use) unless `--token` or `--token-file` names another; the console uses its home's.
`--no-auth` drops the bearer on a loopback bind only, and then `Host` must name loopback,
which a DNS-rebinding page cannot (it names its own). An `Origin`, when one is sent, must
be a loopback origin or this server's own, whatever the auth (403): a page on another
site is never served. A bind beyond loopback without a bearer is refused.

What a client may do. An HTTP client may be on another machine, so it is offered no
argument naming a file on this one (`mcp.LOCAL_FILE_ARGUMENTS`). It acts as any persona
of the home, as a stdio client does: serve a dedicated `--home` to anyone who should
reach only one. One tool call runs at a time (`mcp.call_tool`), as on stdio, so a watch
that waits holds the others for that long. A request body holds at most
`mcp.MAX_FRAME_BYTES` (413). A stream waits on its socket and a wake pipe: nothing
polls."""
from __future__ import annotations

import argparse
import contextlib
import hmac
import ipaddress
import itertools
import json
import re
import secrets
import selectors
import shlex
import socket
import stat
import sys
import threading
import traceback
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from . import __version__, mcp
from ._files import write_private
from .blossom import BlossomError
from .errors import NostrError
from .event import DEFAULT_WAIT_S
from .identity import home
from .relay import RelayError

DEFAULT_HOST, DEFAULT_PORT = "127.0.0.1", 7891     # the console is 7890
TOKEN_FILE = "mcp.token"
MCP, SSE, MESSAGES, OPENAPI, TOOLS_PREFIX = "/mcp", "/sse", "/messages", "/openapi.json", "/tools/"
SESSION_HEADER, VERSION_HEADER = "Mcp-Session-Id", "MCP-Protocol-Version"
ALLOW_METHODS = "GET, POST, DELETE, OPTIONS"
# What a browser client sends: the four every MCP request may carry, the version header
# of 2025-06-18 and later, and the header a stream resumes with.
ALLOW_HEADERS = ("Authorization, Content-Type, Accept, Mcp-Session-Id, MCP-Protocol-Version, "
                 "Last-Event-ID")
# ChatGPT's GPT builder refuses an operation description longer than this; the whole
# tool description goes in the request body's schema instead.
GPT_OPERATION_DESCRIPTION_CHARS = 300
SUMMARIES = {
    "mailbox_list": "List this machine's personas, orgs, channels and keyrings",
    "mailbox_invite": "Mint a single-use invite into a channel or an org",
    "mailbox_join": "Join a relay, org or channel from an nm1_ invite",
    "mailbox_post": "Post a message to a channel",
    "mailbox_watch": "Read this seat's unsettled messages or the history, and ack one",
    "mailbox_board": "Read or write a channel's Route Board, claims, handoffs and checkpoints",
}
_TOKEN = re.compile(r"[\x21-\x7e]+")        # what a header carries: visible ASCII, no space


class McpHttpError(NostrError):
    """A setting or a request this HTTP server refuses."""


class _Status(McpHttpError):
    """A request answered with `status` and why, before or instead of running anything.
    `rpc` is the JSON-RPC error code of a route that speaks JSON-RPC, else None."""

    def __init__(self, status: int, message: str, *, rpc: int | None = None,
                 kind: str | None = None, headers: dict | None = None):
        super().__init__(message)
        self.status, self.rpc, self.headers = status, rpc, headers or {}
        self.kind = kind or HTTPStatus(status).phrase.replace(" ", "")


# ----------------------------------------------------------------- where, and who
def mcp_address(text: str) -> tuple[str | None, int | None]:
    """`[[HOST:]PORT]` as (host, port), each None when not given: `7891`,
    `0.0.0.0:7891`, `[::1]:7891`, `localhost`, `::1`."""
    text = text.strip()
    host, port = None, None
    if text.startswith("["):
        end = text.find("]")
        rest = text[end + 1:] if end > 0 else None
        if rest is None or (rest and not rest.startswith(":")):
            raise argparse.ArgumentTypeError(f"{text!r}: write an IPv6 host as [::1] or [::1]:PORT")
        host, port = text[1:end], rest[1:] if rest else None
    elif text.count(":") == 1:
        host, port = text.split(":")
    elif text.isdigit():
        port = text
    elif text:
        host = text                         # a name, or an IPv6 address with no port
    if port is not None:
        if not port.isdigit() or int(port) > 65535:
            raise argparse.ArgumentTypeError(f"{text!r}: port {port!r} is not 0-65535")
        port = int(port)
    return host or None, port


def http_address(http, bind, port: int | None) -> tuple[str, int] | None:
    """Where `mcp` serves HTTP, or None for stdio. `--http [[HOST:]PORT]`, `--bind
    HOST:PORT` and `--port PORT` each mean HTTP; what none names is 127.0.0.1:7891."""
    if http is not None and bind is not None:
        raise McpHttpError("--http and --bind both name the address; give one")
    given = http if http is not None else bind
    if given is None and port is None:
        return None
    host, at = given or (None, None)
    if port is not None:
        if not 0 <= port <= 65535:
            raise McpHttpError(f"--port {port} is not 0-65535")
        if at is not None and at != port:
            raise McpHttpError(f"two ports: {at} in the address and --port {port}")
        at = port
    return host or DEFAULT_HOST, DEFAULT_PORT if at is None else at


def is_loopback(host: str) -> bool:
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _host_name(header: str | None) -> str | None:
    """The host a `Host` header names, without its port: `a:1` → `a`, `[::1]:7` → `::1`."""
    if not header:
        return None
    if header.startswith("["):
        end = header.find("]")
        return header[1:end] if end > 0 else None
    return header.partition(":")[0]


def loopback_host(header: str | None) -> bool:
    """Whether a `Host` header names loopback (127.0.0.1, localhost, [::1]), any port."""
    name = _host_name(header)
    return name is not None and is_loopback(name)


def origin_allowed(origin: str | None, host: str | None) -> bool:
    """Whether a request's `Origin` may be served: none (not a browser, or a same-origin
    GET), a loopback origin, or this server's own (the one its `Host` names)."""
    if origin is None:
        return True
    parts = urlsplit(origin)
    try:
        name = parts.hostname
    except ValueError:                      # an Origin no browser sends
        return False
    if parts.scheme not in ("http", "https") or not name:
        return False                        # `null`: a sandboxed frame, a file
    return is_loopback(name) or (host is not None and parts.netloc.lower() == host.lower())


def check_token(token: str, what: str) -> str:
    if not _TOKEN.fullmatch(token):
        raise McpHttpError(f"{what} is not a bearer token: one word of visible ASCII")
    return token


def load_token(path: str | Path) -> str:
    """The bearer kept in `path`, made there first (0600, 32 random bytes, as strong as
    the console's own token) when the file is absent. Refused when anyone but this user
    can read it."""
    path = Path(path).expanduser()
    if not path.exists():
        # FileExistsError: another server made it between these two lines. Its token is
        # the one, and it is read below like any other.
        with contextlib.suppress(FileExistsError):
            write_private(path, secrets.token_urlsafe(32) + "\n", exclusive=True)
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & 0o077:
        raise McpHttpError(f"{path} is mode {mode:04o}; a bearer token file must be 0600 "
                           f"(chmod 600 {path})")
    return check_token(path.read_text().strip(), str(path))


# -------------------------------------------------------------- streams, sessions
def _dumps(value) -> str:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False)


def _frame(event: str, data: str, ident: int | None = None) -> bytes:
    """One server-sent event. Compact JSON holds no newline, so `data` is one line."""
    head = f"event: {event}\n" + (f"id: {ident}\n" if ident is not None else "")
    return (head + "".join(f"data: {line}\n" for line in data.split("\n")) + "\n").encode()


class _Stream:
    """One open text/event-stream answer. Frames are pushed from any thread and written
    by the thread holding the response, which waits on the client's socket and a wake
    pipe, nothing else: it learns at once that the client left or a frame came."""

    def __init__(self):
        self._lock = threading.Lock()
        self._frames: deque[bytes] = deque()
        self._closed = False
        self._wake, self._waker = socket.socketpair()
        self._waker.setblocking(False)

    def _ring(self) -> None:
        # BlockingIOError: the pipe is full of wakes not yet read, and one is enough
        with contextlib.suppress(BlockingIOError):
            self._waker.send(b"\0")

    def push(self, frame: bytes) -> bool:
        """Queue `frame`; False when the stream has ended."""
        with self._lock:
            if self._closed:
                return False
            self._frames.append(frame)
            self._ring()
        return True

    def close(self) -> None:
        with self._lock:
            if not self._closed:
                self._closed = True
                self._ring()

    def pump(self, handler: BaseHTTPRequestHandler, first: bytes) -> None:
        """Write `first`, then every frame pushed, until the stream is closed or the
        client leaves."""
        out = handler.wfile
        try:
            with selectors.DefaultSelector() as waiting:
                waiting.register(handler.connection, selectors.EVENT_READ, "client")
                waiting.register(self._wake, selectors.EVENT_READ, "wake")
                out.write(first)
                while True:
                    with self._lock:
                        frames, closed = list(self._frames), self._closed
                        self._frames.clear()
                    for frame in frames:
                        out.write(frame)
                    if closed:
                        return
                    for key, _ in waiting.select():
                        if key.data == "client":
                            return          # a stream's client never writes: it left
                        self._wake.recv(4096)   # any size drains: a byte left over wakes
                                                # the next select at once
        finally:
            with self._lock:
                self._closed = True
                self._wake.close()
                self._waker.close()


@dataclass(eq=False)
class _Session:
    id: str
    legacy: bool                            # opened by GET /sse, else by initialize
    protocol: str | None = None
    streams: set[_Stream] = field(default_factory=set)


class _Exchange:
    """One request's answer. Every response it sends carries the CORS headers its
    Origin earned; `started` is whether a status line went out."""

    def __init__(self, handler: BaseHTTPRequestHandler, cors: dict[str, str]):
        self.handler, self.cors, self.started = handler, cors, False

    def _head(self, status: int, headers: dict) -> None:
        handler = self.handler
        handler.send_response(status)
        for name, value in {**self.cors, "Cache-Control": "no-store",
                            "X-Content-Type-Options": "nosniff", **headers}.items():
            handler.send_header(name, value)
        handler.end_headers()
        self.started = True

    def send(self, status: int, body: bytes = b"", content_type: str | None = None,
             headers: dict | None = None) -> None:
        length = {} if status == HTTPStatus.NO_CONTENT else {"Content-Length": str(len(body))}
        self._head(status, {**({"Content-Type": content_type} if content_type else {}),
                            **length, **(headers or {})})
        if body and self.handler.command != "HEAD":
            self.handler.wfile.write(body)

    def json(self, status: int, value, headers: dict | None = None) -> None:
        self.send(status, _dumps(value).encode(), "application/json; charset=utf-8", headers)

    def stream(self, headers: dict | None = None) -> None:
        """Begin a text/event-stream answer: it ends when this connection closes."""
        self.handler.close_connection = True
        self._head(HTTPStatus.OK, {"Content-Type": "text/event-stream; charset=utf-8",
                                   "Connection": "close", **(headers or {})})

    def refuse(self, refusal: _Status) -> None:
        self.handler.close_connection = True    # a refused request's body may be unread
        if self.started:
            self.handler.log_message("refused after the answer began: %s", refusal)
            return
        body = ({"jsonrpc": "2.0", "id": None,
                 "error": {"code": refusal.rpc, "message": str(refusal)}}
                if refusal.rpc is not None else {"error": str(refusal), "type": refusal.kind})
        self.json(refusal.status, body, {**refusal.headers, "Connection": "close"})


def _media(accept: str | None) -> set[str]:
    return {part.partition(";")[0].strip().lower() for part in (accept or "").split(",")
            if part.strip()}


def _only_sse(handler: BaseHTTPRequestHandler) -> bool:
    kinds = _media(handler.headers.get("Accept"))
    return "text/event-stream" in kinds and not kinds & {"application/json", "application/*",
                                                         "*/*"}


# ------------------------------------------------------------------- the routes
class McpHttp:
    """The MCP routes, for any `BaseHTTPRequestHandler`: `nostr-mailbox mcp --http`
    sends it every request, the console those it `owns`. `token` is the bearer (None:
    none asked); `defaults(handler)` gives `mcp.call_tool`'s keywords for one request;
    `host_ok`, when given, must accept the request's `Host`."""

    def __init__(self, *, token: str | None,
                 defaults: Callable[[BaseHTTPRequestHandler], dict],
                 host_ok: Callable[[str | None], bool] | None = None):
        self.token, self._defaults, self._host_ok = token, defaults, host_ok
        self._lock = threading.Lock()
        self._sessions: dict[str, _Session] = {}
        self._loose: set[_Stream] = set()   # GET /mcp streams of no session
        self._ids = itertools.count(1)      # event ids, on every stream of this server
        self._closed = False

    @staticmethod
    def owns(target: str) -> bool:
        path = urlsplit(target).path.rstrip("/") or "/"
        return path in (MCP, SSE, MESSAGES, OPENAPI) or path.startswith(TOOLS_PREFIX)

    def sessions(self) -> int:
        with self._lock:
            return len(self._sessions)

    def close(self) -> None:
        """End every session and stream: the server is stopping."""
        with self._lock:
            self._closed = True
            streams = [*self._loose, *(s for one in self._sessions.values() for s in one.streams)]
            self._sessions.clear()
            self._loose.clear()
        for stream in streams:
            stream.close()

    # ---- one request
    def handle(self, handler: BaseHTTPRequestHandler) -> None:
        parts = urlsplit(handler.path)
        path, method = parts.path.rstrip("/") or "/", handler.command
        origin, host = handler.headers.get("Origin"), handler.headers.get("Host")
        cors = ({"Access-Control-Allow-Origin": origin, "Vary": "Origin",
                 "Access-Control-Expose-Headers": SESSION_HEADER}
                if origin is not None and origin_allowed(origin, host) else {})
        out = _Exchange(handler, cors)
        try:
            self._gate(handler, method, path, origin, host)
            self._dispatch(out, method, path, parts.query)
        except _Status as refusal:
            out.refuse(refusal)
        except (BrokenPipeError, ConnectionResetError) as exc:
            handler.close_connection = True
            handler.log_message("the client left before its answer was written: %r", exc)
        except Exception:                   # a bug: logged whole, and the client told
            traceback.print_exc(file=sys.stderr)
            handler.close_connection = True
            if not out.started:
                out.json(HTTPStatus.INTERNAL_SERVER_ERROR,
                         {"error": "the MCP server failed; its traceback is on its stderr",
                          "type": "InternalError"}, {"Connection": "close"})

    def _gate(self, handler, method: str, path: str, origin: str | None,
              host: str | None) -> None:
        """The checks every request passes before anything is read or run."""
        if self._host_ok is not None and not self._host_ok(host):
            raise _Status(HTTPStatus.FORBIDDEN, f"Host {host!r} is not this server: a page "
                          "that reaches loopback under another name is turned away")
        if not origin_allowed(origin, host):
            raise _Status(HTTPStatus.FORBIDDEN, f"Origin {origin!r} is neither loopback nor "
                          "this server's own: a page on another site is not served")
        if method == "OPTIONS" or (method == "GET" and path == OPENAPI) or self.token is None:
            return
        scheme, _, given = (handler.headers.get("Authorization") or "").partition(" ")
        if scheme.lower() != "bearer" or not hmac.compare_digest(given.strip().encode(),
                                                                 self.token.encode()):
            raise _Status(HTTPStatus.UNAUTHORIZED, "missing or wrong bearer token: send "
                          "Authorization: Bearer <token>, the one this server printed when "
                          "it started (kept in its token file, <home>/mcp.token by default)",
                          headers={"WWW-Authenticate": 'Bearer realm="nostr-mailbox"'})

    def _dispatch(self, out: _Exchange, method: str, path: str, query: str) -> None:
        if path.startswith(TOOLS_PREFIX):
            methods = {"POST": self._post_tool}
        else:
            methods = {MCP: {"POST": self._post_mcp, "GET": self._get_mcp,
                             "DELETE": self._delete_mcp},
                       SSE: {"GET": self._get_sse}, MESSAGES: {"POST": self._post_messages},
                       OPENAPI: {"GET": self._openapi}}.get(path)
        if methods is None:
            raise _Status(HTTPStatus.NOT_FOUND, f"nothing at {path}: the MCP routes are {MCP}, "
                          f"{SSE}, {MESSAGES}, {OPENAPI} and {TOOLS_PREFIX}<tool>")
        if method == "OPTIONS":             # the CORS preflight
            out.send(HTTPStatus.NO_CONTENT, headers={
                "Access-Control-Allow-Methods": ALLOW_METHODS,
                "Access-Control-Allow-Headers": ALLOW_HEADERS,
                "Access-Control-Expose-Headers": SESSION_HEADER, "Allow": ALLOW_METHODS})
            return
        run = methods.get(method)
        if run is None:
            allowed = ", ".join([*methods, "OPTIONS"])
            raise _Status(HTTPStatus.METHOD_NOT_ALLOWED, f"{path} takes {allowed}, not {method}",
                          headers={"Allow": allowed})
        run(out, path, query)

    def _server(self, handler) -> dict:
        """`mcp.call_tool`'s keywords for this request. Its client may be anywhere."""
        try:
            defaults = self._defaults(handler)
        except NostrError as exc:           # a persona the request names is no name
            raise _Status(HTTPStatus.BAD_REQUEST, str(exc), kind=type(exc).__name__) from exc
        return {**defaults, "local_files": False}

    def _body(self, handler, *, rpc: bool, empty_ok: bool = False):
        """The request's JSON, or None for no body where `empty_ok`. A body without a
        Content-Length, over the frame cap or not JSON is refused unread."""
        invalid = -32600 if rpc else None
        length = handler.headers.get("Content-Length")
        if handler.headers.get("Transfer-Encoding"):
            raise _Status(HTTPStatus.LENGTH_REQUIRED, "send the body with a Content-Length, "
                          "not chunked", rpc=invalid)
        if length is None and empty_ok:
            return None
        if length is None or not length.isdigit():
            raise _Status(HTTPStatus.LENGTH_REQUIRED, "a request body needs a Content-Length",
                          rpc=invalid)
        size, cap = int(length), mcp.MAX_FRAME_BYTES
        if size > cap:
            raise _Status(HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                          f"a {size:,}-byte body, {100 * size / cap:.0f}% of the {cap:,}-byte "
                          "cap (one request carries at most one campaign event): refused "
                          "unread", rpc=invalid)
        if size == 0 and empty_ok:
            return None
        kind = (handler.headers.get("Content-Type") or "").partition(";")[0].strip().lower()
        if kind != "application/json":
            raise _Status(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, "send JSON (Content-Type: "
                          f"application/json), not {kind or 'no type'}", rpc=invalid)
        raw = handler.rfile.read(size)
        if len(raw) < size:
            raise _Status(HTTPStatus.BAD_REQUEST, f"the body ended {len(raw):,} bytes into "
                          f"its {size:,}", rpc=invalid)
        try:
            return json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
            raise _Status(HTTPStatus.BAD_REQUEST, f"parse error: {exc}",
                          rpc=-32700 if rpc else None) from exc

    # ---- sessions
    def _open(self, *, legacy: bool, protocol: str | None = None) -> _Session:
        session = _Session(secrets.token_urlsafe(32), legacy, protocol)
        with self._lock:
            if self._closed:
                raise _Status(HTTPStatus.SERVICE_UNAVAILABLE, "this server is stopping")
            self._sessions[session.id] = session
        return session

    def _session(self, sid: str, *, legacy: bool) -> _Session:
        with self._lock:
            session = self._sessions.get(sid)
        if session is None or session.legacy != legacy:
            opens = f"GET {SSE}" if legacy else "initialize"
            raise _Status(HTTPStatus.NOT_FOUND, f"no open session {sid!r} here: it was closed, "
                          f"or never opened ({opens} opens one)", rpc=-32001)
        return session

    def _drop(self, session: _Session) -> None:
        with self._lock:
            if self._sessions.get(session.id) is session:
                del self._sessions[session.id]
            streams = list(session.streams)
        for stream in streams:
            stream.close()

    def _attach(self, session: _Session | None) -> _Stream:
        stream = _Stream()
        with self._lock:
            if self._closed or (session is not None
                                and self._sessions.get(session.id) is not session):
                stream.close()
                raise _Status(HTTPStatus.NOT_FOUND, "the session closed before its stream "
                              "opened", rpc=-32001)
            (session.streams if session is not None else self._loose).add(stream)
        return stream

    def _detach(self, session: _Session | None, stream: _Stream) -> None:
        stream.close()
        with self._lock:
            (session.streams if session is not None else self._loose).discard(stream)

    # ---- Streamable HTTP
    def _post_mcp(self, out: _Exchange, path: str, query: str) -> None:
        handler = out.handler
        version = handler.headers.get(VERSION_HEADER)
        if version is not None and version not in mcp.PROTOCOL_VERSIONS:
            raise _Status(HTTPStatus.BAD_REQUEST, f"{VERSION_HEADER} {version!r} is not one "
                          f"this server speaks: {list(mcp.PROTOCOL_VERSIONS)}", rpc=-32600)
        message = self._body(handler, rpc=True)
        batch = message if isinstance(message, list) else [message]
        opening = [m["id"] for m in batch if isinstance(m, dict) and "id" in m
                   and m.get("method") == "initialize"]
        named = handler.headers.get(SESSION_HEADER)
        if named is not None and not opening:
            self._session(named, legacy=False)
        reply = mcp.handle_rpc(message, **self._server(handler))
        headers = {}
        if opening:
            replies = reply if isinstance(reply, list) else [reply]
            done = next((r for r in replies if isinstance(r, dict) and "result" in r
                         and r.get("id") == opening[0]), None)
            if done is not None:
                headers[SESSION_HEADER] = self._open(
                    legacy=False, protocol=done["result"]["protocolVersion"]).id
        if reply is None:
            out.send(HTTPStatus.ACCEPTED, headers=headers)
        elif _only_sse(handler):
            out.stream(headers)
            handler.wfile.write(_frame("message", _dumps(reply), next(self._ids)))
        else:
            out.json(HTTPStatus.OK, reply, headers)

    def _get_mcp(self, out: _Exchange, path: str, query: str) -> None:
        handler = out.handler
        if "text/event-stream" not in _media(handler.headers.get("Accept")):
            raise _Status(HTTPStatus.NOT_ACCEPTABLE, f"GET {MCP} opens a stream of server "
                          "messages: send Accept: text/event-stream (requests go by POST)")
        named = handler.headers.get(SESSION_HEADER)
        session = self._session(named, legacy=False) if named is not None else None
        stream = self._attach(session)
        try:
            out.stream({SESSION_HEADER: session.id} if session is not None else {})
            stream.pump(handler, b": ready. This server sends nothing here unasked; the stream "
                                 b"stays open until its session closes\n\n")
        finally:
            self._detach(session, stream)

    def _delete_mcp(self, out: _Exchange, path: str, query: str) -> None:
        named = out.handler.headers.get(SESSION_HEADER)
        if named is None:
            raise _Status(HTTPStatus.BAD_REQUEST, f"DELETE {MCP} closes the session named in "
                          f"{SESSION_HEADER}, and none was named", rpc=-32600)
        session = self._session(named, legacy=False)
        self._drop(session)
        out.json(HTTPStatus.OK, {"closed": session.id})

    # ---- HTTP+SSE (2024-11-05)
    def _get_sse(self, out: _Exchange, path: str, query: str) -> None:
        session = self._open(legacy=True)
        stream = self._attach(session)
        try:
            out.stream()
            stream.pump(out.handler, _frame("endpoint", f"{MESSAGES}?session_id={session.id}"))
        finally:
            self._detach(session, stream)
            self._drop(session)

    def _post_messages(self, out: _Exchange, path: str, query: str) -> None:
        named = (parse_qs(query).get("session_id") or [None])[0]
        if not named:
            raise _Status(HTTPStatus.BAD_REQUEST, f"POST {MESSAGES} names its session, as "
                          f"the endpoint event of GET {SSE} gave it: "
                          f"{MESSAGES}?session_id=<sid>", rpc=-32600)
        session = self._session(named, legacy=True)
        message = self._body(out.handler, rpc=True)
        reply = mcp.handle_rpc(message, **self._server(out.handler))
        if reply is None:
            out.send(HTTPStatus.ACCEPTED)
            return
        frame = _frame("message", _dumps(reply), next(self._ids))
        with self._lock:
            streams = list(session.streams)
        for stream in streams:
            stream.push(frame)
        out.json(HTTPStatus.OK, reply)

    # ---- OpenAPI
    def _openapi(self, out: _Exchange, path: str, query: str) -> None:
        """The document, its server the origin this request reached (as a TLS proxy in
        front says it, in X-Forwarded-Proto and X-Forwarded-Host)."""
        headers = out.handler.headers
        scheme = (headers.get("X-Forwarded-Proto") or "http").partition(",")[0].strip()
        where = (headers.get("X-Forwarded-Host") or headers.get("Host") or "").partition(",")[0]
        base = f"{scheme if scheme in ('http', 'https') else 'http'}://{where.strip()}"
        out.json(HTTPStatus.OK, openapi(base if where.strip() else "/",
                                        auth=self.token is not None))

    def _post_tool(self, out: _Exchange, path: str, query: str) -> None:
        name = path[len(TOOLS_PREFIX):]
        if name not in mcp.HANDLERS:
            raise _Status(HTTPStatus.NOT_FOUND, f"no tool {name!r}; tools: {sorted(mcp.HANDLERS)}")
        arguments = self._body(out.handler, rpc=False, empty_ok=True)
        if arguments is None:
            arguments = {}
        if not isinstance(arguments, dict):
            raise _Status(HTTPStatus.BAD_REQUEST, f"POST {path} takes the tool's arguments as "
                          "one JSON object")
        server = self._server(out.handler)
        try:
            payload = mcp.call_tool(name, arguments, **server)
        except mcp.InvalidArguments as exc:
            raise _Status(HTTPStatus.BAD_REQUEST, str(exc), kind=type(exc).__name__) from exc
        except (RelayError, BlossomError) as exc:
            raise _Status(HTTPStatus.BAD_GATEWAY, str(exc), kind=type(exc).__name__) from exc
        except (NostrError, OSError) as exc:
            raise _Status(HTTPStatus.UNPROCESSABLE_ENTITY, str(exc),
                          kind=type(exc).__name__) from exc
        out.json(HTTPStatus.OK, payload)


def _brief(text: str) -> str:
    """`text` whole when it fits a GPT Action's operation description, else the leading
    sentences that do."""
    cap = GPT_OPERATION_DESCRIPTION_CHARS
    if len(text) <= cap:
        return text
    kept = ""
    for sentence in re.split(r"(?<=\.)\s+", text):
        if len(kept) + 1 + len(sentence) > cap:
            break
        kept = f"{kept} {sentence}".strip()
    return kept or text[:cap]


def openapi(base_url: str, *, auth: bool) -> dict:
    """The OpenAPI 3.1 document of `POST /tools/<tool>`: one operation per tool, as an
    HTTP client is offered it (`mcp.tools(local_files=False)`)."""
    def failure(why: str) -> dict:
        return {"description": why,
                "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}}

    paths = {}
    for tool in mcp.tools(local_files=False):
        name, schema = tool["name"], tool["inputSchema"]
        responses = {
            "200": {"description": "What the tool says: the MCP tool's structuredContent",
                    "content": {"application/json": {"schema": {
                        "type": "object", "additionalProperties": True}}}},
            "400": failure("The arguments do not match the tool's schema"),
            "422": failure("The tool refused or failed; error says why"),
            "502": failure("The relay or the blob server did not answer as needed")}
        if auth:
            responses["401"] = failure("Missing or wrong bearer token")
        operation = {
            "operationId": name, "summary": SUMMARIES[name],
            "description": _brief(tool["description"]),
            "requestBody": {"required": bool(schema.get("required")), "content": {
                "application/json": {"schema": {**schema, "description": tool["description"]}}}},
            "responses": responses}
        if name == "mailbox_list":          # it reads local files only: ChatGPT may let a
            operation["x-openai-isConsequential"] = False   # user allow it once for all
        paths[f"{TOOLS_PREFIX}{name}"] = {"post": operation}
    doc = {"openapi": "3.1.0",
           "info": {"title": "nostr-mailbox", "version": __version__,
                    "description": mcp.INSTRUCTIONS},
           "servers": [{"url": base_url}], "paths": paths,
           "components": {"schemas": {"Error": {
               "type": "object", "required": ["error", "type"],
               "properties": {"error": {"type": "string", "description": "why, in words"},
                              "type": {"type": "string", "description": "the refusal's kind"}}}}}}
    if auth:
        doc["components"]["securitySchemes"] = {"bearerAuth": {
            "type": "http", "scheme": "bearer",
            "description": "The token the server printed when it started, kept in its token "
                           "file (<home>/mcp.token by default)"}}
        doc["security"] = [{"bearerAuth": []}]
    return doc


# -------------------------------------------------------- `nostr-mailbox mcp --http`
class _Http(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, routes: McpHttp, quiet: bool):
        self.routes, self.quiet = routes, quiet
        if ":" in address[0]:                   # ::1 needs an IPv6 socket
            self.address_family = socket.AF_INET6
        super().__init__(address, _Handler)


class _Handler(BaseHTTPRequestHandler):
    server: _Http
    protocol_version = "HTTP/1.1"
    server_version = f"nostr-mailbox-mcp/{__version__}"

    def log_message(self, format: str, *args) -> None:       # noqa: A002 (stdlib name)
        if not self.server.quiet:
            sys.stderr.write(f"mcp: {self.address_string()} {format % args}\n")

    def _route(self) -> None:
        self.server.routes.handle(self)

    do_GET = do_POST = do_DELETE = do_OPTIONS = do_HEAD = _route    # noqa: N815 (stdlib names)


class McpServer:
    """`nostr-mailbox mcp --http` on a background thread: `start()`, `url`, `stop()`.
    Port 0 picks a free port, which is how the witnesses run it. `token` None serves
    without a bearer, and only on loopback."""

    def __init__(self, *, token: str | None, host: str = DEFAULT_HOST, port: int = DEFAULT_PORT,
                 home_dir: str | Path | None = None, default_persona: str | None = None,
                 trust: str | None = None, topic: str | None = None,
                 timeout_seconds: float = DEFAULT_WAIT_S, quiet: bool = False):
        if token is None and not is_loopback(host):
            raise McpHttpError(f"{host!r} is not a loopback address: --no-auth would serve "
                               "whoever reaches it. Beyond loopback every client sends the "
                               "bearer")
        defaults = {"home_dir": home_dir, "default_persona": default_persona, "trust": trust,
                    "topic": topic, "timeout_seconds": timeout_seconds}
        self.routes = McpHttp(token=token, defaults=lambda handler: defaults,
                              host_ok=None if token is not None else loopback_host)
        self._server = _Http((host, port), self.routes, quiet)
        self._thread = threading.Thread(target=self._server.serve_forever,
                                        name="nostr-mailbox-mcp", daemon=True)

    @property
    def url(self) -> str:
        host, port = self._server.server_address[:2]
        return f"http://{'[' + host + ']' if ':' in str(host) else host}:{port}"

    def start(self) -> McpServer:
        self._thread.start()
        return self

    def stop(self) -> None:
        self.routes.close()
        self._server.shutdown()
        self._server.server_close()
        self._thread.join()

    def __enter__(self) -> McpServer:
        return self.start()

    def __exit__(self, *exc_info) -> None:
        self.stop()


def _bearer(args) -> tuple[str | None, Path | None]:
    """The bearer clients send and the file keeping it: --no-auth none, --token as
    given, else --token-file or `<home>/mcp.token`, made when absent."""
    if args.no_auth:
        return None, None
    if args.token is not None:
        return check_token(args.token, "--token"), None
    path = Path(args.token_file).expanduser() if args.token_file else home(args.home) / TOKEN_FILE
    return load_token(path), path


def banner(url: str, host: str, token: str | None, token_file: Path | None, *, home_dir,
           persona: str) -> dict:
    """What `mcp --http` prints when it is up: where, and how a client authenticates."""
    header = f"Authorization: Bearer {token}" if token is not None else None
    out = {"serving": url, "mcp": url + MCP, "sse": url + SSE, "openapi": url + OPENAPI,
           "tools": url + TOOLS_PREFIX + "<tool>",
           "auth": "bearer" if token is not None else "none: loopback, Host naming loopback",
           "token_file": str(token_file) if token_file else None, "header": header,
           "claude_code": shlex.join(["claude", "mcp", "add", "--transport", "http",
                                      "nostr-mailbox", url + MCP,
                                      *(["--header", header] if header else [])]),
           "home": str(home(home_dir)), "persona": persona, "stop": "Ctrl-C"}
    if not is_loopback(host):
        out["note"] = ("listening beyond loopback over plain HTTP: the bearer crosses the "
                       "network as sent. Put TLS in front of this port (a reverse proxy) "
                       "before anyone else can reach it")
    return out


def serve(args, address: tuple[str, int]) -> dict:
    """`nostr-mailbox mcp --http`: serve until Ctrl-C. Prints one JSON line when it is
    up (`banner`), with the bearer header a client sends."""
    host, port = address
    token, token_file = _bearer(args)       # --no-auth reads and makes no file
    server = McpServer(token=token, host=host, port=port, home_dir=args.home,
                       default_persona=args.identity, trust=args.trust, topic=args.topic_trust,
                       timeout_seconds=args.timeout_seconds).start()
    try:
        print(json.dumps(banner(server.url, host, token, token_file, home_dir=args.home,
                                persona=args.identity)), flush=True)
        with contextlib.suppress(KeyboardInterrupt):    # Ctrl-C is how this command ends
            threading.Event().wait()
    finally:
        server.stop()
    return {"stopped": server.url}


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--http", nargs="?", const=(None, None), type=mcp_address,
                        metavar="[HOST:]PORT",
                        help="serve HTTP instead of stdio: Streamable HTTP at /mcp, HTTP+SSE "
                             "at /sse, OpenAPI 3.1 at /openapi.json (default "
                             f"{DEFAULT_HOST}:{DEFAULT_PORT})")
    parser.add_argument("--bind", type=mcp_address, metavar="HOST:PORT",
                        help="the address to serve HTTP on (means --http)")
    parser.add_argument("--port", type=int,
                        help=f"the port to serve HTTP on, at {DEFAULT_HOST} unless --http or "
                             "--bind names a host (means --http; 0 picks a free one)")
    auth = parser.add_mutually_exclusive_group()
    auth.add_argument("--token", help="the bearer HTTP clients send (anyone listing this "
                                      "machine's processes sees it: prefer --token-file)")
    auth.add_argument("--token-file", help="the file keeping the bearer, made 0600 when absent "
                                           f"(default: <home>/{TOKEN_FILE})")
    auth.add_argument("--no-auth", action="store_true",
                      help="serve a loopback bind without a bearer, to requests whose Host "
                           "names loopback; refused on any other address")


__all__ = ["DEFAULT_HOST", "DEFAULT_PORT", "TOKEN_FILE", "McpHttp", "McpHttpError", "McpServer",
           "banner", "http_address", "is_loopback", "load_token", "loopback_host", "mcp_address",
           "openapi", "origin_allowed", "serve"]
