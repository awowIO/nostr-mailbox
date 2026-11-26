"""RFC 6455 WebSocket text messaging on sockets alone: the client a seat dials a relay
with, and the server half the loopback relay answers with.

Deliberately narrow. No extensions are offered, so a frame with a reserved bit set is
a protocol error. Binary frames are refused: Nostr is JSON text. A plain `ws://` URL is
dialled only for a loopback address or when the caller declares cleartext acceptable
(an in-cluster Service); everything else must be `wss://` with a verified certificate.

Bounds. Nothing here waits longer than the deadline its caller passes, including a peer
that keeps the connection busy with pings. A message larger than the caller's
`max_message_bytes` is refused from its frame header, fragments summed, before any of
it is buffered. The HTTP upgrade head is capped at the size the standard library's own
HTTP client allows one header line."""
from __future__ import annotations

import base64
import contextlib
import hashlib
import io
import ipaddress
import os
import socket
import ssl
import struct
import threading
import time
from urllib.parse import urlsplit

from .event import NostrError

_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
_CONT, _TEXT, _BINARY, _CLOSE, _PING, _PONG = 0x0, 0x1, 0x2, 0x8, 0x9, 0xA
_CONTROL_MAX = 125                      # RFC 6455 §5.5: control frame payload limit
_MAX_HEAD = 65_536                      # http.client's cap on one header line (_MAXLINE)
NORMAL_CLOSURE = 1000
NO_STATUS = 1005


class WebSocketError(NostrError):
    """The connection could not be made, or the peer broke the protocol."""


class WebSocketTimeout(WebSocketError):
    """Nothing arrived before the caller's deadline."""


class WebSocketClosed(WebSocketError):
    """The peer closed, or the socket died."""


class CleartextRefused(WebSocketError):
    """A ws:// URL to a host that is not loopback, without an explicit allowance."""


def _mask(payload: bytes, key: bytes) -> bytes:
    if not payload:
        return payload
    repeated = (key * (len(payload) // 4 + 1))[:len(payload)]
    return (int.from_bytes(payload, "big") ^ int.from_bytes(repeated, "big")).to_bytes(
        len(payload), "big")


def _accept_key(key: str) -> str:
    return base64.b64encode(hashlib.sha1((key + _GUID).encode()).digest()).decode()


def is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:                  # a DNS name is never assumed to be loopback
        return False


def _set_deadline(sock, deadline: float | None, what: str) -> None:
    remaining = None
    if deadline is not None:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise WebSocketTimeout(f"deadline passed while {what}")
    try:
        sock.settimeout(remaining)
    except OSError as exc:              # the socket was closed under us
        raise WebSocketClosed(f"socket is closed ({exc})") from exc


def _read_head(sock, deadline: float | None) -> tuple[list[str], bytes]:
    """The lines of an HTTP head, and whatever bytes followed it."""
    data = bytearray()
    while b"\r\n\r\n" not in data:
        _set_deadline(sock, deadline, "reading the HTTP upgrade")
        try:
            chunk = sock.recv(io.DEFAULT_BUFFER_SIZE)
        except TimeoutError as exc:
            raise WebSocketTimeout("no HTTP upgrade answer before the deadline") from exc
        except OSError as exc:
            raise WebSocketClosed(f"socket failed during the HTTP upgrade: {exc}") from exc
        if not chunk:
            raise WebSocketClosed("connection closed during the HTTP upgrade")
        data += chunk
        if len(data) > _MAX_HEAD and b"\r\n\r\n" not in data:
            raise WebSocketError(f"HTTP upgrade head exceeds {_MAX_HEAD:,} bytes")
    head, _, rest = bytes(data).partition(b"\r\n\r\n")
    return head.decode("latin-1").split("\r\n"), rest


def _headers(lines: list[str]) -> dict[str, str]:
    out = {}
    for line in lines:
        name, sep, value = line.partition(":")
        if sep:
            out[name.strip().lower()] = value.strip()
    return out


class WebSocket:
    """One open connection, in either role. `client=True` masks what it sends and
    refuses masked frames; the server half does the opposite."""

    def __init__(self, sock, *, client: bool, buffered: bytes = b"",
                 send_timeout_s: float | None = None,
                 max_message_bytes: int | None = None):
        self._sock = sock
        self._client = client
        self._buf = bytearray(buffered)
        self._fragments: list[bytes] | None = None
        self._fragment_bytes = 0
        self._send_timeout_s = send_timeout_s
        self._max_message_bytes = max_message_bytes
        self._send_lock = threading.Lock()
        self.closed = False

    def send_text(self, text: str) -> None:
        self._send(_TEXT, text.encode("utf-8"))

    def _send(self, opcode: int, payload: bytes) -> None:
        mask_bit = 0x80 if self._client else 0
        head = bytearray([0x80 | opcode])
        size = len(payload)
        if size <= _CONTROL_MAX:
            head.append(mask_bit | size)
        elif size < 1 << 16:
            head.append(mask_bit | 126)
            head += struct.pack("!H", size)
        else:
            head.append(mask_bit | 127)
            head += struct.pack("!Q", size)
        if self._client:
            key = os.urandom(4)
            head += key
            payload = _mask(payload, key)
        with self._send_lock:
            try:
                if self._client:
                    self._sock.settimeout(self._send_timeout_s)
                self._sock.sendall(bytes(head) + payload)
            except TimeoutError as exc:
                raise WebSocketTimeout(
                    f"send did not complete within {self._send_timeout_s}s") from exc
            except OSError as exc:
                raise WebSocketClosed(f"send failed: {exc}") from exc

    def _parse(self) -> tuple[int, bool, bytes] | None:
        """One complete frame off the front of the buffer, or None if it is not all here."""
        buf = self._buf
        if len(buf) < 2:
            return None
        if buf[0] & 0x70:
            raise WebSocketError("frame has reserved bits set; no extension was negotiated")
        fin, opcode = bool(buf[0] & 0x80), buf[0] & 0x0F
        masked, size = bool(buf[1] & 0x80), buf[1] & 0x7F
        if masked == self._client:
            raise WebSocketError("frame masking is wrong for this side of the connection")
        if opcode >= _CLOSE and (not fin or size > _CONTROL_MAX):
            raise WebSocketError("malformed control frame")
        offset = 2
        if size == 126:
            if len(buf) < 4:
                return None
            size, offset = struct.unpack_from("!H", buf, 2)[0], 4
            if size <= _CONTROL_MAX:
                raise WebSocketError("frame length is not in its shortest encoding")
        elif size == 127:
            if len(buf) < 10:
                return None
            size, offset = struct.unpack_from("!Q", buf, 2)[0], 10
            if size >> 63:
                raise WebSocketError("frame length has its top bit set")
            if size < 1 << 16:
                raise WebSocketError("frame length is not in its shortest encoding")
        limit = self._max_message_bytes
        if limit is not None and opcode < _CLOSE and self._fragment_bytes + size > limit:
            raise WebSocketError(
                f"message of at least {self._fragment_bytes + size:,} bytes exceeds the "
                f"{limit:,}-byte limit for this connection; refused before buffering it")
        key = b""
        if masked:
            if len(buf) < offset + 4:
                return None
            key = bytes(buf[offset:offset + 4])
            offset += 4
        if len(buf) < offset + size:
            return None
        payload = bytes(buf[offset:offset + size])
        del buf[:offset + size]
        return opcode, fin, _mask(payload, key) if masked else payload

    def _frame(self, deadline: float | None) -> tuple[int, bool, bytes]:
        while True:
            frame = self._parse()
            if frame is not None:
                return frame
            _set_deadline(self._sock, deadline, "waiting for a frame")
            try:
                chunk = self._sock.recv(io.DEFAULT_BUFFER_SIZE)
            except TimeoutError as exc:
                raise WebSocketTimeout("nothing arrived before the deadline") from exc
            except OSError as exc:
                raise WebSocketClosed(f"socket failed: {exc}") from exc
            if not chunk:
                self.closed = True
                raise WebSocketClosed("connection closed without a close frame")
            self._buf += chunk

    def recv_text(self, deadline: float | None) -> str:
        """The next complete text message. `deadline` is a `time.monotonic()` instant;
        None waits for as long as the connection lives."""
        answered = 0
        while True:
            if answered and deadline is not None and time.monotonic() >= deadline:
                raise WebSocketTimeout(     # a peer that only pings never delivers
                    f"only control frames ({answered}) arrived before the deadline")
            opcode, fin, payload = self._frame(deadline)
            if opcode == _PING:
                answered += 1
                self._send(_PONG, payload)
            elif opcode == _PONG:
                answered += 1
            elif opcode == _CLOSE:
                self.closed = True
                if len(payload) == 1:
                    raise WebSocketError("close frame carries half a status code")
                code = struct.unpack("!H", payload[:2])[0] if len(payload) >= 2 else NO_STATUS
                with contextlib.suppress(WebSocketError):   # the echo is a courtesy
                    self._send(_CLOSE, payload[:2])
                raise WebSocketClosed(
                    f"peer closed the connection (code {code}"
                    f"{': ' + payload[2:].decode('utf-8', 'replace') if payload[2:] else ''})")
            elif opcode == _BINARY:
                raise WebSocketError("binary frame received; Nostr messages are text")
            elif opcode == _TEXT:
                if self._fragments is not None:
                    raise WebSocketError("new message started inside a fragmented one")
                if fin:
                    return self._decode(payload)
                self._fragments, self._fragment_bytes = [payload], len(payload)
            elif opcode == _CONT:
                if self._fragments is None:
                    raise WebSocketError("continuation frame with nothing to continue")
                self._fragments.append(payload)
                self._fragment_bytes += len(payload)
                if fin:
                    whole, self._fragments = b"".join(self._fragments), None
                    self._fragment_bytes = 0
                    return self._decode(whole)
            else:
                raise WebSocketError(f"unknown opcode {opcode:#x}")

    @staticmethod
    def _decode(payload: bytes) -> str:
        try:
            return payload.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise WebSocketError(f"text message is not valid UTF-8: {exc}") from exc

    def close(self, code: int = NORMAL_CLOSURE) -> None:
        if not self.closed:
            self.closed = True
            with contextlib.suppress(WebSocketError):       # the peer may already be gone
                self._send(_CLOSE, struct.pack("!H", code))
        with contextlib.suppress(OSError):
            self._sock.close()

    def abort(self) -> None:
        """Drop the TCP connection with no close handshake."""
        self.closed = True
        with contextlib.suppress(OSError):
            self._sock.shutdown(socket.SHUT_RDWR)
        with contextlib.suppress(OSError):
            self._sock.close()


def _tokens(value: str) -> set[str]:
    """The comma-separated tokens of an HTTP header value, lowercased."""
    return {token.strip().lower() for token in value.split(",")}


def connect(url: str, *, timeout_s: float, allow_cleartext: bool = False,
            max_message_bytes: int | None = None) -> WebSocket:
    """Dial `url` and complete the opening handshake within `timeout_s`."""
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError as exc:
        raise WebSocketError(f"not a usable URL: {url!r} ({exc})") from exc
    if parts.scheme not in ("ws", "wss") or not parts.hostname:
        raise WebSocketError(f"not a ws:// or wss:// URL: {url!r}")
    secure = parts.scheme == "wss"
    if not secure and not allow_cleartext and not is_loopback(parts.hostname):
        raise CleartextRefused(
            f"{url} is cleartext to a host that is not loopback; use wss://, or declare "
            "allow_cleartext for a relay reached over a private cluster network")
    port = port or (443 if secure else 80)
    deadline = time.monotonic() + timeout_s
    try:
        sock = socket.create_connection((parts.hostname, port), timeout=timeout_s)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        if secure:
            sock = ssl.create_default_context().wrap_socket(
                sock, server_hostname=parts.hostname)
    except TimeoutError as exc:
        raise WebSocketTimeout(
            f"{parts.hostname}:{port} did not accept a connection within {timeout_s}s") from exc
    except OSError as exc:              # includes ssl.SSLError: certificate or handshake
        raise WebSocketError(f"cannot connect to {parts.hostname}:{port}: {exc}") from exc
    key = base64.b64encode(os.urandom(16)).decode()
    target = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
    request = (f"GET {target} HTTP/1.1\r\nHost: {parts.netloc.rpartition('@')[2]}\r\n"
               "Upgrade: websocket\r\nConnection: Upgrade\r\n"
               f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n")
    try:
        sock.sendall(request.encode("ascii"))
        lines, rest = _read_head(sock, deadline)
        status = lines[0].split(" ", 2)
        headers = _headers(lines[1:])
        if len(status) < 2 or status[1] != "101":
            raise WebSocketError(f"{url} refused the WebSocket upgrade: {lines[0]!r}")
        if (headers.get("upgrade", "").lower() != "websocket"
                or "upgrade" not in _tokens(headers.get("connection", ""))
                or headers.get("sec-websocket-accept") != _accept_key(key)):
            raise WebSocketError(f"{url} answered 101 without a valid WebSocket accept")
        if headers.get("sec-websocket-extensions"):
            raise WebSocketError(f"{url} turned on an extension that was never offered")
    except WebSocketError:
        sock.close()
        raise
    except (OSError, UnicodeError) as exc:
        sock.close()
        raise WebSocketError(f"WebSocket upgrade with {url} failed: {exc}") from exc
    return WebSocket(sock, client=True, buffered=rest, send_timeout_s=timeout_s,
                     max_message_bytes=max_message_bytes)


class Request:
    """One HTTP request read off a socket: either upgraded (`ws` is set) or left for the
    caller to answer over plain HTTP, with whatever body bytes already arrived."""

    def __init__(self, line: str, headers: dict[str, str], rest: bytes,
                 ws: WebSocket | None = None):
        self.method, _, target = line.partition(" ")
        self.path = target.rpartition(" ")[0] or target
        self.headers, self.rest, self.ws = headers, rest, ws


def accept(sock, *, max_message_bytes: int | None = None) -> Request:
    """Read one HTTP request on `sock`. A WebSocket upgrade is answered and comes back
    with its open connection; anything else comes back for the caller to answer."""
    lines, rest = _read_head(sock, None)
    headers = _headers(lines[1:])
    key = headers.get("sec-websocket-key")
    if headers.get("upgrade", "").lower() != "websocket" or not key:
        return Request(lines[0], headers, rest)
    sock.sendall(("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                  f"Connection: Upgrade\r\nSec-WebSocket-Accept: {_accept_key(key)}\r\n\r\n"
                  ).encode("ascii"))
    return Request(lines[0], headers, b"", WebSocket(
        sock, client=False, buffered=rest, max_message_bytes=max_message_bytes))
