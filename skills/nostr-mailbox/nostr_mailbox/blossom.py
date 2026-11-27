"""Blossom: blobs addressed by their SHA-256, for what does not belong in an event
(reproducer fixtures, patches, wave artifacts). An event carries the 64-hex digest; the
bytes live at `/<sha256>` on the blob server.

Two rules the client never relaxes. Bytes that come back are hashed, and a digest that
is not the one asked for raises: a download is written to its destination only after it
verified. An upload is hashed before it leaves, the signed authorization names that
digest, and the server's answer must name it too.

Authorization is a signed kind-24242 event, sent as `Authorization: Nostr <token>`
where the token is the event as unpadded base64url (the encoding of a JWT segment). It
names the verb, the blob's hash, an expiry `auth_ttl_s` seconds ahead, and the server
it is for: a `server` tag carrying the blob server's public `host[:port]`. The relay's
own Blossom refuses a token that does not name it, so a token signed for one server is
no use on another. A content hash is not a secret: the server has to check who is
asking, which is why downloads are signed as well."""
from __future__ import annotations

import base64
import contextlib
import hashlib
import http.client
import json
import os
import re
import shutil
import ssl
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from .event import Clock, NostrError, dumps, now, unsigned
from .identity import BLOSSOM_AUTH_KIND, Signer
from .relay import DEFAULT_WAIT_S, MAX_MESSAGE_BYTES
from .ws import CleartextRefused, is_loopback

# How long one signed authorization stays valid: the ±120 s freshness window the relay
# report sets for a NIP-42 proof, reused so one clock-skew budget covers both.
AUTH_TTL_S = 120
# The most one blob may be: the relay's own `blossom.maxBlobBytes` (100 MiB, the pinned
# release's default, which deploy/nostr-relay/relay.yaml ships). A server that sends
# more than it could have stored is refused instead of read into memory or onto disk.
# A campaign on a server with another limit passes its own `max_blob_bytes`.
MAX_BLOB_BYTES = 104_857_600
# A server's answer about a blob (its descriptor) is one small JSON object: it gets the
# room one relay message has (relay.MAX_MESSAGE_BYTES), as the NIP-11 document does.
MAX_ANSWER_BYTES = MAX_MESSAGE_BYTES
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class BlossomError(NostrError):
    """The blob server refused, or could not be reached."""


class DigestMismatch(BlossomError):
    """Bytes whose SHA-256 is not the digest they were asked for or sent under."""


@dataclass(frozen=True)
class Blob:
    sha256: str
    size: int
    url: str
    type: str = "application/octet-stream"

    def to_dict(self) -> dict:
        return dict(self.__dict__)


def sha256_file(path: str | Path) -> tuple[str, int]:
    digest, size = hashlib.sha256(), 0
    with open(path, "rb") as fh:
        while chunk := fh.read(shutil.COPY_BUFSIZE):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


class BlossomClient:
    def __init__(self, origin: str, signer: Signer, *, server: str | None = None,
                 timeout_s: float = DEFAULT_WAIT_S, auth_ttl_s: int = AUTH_TTL_S,
                 allow_cleartext: bool = False, clock: Clock = time.time,
                 max_blob_bytes: int = MAX_BLOB_BYTES):
        """`origin` is where requests go. `server` is the `host[:port]` the blob server
        knows itself by, when that differs: a seat inside the cluster dials the Service
        and still has to name the public host in what it signs. `max_blob_bytes` is the
        most this client reads for one blob."""
        try:
            parts = urlsplit(origin)
            _ = parts.port                          # reading it is what rejects a bad port
        except ValueError as exc:
            raise BlossomError(f"blob server {origin!r} is not a usable URL: {exc}") from exc
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise BlossomError(f"blob server must be an http(s) origin, got {origin!r}")
        if (parts.username is not None or parts.password is not None or parts.query
                or parts.fragment or parts.path not in ("", "/")):
            raise BlossomError(
                f"blob server must be an origin (scheme, host, optional port) with no path, "
                f"query or credentials, got {origin!r}: requests go to /upload and /<sha256>")
        if (parts.scheme == "http" and not allow_cleartext
                and not is_loopback(parts.hostname)):
            raise CleartextRefused(
                f"{origin} is cleartext to a host that is not loopback; use https://, or "
                "declare allow_cleartext for a server on a private cluster network")
        self.origin = f"{parts.scheme}://{parts.netloc}"
        self.server = server or parts.netloc
        self._parts, self.signer = parts, signer
        self.timeout_s, self.auth_ttl_s, self.clock = timeout_s, auth_ttl_s, clock
        self.max_blob_bytes = max_blob_bytes

    def _connection(self) -> http.client.HTTPConnection:
        host, port = self._parts.hostname, self._parts.port
        if self._parts.scheme == "https":
            return http.client.HTTPSConnection(host, port, timeout=self.timeout_s,
                                               context=ssl.create_default_context())
        return http.client.HTTPConnection(host, port, timeout=self.timeout_s)

    def _authorization(self, verb: str, sha256: str) -> str:
        stamp = now(self.clock)
        event = self.signer.sign_event(unsigned(
            BLOSSOM_AUTH_KIND,
            [["t", verb], ["x", sha256], ["expiration", str(stamp + self.auth_ttl_s)],
             ["server", self.server]],
            f"{verb} {sha256}", stamp))
        token = base64.urlsafe_b64encode(dumps(event.to_dict()).encode()).rstrip(b"=")
        return "Nostr " + token.decode()

    def _request(self, method: str, path: str, verb: str, sha256: str, *,
                 body=None, headers: dict | None = None):
        conn = self._connection()
        try:
            conn.request(method, path, body=body, headers={
                "Authorization": self._authorization(verb, sha256), **(headers or {})})
            return conn, conn.getresponse()
        except TimeoutError as exc:
            conn.close()
            raise BlossomError(f"{method} {self.origin}{path} gave no answer in "
                               f"{self.timeout_s}s") from exc
        except (OSError, http.client.HTTPException) as exc:     # refused, reset, DNS, TLS
            conn.close()
            raise BlossomError(f"{method} {self.origin}{path} failed: {exc}") from exc

    def _read(self, response, what: str, amount: int) -> bytes:
        try:
            return response.read(amount)
        except TimeoutError as exc:
            raise BlossomError(f"{what} stalled for {self.timeout_s}s mid-transfer") from exc
        except (OSError, http.client.HTTPException) as exc:
            raise BlossomError(f"{what} broke mid-transfer: {exc}") from exc

    @staticmethod
    def _over(what: str, size: int, cap: int, *, declared: bool) -> BlossomError:
        """The refusal of a body over its cap: how far over, and which cap it was."""
        said = "declares" if declared else "sent at least"
        return BlossomError(f"{what} {said} {size:,} bytes, {100 * size / cap:.0f}% of the "
                            f"{cap:,}-byte cap this client reads; discarded")

    def _bounded(self, response, what: str, cap: int) -> bytes:
        """The whole body, or `BlossomError` when it is (or says it is) over `cap`: a
        server never decides how much this process holds in memory."""
        declared = response.getheader("Content-Length")
        if declared is not None and declared.isdigit() and int(declared) > cap:
            raise self._over(what, int(declared), cap, declared=True)
        data = self._read(response, what, cap + 1)
        if len(data) > cap:
            raise self._over(what, len(data), cap, declared=False)
        return data

    @staticmethod
    def _refuse(method: str, url: str, response) -> BlossomError:
        reason = response.getheader("X-Reason") or response.reason
        return BlossomError(f"{method} {url} answered {response.status}: {reason}")

    def _descriptor(self, raw: bytes, sha256: str, size: int) -> Blob:
        try:
            got = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise BlossomError(f"{self.origin} answered the upload with non-JSON: {exc}") from exc
        if not isinstance(got, dict) or got.get("sha256") != sha256:
            raise DigestMismatch(
                f"{self.origin} stored the upload under "
                f"{got.get('sha256') if isinstance(got, dict) else got!r}, "
                f"not the {sha256} that was sent")
        return Blob(sha256=sha256, size=size, url=str(got.get("url") or f"{self.origin}/{sha256}"),
                    type=str(got.get("type") or "application/octet-stream"))

    # ------------------------------------------------------------------------ verbs
    def upload(self, data: bytes, *, content_type: str = "application/octet-stream") -> Blob:
        sha256 = hashlib.sha256(data).hexdigest()
        conn, response = self._request("PUT", "/upload", "upload", sha256, body=data,
                                       headers={"Content-Type": content_type,
                                                "Content-Length": str(len(data))})
        with contextlib.closing(conn):
            if response.status not in (200, 201):
                raise self._refuse("PUT", f"{self.origin}/upload", response)
            return self._descriptor(
                self._bounded(response, "the upload answer", MAX_ANSWER_BYTES), sha256, len(data))

    def upload_file(self, path: str | Path, *,
                    content_type: str = "application/octet-stream") -> Blob:
        """Upload a file without holding it in memory: one pass to hash, one to send."""
        sha256, size = sha256_file(path)
        with open(path, "rb") as fh:
            conn, response = self._request("PUT", "/upload", "upload", sha256, body=fh,
                                           headers={"Content-Type": content_type,
                                                    "Content-Length": str(size)})
            with contextlib.closing(conn):
                if response.status not in (200, 201):
                    raise self._refuse("PUT", f"{self.origin}/upload", response)
                return self._descriptor(
                    self._bounded(response, "the upload answer", MAX_ANSWER_BYTES), sha256, size)

    def exists(self, sha256: str) -> bool:
        self._check(sha256)
        conn, response = self._request("HEAD", f"/{sha256}", "get", sha256)
        with contextlib.closing(conn):
            self._read(response, "the HEAD answer", MAX_ANSWER_BYTES)   # a HEAD has no body
            if response.status == 200:
                return True
            if response.status == 404:
                return False
            raise self._refuse("HEAD", f"{self.origin}/{sha256}", response)

    def download(self, sha256: str) -> bytes:
        """The blob's bytes, verified. `DigestMismatch` if the server sent anything else."""
        self._check(sha256)
        conn, response = self._request("GET", f"/{sha256}", "get", sha256)
        with contextlib.closing(conn):
            if response.status != 200:
                raise self._refuse("GET", f"{self.origin}/{sha256}", response)
            data = self._bounded(response, f"the download of {sha256[:12]}…",
                                 self.max_blob_bytes)
        got = hashlib.sha256(data).hexdigest()
        if got != sha256:
            raise DigestMismatch(f"{self.origin}/{sha256} returned {len(data):,} bytes "
                                 f"hashing to {got}; discarded")
        return data

    def download_to(self, sha256: str, dest: str | Path) -> Blob:
        """Stream the blob into `dest`. The bytes land in a temporary file beside it and
        are renamed into place only once the digest matched; on a mismatch the
        temporary file is removed and `dest` is untouched."""
        self._check(sha256)
        dest = Path(dest)
        conn, response = self._request("GET", f"/{sha256}", "get", sha256)
        with contextlib.closing(conn):
            if response.status != 200:
                raise self._refuse("GET", f"{self.origin}/{sha256}", response)
            digest, size = hashlib.sha256(), 0
            fd, partial = tempfile.mkstemp(dir=dest.parent, prefix=f".{dest.name}.")
            try:
                what = f"the download of {sha256[:12]}…"
                with os.fdopen(fd, "wb") as out:
                    while chunk := self._read(response, what, shutil.COPY_BUFSIZE):
                        size += len(chunk)
                        if size > self.max_blob_bytes:
                            raise self._over(what, size, self.max_blob_bytes, declared=False)
                        digest.update(chunk)
                        out.write(chunk)
                if digest.hexdigest() != sha256:
                    raise DigestMismatch(
                        f"{self.origin}/{sha256} returned {size:,} bytes hashing to "
                        f"{digest.hexdigest()}; discarded, {dest} is untouched")
                os.replace(partial, dest)
            except BaseException:
                Path(partial).unlink(missing_ok=True)
                raise
        return Blob(sha256=sha256, size=size, url=f"{self.origin}/{sha256}",
                    type=response.getheader("Content-Type") or "application/octet-stream")

    @staticmethod
    def _check(sha256: str) -> None:
        if not _SHA256.fullmatch(sha256):
            raise BlossomError(f"{sha256!r} is not a sha256 in lowercase hex")
