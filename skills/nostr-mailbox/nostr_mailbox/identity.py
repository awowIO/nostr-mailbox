"""Keys, and the three ways a process can sign with one.

Every person and every agent seat has its own key. An identity file names the public
key and says where signing happens:

- `local`   — the secret sits in the file (mode 0600, refused at any wider mode);
- `command` — a program reads the unsigned event on stdin and writes the signed one on
              stdout (a keychain helper, `ncli id sign … -e - -o -`);
- `socket`  — a Unix socket answers one JSON line per request (`SignerServer` below is
              that server).

`command` and `socket` exist so a container seat never holds a raw key: the operator's
machine runs the signer, mounts the socket into the container, and `SignerServer`
signs only the kinds the seat's role needs. Whatever an out-of-process signer returns
is verified before it is used: the right key, a valid signature, and the very event it
was asked to sign."""
from __future__ import annotations

import contextlib
import json
import os
import re
import socket
import stat
import subprocess
import tempfile
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from . import bech32, secp256k1
from ._serve import Listener
from .event import DEFAULT_WAIT_S, Event, NostrError, dumps, sign_with_secret, verify_event

SCHEMA = "cf.identity/1"
HOME_ENV = "NOSTR_MAILBOX_HOME"
DEFAULT_HOME = "~/.config/nostr-mailbox"
DEFAULT_NAME = "default"
_SLUG = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")  # path-safe; the rule a seat id follows
_PRIVATE = 0o600
_PRIVATE_DIR = 0o700
AUTH_KIND = 22_242                                  # NIP-42
BLOSSOM_AUTH_KIND = 24_242                          # Blossom authorization (BUD-11)
# One signing request is one unsigned event and a few bytes of envelope. The campaign
# caps a whole signed event at 16,384 bytes (profile.MAX_EVENT_BYTES); twice that is
# room for the envelope and for JSON escaping, and nothing legitimate comes close.
MAX_REQUEST_BYTES = 2 * 16_384


class IdentityError(NostrError):
    """A key file that is missing, already present, malformed or readable by others."""


class SignerError(NostrError):
    """A signer refused, failed, or answered with something other than what was asked."""


class Signer(Protocol):
    pubkey: str

    def sign_event(self, template: dict) -> Event: ...


def accept_signed(template: dict, signed, pubkey: str) -> Event:
    """Admit what an out-of-process signer returned, or refuse it."""
    event = verify_event(signed)
    if event.pubkey != pubkey:
        raise SignerError(f"signer answered as {event.pubkey[:12]}…, expected {pubkey[:12]}…")
    asked = (template["created_at"], template["kind"],
             [list(t) for t in template["tags"]], template["content"])
    if (event.created_at, event.kind, [list(t) for t in event.tags], event.content) != asked:
        raise SignerError("signer returned a different event than the one it was given")
    return event


class LocalSigner:
    """Signs in this process with a secret held in memory."""

    def __init__(self, secret: bytes):
        self._secret = secret
        self.pubkey = secp256k1.pubkey_gen(secret).hex()

    def sign_event(self, template: dict) -> Event:
        return sign_with_secret(template, self._secret, self.pubkey)

    def __repr__(self) -> str:                      # never the secret
        return f"LocalSigner({bech32.encode(bech32.NPUB, bytes.fromhex(self.pubkey))})"


class CommandSigner:
    """Signs by running a program: unsigned event JSON on stdin, signed event on stdout."""

    def __init__(self, argv: list[str], pubkey: str, *, timeout_s: float):
        if not argv:
            raise SignerError("a command signer needs a command")
        self.argv, self.pubkey, self.timeout_s = list(argv), pubkey, timeout_s

    def sign_event(self, template: dict) -> Event:
        try:
            done = subprocess.run(self.argv, input=dumps(template), capture_output=True,
                                  text=True, timeout=self.timeout_s, check=False)
        except subprocess.TimeoutExpired as exc:
            raise SignerError(
                f"signer command {self.argv[0]!r} gave no answer in {self.timeout_s}s") from exc
        except OSError as exc:
            raise SignerError(f"signer command {self.argv[0]!r} could not run: {exc}") from exc
        if done.returncode != 0:
            said = done.stderr.strip().splitlines()
            raise SignerError(      # its last line only: a signer's stderr can be long,
                f"signer command {self.argv[0]!r} exited {done.returncode}"  # or private
                f"{': ' + said[-1] if said else ''}")
        try:
            signed = json.loads(done.stdout)
        except json.JSONDecodeError as exc:
            raise SignerError(f"signer command {self.argv[0]!r} did not print JSON: {exc}") from exc
        return accept_signed(template, signed, self.pubkey)


def _socket_call(path: str, request: dict, timeout_s: float) -> dict:
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
            conn.settimeout(timeout_s)
            conn.connect(path)
            conn.sendall((dumps(request) + "\n").encode())
            with conn.makefile("r", encoding="utf-8") as reader:
                line = reader.readline()
    except TimeoutError as exc:
        raise SignerError(f"signer socket {path} gave no answer in {timeout_s}s") from exc
    except OSError as exc:
        raise SignerError(f"signer socket {path} is unreachable: {exc}") from exc
    try:
        answer = json.loads(line)
    except json.JSONDecodeError as exc:
        raise SignerError(f"signer socket {path} did not answer with JSON: {exc}") from exc
    if not isinstance(answer, dict):
        raise SignerError(f"signer socket {path} did not answer with a JSON object")
    if "error" in answer:
        raise SignerError(f"signer refused: {answer['error']}")
    return answer


class SocketSigner:
    """Signs by asking a `SignerServer` on a Unix socket."""

    def __init__(self, path: str | Path, pubkey: str, *, timeout_s: float):
        self.path, self.pubkey, self.timeout_s = str(path), pubkey, timeout_s

    @staticmethod
    def ask_pubkey(path: str | Path, *, timeout_s: float) -> str:
        answer = _socket_call(str(path), {"method": "get_public_key"}, timeout_s)
        return bech32.pubkey_hex(str(answer.get("pubkey", "")))

    def sign_event(self, template: dict) -> Event:
        answer = _socket_call(self.path, {"method": "sign_event", "event": template},
                              self.timeout_s)
        return accept_signed(template, answer.get("event"), self.pubkey)


class SignerServer:
    """Holds a key on one side of a Unix socket and signs for the other side.

    The policy is what this server will put the key's name to, nothing else:

    - `allow_kinds`: a kind outside it is refused, so a seat's signer cannot be made
      to sign an operator directive;
    - `relay`: when set, a NIP-42 proof is signed for that relay URL only. This pin
      covers NIP-42 and nothing else;
    - `blossom_server` and `blossom_verbs`: when set, a blob authorization is signed
      only for that server name and those verbs, so the key cannot be used to fetch
      or delete blobs anywhere else.

    One request is one line of at most `MAX_REQUEST_BYTES`, read within
    `read_timeout_s`. `close()` returns only after every open connection is shut and no
    signature can still be produced. The socket is created 0600; its directory is
    created 0700 when it does not exist yet, and is left as it is when it does."""

    def __init__(self, path: str | Path, signer: Signer, *, allow_kinds: frozenset[int],
                 relay: str | None = None, blossom_server: str | None = None,
                 blossom_verbs: frozenset[str] = frozenset(),
                 read_timeout_s: float = DEFAULT_WAIT_S):
        self.path, self.signer = Path(path), signer
        self.allow_kinds, self.relay = frozenset(allow_kinds), relay
        self.blossom_server, self.blossom_verbs = blossom_server, frozenset(blossom_verbs)
        self.read_timeout_s = read_timeout_s
        self._listener: Listener | None = None
        self._signing = threading.Lock()         # held while a signature is produced
        self._open: set[socket.socket] = set()
        self._closed = False

    @staticmethod
    def _values(tags: list, name: str) -> list:
        return [t[1] for t in tags if isinstance(t, list) and len(t) > 1 and t[0] == name]

    def _answer(self, line: str) -> dict:
        try:
            request = json.loads(line)
        except json.JSONDecodeError as exc:
            return {"error": f"request is not JSON: {exc}"}
        if not isinstance(request, dict):
            return {"error": "request is not a JSON object"}
        method = request.get("method")
        if method == "get_public_key":
            return {"pubkey": self.signer.pubkey}
        if method != "sign_event":
            return {"error": f"unknown method {method!r}"}
        template = request.get("event")
        if not isinstance(template, dict) or set(template) != {
                "created_at", "kind", "tags", "content"}:
            return {"error": "event must carry exactly created_at, kind, tags and content"}
        kind, tags = template["kind"], template["tags"]
        if type(kind) is not int or kind not in self.allow_kinds:
            return {"error": f"kind {kind} is not on this signer's allow list "
                             f"{sorted(self.allow_kinds)}"}
        if not isinstance(tags, list):
            return {"error": "event tags must be an array"}
        if (kind == AUTH_KIND and self.relay is not None
                and self._values(tags, "relay") != [self.relay]):
            return {"error": f"this signer authenticates to {self.relay} only"}
        if kind == BLOSSOM_AUTH_KIND and self.blossom_server is not None:
            if self._values(tags, "server") != [self.blossom_server]:
                return {"error": f"this signer authorizes blobs on {self.blossom_server} only"}
            verbs = self._values(tags, "t")
            if len(verbs) != 1 or verbs[0] not in self.blossom_verbs:
                return {"error": f"this signer authorizes blob verbs "
                                 f"{sorted(self.blossom_verbs)} only"}
        with self._signing:
            if self._closed:
                return {"error": "this signer has shut down"}
            try:
                return {"event": self.signer.sign_event(template).to_dict()}
            except NostrError as exc:
                return {"error": f"signing failed: {exc}"}

    def _read_line(self, conn: socket.socket) -> str | None:
        """One request line, or None when the peer sent too much or went quiet."""
        conn.settimeout(self.read_timeout_s)
        data = bytearray()
        try:
            while b"\n" not in data:
                if len(data) > MAX_REQUEST_BYTES:
                    return None
                chunk = conn.recv(MAX_REQUEST_BYTES + 1 - len(data))
                if not chunk:
                    break
                data += chunk
        except OSError:                             # timed out, or closed by shutdown
            return None
        return bytes(data).split(b"\n", 1)[0].decode("utf-8", "replace")

    def _connection(self, conn: socket.socket) -> None:
        with self._signing:
            if self._closed:
                conn.close()
                return
            self._open.add(conn)
        try:
            line = self._read_line(conn)
            answer = ({"error": f"a request is one line of at most {MAX_REQUEST_BYTES:,} "
                                f"bytes, sent within {self.read_timeout_s:g}s"}
                      if line is None else self._answer(line))
            with contextlib.suppress(OSError):      # the asker may have hung up
                conn.sendall((dumps(answer) + "\n").encode())
        finally:
            with self._signing:
                self._open.discard(conn)
            with contextlib.suppress(OSError):
                conn.close()

    def start(self) -> SignerServer:
        self.path.parent.mkdir(mode=_PRIVATE_DIR, parents=True, exist_ok=True)
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        previous = os.umask(0o777 & ~_PRIVATE)       # the socket is born 0600
        try:
            sock.bind(str(self.path))
        except OSError as exc:
            sock.close()
            raise SignerError(f"cannot serve a signer at {self.path}: {exc}") from exc
        finally:
            os.umask(previous)
        sock.listen()
        self._listener = Listener(sock, self._connection, "cf-signer").start()
        return self

    def close(self) -> None:
        """Stop accepting, cut every connection still open, and return once nothing
        can sign any more: a signature in flight finishes first."""
        if self._listener is None:
            return
        self._listener.stop()
        self._listener = None
        with self._signing:
            self._closed = True
            for conn in list(self._open):
                with contextlib.suppress(OSError):
                    conn.shutdown(socket.SHUT_RDWR)
        with contextlib.suppress(FileNotFoundError):
            self.path.unlink()

    def __enter__(self) -> SignerServer:
        return self.start()

    def __exit__(self, *exc_info) -> None:
        self.close()


# ----------------------------------------------------------------------- key files
def home(override: str | Path | None = None) -> Path:
    return Path(override or os.environ.get(HOME_ENV) or DEFAULT_HOME).expanduser()


@dataclass(frozen=True)
class Identity:
    name: str
    pubkey: str
    path: Path
    signer_spec: dict

    @property
    def npub(self) -> str:
        return bech32.encode(bech32.NPUB, bytes.fromhex(self.pubkey))

    def signer(self, *, timeout_s: float) -> Signer:
        kind = self.signer_spec["type"]
        if kind == "local":
            try:
                signer = LocalSigner(bech32.decode(bech32.NSEC, self.signer_spec["nsec"]))
            except (bech32.Bech32Error, secp256k1.Secp256k1Error) as exc:
                raise IdentityError(f"{self.path}: the stored secret key is unusable "
                                    f"({exc})") from exc
            if signer.pubkey != self.pubkey:
                raise IdentityError(f"{self.path}: the secret does not belong to the "
                                    "public key recorded beside it")
            return signer
        if kind == "command":
            return CommandSigner(self.signer_spec["argv"], self.pubkey, timeout_s=timeout_s)
        if kind == "socket":
            return SocketSigner(self.signer_spec["path"], self.pubkey, timeout_s=timeout_s)
        raise IdentityError(f"{self.path}: unknown signer type {kind!r}")

    def describe(self) -> dict:
        """What is safe to print: never the secret."""
        return {"name": self.name, "npub": self.npub, "pubkey": self.pubkey,
                "signer": self.signer_spec["type"], "path": str(self.path),
                "schnorr_backend": secp256k1.BACKEND}


def _identity_path(name: str, base: str | Path | None) -> Path:
    if not _SLUG.match(name):
        raise IdentityError(f"identity name {name!r} must match {_SLUG.pattern}")
    return home(base) / "identities" / f"{name}.json"


def create_identity(name: str = DEFAULT_NAME, *, base: str | Path | None = None,
                    command: list[str] | None = None, socket_path: str | None = None,
                    pubkey: str | None = None, timeout_s: float | None = None) -> Identity:
    """Write a new identity file and return it. Generates a key unless `command` or
    `socket_path` says signing happens elsewhere. Never overwrites: a key that exists
    is a key somebody may be enrolled with."""
    path = _identity_path(name, base)
    if command and socket_path:
        raise IdentityError("choose one of a signer command or a signer socket")
    if command:
        if not pubkey:
            raise IdentityError("a command signer needs --pubkey: the command only signs")
        spec, pub = {"type": "command", "argv": list(command)}, bech32.pubkey_hex(pubkey)
    elif socket_path:
        if timeout_s is None:
            raise IdentityError("asking a signer socket for its key needs a timeout")
        asked = SocketSigner.ask_pubkey(socket_path, timeout_s=timeout_s)
        if pubkey and bech32.pubkey_hex(pubkey) != asked:
            raise IdentityError("the signer socket holds a different key than --pubkey")
        spec, pub = {"type": "socket", "path": str(socket_path)}, asked
    else:
        secret = secp256k1.generate_secret()
        spec = {"type": "local", "nsec": bech32.encode(bech32.NSEC, secret)}
        pub = secp256k1.pubkey_gen(secret).hex()
    body = {"schema": SCHEMA, "name": name, "pubkey": pub,
            "npub": bech32.encode(bech32.NPUB, bytes.fromhex(pub)), "signer": spec}
    path.parent.mkdir(mode=_PRIVATE_DIR, parents=True, exist_ok=True)
    # Whole or absent, and never over an existing key: the file is written complete to
    # a private sibling (mkstemp makes it 0600), then published under its real name
    # with a hard link, which fails if that name is already taken.
    fd, staged = tempfile.mkstemp(dir=path.parent, prefix=f".{name}.", suffix=".part")
    try:
        with os.fdopen(fd, "w") as fh:
            json.dump(body, fh, indent=2)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.link(staged, path)
    except FileExistsError as exc:
        raise IdentityError(
            f"{path} already exists; refusing to overwrite a key. Pick another --name, "
            "or move the file away yourself if that key is truly retired") from exc
    except OSError as exc:
        raise IdentityError(f"cannot write the identity file {path}: {exc}") from exc
    finally:
        Path(staged).unlink(missing_ok=True)
    return Identity(name=name, pubkey=pub, path=path, signer_spec=spec)


def load_identity(name: str = DEFAULT_NAME, *, base: str | Path | None = None) -> Identity:
    path = _identity_path(name, base)
    try:
        mode = stat.S_IMODE(path.stat().st_mode)
    except FileNotFoundError as exc:
        raise IdentityError(f"no identity {name!r} at {path}; create one with `init`") from exc
    if mode & ~_PRIVATE:
        raise IdentityError(f"{path} is mode {mode:04o}; a key file must be 0600 "
                            f"(chmod 600 {path})")
    try:
        body = json.loads(path.read_text())
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise IdentityError(f"{path} is not JSON: {exc}") from exc
    if not isinstance(body, dict) or body.get("schema") != SCHEMA:
        raise IdentityError(f"{path} is not a {SCHEMA} identity file")
    spec = body.get("signer")
    kind = spec.get("type") if isinstance(spec, dict) else None
    argv = spec.get("argv") if kind == "command" else None
    usable = (
        (kind == "local" and isinstance(spec.get("nsec"), str))
        or (kind == "socket" and isinstance(spec.get("path"), str) and spec["path"])
        or (kind == "command" and isinstance(argv, list) and bool(argv)
            and all(isinstance(item, str) for item in argv)))
    if not usable:
        raise IdentityError(
            f"{path} names no usable signer: expected a `local` signer with `nsec`, a "
            "`command` signer with an `argv` list, or a `socket` signer with a `path`")
    try:
        pubkey = bech32.pubkey_hex(str(body.get("pubkey", "")))
    except bech32.Bech32Error as exc:
        raise IdentityError(f"{path} records an unusable public key: {exc}") from exc
    return Identity(name=name, pubkey=pubkey, path=path, signer_spec=spec)
