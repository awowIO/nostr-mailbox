"""NIP-44 version 2: secp256k1 ECDH / campaign key + HKDF + padding + ChaCha20 + HMAC-SHA256.

Implements the current revision of the NIP-44 v2 specification using the Python standard
library only, including the extended 6-byte length prefix for payloads of 65,536 bytes and
above (up to 2^32 - 1 bytes) so both campaign events and Blossom blobs share one cipher.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import os
import struct

from .errors import NostrError
from .secp256k1 import N, _affine, _lift_x, _mul

VERSION = 2
MIN_PLAINTEXT = 1
MAX_PLAINTEXT = 0xFFFFFFFF
EXTENDED_PREFIX_THRESHOLD = 65536
SALT = b"nip44-v2"

_SIGMA = (0x61707865, 0x3320646E, 0x79622D32, 0x6B206574)
_M32 = 0xFFFFFFFF


class Nip44Error(NostrError):
    """A payload failed NIP-44 v2 validation (version, length, MAC or padding)."""


def hkdf_extract(ikm: bytes, salt: bytes) -> bytes:
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    out, block, counter = b"", b"", 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        out += block
        counter += 1
    return out[:length]


def ecdh_x(secret: bytes, peer_pub_x: bytes) -> bytes:
    if len(secret) != 32 or len(peer_pub_x) != 32:
        raise Nip44Error("ECDH keys must be 32 bytes")
    d = int.from_bytes(secret, "big")
    if not 1 <= d < N:
        raise Nip44Error("secret scalar out of range")
    pt = _lift_x(int.from_bytes(peer_pub_x, "big"))
    if pt is None:
        raise Nip44Error("peer public key is not on secp256k1")
    shared = _mul(d, *pt)
    if shared is None:
        raise Nip44Error("shared point at infinity")
    x, _ = _affine(shared)
    return x.to_bytes(32, "big")


def conversation_key(secret: bytes, peer_pub_x: bytes) -> bytes:
    """Pairwise NIP-44 v2 conversation key: conv(a, B) == conv(b, A)."""
    return hkdf_extract(ecdh_x(secret, peer_pub_x), SALT)


def campaign_conversation_key(secret_key: bytes, campaign: str) -> bytes:
    """Campaign-scoped 32-byte NIP-44 v2 conversation key derived via HKDF-SHA256."""
    if len(secret_key) != 32:
        raise Nip44Error("campaign_key must be 32 bytes")
    return hkdf_extract(secret_key, SALT + b":" + campaign.encode("utf-8"))


def _chacha_block(state: list[int]) -> bytes:
    x = state[:]

    def qr(a: int, b: int, c: int, d: int) -> None:
        x[a] = (x[a] + x[b]) & _M32
        v = x[d] ^ x[a]
        x[d] = ((v << 16) | (v >> 16)) & _M32
        x[c] = (x[c] + x[d]) & _M32
        v = x[b] ^ x[c]
        x[b] = ((v << 12) | (v >> 20)) & _M32
        x[a] = (x[a] + x[b]) & _M32
        v = x[d] ^ x[a]
        x[d] = ((v << 8) | (v >> 24)) & _M32
        x[c] = (x[c] + x[d]) & _M32
        v = x[b] ^ x[c]
        x[b] = ((v << 7) | (v >> 25)) & _M32

    for _ in range(10):
        qr(0, 4, 8, 12)
        qr(1, 5, 9, 13)
        qr(2, 6, 10, 14)
        qr(3, 7, 11, 15)
        qr(0, 5, 10, 15)
        qr(1, 6, 11, 12)
        qr(2, 7, 8, 13)
        qr(3, 4, 9, 14)
    return struct.pack("<16I", *((x[i] + state[i]) & _M32 for i in range(16)))


def chacha20(key: bytes, nonce: bytes, data: bytes) -> bytes:
    if len(key) != 32 or len(nonce) != 12:
        raise Nip44Error("ChaCha20 needs a 32-byte key and a 12-byte nonce")
    if not data:
        return b""
    state = [*_SIGMA, *struct.unpack("<8I", key), 0, *struct.unpack("<3I", nonce)]
    blocks = []
    for counter in range((len(data) + 63) // 64):
        state[12] = counter & _M32
        blocks.append(_chacha_block(state))
    keystream = b"".join(blocks)[: len(data)]
    mixed = int.from_bytes(data, "little") ^ int.from_bytes(keystream, "little")
    return mixed.to_bytes(len(data), "little")


def message_keys(conv_key: bytes, nonce: bytes) -> tuple[bytes, bytes, bytes]:
    if len(conv_key) != 32:
        raise Nip44Error("invalid conversation_key length")
    if len(nonce) != 32:
        raise Nip44Error("invalid nonce length")
    keys = hkdf_expand(conv_key, nonce, 76)
    return keys[0:32], keys[32:44], keys[44:76]


def calc_padded_len(unpadded_len: int) -> int:
    if unpadded_len <= 32:
        return 32
    next_power = 1 << (unpadded_len - 1).bit_length()
    chunk = 32 if next_power <= 256 else next_power // 8
    return chunk * ((unpadded_len - 1) // chunk + 1)


def pad(plaintext: bytes) -> bytes:
    n = len(plaintext)
    if not MIN_PLAINTEXT <= n <= MAX_PLAINTEXT:
        raise Nip44Error(f"invalid plaintext length {n}")
    prefix = ((b"\x00\x00" + n.to_bytes(4, "big"))
              if n >= EXTENDED_PREFIX_THRESHOLD else n.to_bytes(2, "big"))
    return prefix + plaintext + b"\x00" * (calc_padded_len(n) - n)


def unpad(padded: bytes) -> bytes:
    first_two = int.from_bytes(padded[0:2], "big")
    if first_two == 0:
        n = int.from_bytes(padded[2:6], "big")
        if n < EXTENDED_PREFIX_THRESHOLD:
            raise Nip44Error("invalid padding")
        prefix_len = 6
    else:
        n, prefix_len = first_two, 2
    unpadded = padded[prefix_len:prefix_len + n]
    if n == 0 or len(unpadded) != n or len(padded) != prefix_len + calc_padded_len(n):
        raise Nip44Error("invalid padding")
    return unpadded


def _hmac_aad(key: bytes, message: bytes, aad: bytes) -> bytes:
    if len(aad) != 32:
        raise Nip44Error("AAD associated data must be 32 bytes")
    return hmac.new(key, aad + message, hashlib.sha256).digest()


def encrypt_bytes(plaintext: bytes, conv_key: bytes, nonce: bytes | None = None) -> str:
    nonce = os.urandom(32) if nonce is None else nonce
    chacha_key, chacha_nonce, hmac_key = message_keys(conv_key, nonce)
    ciphertext = chacha20(chacha_key, chacha_nonce, pad(plaintext))
    mac = _hmac_aad(hmac_key, ciphertext, nonce)
    return base64.b64encode(bytes([VERSION]) + nonce + ciphertext + mac).decode("ascii")


def encrypt(plaintext: str, conv_key: bytes, nonce: bytes | None = None) -> str:
    return encrypt_bytes(plaintext.encode("utf-8"), conv_key, nonce)


def decode_payload(payload: str) -> tuple[bytes, bytes, bytes]:
    if not payload or payload[0] in ("#", "{"):
        raise Nip44Error("payload is not NIP-44 v2 ciphertext")
    if len(payload) < 132:
        raise Nip44Error("invalid payload size")
    if not payload.isascii():
        raise Nip44Error("invalid base64: payload contains non-ASCII characters")
    try:
        data = base64.b64decode(payload, validate=True)
    except binascii.Error as exc:
        raise Nip44Error(f"invalid base64: {exc}") from exc
    if len(data) < 99:
        raise Nip44Error("invalid data size")
    if data[0] != VERSION:
        raise Nip44Error(f"unknown encryption version {data[0]}")
    return data[1:33], data[33:-32], data[-32:]


def decrypt_bytes(payload: str, conv_key: bytes) -> bytes:
    nonce, ciphertext, mac = decode_payload(payload)
    chacha_key, chacha_nonce, hmac_key = message_keys(conv_key, nonce)
    if not hmac.compare_digest(_hmac_aad(hmac_key, ciphertext, nonce), mac):
        raise Nip44Error("invalid MAC (wrong campaign_key or tampered ciphertext)")
    return unpad(chacha20(chacha_key, chacha_nonce, ciphertext))


def decrypt(payload: str, conv_key: bytes) -> str:
    raw = decrypt_bytes(payload, conv_key)
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise Nip44Error("plaintext is not valid UTF-8") from exc
