"""NIP-19 `npub1…` / `nsec1…`: the human-facing Bech32 spelling of a 32-byte key.

On the wire a key is 64 lowercase hex characters, always. These two functions exist
for what a person reads, pastes and stores; nothing here is sent to a relay."""
from __future__ import annotations

from .errors import NostrError

_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_GENERATORS = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
_CHECKSUM_LEN = 6
NPUB, NSEC = "npub", "nsec"


class Bech32Error(NostrError, ValueError):
    """Not a well-formed Bech32 key of the expected kind."""


def _polymod(values: list[int]) -> int:
    chk = 1
    for value in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ value
        for i, generator in enumerate(_GENERATORS):
            if (top >> i) & 1:
                chk ^= generator
    return chk


def _hrp_expand(hrp: str) -> list[int]:
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _regroup(data: list[int], from_bits: int, to_bits: int, *, pad: bool) -> list[int]:
    acc = bits = 0
    out = []
    mask = (1 << to_bits) - 1
    for value in data:
        acc = acc << from_bits | value
        bits += from_bits
        while bits >= to_bits:
            bits -= to_bits
            out.append(acc >> bits & mask)
    if pad:
        if bits:
            out.append(acc << (to_bits - bits) & mask)
    elif bits >= from_bits or acc << (to_bits - bits) & mask:
        raise Bech32Error("non-zero or oversized padding")
    return out


def encode(hrp: str, payload: bytes) -> str:
    if len(payload) != 32:
        raise Bech32Error("a key is 32 bytes")
    words = _regroup(list(payload), 8, 5, pad=True)
    polymod = _polymod(_hrp_expand(hrp) + words + [0] * _CHECKSUM_LEN) ^ 1
    checksum = [polymod >> 5 * (_CHECKSUM_LEN - 1 - i) & 31 for i in range(_CHECKSUM_LEN)]
    return hrp + "1" + "".join(_CHARSET[w] for w in words + checksum)


def decode(expected_hrp: str, text: str) -> bytes:
    """The 32 bytes behind `text`, which must carry `expected_hrp` and a valid checksum."""
    if text != text.lower() and text != text.upper():
        raise Bech32Error("mixed-case Bech32")
    text = text.lower()
    hrp, sep, rest = text.rpartition("1")
    if not sep or hrp != expected_hrp:
        raise Bech32Error(f"expected a {expected_hrp}1… key")
    if any(c not in _CHARSET for c in rest) or len(rest) <= _CHECKSUM_LEN:
        raise Bech32Error("characters outside the Bech32 alphabet, or no payload")
    words = [_CHARSET.index(c) for c in rest]
    if _polymod(_hrp_expand(hrp) + words) != 1:
        raise Bech32Error("checksum mismatch: the key was mistyped or truncated")
    payload = bytes(_regroup(words[:-_CHECKSUM_LEN], 5, 8, pad=False))
    if len(payload) != 32:
        raise Bech32Error("a key is 32 bytes")
    return payload


def pubkey_hex(text: str) -> str:
    """A public key given as `npub1…` or as 64 hex characters, as lowercase hex."""
    text = text.strip()
    if text.lower().startswith(NPUB + "1"):
        return decode(NPUB, text).hex()
    if text.lower().startswith(NSEC + "1"):
        raise Bech32Error("that is a SECRET key (nsec1…); a public key is npub1… or hex")
    try:
        raw = bytes.fromhex(text)
    except ValueError as exc:
        raise Bech32Error(f"neither npub1… nor hex: {text[:12]}…") from exc
    if len(raw) != 32:
        raise Bech32Error("a public key is 32 bytes (64 hex characters)")
    return raw.hex()
