"""BIP-340 Schnorr signatures over secp256k1, on the standard library alone.

Two backends, one contract. `pure-python` is always present, so a seat signs and
verifies with zero third-party wheels installed. `coincurve` (libsecp256k1, the
`nostr-mailbox[nostr]` extra) is picked up when it imports, and is checked against a
BIP-340 vector before its first use: a binding that disagrees with the specification
raises, it is never quietly swapped for the other backend. `BACKEND` names the one in
use, and the CLI prints it.

What the pure-Python backend is NOT: constant-time. Python integers leak the bits of a
secret scalar through timing. Verification handles public data only and is unaffected.
For signing, that matters when an attacker can time many signatures made on the same
machine (a shared host, a signing service answering strangers). A seat signing its own
events on its own machine is outside that threat; an operator key that signs on a
shared host should install the extra, or sit behind a signer on another machine."""
from __future__ import annotations

import hashlib
import secrets

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

_WINDOW_BITS = 4                       # scalar digits are nibbles: 64 of them in 256 bits
_WINDOWS = 256 // _WINDOW_BITS
_DIGITS = (1 << _WINDOW_BITS) - 1      # non-zero digit values per window

try:
    import coincurve as _coincurve
except ModuleNotFoundError as exc:
    if exc.name != "coincurve":        # coincurve IS installed and one of its own
        raise                          # dependencies is missing: a broken install, shown
    _coincurve = None                  # the optional extra is simply not installed

BACKEND = "coincurve" if _coincurve is not None else "pure-python"


class Secp256k1Error(ValueError):
    """A key, message or signature that the curve arithmetic cannot accept."""


# ------------------------------------------------------------------ tagged hashes
def _tag_state(tag: str):
    digest = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(digest + digest)


_AUX, _NONCE, _CHALLENGE = (_tag_state(f"BIP0340/{name}")
                            for name in ("aux", "nonce", "challenge"))


def _tagged(state, *parts: bytes) -> bytes:
    h = state.copy()
    for part in parts:
        h.update(part)
    return h.digest()


# ---------------------------------------------------------------- point arithmetic
# Points are Jacobian triples (X, Y, Z) with x = X/Z², y = Y/Z³; None is infinity.
# Every addition takes its second operand in affine form, which is all the two
# multiplication routines below ever need.
def _double(point):
    if point is None:
        return None
    x, y, z = point
    a = x * x % P
    b = y * y % P
    c = b * b % P
    d = 4 * x * b % P
    e = 3 * a
    x3 = (e * e - 2 * d) % P
    return x3, (e * (d - x3) - 8 * c) % P, 2 * y * z % P


def _add_affine(point, x2: int, y2: int):
    if point is None:
        return x2, y2, 1
    x1, y1, z1 = point
    z1z1 = z1 * z1 % P
    h = (x2 * z1z1 - x1) % P
    r = (y2 * z1 * z1z1 - y1) % P
    if h == 0:
        return _double(point) if r == 0 else None
    hh = h * h % P
    hhh = h * hh % P
    v = x1 * hh % P
    x3 = (r * r - hhh - 2 * v) % P
    return x3, (r * (v - x3) - y1 * hhh) % P, z1 * h % P


def _affine(point) -> tuple[int, int]:
    x, y, z = point
    z_inv = pow(z, -1, P)
    z_inv2 = z_inv * z_inv % P
    return x * z_inv2 % P, y * z_inv2 * z_inv % P


def _affine_all(points: list) -> list[tuple[int, int]]:
    """`_affine` for many points with one modular inversion (Montgomery's trick): invert
    the product of every Z, then peel one inverse off per point, last to first."""
    running, prefix = 1, []
    for _, _, z in points:
        prefix.append(running)
        running = running * z % P
    inverse = pow(running, -1, P)
    out = [None] * len(points)
    for i in range(len(points) - 1, -1, -1):
        x, y, z = points[i]
        z_inv = inverse * prefix[i] % P
        inverse = inverse * z % P
        z_inv2 = z_inv * z_inv % P
        out[i] = (x * z_inv2 % P, y * z_inv2 * z_inv % P)
    return out


def _multiples(x: int, y: int) -> list[tuple[int, int]]:
    """[1·Q, 2·Q, … 15·Q] in affine form."""
    jacobian, acc = [], None
    for _ in range(_DIGITS):
        acc = _add_affine(acc, x, y)
        jacobian.append(acc)
    return _affine_all(jacobian)


_G_TABLE: list[list[tuple[int, int]]] = []


def _g_table() -> list[list[tuple[int, int]]]:
    """Row i holds the non-zero digit multiples of 16^i·G, so k·G is one table
    addition per non-zero nibble of k and no doublings. Built on first use."""
    if not _G_TABLE:
        base = (GX, GY)
        rows = []
        for _ in range(_WINDOWS):
            row = _multiples(*base)
            rows.append(row)
            base = _affine(_add_affine((*row[-1], 1), *base))    # 15·B + B = 16·B
        _G_TABLE.extend(rows)
    return _G_TABLE


def _mul_g(k: int, acc=None):
    """acc + k·G."""
    table = _g_table()
    window = 0
    while k:
        digit = k & _DIGITS
        if digit:
            acc = _add_affine(acc, *table[window][digit - 1])
        k >>= _WINDOW_BITS
        window += 1
    return acc


def _mul(k: int, x: int, y: int):
    """k·(x, y) for an arbitrary point: fixed four-bit windows, high nibble first."""
    multiples = _multiples(x, y)
    acc = None
    for shift in range(256 - _WINDOW_BITS, -1, -_WINDOW_BITS):
        acc = _double(_double(_double(_double(acc))))
        digit = (k >> shift) & _DIGITS
        if digit:
            acc = _add_affine(acc, *multiples[digit - 1])
    return acc


def _lift_x(x: int) -> tuple[int, int] | None:
    """The curve point with this x and an even y, or None when x is not on the curve."""
    if x >= P:
        return None
    y_sq = (pow(x, 3, P) + 7) % P
    y = pow(y_sq, (P + 1) // 4, P)
    if y * y % P != y_sq:
        return None
    return x, (y if y % 2 == 0 else P - y)


def _scalar(secret: bytes) -> int:
    if len(secret) != 32:
        raise Secp256k1Error("a secret key is 32 bytes")
    d = int.from_bytes(secret, "big")
    if not 1 <= d < N:
        raise Secp256k1Error("secret key is outside the range 1..n-1")
    return d


# ------------------------------------------------------------- the pure backend
def _py_pubkey(secret: bytes) -> bytes:
    x, _ = _affine(_mul_g(_scalar(secret)))
    return x.to_bytes(32, "big")


def _py_sign(msg: bytes, secret: bytes, aux: bytes) -> bytes:
    d0 = _scalar(secret)
    px, py = _affine(_mul_g(d0))
    d = d0 if py % 2 == 0 else N - d0
    pub = px.to_bytes(32, "big")
    masked = (d ^ int.from_bytes(_tagged(_AUX, aux), "big")).to_bytes(32, "big")
    k0 = int.from_bytes(_tagged(_NONCE, masked, pub, msg), "big") % N
    if k0 == 0:
        raise Secp256k1Error("nonce derivation produced zero; sign with fresh aux randomness")
    rx, ry = _affine(_mul_g(k0))
    k = k0 if ry % 2 == 0 else N - k0
    r = rx.to_bytes(32, "big")
    e = int.from_bytes(_tagged(_CHALLENGE, r, pub, msg), "big") % N
    sig = r + ((k + e * d) % N).to_bytes(32, "big")
    if not _py_verify(msg, pub, sig):      # BIP-340: never release an unverified signature
        raise Secp256k1Error("the signature just produced does not verify")
    return sig


def _py_verify(msg: bytes, pubkey: bytes, sig: bytes) -> bool:
    if len(pubkey) != 32 or len(sig) != 64:
        return False
    point = _lift_x(int.from_bytes(pubkey, "big"))
    if point is None:
        return False
    r = int.from_bytes(sig[:32], "big")
    s = int.from_bytes(sig[32:], "big")
    if r >= P or s >= N:
        return False
    e = int.from_bytes(_tagged(_CHALLENGE, sig[:32], pubkey, msg), "big") % N
    # R = s·G − e·P, computed as s·G + (n − e)·P
    minus_e_p = _mul((N - e) % N, *point)
    start = None if minus_e_p is None else (*_affine(minus_e_p), 1)
    total = _mul_g(s, start)
    if total is None:
        return False
    x, y = _affine(total)
    return y % 2 == 0 and x == r


# -------------------------------------------------------- the coincurve backend
# BIP-340 test vector 1: a fixed key, message and aux randomness with one right answer.
_SELFTEST = tuple(bytes.fromhex(h) for h in (
    "B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF",
    "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
    "0000000000000000000000000000000000000000000000000000000000000001",
    "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
    "6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE3341"
    "8906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A",
))
_accelerated_checked = False


def _accelerated() -> bool:
    """True when coincurve is installed, after proving once that it and the pure
    backend agree with the specification's vector."""
    global _accelerated_checked
    if _coincurve is None:
        return False
    if not _accelerated_checked:
        secret, pub, aux, msg, sig = _SELFTEST
        problems = []
        if _coincurve.PublicKeyXOnly.from_secret(secret).format() != pub:
            problems.append("public key derivation")
        if _coincurve.PrivateKey(secret).sign_schnorr(msg, aux) != sig:
            problems.append("signing")
        if not _coincurve.PublicKeyXOnly(pub).verify(sig, msg):
            problems.append("verification")
        if _coincurve.PublicKeyXOnly(pub).verify(sig[:63] + bytes([sig[63] ^ 1]), msg):
            problems.append("rejection of a tampered signature")
        if problems:
            raise RuntimeError(
                "the installed coincurve disagrees with BIP-340 test vector 1 on "
                f"{', '.join(problems)}; uninstall it to use the pure-Python backend")
        _accelerated_checked = True
    return True


# ------------------------------------------------------------------ public surface
def generate_secret() -> bytes:
    """32 fresh secret bytes in 1..n-1."""
    while True:
        candidate = secrets.token_bytes(32)
        if 1 <= int.from_bytes(candidate, "big") < N:
            return candidate


def pubkey_gen(secret: bytes) -> bytes:
    """The 32-byte x-only public key of a 32-byte secret key."""
    _scalar(secret)
    if _accelerated():
        return _coincurve.PublicKeyXOnly.from_secret(secret).format()
    return _py_pubkey(secret)


def schnorr_sign(msg: bytes, secret: bytes, aux: bytes | None = None) -> bytes:
    """A 64-byte BIP-340 signature. `aux` is 32 bytes of fresh randomness and is drawn
    from the OS when omitted; pass it explicitly only to reproduce a test vector."""
    aux = secrets.token_bytes(32) if aux is None else aux
    if len(aux) != 32:
        raise Secp256k1Error("aux randomness is 32 bytes")
    _scalar(secret)
    if len(msg) == 32 and _accelerated():       # libsecp256k1's binding signs digests only
        return _coincurve.PrivateKey(secret).sign_schnorr(msg, aux)
    return _py_sign(msg, secret, aux)


def schnorr_verify(msg: bytes, pubkey: bytes, sig: bytes) -> bool:
    """True only for a valid BIP-340 signature of `msg` under the x-only `pubkey`."""
    if len(pubkey) != 32 or len(sig) != 64:
        return False
    if _accelerated():
        try:
            key = _coincurve.PublicKeyXOnly(pubkey)
        except ValueError:                      # not a point on the curve
            return False
        return key.verify(sig, msg)
    return _py_verify(msg, pubkey, sig)
