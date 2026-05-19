"""Noise_XK_25519_ChaChaPoly_BLAKE2s — direct port of the TS reference.

Hand-rolled to guarantee byte-for-byte interop with the @noble/curves-backed
TypeScript reference. Uses cryptography's BLAKE2s/ChaCha20-Poly1305 + a manual
X25519 implementation (RFC 7748).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import blake2s

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

PROTOCOL = b"Noise_XK_25519_ChaChaPoly_BLAKE2s"
HASHLEN = 32
BLOCKLEN = 64


# --- X25519 (RFC 7748) ---
_P = (1 << 255) - 19
_A24 = 121665


def _clamp(scalar: bytes) -> int:
    s = bytearray(scalar)
    s[0] &= 248
    s[31] &= 127
    s[31] |= 64
    return int.from_bytes(bytes(s), "little")


def _decode_u(u_bytes: bytes) -> int:
    u = bytearray(u_bytes)
    u[31] &= 0x7F  # mask high bit
    return int.from_bytes(bytes(u), "little") % _P


def _encode_u(u: int) -> bytes:
    return (u % _P).to_bytes(32, "little")


def _x25519_scalar_mult(scalar: bytes, u_bytes: bytes) -> bytes:
    k = _clamp(scalar)
    x1 = _decode_u(u_bytes)
    x2, z2 = 1, 0
    x3, z3 = x1, 1
    swap = 0
    for t in range(254, -1, -1):
        kt = (k >> t) & 1
        swap ^= kt
        if swap:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = kt
        a = (x2 + z2) % _P
        aa = (a * a) % _P
        b = (x2 - z2) % _P
        bb = (b * b) % _P
        e = (aa - bb) % _P
        c = (x3 + z3) % _P
        d = (x3 - z3) % _P
        da = (d * a) % _P
        cb = (c * b) % _P
        x3 = pow((da + cb) % _P, 2, _P)
        z3 = (x1 * pow((da - cb) % _P, 2, _P)) % _P
        x2 = (aa * bb) % _P
        z2 = (e * ((aa + _A24 * e) % _P)) % _P
    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2
    return _encode_u((x2 * pow(z2, _P - 2, _P)) % _P)


_BASE_U = (9).to_bytes(32, "little")


def x25519_public_from_private(priv: bytes) -> bytes:
    return _x25519_scalar_mult(priv, _BASE_U)


def x25519_random_private() -> bytes:
    import secrets

    return secrets.token_bytes(32)


# --- hashing primitives ---


def _hash(data: bytes) -> bytes:
    return blake2s(data).digest()


def hmac_blake2s(key: bytes, data: bytes) -> bytes:
    k = key if len(key) <= BLOCKLEN else _hash(key)
    padded = bytearray(BLOCKLEN)
    padded[: len(k)] = k
    ipad = bytes(b ^ 0x36 for b in padded)
    opad = bytes(b ^ 0x5C for b in padded)
    inner = _hash(ipad + data)
    return _hash(opad + inner)


def hkdf2(ck: bytes, ikm: bytes) -> tuple[bytes, bytes]:
    t0 = hmac_blake2s(ck, ikm)
    t1 = hmac_blake2s(t0, b"\x01")
    t2 = hmac_blake2s(t0, t1 + b"\x02")
    return t1, t2


def _nonce_bytes(n: int) -> bytes:
    # 4 zero bytes || 8-byte little-endian counter.
    return b"\x00\x00\x00\x00" + n.to_bytes(8, "little")


@dataclass
class CipherState:
    k: bytes | None = None
    n: int = 0

    def encrypt_with_ad(self, ad: bytes, plaintext: bytes) -> bytes:
        if self.k is None:
            return plaintext
        ct = ChaCha20Poly1305(self.k).encrypt(_nonce_bytes(self.n), plaintext, ad)
        self.n += 1
        return ct

    def decrypt_with_ad(self, ad: bytes, ciphertext: bytes) -> bytes:
        if self.k is None:
            return ciphertext
        pt = ChaCha20Poly1305(self.k).decrypt(_nonce_bytes(self.n), ciphertext, ad)
        self.n += 1
        return pt


@dataclass
class SymmetricState:
    ck: bytes = field(init=False)
    h: bytes = field(init=False)
    cs: CipherState = field(default_factory=CipherState)

    def __post_init__(self) -> None:
        if len(PROTOCOL) <= HASHLEN:
            self.h = PROTOCOL + b"\x00" * (HASHLEN - len(PROTOCOL))
        else:
            self.h = _hash(PROTOCOL)
        self.ck = self.h

    def mix_hash(self, data: bytes) -> None:
        self.h = _hash(self.h + data)

    def mix_key(self, ikm: bytes) -> None:
        new_ck, temp_k = hkdf2(self.ck, ikm)
        self.ck = new_ck
        self.cs = CipherState(k=temp_k, n=0)

    def encrypt_and_hash(self, plaintext: bytes) -> bytes:
        ct = self.cs.encrypt_with_ad(self.h, plaintext)
        self.mix_hash(ct)
        return ct

    def decrypt_and_hash(self, ciphertext: bytes) -> bytes:
        pt = self.cs.decrypt_with_ad(self.h, ciphertext)
        self.mix_hash(ciphertext)
        return pt

    def split(self) -> tuple[CipherState, CipherState]:
        k1, k2 = hkdf2(self.ck, b"")
        return CipherState(k=k1), CipherState(k=k2)


@dataclass
class HandshakeResult:
    """Two-direction transport: send (this side) and recv (the other side)."""

    send_cs: CipherState
    recv_cs: CipherState

    def send(self, plaintext: bytes) -> bytes:
        return self.send_cs.encrypt_with_ad(b"", plaintext)

    def recv(self, ciphertext: bytes) -> bytes:
        return self.recv_cs.decrypt_with_ad(b"", ciphertext)


def build_prologue(initiator_did: str, responder_did: str) -> bytes:
    prefix = b"agent-phone/1"
    init = initiator_did.encode("utf-8")
    resp = responder_did.encode("utf-8")
    return (
        prefix
        + len(init).to_bytes(2, "big")
        + init
        + len(resp).to_bytes(2, "big")
        + resp
    )


def _dh(priv: bytes, pub: bytes) -> bytes:
    return _x25519_scalar_mult(priv, pub)


class InitiatorHandshake:
    def __init__(
        self,
        *,
        prologue: bytes,
        static_priv: bytes,
        static_pub: bytes,
        responder_static_pub: bytes,
    ) -> None:
        self.ss = SymmetricState()
        self.ss.mix_hash(prologue)
        # XK pre-message: responder's static is known to the initiator.
        self.ss.mix_hash(responder_static_pub)
        self.static_priv = static_priv
        self.static_pub = static_pub
        self.responder_static_pub = responder_static_pub
        self._e_priv: bytes | None = None
        self._re_pub: bytes | None = None

    def write_message_1(self) -> bytes:
        # -> e, es
        self._e_priv = x25519_random_private()
        e_pub = x25519_public_from_private(self._e_priv)
        self.ss.mix_hash(e_pub)
        self.ss.mix_key(_dh(self._e_priv, self.responder_static_pub))
        enc_payload = self.ss.encrypt_and_hash(b"")
        return e_pub + enc_payload

    def read_message_2(self, msg: bytes) -> None:
        # <- e, ee
        if self._e_priv is None:
            raise RuntimeError("write_message_1 must run first")
        self._re_pub = msg[:32]
        rest = msg[32:]
        self.ss.mix_hash(self._re_pub)
        self.ss.mix_key(_dh(self._e_priv, self._re_pub))
        self.ss.decrypt_and_hash(rest)

    def write_message_3(self) -> bytes:
        # -> s, se
        if self._re_pub is None:
            raise RuntimeError("read_message_2 must run first")
        enc_s = self.ss.encrypt_and_hash(self.static_pub)
        self.ss.mix_key(_dh(self.static_priv, self._re_pub))
        enc_payload = self.ss.encrypt_and_hash(b"")
        return enc_s + enc_payload

    def finish(self) -> HandshakeResult:
        send_cs, recv_cs = self.ss.split()
        return HandshakeResult(send_cs=send_cs, recv_cs=recv_cs)


class ResponderHandshake:
    def __init__(
        self,
        *,
        prologue: bytes,
        static_priv: bytes,
        static_pub: bytes,
    ) -> None:
        self.ss = SymmetricState()
        self.ss.mix_hash(prologue)
        # XK pre-message: responder's own static is absorbed.
        self.ss.mix_hash(static_pub)
        self.static_priv = static_priv
        self.static_pub = static_pub
        self._e_priv: bytes | None = None
        self._re_init_pub: bytes | None = None

    def read_message_1(self, msg: bytes) -> None:
        # -> e, es
        self._re_init_pub = msg[:32]
        rest = msg[32:]
        self.ss.mix_hash(self._re_init_pub)
        self.ss.mix_key(_dh(self.static_priv, self._re_init_pub))
        self.ss.decrypt_and_hash(rest)

    def write_message_2(self) -> bytes:
        # <- e, ee
        if self._re_init_pub is None:
            raise RuntimeError("read_message_1 must run first")
        self._e_priv = x25519_random_private()
        e_pub = x25519_public_from_private(self._e_priv)
        self.ss.mix_hash(e_pub)
        self.ss.mix_key(_dh(self._e_priv, self._re_init_pub))
        enc_payload = self.ss.encrypt_and_hash(b"")
        return e_pub + enc_payload

    def read_message_3(self, msg: bytes) -> None:
        # -> s, se
        if self._e_priv is None:
            raise RuntimeError("write_message_2 must run first")
        enc_s = msg[: 32 + 16]
        rest = msg[32 + 16 :]
        ris_pub = self.ss.decrypt_and_hash(enc_s)
        self.ss.mix_key(_dh(self._e_priv, ris_pub))
        self.ss.decrypt_and_hash(rest)

    def finish(self) -> HandshakeResult:
        # Note: on the responder side, the split tuple is (recv, send) because
        # the first key produced by HKDF is the initiator→responder one.
        recv_cs, send_cs = self.ss.split()
        return HandshakeResult(send_cs=send_cs, recv_cs=recv_cs)
