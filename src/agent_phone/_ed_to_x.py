"""Ed25519 → X25519 conversion.

Matches the `@noble/curves` `edwardsToMontgomeryPub` / `edwardsToMontgomeryPriv`
helpers used by the TS reference. The conversion is documented at
https://blog.filippo.io/using-ed25519-keys-for-encryption/ and the math is:

  * pub:  u = (1 + y) / (1 - y) mod p, where y is the little-endian Edwards
          y-coordinate (sign bit cleared).
  * priv: SHA-512(seed)[0..32] with the standard X25519 clamping.
"""

from __future__ import annotations

import hashlib

P = (1 << 255) - 19


def _inv_mod_p(x: int) -> int:
    return pow(x, P - 2, P)


def ed25519_pub_to_x25519(ed_pub: bytes) -> bytes:
    if len(ed_pub) != 32:
        raise ValueError("Ed25519 public key must be 32 bytes")
    # Little-endian; high bit of the last byte is the x-sign.
    y_bytes = bytearray(ed_pub)
    y_bytes[31] &= 0x7F
    y = int.from_bytes(bytes(y_bytes), "little")
    # u = (1 + y) / (1 - y) mod p
    one_minus_y = (1 - y) % P
    one_plus_y = (1 + y) % P
    u = (one_plus_y * _inv_mod_p(one_minus_y)) % P
    return u.to_bytes(32, "little")


def ed25519_priv_to_x25519(ed_priv: bytes) -> bytes:
    if len(ed_priv) != 32:
        raise ValueError("Ed25519 private key seed must be 32 bytes")
    h = bytearray(hashlib.sha512(ed_priv).digest()[:32])
    # X25519 clamping per RFC 7748.
    h[0] &= 248
    h[31] &= 127
    h[31] |= 64
    return bytes(h)
