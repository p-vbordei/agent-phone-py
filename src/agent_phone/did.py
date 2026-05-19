"""DID + key handling: Ed25519 keypairs, did:key codec, Ed25519↔X25519 conversion."""

from __future__ import annotations

from dataclasses import dataclass

import base58
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

from ._ed_to_x import ed25519_priv_to_x25519, ed25519_pub_to_x25519

MULTICODEC_ED25519_PUB = bytes([0xED, 0x01])


@dataclass(frozen=True)
class KeyPair:
    public_key: bytes
    private_key: bytes


def generate_key_pair() -> KeyPair:
    sk = Ed25519PrivateKey.generate()
    pk = sk.public_key()
    return KeyPair(
        public_key=pk.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        ),
        private_key=sk.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        ),
    )


def encode_did_key(public_key: bytes) -> str:
    if len(public_key) != 32:
        raise ValueError("Ed25519 pubkey must be 32 bytes")
    encoded = base58.b58encode(MULTICODEC_ED25519_PUB + public_key).decode("ascii")
    return f"did:key:z{encoded}"


def decode_did_key(did: str) -> bytes:
    if not did.startswith("did:key:z"):
        raise ValueError("not a did:key identifier")
    decoded = base58.b58decode(did[len("did:key:z") :])
    if (
        len(decoded) < 34
        or decoded[0] != MULTICODEC_ED25519_PUB[0]
        or decoded[1] != MULTICODEC_ED25519_PUB[1]
    ):
        raise ValueError(
            "did:key is not an Ed25519 key (wrong multicodec prefix or truncated)"
        )
    return decoded[2:]


# Re-export so the public surface mirrors the TS one.
__all__ = [
    "KeyPair",
    "decode_did_key",
    "ed25519_priv_to_x25519",
    "ed25519_pub_to_x25519",
    "encode_did_key",
    "generate_key_pair",
]
