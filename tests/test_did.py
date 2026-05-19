import re

import pytest

from agent_phone import decode_did_key, encode_did_key, generate_key_pair
from agent_phone._ed_to_x import ed25519_priv_to_x25519, ed25519_pub_to_x25519
from agent_phone.noise import x25519_public_from_private


def test_encode_decode_did_key_roundtrip() -> None:
    kp = generate_key_pair()
    did = encode_did_key(kp.public_key)
    assert re.match(r"^did:key:z[1-9A-HJ-NP-Za-km-z]+$", did)
    assert decode_did_key(did) == kp.public_key


def test_decode_did_key_rejects_bad_multicodec() -> None:
    # secp256k1 did:key — valid encoding, wrong algorithm.
    did = "did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme"
    with pytest.raises(ValueError):
        decode_did_key(did)


def test_decode_did_key_rejects_truncated() -> None:
    with pytest.raises(ValueError):
        decode_did_key("did:key:zR2")


def test_ed25519_to_x25519_conversion_is_consistent() -> None:
    kp = generate_key_pair()
    x_priv = ed25519_priv_to_x25519(kp.private_key)
    x_pub = ed25519_pub_to_x25519(kp.public_key)
    assert len(x_priv) == 32
    assert len(x_pub) == 32
    # X25519 pubkey derived from converted private must match the converted public.
    assert x25519_public_from_private(x_priv) == x_pub
