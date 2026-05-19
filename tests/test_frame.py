import pytest

from agent_phone._ed_to_x import ed25519_priv_to_x25519, ed25519_pub_to_x25519
from agent_phone.did import encode_did_key, generate_key_pair
from agent_phone.frame import FrameCipher
from agent_phone.noise import InitiatorHandshake, ResponderHandshake, build_prologue


def _pair() -> tuple[FrameCipher, FrameCipher]:
    i = generate_key_pair()
    r = generate_key_pair()
    prologue = build_prologue(encode_did_key(i.public_key), encode_did_key(r.public_key))
    init = InitiatorHandshake(
        prologue=prologue,
        static_priv=ed25519_priv_to_x25519(i.private_key),
        static_pub=ed25519_pub_to_x25519(i.public_key),
        responder_static_pub=ed25519_pub_to_x25519(r.public_key),
    )
    resp = ResponderHandshake(
        prologue=prologue,
        static_priv=ed25519_priv_to_x25519(r.private_key),
        static_pub=ed25519_pub_to_x25519(r.public_key),
    )
    resp.read_message_1(init.write_message_1())
    init.read_message_2(resp.write_message_2())
    resp.read_message_3(init.write_message_3())
    return FrameCipher(init.finish()), FrameCipher(resp.finish())


def test_frame_round_trip() -> None:
    init, resp = _pair()
    wire = init.seal(b'{"hello":"world"}')
    assert resp.open(wire) == b'{"hello":"world"}'


def test_frame_rejects_tampered_ciphertext() -> None:
    init, resp = _pair()
    wire = bytearray(init.seal(b"x"))
    wire[0] ^= 0x80
    with pytest.raises(Exception):
        resp.open(bytes(wire))


def test_seal_rejects_oversize_plaintext() -> None:
    init, _resp = _pair()
    with pytest.raises(ValueError, match="too large"):
        init.seal(b"\x00" * 65520)
