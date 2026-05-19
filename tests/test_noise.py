import pytest

from agent_phone._ed_to_x import ed25519_priv_to_x25519, ed25519_pub_to_x25519
from agent_phone.did import encode_did_key, generate_key_pair
from agent_phone.noise import (
    InitiatorHandshake,
    ResponderHandshake,
    build_prologue,
    hmac_blake2s,
)


def test_hmac_blake2s_basic() -> None:
    a = hmac_blake2s(b"\x01\x02\x03", b"\x04\x05\x06")
    b = hmac_blake2s(b"\x01\x02\x03", b"\x04\x05\x06")
    c = hmac_blake2s(b"\x01\x02\x03", b"\x04\x05\x07")
    assert len(a) == 32
    assert a == b
    assert a != c


def test_prologue_shape() -> None:
    p = build_prologue("did:key:zInit", "did:key:zResp")
    text = p.decode("utf-8", errors="replace")
    assert text.startswith("agent-phone/1")
    assert "did:key:zInit" in text
    assert text.endswith("did:key:zResp")


def test_noise_xk_handshake_round_trip() -> None:
    init_ed = generate_key_pair()
    resp_ed = generate_key_pair()
    init_did = encode_did_key(init_ed.public_key)
    resp_did = encode_did_key(resp_ed.public_key)
    prologue = build_prologue(init_did, resp_did)

    init_static_priv = ed25519_priv_to_x25519(init_ed.private_key)
    init_static_pub = ed25519_pub_to_x25519(init_ed.public_key)
    resp_static_priv = ed25519_priv_to_x25519(resp_ed.private_key)
    resp_static_pub = ed25519_pub_to_x25519(resp_ed.public_key)

    init = InitiatorHandshake(
        prologue=prologue,
        static_priv=init_static_priv,
        static_pub=init_static_pub,
        responder_static_pub=resp_static_pub,
    )
    resp = ResponderHandshake(
        prologue=prologue,
        static_priv=resp_static_priv,
        static_pub=resp_static_pub,
    )

    m1 = init.write_message_1()
    resp.read_message_1(m1)
    m2 = resp.write_message_2()
    init.read_message_2(m2)
    m3 = init.write_message_3()
    resp.read_message_3(m3)

    init_t = init.finish()
    resp_t = resp.finish()

    ct1 = init_t.send(b"hi from initiator")
    assert resp_t.recv(ct1) == b"hi from initiator"
    ct2 = resp_t.send(b"hi back")
    assert init_t.recv(ct2) == b"hi back"


def test_noise_xk_aborts_on_responder_static_mismatch() -> None:
    init_ed = generate_key_pair()
    resp_ed = generate_key_pair()
    other_ed = generate_key_pair()
    prologue = build_prologue(
        encode_did_key(init_ed.public_key), encode_did_key(resp_ed.public_key)
    )

    init = InitiatorHandshake(
        prologue=prologue,
        static_priv=ed25519_priv_to_x25519(init_ed.private_key),
        static_pub=ed25519_pub_to_x25519(init_ed.public_key),
        responder_static_pub=ed25519_pub_to_x25519(resp_ed.public_key),
    )
    resp = ResponderHandshake(
        prologue=prologue,
        static_priv=ed25519_priv_to_x25519(other_ed.private_key),
        static_pub=ed25519_pub_to_x25519(other_ed.public_key),
    )
    m1 = init.write_message_1()
    with pytest.raises(Exception):
        resp.read_message_1(m1)
