import pytest

from agent_phone.envelope import decode, encode


def test_envelope_unary_roundtrip() -> None:
    env = {"stream_id": 1, "type": "req", "seq": 0, "method": "echo", "params": {"x": 1}}
    bytes_ = encode(env)
    assert decode(bytes_) == env


def test_envelope_encoding_is_canonical() -> None:
    a = encode({"stream_id": 1, "type": "req", "seq": 0, "method": "m", "params": {"b": 2, "a": 1}})
    b = encode({"stream_id": 1, "type": "req", "seq": 0, "method": "m", "params": {"a": 1, "b": 2}})
    assert a == b


def test_envelope_rejects_unknown_type() -> None:
    bad = b'{"stream_id":1,"type":"bogus","seq":0}'
    with pytest.raises(ValueError):
        decode(bad)


def test_envelope_error_roundtrip() -> None:
    env = {
        "stream_id": 3,
        "type": "error",
        "seq": 0,
        "error": {"code": -32000, "message": "boom"},
    }
    assert decode(encode(env)) == env


def test_envelope_stream_chunk_with_credits() -> None:
    env = {
        "stream_id": 5,
        "type": "stream_chunk",
        "seq": 42,
        "credits": 8,
        "result": [1, 2, 3],
    }
    assert decode(encode(env)) == env
