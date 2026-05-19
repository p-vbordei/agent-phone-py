"""JSON envelope: encode/decode with canonical (JCS) ordering."""

from __future__ import annotations

import json
from typing import Any, Literal, TypedDict

import jcs

EnvelopeType = Literal["req", "res", "stream_chunk", "stream_end", "cancel", "error"]
_VALID_TYPES: frozenset[str] = frozenset(
    {"req", "res", "stream_chunk", "stream_end", "cancel", "error"}
)


class _Error(TypedDict):
    code: int
    message: str


class Envelope(TypedDict, total=False):
    stream_id: int
    type: EnvelopeType
    seq: int
    credits: int
    method: str
    params: Any
    result: Any
    reason: str
    error: _Error


def _validate(env: dict[str, Any]) -> None:
    if not isinstance(env.get("stream_id"), int) or env["stream_id"] < 0:
        raise ValueError("envelope.stream_id must be a non-negative int")
    if env.get("type") not in _VALID_TYPES:
        raise ValueError(f"envelope.type invalid: {env.get('type')!r}")
    if not isinstance(env.get("seq"), int) or env["seq"] < 0:
        raise ValueError("envelope.seq must be a non-negative int")
    if "credits" in env and (not isinstance(env["credits"], int) or env["credits"] < 0):
        raise ValueError("envelope.credits must be a non-negative int")
    if "method" in env and not isinstance(env["method"], str):
        raise ValueError("envelope.method must be a string")
    if "reason" in env and not isinstance(env["reason"], str):
        raise ValueError("envelope.reason must be a string")
    if "error" in env:
        err = env["error"]
        if (
            not isinstance(err, dict)
            or not isinstance(err.get("code"), int)
            or not isinstance(err.get("message"), str)
        ):
            raise ValueError("envelope.error must be {code:int, message:str}")


def encode(env: Envelope | dict[str, Any]) -> bytes:
    d = dict(env)
    _validate(d)
    return jcs.canonicalize(d)


def decode(buf: bytes) -> Envelope:
    obj = json.loads(buf.decode("utf-8"))
    if not isinstance(obj, dict):
        raise ValueError("envelope must decode to a JSON object")
    _validate(obj)
    return obj  # type: ignore[return-value]
