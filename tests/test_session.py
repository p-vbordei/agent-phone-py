"""Session-level tests using an in-memory linked transport pair."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import Any

import pytest

from agent_phone.envelope import Envelope
from agent_phone.session import Session, SessionTransport


def _linked_sessions() -> tuple[Session, Session]:
    a_cb: list[Callable[[Envelope], None] | None] = [None]
    b_cb: list[Callable[[Envelope], None] | None] = [None]
    loop = asyncio.get_event_loop()

    def a_send(e: Envelope) -> None:
        loop.call_soon(lambda: b_cb[0](e) if b_cb[0] else None)

    def b_send(e: Envelope) -> None:
        loop.call_soon(lambda: a_cb[0](e) if a_cb[0] else None)

    def a_set_recv(cb: Any) -> None:
        a_cb[0] = cb

    def b_set_recv(cb: Any) -> None:
        b_cb[0] = cb

    a = Session(SessionTransport(send=a_send, set_recv=a_set_recv, close=lambda: None), "initiator")
    b = Session(SessionTransport(send=b_send, set_recv=b_set_recv, close=lambda: None), "responder")
    return a, b


async def test_unary_round_trip() -> None:
    a, b = _linked_sessions()
    b.handle("echo", lambda params: params)
    assert await a.call("echo", {"hello": "world"}) == {"hello": "world"}


async def test_unknown_method_rejects() -> None:
    a, _ = _linked_sessions()
    with pytest.raises(RuntimeError, match="method not found"):
        await a.call("no_such_method", {})


async def test_handler_throw_propagates() -> None:
    a, b = _linked_sessions()

    def boom(_: Any) -> None:
        raise RuntimeError("kaboom")

    b.handle("boom", boom)
    with pytest.raises(RuntimeError, match="kaboom"):
        await a.call("boom", {})


async def test_server_stream_in_order() -> None:
    a, b = _linked_sessions()

    async def count(_: Any) -> Any:
        async def gen() -> Any:
            for i in range(5):
                yield i

        return gen()

    b.handle("count", count)
    got: list[int] = []
    async for chunk in a.stream("count", {}, 10):
        got.append(chunk)
    assert got == [0, 1, 2, 3, 4]


async def test_streaming_backpressure() -> None:
    a, b = _linked_sessions()
    state = {"emitted": 0}

    async def torrent(_: Any) -> Any:
        async def gen() -> Any:
            for i in range(20):
                state["emitted"] = i + 1
                yield i

        return gen()

    b.handle("torrent", torrent)
    initial_credits = 5
    it = a.stream("torrent", {}, initial_credits)

    first = await it.__anext__()
    assert first == 0
    await asyncio.sleep(0.05)
    assert state["emitted"] <= initial_credits

    got = [first]
    while True:
        try:
            got.append(await it.__anext__())
        except StopAsyncIteration:
            break
    assert got == list(range(20))


async def test_session_survives_handler_throw() -> None:
    a, b = _linked_sessions()

    def boom(_: Any) -> None:
        raise RuntimeError("kaboom")

    b.handle("boom", boom)
    b.handle("echo", lambda p: p)
    with pytest.raises(RuntimeError, match="kaboom"):
        await a.call("boom")
    assert await a.call("echo", {"ok": 1}) == {"ok": 1}


async def test_cancel_mid_stream_keeps_session_usable() -> None:
    a, b = _linked_sessions()
    high_water = {"v": -1}

    async def infinite(_: Any) -> Any:
        async def gen() -> Any:
            i = 0
            while True:
                high_water["v"] = i
                yield i
                i += 1
                await asyncio.sleep(0)

        return gen()

    b.handle("infinite", infinite)
    b.handle("echo", lambda p: p)

    it = a.stream("infinite", {}, 8)
    for _ in range(3):
        await it.__anext__()
    cancel_at = high_water["v"]
    await it.aclose()
    await asyncio.sleep(0.05)
    assert high_water["v"] < cancel_at + 50

    assert await a.call("echo", {"ok": True}) == {"ok": True}
