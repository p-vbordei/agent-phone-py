"""Session: multiplexes streams over a transport, handles RPC + backpressure."""

from __future__ import annotations

import asyncio
import inspect
from collections.abc import AsyncIterable, AsyncIterator, Callable
from dataclasses import dataclass, field
from typing import Any, Literal

from .envelope import Envelope

Handler = Callable[[Any], Any]
Role = Literal["initiator", "responder"]


@dataclass
class SessionTransport:
    send: Callable[[Envelope], None]
    set_recv: Callable[[Callable[[Envelope], None]], None]
    close: Callable[[], None]


@dataclass
class _StreamState:
    queue: list[Any] = field(default_factory=list)
    waiter: asyncio.Future[Any] | None = None
    ended: bool = False
    error: Exception | None = None
    granted: int = 0
    emitted: int = 0


@dataclass
class _ServerStreamCtl:
    grant: Callable[[int], None]
    cancel: Callable[[], None]
    credit_waiter: asyncio.Future[None] | None = None


_END_SENTINEL = object()


class Session:
    def __init__(self, transport: SessionTransport, role: Role) -> None:
        self._t = transport
        self._next_stream_id = 1 if role == "initiator" else 2
        self._pending: dict[int, asyncio.Future[Any]] = {}
        self._handlers: dict[str, Handler] = {}
        self._streams: dict[int, _StreamState] = {}
        self._server_streams: dict[int, _ServerStreamCtl] = {}
        self._loop = asyncio.get_event_loop()
        self._t.set_recv(self._on_frame)

    def handle(self, method: str, h: Handler) -> None:
        self._handlers[method] = h

    async def call(self, method: str, params: Any = None) -> Any:
        sid = self._alloc()
        fut: asyncio.Future[Any] = self._loop.create_future()
        self._pending[sid] = fut
        env: Envelope = {"stream_id": sid, "type": "req", "seq": 0, "method": method}
        if params is not None:
            env["params"] = params
        self._t.send(env)
        return await fut

    def stream(
        self, method: str, params: Any = None, credits: int = 8
    ) -> AsyncIterator[Any]:
        sid = self._alloc()
        state = _StreamState(granted=credits)
        self._streams[sid] = state
        env: Envelope = {
            "stream_id": sid,
            "type": "req",
            "seq": 0,
            "method": method,
            "credits": credits,
        }
        if params is not None:
            env["params"] = params
        self._t.send(env)
        return _StreamIterator(self, sid, state, credits)

    def close(self) -> None:
        self._t.close()

    def _alloc(self) -> int:
        sid = self._next_stream_id
        self._next_stream_id += 2
        return sid

    async def _run_server_stream(
        self, sid: int, src: AsyncIterable[Any], initial_credits: int
    ) -> None:
        granted = initial_credits
        cancelled = False
        seq = 0

        def grant(n: int) -> None:
            nonlocal granted
            granted += n
            ctl = self._server_streams.get(sid)
            if ctl and ctl.credit_waiter and not ctl.credit_waiter.done():
                w = ctl.credit_waiter
                ctl.credit_waiter = None
                w.set_result(None)

        def cancel() -> None:
            nonlocal cancelled
            cancelled = True
            ctl = self._server_streams.get(sid)
            if ctl and ctl.credit_waiter and not ctl.credit_waiter.done():
                w = ctl.credit_waiter
                ctl.credit_waiter = None
                w.set_result(None)

        self._server_streams[sid] = _ServerStreamCtl(grant=grant, cancel=cancel)
        try:
            it = src.__aiter__()
            while True:
                while granted <= 0:
                    fut: asyncio.Future[None] = self._loop.create_future()
                    self._server_streams[sid].credit_waiter = fut
                    await fut
                    if cancelled:
                        break
                if cancelled:
                    break
                try:
                    value = await it.__anext__()
                except StopAsyncIteration:
                    break
                granted -= 1
                self._t.send(
                    {
                        "stream_id": sid,
                        "type": "stream_chunk",
                        "seq": seq,
                        "result": value,
                    }
                )
                seq += 1
            self._t.send(
                {
                    "stream_id": sid,
                    "type": "stream_end",
                    "seq": seq,
                    "reason": "cancelled" if cancelled else "ok",
                }
            )
        finally:
            self._server_streams.pop(sid, None)

    def _on_frame(self, e: Envelope) -> None:
        # Dispatch synchronously to mirror TS; async work is scheduled as tasks.
        t = e["type"]
        sid = e["stream_id"]

        if t == "req":
            h = self._handlers.get(e.get("method", ""))
            if h is None:
                self._t.send(
                    {
                        "stream_id": sid,
                        "type": "error",
                        "seq": 0,
                        "error": {
                            "code": -32601,
                            "message": f"method not found: {e.get('method')}",
                        },
                    }
                )
                return
            self._loop.create_task(self._invoke_handler(sid, h, e))
            return

        if t == "res":
            ctl = self._server_streams.get(sid)
            if ctl is not None:
                ctl.grant(int(e.get("credits", 0)))
                return
            fut = self._pending.pop(sid, None)
            if fut is not None and not fut.done():
                fut.set_result(e.get("result"))
            return

        if t == "error":
            fut = self._pending.pop(sid, None)
            err = e.get("error") or {"code": 0, "message": "unknown error"}
            if fut is not None and not fut.done():
                fut.set_exception(RuntimeError(err["message"]))
            return

        if t == "stream_chunk":
            s = self._streams.get(sid)
            if s is None:
                return
            if s.waiter is not None and not s.waiter.done():
                w = s.waiter
                s.waiter = None
                w.set_result(e.get("result"))
            else:
                s.queue.append(e.get("result"))
            return

        if t == "cancel":
            ctl = self._server_streams.get(sid)
            if ctl is not None:
                ctl.cancel()
            return

        if t == "stream_end":
            s = self._streams.get(sid)
            if s is None:
                return
            s.ended = True
            if s.waiter is not None and not s.waiter.done():
                w = s.waiter
                s.waiter = None
                w.set_result(_END_SENTINEL)
            self._streams.pop(sid, None)
            return

    async def _invoke_handler(self, sid: int, h: Handler, e: Envelope) -> None:
        params = e.get("params")
        try:
            ret = h(params)
            if inspect.isawaitable(ret):
                ret = await ret  # type: ignore[assignment]
            if isinstance(ret, AsyncIterable) and not isinstance(ret, (str, bytes)):
                await self._run_server_stream(sid, ret, int(e.get("credits", 0)))
            else:
                self._t.send(
                    {"stream_id": sid, "type": "res", "seq": 0, "result": ret}
                )
        except Exception as err:
            self._t.send(
                {
                    "stream_id": sid,
                    "type": "error",
                    "seq": 0,
                    "error": {"code": -32000, "message": str(err)},
                }
            )


class _StreamIterator:
    def __init__(
        self, session: Session, sid: int, state: _StreamState, initial_credits: int
    ) -> None:
        self._session = session
        self._sid = sid
        self._state = state
        self._initial_credits = initial_credits

    def __aiter__(self) -> _StreamIterator:
        return self

    async def __anext__(self) -> Any:
        s = self._state
        # Auto-refresh: top up when consumed past halfway through the grant.
        if not s.ended and s.emitted >= s.granted - (self._initial_credits // 2):
            s.granted += self._initial_credits
            self._session._t.send(
                {
                    "stream_id": self._sid,
                    "type": "res",
                    "seq": 0,
                    "credits": self._initial_credits,
                }
            )
        if s.error is not None:
            raise s.error
        if s.queue:
            s.emitted += 1
            return s.queue.pop(0)
        if s.ended:
            raise StopAsyncIteration
        fut: asyncio.Future[Any] = self._session._loop.create_future()
        s.waiter = fut
        value = await fut
        if value is _END_SENTINEL:
            raise StopAsyncIteration
        s.emitted += 1
        return value

    async def aclose(self) -> None:
        self._session._t.send(
            {"stream_id": self._sid, "type": "cancel", "seq": 0}
        )
        self._session._streams.pop(self._sid, None)
