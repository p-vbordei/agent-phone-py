"""WebSocket client: dial, do Noise XK handshake, expose a Session."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse, urlunparse

from websockets.asyncio.client import ClientConnection
from websockets.asyncio.client import connect as _ws_connect

from ._ed_to_x import ed25519_priv_to_x25519, ed25519_pub_to_x25519
from .did import decode_did_key
from .envelope import Envelope, decode, encode
from .frame import FrameCipher
from .noise import InitiatorHandshake, build_prologue
from .session import Session, SessionTransport


@dataclass
class ClientOptions:
    url: str
    did: str
    private_key: bytes
    responder_did: str
    responder_public_key: bytes | None = None


@dataclass
class Client:
    _ws: ClientConnection
    _session: Session
    _reader_task: asyncio.Task[None]

    async def call(self, method: str, params: Any = None) -> Any:
        return await self._session.call(method, params)

    def stream(
        self, method: str, params: Any = None, credits: int = 8
    ) -> AsyncIterator[Any]:
        return self._session.stream(method, params, credits)

    async def close(self) -> None:
        try:
            await self._ws.close()
        finally:
            self._reader_task.cancel()
            try:
                await self._reader_task
            except (asyncio.CancelledError, Exception):
                pass


def _with_caller_query(url: str, did: str) -> str:
    parsed = urlparse(url)
    sep = "&" if parsed.query else ""
    return urlunparse(parsed._replace(query=f"{parsed.query}{sep}caller={did}"))


async def connect(opts: ClientOptions) -> Client:
    responder_static_pub = opts.responder_public_key or ed25519_pub_to_x25519(
        decode_did_key(opts.responder_did)
    )
    static_priv = ed25519_priv_to_x25519(opts.private_key)
    static_pub = ed25519_pub_to_x25519(decode_did_key(opts.did))

    url = _with_caller_query(opts.url, opts.did)
    ws = await _ws_connect(url, subprotocols=["agent-phone.v1"])

    hs = InitiatorHandshake(
        prologue=build_prologue(opts.did, opts.responder_did),
        static_priv=static_priv,
        static_pub=static_pub,
        responder_static_pub=responder_static_pub,
    )

    try:
        await ws.send(hs.write_message_1())
        try:
            m2 = await asyncio.wait_for(ws.recv(), timeout=1.0)
        except (TimeoutError, asyncio.TimeoutError) as e:
            await ws.close()
            raise RuntimeError(
                f"agent-phone: handshake failed before message 2 ({e}). "
                f"Most likely cause: the server at {opts.url} does not hold the static key "
                f"pinned by {opts.responder_did}. Verify the responder DID Document."
            ) from e
        except Exception as e:
            await ws.close()
            raise RuntimeError(
                f"agent-phone: handshake failed before message 2 ({e}). "
                f"Most likely cause: the server at {opts.url} does not hold the static key "
                f"pinned by {opts.responder_did}. Verify the responder DID Document."
            ) from e
        if isinstance(m2, str):
            await ws.close()
            raise RuntimeError("agent-phone: server sent text frame during handshake")
        try:
            hs.read_message_2(m2)
        except Exception as e:
            await ws.close()
            raise RuntimeError(
                f"agent-phone: message 2 AEAD failed. Responder's advertised static "
                f"does not match {opts.responder_did}."
            ) from e
        await ws.send(hs.write_message_3())
    except Exception:
        await ws.close()
        raise

    transport = hs.finish()
    cipher = FrameCipher(transport)
    recv_cb: list[Any] = [None]
    loop = asyncio.get_event_loop()

    def _send_env(env: Envelope) -> None:
        sealed = cipher.seal(encode(env))
        loop.create_task(ws.send(sealed))

    def _set_recv(cb: Any) -> None:
        recv_cb[0] = cb

    def _close() -> None:
        loop.create_task(ws.close())

    transport_iface = SessionTransport(send=_send_env, set_recv=_set_recv, close=_close)
    session = Session(transport_iface, "initiator")

    async def reader() -> None:
        try:
            async for msg in ws:
                if isinstance(msg, str):
                    continue
                try:
                    pt = cipher.open(msg)
                    env = decode(pt)
                except Exception:
                    continue
                cb = recv_cb[0]
                if cb is not None:
                    cb(env)
        except Exception:
            pass

    reader_task = loop.create_task(reader())
    return Client(_ws=ws, _session=session, _reader_task=reader_task)
