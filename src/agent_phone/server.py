"""WebSocket server: accept, do Noise XK handshake, host a Session per peer."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs, urlparse

from websockets.asyncio.server import ServerConnection, serve

from ._ed_to_x import ed25519_priv_to_x25519, ed25519_pub_to_x25519
from .did import decode_did_key
from .envelope import Envelope, decode, encode
from .frame import FrameCipher
from .noise import ResponderHandshake, build_prologue
from .session import Handler, Session, SessionTransport


@dataclass
class ServerOptions:
    did: str
    private_key: bytes
    handlers: dict[str, Handler] = field(default_factory=dict)


@dataclass
class _Address:
    port: int
    hostname: str


class Server:
    def __init__(self, opts: ServerOptions) -> None:
        self._opts = opts
        self._static_priv = ed25519_priv_to_x25519(opts.private_key)
        self._static_pub = ed25519_pub_to_x25519(decode_did_key(opts.did))
        self._srv: Any = None
        self._address: _Address | None = None

    async def listen(self, port: int, hostname: str = "localhost") -> None:
        self._srv = await serve(
            self._on_connection,
            host=hostname,
            port=port,
            subprotocols=["agent-phone.v1"],
            process_request=self._process_request,
        )
        # Pick the actual bound port (handles port=0 for ephemeral assignment).
        socks = self._srv.sockets
        bound_port = socks[0].getsockname()[1] if socks else port
        self._address = _Address(port=bound_port, hostname=hostname)

    async def close(self) -> None:
        if self._srv is not None:
            self._srv.close()
            await self._srv.wait_closed()
            self._srv = None

    def address(self) -> _Address:
        if self._address is None:
            raise RuntimeError("server not bound")
        return self._address

    async def _process_request(self, connection: ServerConnection, request: Any) -> Any:
        # websockets' new asyncio API passes (connection, request); we use it to
        # reject malformed handshakes before upgrade.
        path = getattr(request, "path", "/") or "/"
        try:
            url = urlparse(path)
        except Exception:
            from websockets.http11 import Response

            return Response(400, "Bad Request", {}, b"bad path")
        qs = parse_qs(url.query)
        caller = qs.get("caller", [""])[0]
        if not caller:
            from websockets.http11 import Response

            return Response(400, "Bad Request", {}, b"missing ?caller=<did>\n")
        # Stash the caller DID on the connection so on_connection can grab it.
        connection.caller_did = caller  # type: ignore[attr-defined]
        return None

    async def _on_connection(self, ws: ServerConnection) -> None:
        caller_did: str | None = getattr(ws, "caller_did", None)
        if caller_did is None:
            # Fallback: parse the path on the connection directly.
            url = urlparse(getattr(ws.request, "path", "/") or "/")
            qs = parse_qs(url.query)
            caller_did = qs.get("caller", [""])[0]
        if not caller_did:
            await ws.close()
            return

        hs = ResponderHandshake(
            prologue=build_prologue(caller_did, self._opts.did),
            static_priv=self._static_priv,
            static_pub=self._static_pub,
        )

        # Handshake message 1 (client → server)
        try:
            m1 = await ws.recv()
            if isinstance(m1, str):
                await ws.close()
                return
            hs.read_message_1(m1)
            await ws.send(hs.write_message_2())
            m3 = await ws.recv()
            if isinstance(m3, str):
                await ws.close()
                return
            hs.read_message_3(m3)
        except Exception:
            await ws.close()
            return

        transport = hs.finish()
        cipher = FrameCipher(transport)
        recv_cb: list[Any] = [None]
        loop = asyncio.get_event_loop()

        def _send_env(env: Envelope) -> None:
            try:
                sealed = cipher.seal(encode(env))
            except Exception:
                return
            loop.create_task(ws.send(sealed))

        def _set_recv(cb: Any) -> None:
            recv_cb[0] = cb

        def _close() -> None:
            loop.create_task(ws.close())

        transport_iface = SessionTransport(send=_send_env, set_recv=_set_recv, close=_close)
        session = Session(transport_iface, "responder")
        for method, h in self._opts.handlers.items():
            session.handle(method, h)

        try:
            async for raw in ws:
                if isinstance(raw, str):
                    continue
                try:
                    pt = cipher.open(raw)
                    env = decode(pt)
                except Exception:
                    break
                cb = recv_cb[0]
                if cb is not None:
                    cb(env)
        except Exception:
            pass


def create_server(opts: ServerOptions) -> Server:
    return Server(opts)
