"""End-to-end WebSocket+Noise tests using ephemeral local servers."""

from __future__ import annotations

import asyncio
import time
from typing import Any

import pytest

from agent_phone import (
    ClientOptions,
    ServerOptions,
    connect,
    create_server,
    encode_did_key,
    generate_key_pair,
)
from agent_phone._ed_to_x import ed25519_pub_to_x25519


async def _pair(handlers: dict[str, Any] | None = None):
    resp_kp = generate_key_pair()
    init_kp = generate_key_pair()
    resp_did = encode_did_key(resp_kp.public_key)
    init_did = encode_did_key(init_kp.public_key)

    server = create_server(
        ServerOptions(
            did=resp_did,
            private_key=resp_kp.private_key,
            handlers=handlers if handlers is not None else {"echo": lambda p: p},
        )
    )
    await server.listen(0)
    addr = server.address()
    client = await connect(
        ClientOptions(
            url=f"ws://localhost:{addr.port}",
            did=init_did,
            private_key=init_kp.private_key,
            responder_did=resp_did,
            responder_public_key=ed25519_pub_to_x25519(resp_kp.public_key),
        )
    )
    return server, client


async def test_end_to_end_unary_echo() -> None:
    server, client = await _pair()
    try:
        assert await client.call("echo", {"message": "hi"}) == {"message": "hi"}
    finally:
        await client.close()
        await server.close()


async def test_connect_aborts_on_mismatched_responder_static() -> None:
    resp_kp = generate_key_pair()
    impostor_kp = generate_key_pair()
    resp_did = encode_did_key(resp_kp.public_key)

    server = create_server(
        ServerOptions(
            did=resp_did,
            private_key=impostor_kp.private_key,  # the lie
            handlers={"echo": lambda p: p},
        )
    )
    await server.listen(0)
    addr = server.address()
    init_kp = generate_key_pair()

    t0 = time.monotonic()
    with pytest.raises(Exception):
        await connect(
            ClientOptions(
                url=f"ws://localhost:{addr.port}",
                did=encode_did_key(init_kp.public_key),
                private_key=init_kp.private_key,
                responder_did=resp_did,
            )
        )
    elapsed = time.monotonic() - t0
    assert elapsed < 2.0
    await server.close()


async def test_two_handshakes_produce_independent_session_keys() -> None:
    resp_kp = generate_key_pair()
    resp_did = encode_did_key(resp_kp.public_key)

    server = create_server(
        ServerOptions(did=resp_did, private_key=resp_kp.private_key, handlers={"echo": lambda p: p})
    )
    await server.listen(0)
    addr = server.address()
    try:
        init_kp = generate_key_pair()
        client = await connect(
            ClientOptions(
                url=f"ws://localhost:{addr.port}",
                did=encode_did_key(init_kp.public_key),
                private_key=init_kp.private_key,
                responder_did=resp_did,
            )
        )
        assert await client.call("echo", {"n": 1}) == {"n": 1}
        assert await client.call("echo", {"n": 2}) == {"n": 2}
        await client.close()
    finally:
        await server.close()


async def test_streaming_with_cancel_e2e() -> None:
    async def infinite(_: Any) -> Any:
        async def gen() -> Any:
            i = 0
            while True:
                yield i
                i += 1
                await asyncio.sleep(0)

        return gen()

    server, client = await _pair({"infinite": infinite, "ping": lambda p: p})
    try:
        it = client.stream("infinite", {}, credits=8)
        for _ in range(10):
            await it.__anext__()
        await it.aclose()
        await asyncio.sleep(0.05)
        assert await client.call("ping", {"still": "alive"}) == {"still": "alive"}
    finally:
        await client.close()
        await server.close()
