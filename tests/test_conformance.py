"""Conformance vectors C1–C4 (mirrors TS conformance/run.ts)."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

from agent_phone import (
    ClientOptions,
    ServerOptions,
    connect,
    create_server,
    encode_did_key,
    generate_key_pair,
)
from agent_phone.envelope import decode, encode

VECTORS = Path(__file__).resolve().parent.parent / "vectors"


async def test_c1_handshake_did_binding() -> None:
    real = generate_key_pair()
    fake = generate_key_pair()
    real_did = encode_did_key(real.public_key)
    server = create_server(
        ServerOptions(did=real_did, private_key=fake.private_key, handlers={})
    )
    await server.listen(0)
    try:
        port = server.address().port
        init = generate_key_pair()
        aborted = False
        try:
            await connect(
                ClientOptions(
                    url=f"ws://localhost:{port}",
                    did=encode_did_key(init.public_key),
                    private_key=init.private_key,
                    responder_did=real_did,
                )
            )
        except Exception:
            aborted = True
        assert aborted, "C1: initiator accepted impostor"
    finally:
        await server.close()


async def test_c2_streaming_backpressure() -> None:
    resp = generate_key_pair()
    init = generate_key_pair()
    resp_did = encode_did_key(resp.public_key)
    N = 10_000
    state = {"acked": 0, "max_outstanding": 0}

    async def torrent(_: Any) -> Any:
        async def gen() -> Any:
            for i in range(N):
                outstanding = i - state["acked"]
                if outstanding > state["max_outstanding"]:
                    state["max_outstanding"] = outstanding
                yield i

        return gen()

    server = create_server(
        ServerOptions(did=resp_did, private_key=resp.private_key, handlers={"torrent": torrent})
    )
    await server.listen(0)
    try:
        port = server.address().port
        client = await connect(
            ClientOptions(
                url=f"ws://localhost:{port}",
                did=encode_did_key(init.public_key),
                private_key=init.private_key,
                responder_did=resp_did,
            )
        )
        credits = 8
        got: list[int] = []
        async for v in client.stream("torrent", {}, credits=credits):
            got.append(v)
            state["acked"] = len(got)
        await client.close()
        assert len(got) == N
        assert got == list(range(N))
        assert state["max_outstanding"] <= credits * 4, state["max_outstanding"]
    finally:
        await server.close()


async def test_c3_graceful_cancel() -> None:
    resp = generate_key_pair()
    init = generate_key_pair()
    resp_did = encode_did_key(resp.public_key)

    async def infinite(_: Any) -> Any:
        async def gen() -> Any:
            i = 0
            while True:
                yield i
                i += 1
                await asyncio.sleep(0)

        return gen()

    server = create_server(
        ServerOptions(
            did=resp_did,
            private_key=resp.private_key,
            handlers={"infinite": infinite, "ping": lambda p: p},
        )
    )
    await server.listen(0)
    try:
        port = server.address().port
        client = await connect(
            ClientOptions(
                url=f"ws://localhost:{port}",
                did=encode_did_key(init.public_key),
                private_key=init.private_key,
                responder_did=resp_did,
            )
        )
        it = client.stream("infinite", {}, credits=8)
        for _ in range(10):
            await it.__anext__()
        await it.aclose()
        await asyncio.sleep(0.05)
        r = await client.call("ping", {"still": "alive"})
        assert r == {"still": "alive"}
        await client.close()
    finally:
        await server.close()


def test_c4_frame_determinism() -> None:
    raw = (VECTORS / "c4.json").read_text()
    vectors = json.loads(raw)
    for name, entry in vectors.items():
        env = entry["plaintext_envelope"]
        expected_hex = entry["canonical_json_hex"]
        got_bytes = encode(env)
        assert got_bytes.hex() == expected_hex, f"C4 {name}: canonical JSON mismatch"
        assert decode(got_bytes) == env, f"C4 {name}: decode roundtrip mismatch"
