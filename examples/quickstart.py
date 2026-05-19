"""agent-phone quickstart: in-process server + client over loopback WS.

Spins up a responder on 127.0.0.1 (ephemeral port), connects a client over
WebSocket, completes the Noise_XK handshake bound to both agents' DIDs,
runs one unary RPC, prints the result, and shuts everything down cleanly.

Run with:
    uv run python examples/quickstart.py
"""

from __future__ import annotations

import asyncio

from agent_phone import (
    ClientOptions,
    ServerOptions,
    connect,
    create_server,
    encode_did_key,
    generate_key_pair,
)


async def main() -> None:
    # Two self-custody Ed25519 keypairs → two did:key identifiers.
    responder = generate_key_pair()
    initiator = generate_key_pair()
    responder_did = encode_did_key(responder.public_key)
    initiator_did = encode_did_key(initiator.public_key)

    # Start a responder on an ephemeral loopback port.
    server = create_server(
        ServerOptions(
            did=responder_did,
            private_key=responder.private_key,
            handlers={"echo": lambda p: p},
        )
    )
    await server.listen(0, hostname="127.0.0.1")
    port = server.address().port
    print(f"server listening on 127.0.0.1:{port}")

    # Dial the responder. The handshake binds the channel to both DIDs.
    client = await connect(
        ClientOptions(
            url=f"ws://127.0.0.1:{port}",
            did=initiator_did,
            private_key=initiator.private_key,
            responder_did=responder_did,
        )
    )
    print("noise-xk handshake complete; channel authenticated")

    # One unary round-trip.
    reply = await client.call("echo", {"hello": "agent-phone"})
    print(f"echo result  : {reply}")
    assert reply == {"hello": "agent-phone"}

    await client.close()
    await server.close()
    print("closed cleanly")


if __name__ == "__main__":
    asyncio.run(main())
