# agent-phone (Python)

> Minimal sync RPC between two AI agents. Self-custody keys, Noise-framework handshake, DID-bound WebSocket.

Python port of [`@p-vbordei/agent-phone`](https://github.com/p-vbordei/agent-phone). Wire-compatible with the TypeScript reference: same Noise_XK handshake bytes, same canonical JSON envelopes, same conformance vectors.

## Install

```bash
pip install agent-phone
```

## Quickstart

```python
import asyncio
from agent_phone import (
    ClientOptions, ServerOptions, connect, create_server,
    encode_did_key, generate_key_pair,
)

async def main() -> None:
    kp = generate_key_pair()
    did = encode_did_key(kp.public_key)

    server = create_server(ServerOptions(
        did=did, private_key=kp.private_key,
        handlers={"echo": lambda p: p},
    ))
    await server.listen(7777)

    client = await connect(ClientOptions(
        url="ws://localhost:7777",
        did=did, private_key=kp.private_key, responder_did=did,
    ))
    print(await client.call("echo", {"hi": 1}))
    await client.close()
    await server.close()

asyncio.run(main())
```

## What

`agent-phone` is a small protocol for two agents to hold a live, authenticated,
bidirectional conversation over WebSocket. Both agents identify with
self-custody DIDs (`did:key` v0.1). A Noise_XK handshake binds the transport
to those DIDs — the session cannot be MITM-swapped. On top of the authenticated
channel sits a JSON-RPC-like frame with stream support and credit-based
backpressure.

## Status

v0.1 — released 2026-04-24. Spec: [SPEC.md](./SPEC.md).

## Cross-port compatibility

- Wire-format-compatible with the TypeScript reference and Rust sibling.
- Passes the same C4 frame-determinism vector as the TS reference.

## Sibling ports

- TypeScript reference: <https://github.com/p-vbordei/agent-phone>
- Rust port: <https://github.com/p-vbordei/agent-phone-rs>

## License

Apache-2.0 — see [LICENSE](./LICENSE).
