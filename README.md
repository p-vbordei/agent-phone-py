# agent-phone (Python)

[![CI](https://github.com/p-vbordei/agent-phone-py/actions/workflows/ci.yml/badge.svg)](https://github.com/p-vbordei/agent-phone-py/actions/workflows/ci.yml)
[![Spec](https://img.shields.io/badge/spec-v0.1-blue)](./SPEC.md)
[![License](https://img.shields.io/badge/license-Apache%202.0-green)](./LICENSE)

> **Idiomatic Python port of [@p-vbordei/agent-phone](https://github.com/p-vbordei/agent-phone).** Minimal sync RPC between two AI agents — Noise-XK handshake over WebSocket, DID-bound peer identity, framed binary transport, self-custody keys. **Wire-format-identical** with the TS reference: the C4 hex vector matches byte-for-byte.

## What's in the box

- Noise-XK handshake (X25519 + ChaCha20Poly1305 + BLAKE2s + HKDF)
- DID-bound peer identity (Ed25519 → X25519 via SHA-512 + RFC 7748 clamp)
- Length-prefixed frame transport (ChaChaPoly seal/open)
- WebSocket client + server (`websockets` asyncio)
- Session lifecycle (connect, call, stream, close)
- Backpressure (credit-based streaming with auto-refresh at the half-mark)

## Install

```bash
pip install agent-phone
# or, for development:
uv sync --extra dev
```

## Quickstart

```python
import asyncio
from agent_phone import (
    ClientOptions, ServerOptions, connect, create_server,
    encode_did_key, generate_key_pair,
)

async def main() -> None:
    resp, init = generate_key_pair(), generate_key_pair()
    resp_did = encode_did_key(resp.public_key)

    server = create_server(ServerOptions(
        did=resp_did, private_key=resp.private_key,
        handlers={"echo": lambda p: p},
    ))
    await server.listen(0, hostname="127.0.0.1")
    port = server.address().port

    client = await connect(ClientOptions(
        url=f"ws://127.0.0.1:{port}",
        did=encode_did_key(init.public_key),
        private_key=init.private_key,
        responder_did=resp_did,
    ))
    print(await client.call("echo", {"hi": 1}))  # {'hi': 1}
    await client.close()
    await server.close()

asyncio.run(main())
```

```bash
uv run python examples/quickstart.py
# server listening on 127.0.0.1:<port>
# noise-xk handshake complete; channel authenticated
# echo result  : {'hello': 'agent-phone'}
# closed cleanly
```

## How it relates

| Implementation | Status | Wire format |
|---|---|---|
| [`@p-vbordei/agent-phone`](https://github.com/p-vbordei/agent-phone) (TypeScript) | Reference | source of truth |
| [`agent-phone`](https://github.com/p-vbordei/agent-phone-py) (Python, this repo) | Port | byte-identical |
| [`agent-phone`](https://github.com/p-vbordei/agent-phone-rs) (Rust) | Port | byte-identical |

## Conformance

The [v0.1 spec](./SPEC.md) defines four conformance clauses; all four pass against the TS test suite.

- **C1 — Handshake DID-binding.** Swap the responder's static mid-handshake → initiator aborts deterministically at message 2 (AEAD fails). `tests/test_conformance.py::test_c1_handshake_did_binding`.
- **C2 — Streaming backpressure.** Server emits 10 000 chunks, client grants 8 at a time → outstanding chunks stay bounded; every chunk arrives in order. `test_c2_streaming_backpressure`.
- **C3 — Graceful cancel.** Cancel mid-stream → server stops within one frame, session stays open for further RPCs. `test_c3_graceful_cancel`.
- **C4 — Frame determinism.** Canonical envelope bytes match the TS hex vector byte-for-byte. `test_c4_frame_determinism` reads [`vectors/c4.json`](./vectors/c4.json), which mirrors the [TS suite](https://github.com/p-vbordei/agent-phone/tree/main/conformance).

```bash
uv run pytest -v
# 31 passed
```

## Architecture

Module map, dependency choices (hand-rolled Noise XK on `cryptography` + manual X25519), Ed25519→X25519 derivation gotcha, byte-determinism invariants, and testing strategy: see [docs/architecture.md](docs/architecture.md).

## Development

```bash
git clone https://github.com/p-vbordei/agent-phone-py
cd agent-phone-py
uv sync --extra dev
uv run pytest -v
uv run ruff check .
```

Contributions welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). Any change to `noise.py`, `frame.py`, or `envelope.py` must keep the C4 hex vector passing; that's the wire-format contract.

## License

Apache-2.0 — see [LICENSE](./LICENSE).
