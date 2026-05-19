# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — 2026-04-24

Initial public release. Python port of [`@p-vbordei/agent-phone`](https://github.com/p-vbordei/agent-phone), wire-format-identical with the TS reference.

### Added

- `Noise_XK_25519_ChaChaPoly_BLAKE2s` handshake (hand-rolled to guarantee byte-for-byte interop with TS).
- DID-bound WebSocket transport (`?caller=<did>` query + prologue binding).
- JCS-canonical JSON envelope with `req` / `res` / `stream_chunk` / `stream_end` / `cancel` / `error` types.
- Length-prefixed frame transport (`FrameCipher.seal` / `open`).
- `Session` with unary RPC, server-streaming + credit-based backpressure, graceful cancel.
- `create_server` (asyncio `websockets` server) and `connect` (asyncio `websockets` client).
- `generate_key_pair`, `encode_did_key`, `decode_did_key` helpers; `KeyPair` dataclass.
- End-to-end loopback tests (echo, two-call session reuse, mismatched-responder abort, streaming + cancel).
- Conformance vectors C1–C4 passing, including the shared C4 hex byte-match with the TS reference.

[0.1.0]: https://github.com/p-vbordei/agent-phone-py/releases/tag/v0.1.0
