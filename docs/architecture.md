# Architecture — agent-phone (Python)

## Goal

Port the [`agent-phone` v0.1 spec](../SPEC.md) to idiomatic Python while staying **wire-format-identical** with the [TypeScript reference](https://github.com/p-vbordei/agent-phone). "Identical" here means: given the same DIDs, prologue, and ephemeral keys, every byte the Python implementation puts on the wire — Noise handshake messages, post-handshake transport frames, JCS-canonical envelopes — matches what the TS reference produces. The shared C4 hex vector enforces the envelope side of that contract in CI on both sides.

## Module map

The Python package mirrors the TS reference module-for-module, so a change on one side is easy to mirror on the other.

| Python (`src/agent_phone/`) | TS reference (`src/`) | Responsibility |
|---|---|---|
| `envelope.py` | `envelope.ts` | JCS-canonical encode/decode + envelope validation. |
| `noise.py` | `noise.ts` | `Noise_XK_25519_ChaChaPoly_BLAKE2s` state machine + primitives. |
| `frame.py` | `frame.ts` | Post-handshake `seal`/`open` over the Noise CipherStates. |
| `did.py` + `_ed_to_x.py` | `did.ts` | `did:key` codec + Ed25519↔X25519 conversion. |
| `session.py` | `session.ts` | Stream multiplexing, unary RPC, credit-based backpressure, cancel. |
| `client.py` | `client.ts` | WebSocket dial + handshake + Session wiring. |
| `server.py` | `server.ts` | WebSocket accept (with `?caller=<did>` query) + handshake + Session per peer. |

## Dependency choices

**Crypto: hand-rolled Noise XK, not `snow` / `dissononce`.** The wire-format contract is byte-for-byte equality with TS, including specifics like the BLAKE2s-only HMAC, the nonce layout (`0x00000000 || u64 LE counter`), and the HKDF-2 split orientation per role. The mature Noise libraries can do XK, but each has its own framing quirks and they're hard to pin to "exactly what `@noble/curves` does." So Noise is reimplemented directly from the protocol description:

- **`cryptography`** for `ChaCha20Poly1305` and `blake2s`. Audited, wheels everywhere, no optional-dependency dance.
- **Manual X25519** (RFC 7748 reference Montgomery ladder, in `noise.py`). Used both for ephemeral key generation and for the `dh()` operations in the handshake. Pure Python, ~50 LoC, runs in <1 ms per scalar mult — plenty for a handshake.
- **`base58`** for the `did:key` multibase encoding.
- **`jcs`** for RFC 8785 canonical-JSON bytes.
- **`websockets`** (the asyncio API) for both client and server.

**No `pydantic`.** Envelope validation is ~30 lines of explicit type checks; pulling in a schema framework would obscure rather than help.

### Ed25519 → X25519 derivation: not BIP-32

Both repos derive a static X25519 keypair from each agent's Ed25519 signing key, so the DID alone determines the Noise static key. The derivation is **not** any sort of HD wallet path:

- **Public key:** Montgomery `u = (1 + y) / (1 − y) mod p` from the Edwards `y`-coordinate (with the sign bit cleared). Matches `@noble/curves`' `edwardsToMontgomeryPub`.
- **Private key:** `SHA-512(seed)[0..32]`, then RFC 7748 X25519 clamping (`h[0] &= 248; h[31] &= 127; h[31] |= 64`). Matches `edwardsToMontgomeryPriv`. Implemented in `_ed_to_x.py`.

The temptation when you see "derive an X25519 key from an Ed25519 key" is to reach for HKDF or BIP-32. Doing that here would silently break interop with the TS reference. The SHA-512-then-clamp construction is the only thing that produces the same Montgomery scalar the TS path produces, which is the only thing that produces the same `es`/`se` shared secrets, which is the only thing that lets the handshake succeed at all.

## Byte-determinism invariants

Three things must agree across all ports for a session to even establish, let alone interoperate:

1. **Noise handshake bytes.** Prologue layout (`"agent-phone/1" || u16-be(len(init_did)) || init_did || u16-be(len(resp_did)) || resp_did`), `mixHash` of the responder's pre-known static at start, exact nonce format, HKDF-2 output order per side at split. Pinned by `tests/test_noise.py`.
2. **Frame bytes.** A WebSocket binary message *is* one Noise transport frame: ChaChaPoly ciphertext of the JCS envelope, 16-byte tag appended. The WS message boundary is the frame boundary; no extra length prefix. Pinned by `tests/test_frame.py`.
3. **Envelope JCS bytes.** RFC 8785 lexical key ordering, no whitespace, no extra precision. Pinned by `tests/test_conformance.py::test_c4_frame_determinism` against `vectors/c4.json` — the same vector the TS suite verifies.

## Testing strategy

`uv run pytest -v` runs 31 tests in under a second:

- Unit tests per module: `did`, `envelope`, `frame`, `noise`, `session`.
- End-to-end loopback in `test_e2e.py`: ephemeral-port WS server + client + round-trip + streaming + cancel.
- Conformance C1–C4 in `test_conformance.py`. C1/C2/C3 are loopback scenarios; C4 reads the shared hex vector.

The end-to-end tests are the strongest guard against accidental wire-format drift, because any byte-level disagreement between client and server surfaces as a handshake or AEAD failure during the test.
