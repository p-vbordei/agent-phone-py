# agent-phone — v0.1 specification

**Status:** 1.0 — released 2026-04-24.

## Abstract

`agent-phone` defines a minimal sync RPC protocol between two AI agents: a Noise_XK handshake over WebSocket binds the transport to the agents' DIDs, and a small JSON-RPC-like frame layer carries requests, responses, streams, and cancellations with credit-based backpressure.

## 1. Terminology

- **Initiator** — the agent starting the call.
- **Responder** — the agent receiving the call.
- **DID** — W3C Decentralized Identifier (see [`agent-id`](../agent-id/)).
- **Session** — one Noise-authenticated channel. Stays open until one side closes.
- **Stream** — a logical request-response (or request-stream) flow multiplexed over the session.

## 2. Transport

### 2.1 Connection

Initiator opens a WebSocket to a URL discovered out of band (e.g. the responder's `agent-id` DID Document's `service.endpoint`). Subprotocol: `agent-phone.v1`.

### 2.2 Handshake

**Pattern**: `Noise_XK_25519_ChaChaPoly_BLAKE2s`.

Static keys are derived from agents' Ed25519 signing keys via Ed25519-to-X25519 conversion per [RFC 7748] appendix / [this common construction](https://blog.filippo.io/using-ed25519-keys-for-encryption/).

**Prologue** (fed to Noise hash at start):

```
"agent-phone/1" || len(initiator_did) || initiator_did || len(responder_did) || responder_did
```

Three WebSocket binary frames carry the Noise messages:

1. `e, es`           (initiator → responder)
2. `e, ee`           (responder → initiator)
3. `s, se`           (initiator → responder)

After the third message, transport encryption begins.

Initiator MUST obtain the responder's static public key from the
responder's DID Document verification method (via the referenced DID
method — `did:key` in v0.1) BEFORE opening the WebSocket. The static
key is fed to the Noise state machine as the pre-known responder
static. If the responder does not actually hold that static (e.g. the
DID Document is stale or tampered), the handshake aborts deterministically
at message 2 (AEAD failure on `ee`/`es` key derivation).

Initiator MUST signal its own DID to the responder before the handshake
begins, so the responder can construct the matching prologue. The
reference signaling mechanism is a URL query parameter: initiator dials
`ws://<host>[:<port>][/<path>]?caller=<initiator_did>`. The DID is
public, so plaintext transmission is acceptable; prologue binding still
prevents any other party from impersonating the initiator.

## 3. Frame format

Post-handshake, each WebSocket binary message carries exactly one
Noise transport frame: the ChaChaPoly ciphertext of the plaintext
JSON envelope with the 16-byte authentication tag appended. The
WebSocket message boundary is the frame boundary; no additional
length prefix is required.

The decrypted plaintext is a JSON object:

```
{
  "stream_id": <uint>,                         // unique per session, chosen by initiator (odd) or responder (even)
  "type": "req" | "res" | "stream_chunk" | "stream_end" | "cancel" | "error",
  "seq": <uint>,                               // monotonic per stream_id
  "credits?": <uint>,                          // flow-control: receiver grants N chunks
  "method?": "...",                            // for "req"
  "params?": {...},                            // for "req"
  "result?": {...} | null,                     // for "res" and "stream_chunk"
  "reason?": "...",                            // for "cancel" and "stream_end"
  "error?": { "code": <int>, "message": "..." }
}
```

## 4. RPC semantics

### 4.1 Unary request/response

```
initiator → { stream_id:1, type:"req",  seq:0, method:"echo", params:{...} }
responder → { stream_id:1, type:"res",  seq:0, result:{...} }
```

### 4.2 Server-streaming

```
initiator → { stream_id:3, type:"req",          seq:0, method:"search", params:{q:"..."}, credits:8 }
responder → { stream_id:3, type:"stream_chunk", seq:0, result:{...} }
responder → { stream_id:3, type:"stream_chunk", seq:1, result:{...} }
... (pause when 8 chunks sent)
initiator → { stream_id:3, type:"res",          seq:0, credits:8 }     // grant more credits
responder → ...
responder → { stream_id:3, type:"stream_end",   seq:N, reason:"ok" }
```

Responder MUST pause when credits reach zero; resume when more are granted.

### 4.3 Cancel

Initiator sends `{ type:"cancel", stream_id:3 }`. Responder MUST stop emitting `stream_chunk` within 1 frame and reply `{ type:"stream_end", reason:"cancelled" }`. The session stays open for further streams.

### 4.4 Errors

Any side can emit `{ type:"error", error:{ code, message } }` for a stream. Stream is terminated; session unaffected.

## 5. Security considerations

- **DID binding via prologue.** Swapping the responder's static key mid-handshake invalidates the prologue hash, causing handshake failure. This is the core defense against MITM.
- **Replay**: the Noise handshake uses fresh ephemeral keys each session; no explicit nonce exchange is needed.
- **Traffic analysis**: not in scope. Message sizes leak; pad if you care.
- **Key rotation**: if a DID Document rotates its Ed25519 key, existing sessions remain valid (session keys are already derived); new sessions use the new key.
- **Session resumption**: not in scope for v0.1. Clients MUST be prepared to re-handshake on reconnect.

## 6. Conformance

A conforming implementation MUST:

- (C1) **Handshake DID-binding**: swap responder's static key mid-handshake → initiator aborts.
- (C2) **Streaming backpressure**: server emits 10 000 chunks, client grants 8 at a time → server blocks after 8 unacked chunks; resumes on credit; all 10 000 delivered in order.
- (C3) **Graceful cancel**: `cancel(stream_id)` causes server to stop within 1 frame; session remains open for further RPCs.
- (C4) **Frame decoding determinism**: identical plaintext `type`+`params` MUST produce identical decoded frames across implementations.

Test vectors live in `conformance/`.

## 7. References

- [Noise Protocol Framework](https://noiseprotocol.org/)
- [BOLT-8 (Lightning handshake)](https://github.com/lightning/bolts/blob/master/08-transport.md)
- [Ed25519 → X25519 conversion](https://blog.filippo.io/using-ed25519-keys-for-encryption/)
- [`agent-id` spec](../agent-id/SPEC.md)
- [JSON-RPC 2.0](https://www.jsonrpc.org/specification)
