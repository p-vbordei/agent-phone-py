"""Post-handshake transport frame cipher: ChaChaPoly seal/open over Noise CipherState."""

from __future__ import annotations

from .noise import HandshakeResult

MAX_PLAINTEXT = 65519


class FrameCipher:
    def __init__(self, transport: HandshakeResult) -> None:
        self._t = transport

    def seal(self, plaintext: bytes) -> bytes:
        if len(plaintext) > MAX_PLAINTEXT:
            raise ValueError(f"plaintext too large: {len(plaintext)} > {MAX_PLAINTEXT}")
        return self._t.send(plaintext)

    def open(self, ciphertext: bytes) -> bytes:
        return self._t.recv(ciphertext)
