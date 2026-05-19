"""agent-phone — minimal sync RPC between two AI agents.

Python port of @p-vbordei/agent-phone. Self-custody keys, Noise-framework
handshake, DID-bound WebSocket.
"""

from __future__ import annotations

from .client import Client, ClientOptions, connect
from .did import KeyPair, decode_did_key, encode_did_key, generate_key_pair
from .envelope import Envelope
from .server import Handler, Server, ServerOptions, create_server

__all__ = [
    "Client",
    "ClientOptions",
    "Envelope",
    "Handler",
    "KeyPair",
    "Server",
    "ServerOptions",
    "connect",
    "create_server",
    "decode_did_key",
    "encode_did_key",
    "generate_key_pair",
]
