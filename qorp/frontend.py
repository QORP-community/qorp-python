from __future__ import annotations

from abc import ABC
from dataclasses import dataclass, field
from typing import Callable, Dict

from .encryption import Ed25519PrivateKey, Ed25519PublicKey
from .encryption import X25519PrivateKey
from .encryption import ChaCha20Poly1305
from .messages import NetworkMessage
from .messages import NetworkData, RouteRequest, RouteResponse, RouteError
from .nodes import Node, KnownNode, Neighbour


@dataclass()
class SessionInfo:

    key: ChaCha20Poly1305
    counter: int = field(init=False, default=0)


class Frontend(ABC, Neighbour):
    """
    Frontend is intermediator between router and OS or some software.

    Frontend obtains Data messages from OS or router, encode-decode it and then
    rely it to OS (if message comes from router) or router (if message comes
    from OS).

    `message_callback` is a callback function which must be called on each
    message that frontend fetches from OS or other software.
    """

    private_key: Ed25519PrivateKey
    public_key: Ed25519PublicKey
    sessions: Dict[KnownNode, SessionInfo]
    halfopened: Dict[Node, X25519PrivateKey]

    message_callback: Callable[[Frontend, NetworkMessage], None]
    data_callback: Callable[[Frontend, bytes], None]

    def send(self, message: NetworkMessage) -> None:
        """
        Handle messages from Router.
        """
        if isinstance(message, NetworkData):
            session = self.sessions[message.source]
            data = session.key.decrypt(message.nonce, message.payload, None)
            self.data_callback(data)
        elif isinstance(message, RouteRequest):
            private_key = X25519PrivateKey.generate()
            public_key = private_key.public_key()
            source_public_key = message.public_key
            raw_encryption_key = private_key.exchange(source_public_key)
            # NOTE: there is no need to cut 32-bytes shared secret because
            #       ChaCha20 uses exactly 32-bytes long key
            encryption_key = ChaCha20Poly1305(raw_encryption_key)
            session = SessionInfo(encryption_key)
            # TODO: check that there is no existed route info for request
            #       source (it might allow replay attacks)
            self.sessions[message.source] = session
            response = RouteResponse(self, message.source, source_public_key, public_key)
            response.sign(self.private_key)
            self.message_callback(response)
        elif isinstance(message, RouteResponse):
            private_key = self.halfopened[message.source]
            public_key = private_key.public_key()
            destination_public_key = message.public_key
            raw_encryption_key = private_key.exchange(destination_public_key)
            # NOTE: there is no need to cut 32-bytes shared secret because
            #       ChaCha20 uses exactly 32-bytes long key
            encryption_key = ChaCha20Poly1305(raw_encryption_key)
            session = SessionInfo(encryption_key)
            # TODO: check that there is no existed route info for request
            #       source (it might allow replay attacks)
            self.sessions[message.source] = session
        elif isinstance(message, RouteError):
            if message.route_destination in self.sessions:
                self.sessions.pop(message.route_destination)
        else:
            raise TypeError
