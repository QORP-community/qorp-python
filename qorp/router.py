from __future__ import annotations

from dataclasses import dataclass, field

from typing import Callable, Dict, Union

from .encryption import Ed25519PrivateKey, Ed25519PublicKey, X25519PrivateKey
from .encryption import ChaCha20Poly1305
from .frontend import Frontend
from .messages import NetworkMessage, FrontendData
from .messages import NetworkData, RouteRequest, RouteResponse, RouteError
from .nodes import Node, KnownNode, Neighbour
from .routing import MessagesForwarder


@dataclass
class SessionInfo:

    key: ChaCha20Poly1305
    counter: int = field(init=False, default=0)


class Router(Neighbour):

    private_key: Ed25519PrivateKey
    public_key: Ed25519PublicKey
    frontend: Frontend
    forwarder: MessagesForwarder
    sessions: Dict[KnownNode, SessionInfo]
    halfopened: Dict[Node, X25519PrivateKey]

    def __init__(
        self,
        private_key: Ed25519PrivateKey,
        frontend: Frontend = None,
        frontend_factory: Callable[[Router], Frontend] = None,
        forwarder_factory: Callable[[Router], MessagesForwarder] = MessagesForwarder
    ) -> None:
        self.private_key = private_key
        super().__init__(private_key.public_key())
        if frontend is not None:
            self.frontend = frontend
        elif frontend_factory is not None:
            self.frontend = frontend_factory(self)
        else:
            raise TypeError("Missing 'frontend' or 'frontend_factory' argument.")
        self.sessions = {}
        self.halfopened = {}
        self.forwarder = forwarder_factory(self)

    def send(self, message: Union[NetworkMessage, FrontendData]) -> None:
        """
        Handle messages from MessageForwarder or Frontend.
        """
        if isinstance(message, FrontendData):
            if message.source != self.address:
                pass
            if message.destination in self.sessions:
                pass
            elif message.destination in self.halfopened:
                pass
            else:
                pass
        elif isinstance(message, NetworkData):
            session = self.sessions[message.source]
            data = session.key.decrypt(message.nonce, message.payload, None)
            frontend_msg = FrontendData(message.source, message.destination, data)
            self.frontend.message_callback(frontend_msg)
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
            self.forwarder.message_callback(self, response)
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
