"""
Module for definitions of each message type's structure.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional, Union

from .encryption import Ed25519PrivateKey, X25519PublicKey, ChaCha20Poly1305
from .encoding import pubkey_to_bytes

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from .nodes import KnownNode, Node


@dataclass  # type: ignore  # (due to mypy issue #5374)
class Message(ABC):
    """
    Base class for all protocol messages.
    """

    source: Node
    destination: Node
    signature: Optional[bytes]


@dataclass
class FrontendData(Message):

    source: Node
    destination: Node
    payload: bytes
    signature: Optional[bytes] = field(init=False, default=None)


@dataclass  # type: ignore  # (due to mypy issue #5374)
class NetworkMessage(Message, ABC):

    @abstractmethod
    def sign(self, source_signing_key: Ed25519PrivateKey) -> None:
        """
        Signs message. Signature will be placed to `signature` attribute.
        """

    @abstractmethod
    def verify(self) -> bool:
        """
        Verify a message's signature.
        """


@dataclass
class NetworkData(NetworkMessage):
    """
    Data message used to transfer payload to other nodes. Payload is bytes
    that typically represents some higher-layer protocol message.
    """

    source: KnownNode
    destination: KnownNode
    signature: bytes = field(init=False)
    nonce: bytes
    length: int
    payload: bytes

    def decrypt(self, key: ChaCha20Poly1305) -> bytes:
        """
        Returns decrypted message's payload.
        """
        return key.decrypt(self.nonce, self.payload, None)

    def sign(self, source_signing_key: Ed25519PrivateKey) -> None:
        fields = [
            pubkey_to_bytes(self.source.public_key),
            pubkey_to_bytes(self.destination.public_key),
            self.nonce,
            self.length.to_bytes(2, "big"),
            self.payload,
        ]
        message = b"".join(fields)
        self.signature = source_signing_key.sign(message)

    def verify(self) -> bool:
        # TODO: make this done
        pass


@dataclass
class RouteRequest(NetworkMessage):
    """
    Route Request (RReq) message used to obtain route to other node of the
    network.

    RReq propagates over the entire network until it reaches destination
    node, which responds with Route Response message.

    Propagation process for RReq messages must use `split horizon` technique
    to prevent broadcast storms in the network.
    """

    source: KnownNode
    destination: Union[Node, KnownNode]
    public_key: X25519PublicKey

    def sign(self, source_signing_key: Ed25519PrivateKey) -> None:
        if isinstance(self.destination, KnownNode):
            dst_field = pubkey_to_bytes(self.destination.public_key)
        else:
            dst_field = self.destination.address
        fields = [
            pubkey_to_bytes(self.source.public_key),
            dst_field,
            pubkey_to_bytes(self.public_key),
        ]
        message = b"".join(fields)
        self.signature = source_signing_key.sign(message)

    def verify(self) -> bool:
        # TODO: make this done
        pass


@dataclass
class RouteResponse(NetworkMessage):
    """
    Route Response (RRep) message used to reply to RReq message.
    """

    source: KnownNode
    destination: KnownNode
    requester_key: X25519PublicKey  # to prevent replay attack in route search process
    public_key: X25519PublicKey

    def sign(self, source_signing_key: Ed25519PrivateKey) -> None:
        fields = [
            pubkey_to_bytes(self.source.public_key),
            pubkey_to_bytes(self.destination.public_key),
            pubkey_to_bytes(self.requester_key),
            pubkey_to_bytes(self.public_key),
        ]
        message = b"".join(fields)
        self.signature = source_signing_key.sign(message)

    def verify(self) -> bool:
        # TODO: make this done
        pass


@dataclass
class RouteError(NetworkMessage):
    """
    Route Error (RErr) message used to signal that some route over this node
    becomes invalid (due to any reason).

    RErr messages must be sended back right to route source node over the all
    nodes in the current node.
    """

    source: KnownNode
    destination: KnownNode
    route_source: KnownNode
    route_destination: KnownNode

    def sign(self, source_signing_key: Ed25519PrivateKey) -> None:
        fields = [
            pubkey_to_bytes(self.source.public_key),
            pubkey_to_bytes(self.destination.public_key),
            pubkey_to_bytes(self.route_source.public_key),
            pubkey_to_bytes(self.route_destination.public_key),
        ]
        message = b"".join(fields)
        self.signature = source_signing_key.sign(message)

    def verify(self) -> bool:
        # TODO: make this done
        pass
