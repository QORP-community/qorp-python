"""
Module for definitions of each message type's structure.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional, Union

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from .encryption import X25519PublicKey
    from .nodes import KnownNode, Node


@dataclass  # type: ignore  # (due to mypy issue #5374)
class Message(ABC):
    """
    Base class for all protocol messages.
    """

    source: Node
    destination: Node
    signature: Optional[bytes] = field(init=False, default=None)

    @abstractmethod
    def sign(self) -> None:
        pass


@dataclass
class FrontendData(Message):

    source: Node
    destination: Node
    payload: bytes

    def sign(self) -> None:
        # TODO: make this done
        pass


@dataclass  # type: ignore  # (due to mypy issue #5374)
class NetworkMessage(Message, ABC):

    @abstractmethod
    def verify(self) -> bool:
        pass


@dataclass
class NetworkData(NetworkMessage):
    """
    Data message used to transfer payload to other nodes. Typically
    payload is some higher-layer protocol message.
    """

    source: KnownNode
    destination: KnownNode
    nonce: bytes
    payload: bytes

    def decrypt(self, key) -> bytes:
        # TODO: make this done
        pass

    def sign(self) -> None:
        # TODO: make this done
        pass

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

    def sign(self) -> None:
        # TODO: make this done
        pass

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
    public_key: X25519PublicKey

    def sign(self) -> None:
        # TODO: make this done
        pass

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
    route_destination: Union[Node, KnownNode]

    def sign(self) -> None:
        # TODO: make this done
        pass

    def verify(self) -> bool:
        # TODO: make this done
        pass
