"""
Module for definitions of each message type's structure.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from . import Node


@dataclass  # type: ignore  # (due to mypy issue #5374)
class Message(ABC):
    """
    Base class for all protocol messages.
    """

    source: Node
    destination: Node
    signature: Optional[bytes] = field(init=False)

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
class Data(Message):
    """
    Data message used to transfer payload to other nodes. Typically
    payload is some higher-layer protocol message.
    """

    payload: bytes


@dataclass
class RouteRequest(Message):
    """
    Route Request (RReq) message used to obtain route to other node of the
    network.
    
    RReq propagates over the entire network until it reaches destination
    node, which responds with Route Response message.

    Propagation process for RReq messages must use `split horizon` technique
    to prevent broadcast storms in the network.
    """


@dataclass
class RouteResponse(Message):
    """
    Route Response (RRep) message used to reply to RReq message.
    """


@dataclass
class RouteError(Message):
    """
    Route Error (RErr) message used to signal that some route over this node
    becomes invalid (due to any reason).

    RErr messages must be sended back right to route source node over the all
    nodes in the current node.
    """
