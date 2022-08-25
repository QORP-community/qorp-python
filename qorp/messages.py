from __future__ import annotations

from abc import ABC
from dataclasses import dataclass

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from . import Node


@dataclass
class Message(ABC):

    source: Node
    destination: Node


@dataclass
class Data(Message):

    payload: bytes


@dataclass
class RouteRequest(Message):
    pass


@dataclass
class RouteResponse(Message):
    pass


@dataclass
class RouteError(Message):
    pass
