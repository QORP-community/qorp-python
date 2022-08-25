from typing import Set

from .encryption import X25519PublicKey
from .messages import Message
from .transports import Listener, Transporter


class Node:

    address: X25519PublicKey

    def __eq__(self, other) -> bool:
        if isinstance(other, Node):
            return self.address == other.address
        return NotImplemented

    def __hash__(self) -> int:
        return hash(self.address)


class Neighbour(Node):

    listeners: Set[Listener]
    transporters: Set[Transporter]

    def send(self, message: Message):
        pass
