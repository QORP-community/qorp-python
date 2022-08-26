from typing import Set

from .encryption import X25519PublicKey
from .messages import Message
from .transports import Listener, Transporter


class Node:
    """
    Network node representation.
    Node's address is a X25519 public key.
    """

    address: X25519PublicKey

    def __eq__(self, other) -> bool:
        if isinstance(other, Node):
            return self.address == other.address
        return NotImplemented

    def __hash__(self) -> int:
        """
        Calculates node's 'hash' from its address.
        This is necessary for using Node instances as keys of dicionaries and
        participants of sets.

        THIS HASH IS NOT FOR CRYPTOGRAPHIC USAGE!
        """
        return hash(self.address)


class Neighbour(Node):
    """
    Neighbour is the node with which there is a direct 'connection'.
    Listeners and neighbours are sets of unidirectional links.
    """

    listeners: Set[Listener]
    transporters: Set[Transporter]

    def send(self, message: Message):
        """
        Sends message to neighbour using one of neighbour's transporters.
        """
