from typing import NewType, Set

from .encryption import Ed25519PublicKey
from .messages import NetworkMessage
from .transports import Listener, Transporter


NodeAddress = NewType("NodeAddress", bytes)


class Node:
    """
    Network node representation.
    Node's address is a derivate from Ed25519 public key.
    """

    address: NodeAddress

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


class KnownNode(Node):
    
    public_key: Ed25519PublicKey


class Neighbour(KnownNode):
    """
    Neighbour is the node with which there is a direct 'connection'.
    Listeners and neighbours are sets of unidirectional links.
    """

    listeners: Set[Listener]
    transporters: Set[Transporter]

    def send(self, message: NetworkMessage) -> None:
        """
        Sends message to neighbour using one of neighbour's transporters.
        """
        # TODO: implement selecting and using transporter from transporters set
