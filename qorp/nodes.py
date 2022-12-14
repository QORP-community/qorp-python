from __future__ import annotations

from dataclasses import dataclass
from typing import List, NewType

from .encryption import Ed25519PublicKey, pubkey_to_bytes

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from .transports import Connection
    from .messages import NetworkMessage


NodeAddress = NewType("NodeAddress", bytes)


def address_from_pubkey(public_key: Ed25519PublicKey) -> NodeAddress:
    address_bytes = pubkey_to_bytes(public_key)
    return NodeAddress(address_bytes)


@dataclass(frozen=True)
class Node:
    """
    Network node representation.
    Node's address is a derivate from Ed25519 public key.
    """

    address: NodeAddress

    def __eq__(self, other: object) -> bool:
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

    def __init__(self, public_key: Ed25519PublicKey):
        self.public_key = public_key
        super().__init__(address_from_pubkey(public_key))


class Neighbour(KnownNode):
    """
    Neighbour is the node with which there is a direct 'connection'.
    Listeners and transporters are sets of unidirectional links.
    """

    connections: List[Connection]  # type: ignore

    def __init__(self, public_key: Ed25519PublicKey):
        super().__init__(public_key)
        self.connections = []

    def send(self, message: NetworkMessage) -> None:
        """
        Sends message to neighbour using one of neighbour's transporters.
        """
        # TODO?: Replace this with some connection selecting procedure
        self.connections[0].send(message)
