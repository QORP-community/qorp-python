from abc import ABC
from typing import Callable

from .encryption import Ed25519PrivateKey, Ed25519PublicKey
from .messages import NetworkMessage
from .nodes import Neighbour


class Frontend(ABC, Neighbour):
    """
    Frontend is intermediator between router and OS or some software.

    Frontend obtains Data messages from OS or router, encode-decode it and then
    rely it to OS (if message comes from router) or router (if message comes
    from OS).

    `data_callback` is a callback function which must be called on each message
    that frontend fetches from OS or other software.
    """

    private_key: Ed25519PrivateKey
    public_key: Ed25519PublicKey

    message_callback: Callable[[NetworkMessage], None]

    def send(self, message: NetworkMessage) -> None:
        """
        Sends Data message to frontend (which relies it to OS or some other
        software).
        """
