from abc import ABC, abstractmethod

from typing import Callable, Union

from .encryption import Ed25519PublicKey, X25519PublicKey, pubkey_to_bytes
from .messages import NetworkData, RouteError, RouteRequest, RouteResponse

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from .messages import NetworkMessage




class Encoder(ABC, Callable[["NetworkMessage"], bytes]):
    """
    Base class for messages encoders.
    """

    @abstractmethod
    def __call__(self, message: "NetworkMessage") -> bytes:
        pass


class Decoder(ABC, Callable[[bytes], "NetworkMessage"]):
    """
    Base class for messages decoders.
    """

    @abstractmethod
    def __call__(self, data: bytes) -> "NetworkMessage":
        pass
