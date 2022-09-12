from __future__ import annotations

from typing import Union
from typing_extensions import Literal, Protocol

from .encryption import Ed25519PublicKey, X25519PublicKey, pubkey_to_bytes
from .messages import NetworkData, RouteError, RouteRequest, RouteResponse

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from .messages import NetworkMessage





class Encoder(Protocol):
    """
    Base class for messages encoders.
    """

    def __call__(self, message: NetworkMessage) -> bytes:
        pass


class Decoder(Protocol):
    """
    Base class for messages decoders.
    """

    def __call__(self, data: bytes) -> NetworkMessage:
        pass
