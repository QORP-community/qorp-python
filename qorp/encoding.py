from abc import ABC, abstractmethod

from typing import Callable, Union

from .encryption import Ed25519PublicKey, X25519PublicKey
from cryptography.hazmat.primitives import serialization

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from .messages import NetworkMessage


def pubkey_to_bytes(key: Union[Ed25519PublicKey, X25519PublicKey]) -> bytes:
    return key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


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
