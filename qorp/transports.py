from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Callable, Generic, Type, TypeVar

from .encoding import Decoder, Encoder, default_decoder, default_encoder

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from .messages import NetworkMessage


Address = TypeVar("Address")


class Protocol(ABC, Generic[Address]):

    @classmethod
    @abstractmethod
    def listen(
        cls: Type[Proto], address: Address, decoder: Decoder = default_decoder
    ) -> Listener[Proto]:
        pass

    @classmethod
    @abstractmethod
    def connect(
        cls: Type[Proto], address: Address, encoder: Encoder = default_encoder
    ) -> Transporter[Proto]:
        pass


Proto = TypeVar("Proto", bound=Protocol)


class Transporter(ABC, Generic[Proto]):
    """
    Wrapper around unidirectional link to some network.

    `encoder` is encoding.Encoder instance for serialize messages before
    sending.
    """

    protocol: Type[Proto]
    encoder: Encoder

    @abstractmethod
    def send(self, message: NetworkMessage):
        """
        Sends message through specific transport.
        """


class Listener(ABC, Generic[Proto]):
    """
    Wrapper around unidirectional link from some network.

    `callback` is a callback function which must be called on each message
    that listener fetches from the network.

    `decoder` is encoding.Decoder instance for deserialize received messages.
    """

    protocol: Type[Proto]
    callback: Callable[[NetworkMessage], None]
    decoder: Decoder
