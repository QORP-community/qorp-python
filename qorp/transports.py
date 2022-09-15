from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Callable, ClassVar, Generic, Type, TypeVar

from .encoding import Decoder, Encoder, default_decoder, default_encoder

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from .messages import NetworkMessage


Address = TypeVar("Address")


class Protocol(ABC, Generic[Address]):

    alias: ClassVar[str]
    address: Address

    def __init__(self, address: Address) -> None:
        self.address = address

    @abstractmethod
    def connect(
        self: Proto,
        decoder: Decoder = default_decoder,
        encoder: Encoder = default_encoder,
    ) -> Connection[Proto]:
        pass

    @abstractmethod
    def listen(
        self: Proto,
        connection_callback: Callable[[Address, Connection[Proto]], None],
        decoder: Decoder = default_decoder,
        encoder: Encoder = default_encoder,
    ) -> Server[Proto]:
        pass


Proto = TypeVar("Proto", bound=Protocol)


class Connection(ABC, Generic[Proto]):
    """
    Wrapper around bidirectional link from/to some network.

    `decoder` is encoding.Decoder instance for deserialize received messages.
    """

    protocol: Proto
    decoder: Decoder
    encoder: Encoder

    @abstractmethod
    def send(self, message: NetworkMessage) -> None:
        """
        Sends message through specific connection.
        """

    @abstractmethod
    def callback(self, message: NetworkMessage) -> None:
        """
        Callback function for messages received from specific connection.
        """


class Server(ABC, Generic[Proto]):

    protocol: Proto
    decoder: Decoder
    encoder: Encoder

    def connection_callback(
        self,
        address,
        connection: Connection[Proto]
    ) -> None:
        pass
