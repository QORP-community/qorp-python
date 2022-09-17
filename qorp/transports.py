from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Callable, ClassVar, Generic, TypeVar

from .codecs import MessagesCodec

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from .messages import NetworkMessage


Address = TypeVar("Address")
DataType = TypeVar("DataType")


class Protocol(ABC, Generic[Address, DataType]):

    alias: ClassVar[str]
    address: Address

    @abstractmethod
    def connect(
        self: Proto,
        codec: MessagesCodec[DataType]
    ) -> Connection[Proto, DataType]:
        pass

    @abstractmethod
    def listen(
        self: Proto,
        callback: Callable[[Address, Connection[Proto, DataType]], None],
        codec: MessagesCodec[DataType]
    ) -> Server[Proto, DataType]:
        pass


Proto = TypeVar("Proto", bound=Protocol)


class Connection(ABC, Generic[Proto, DataType]):
    """
    Wrapper around bidirectional link from/to some network.
    """

    protocol: Proto
    codec: MessagesCodec[DataType]

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


class Server(ABC, Generic[Proto, DataType]):

    protocol: Proto
    codec: MessagesCodec[DataType]

    def connection_callback(
        self,
        address,
        connection: Connection[Proto, DataType]
    ) -> None:
        pass
