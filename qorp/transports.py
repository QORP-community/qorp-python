from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Callable, Generic, Type, TypeVar

from .encoding import Decoder, Encoder
from .messages import NetworkMessage


class Protocol(ABC):

    @classmethod
    @abstractmethod
    def listen(
        cls: Type[Proto], *args, decoder: Decoder, **kwargs
    ) -> Listener[Proto]:
        pass

    @classmethod
    @abstractmethod
    def connect(
        cls: Type[Proto], *args, encoder: Encoder, **kwargs
    ) -> Transporter[Proto]:
        pass


Proto = TypeVar("Proto", bound=Protocol)


class Transporter(ABC, Generic[Proto]):
    """
    Wrapper around unidirectional link to some network.

    `encoder` is encoding.Encoder instance for serialize messages before
    sending.
    """

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

    callback: Callable[[NetworkMessage], None]
    decoder: Decoder
