from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Callable, Generic, Type, TypeVar

from .encoding import Decoder, Encoder
from .messages import Message


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

    encoder: Encoder

    @abstractmethod
    def send(self, message: Message):
        pass


class Listener(ABC, Generic[Proto]):

    callback: Callable[[Message], None]
    decoder: Decoder
