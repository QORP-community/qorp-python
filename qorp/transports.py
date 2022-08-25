from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Callable, Generic, Type, TypeVar

from .messages import Message


class Protocol(ABC):

    @classmethod
    @abstractmethod
    def listen(cls: Type[Proto], *args, **kwargs) -> Listener[Proto]:
        pass

    @classmethod
    @abstractmethod
    def connect(cls: Type[Proto], *args, **kwargs) -> Transporter[Proto]:
        pass


Proto = TypeVar("Proto", bound=Protocol)


class Transporter(ABC, Generic[Proto]):

    @abstractmethod
    def send(self, message: Message):
        pass


class Listener(ABC, Generic[Proto]):

    callback: Callable[[Message], None]
