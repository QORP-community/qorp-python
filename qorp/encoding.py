from abc import ABC, abstractmethod
from typing import Callable
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from .messages import Message



class Encoder(ABC, Callable[["Message"], bytes]):

    @abstractmethod
    def __call__(self, message: "Message") -> bytes:
        pass


class Decoder(ABC, Callable[[bytes], "Message"]):

    @abstractmethod
    def __call__(self, data: bytes) -> "Message":
        pass
