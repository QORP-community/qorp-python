from abc import ABC
from typing import Callable

from .messages import Data


class Frontend(ABC):

    data_callback: Callable[[Data], None]

    def send(self, message: Data):
        pass
