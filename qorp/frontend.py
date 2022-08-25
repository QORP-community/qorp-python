from typing import Callable

from .messages import Data


class Frontend:

    data_callback: Callable[[Data], None]

    def send(self, message: Data):
        pass
