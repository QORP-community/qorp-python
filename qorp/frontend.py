from abc import ABC
from typing import Callable

from .messages import Data


class Frontend(ABC):
    """
    Frontend is intermediator between router and OS or some software.

    Frontend obtains Data messages from OS or router, encode-decode it and then
    rely it to OS (if message comes from router) or router (if message comes
    from OS).

    `data_callback` is a callback function which must be called on each message
    that frontend fetches from OS or other software.
    """

    data_callback: Callable[[Data], None]

    def send(self, message: Data):
        """
        Sends Data message to frontend (which relies it to OS or some other
        software).
        """
