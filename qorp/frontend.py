from __future__ import annotations

from abc import ABC, abstractmethod

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from .router import Router

from .messages import FrontendData


class Frontend(ABC):
    """
    Frontend is intermediator between router and OS or some software.

    Frontend obtains Data messages from OS or router, encode-decode it and then
    rely it to OS (if message comes from router) or router (if message comes
    from OS).

    `message_callback` is a callback function which will be called on each
    message that frontend fetches from OS or other software.
    """

    router: Router

    def __init__(self, router: Router) -> None:
        super().__init__()

    @abstractmethod
    def message_callback(self, message: FrontendData) -> None:
        """
        Handle messages from Router.
        """
