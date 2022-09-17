from __future__ import annotations

import asyncio

from typing import Callable, List

from qorp.codecs import MessagesCodec, DEFAULT_CODEC
from qorp.frontend import Frontend
from qorp.messages import FrontendData, NetworkMessage
from qorp.router import Router
from qorp.transports import Protocol, Connection, Server


def echo(message: FrontendData) -> FrontendData:
    echo = FrontendData(
        message.destination, 
        message.source, 
        message.payload
    )
    return echo


class TestEchoFrontend(Frontend):

    received: List[FrontendData]

    def __init__(self, router: Router) -> None:
        self.router = router
        self.received = []

    def message_callback(self, message: FrontendData) -> None:
        self.received.append(message)
        echo_message = echo(message)
        self.router.send(echo_message)


class TestProtocol(Protocol["TestConnection", bytes]):

    address: TestConnection
    alias = "testproto"

    def connect(
        self, codec: MessagesCodec[bytes] = DEFAULT_CODEC, delay: float = 0.1
    ) -> Connection[TestProtocol, bytes]:
        return TestConnection(self, codec, delay)

    def listen(
        self,
        callback: Callable[[TestConnection, Connection[TestProtocol, bytes]], None],
        codec: MessagesCodec[bytes] = DEFAULT_CODEC,
        delay: float = 0.1
    ) -> Server[TestProtocol, bytes]:
        return TestServer(self, callback, codec, delay)


class TestConnection(Connection[TestProtocol, bytes]):

    def __init__(
        self,
        proto: TestProtocol,
        codec: MessagesCodec[bytes],
        delay: float
    ) -> None:
        self.protocol = proto
        self.codec = codec
        self.delay = delay

    def callback(self, message: NetworkMessage) -> None:
        pass

    def send(self, message: NetworkMessage) -> None:
        loop = asyncio.get_running_loop()
        loop.call_later(self.delay, self.protocol.address.callback, message)


class TestServer(Server[TestProtocol, bytes]):

    def __init__(
        self,
        proto: TestProtocol,
        callback: Callable[[TestConnection, Connection[TestProtocol, bytes]], None],
        codec: MessagesCodec[bytes],
        delay: float
    ) -> None:
        self.protocol = proto
        self.callback = callback
        self.codec = codec
        self.delay = delay

    def connection_callback(self, address: TestConnection, connection: Connection[TestProtocol, bytes]) -> None:
        self.callback(address, connection)
