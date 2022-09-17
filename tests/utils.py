from __future__ import annotations

import asyncio

from typing import Callable, List, Union

from qorp.codecs import MessagesCodec, DEFAULT_CODEC
from qorp.encryption import Ed25519PrivateKey, Ed25519PublicKey
from qorp.frontend import Frontend
from qorp.messages import FrontendData, NetworkMessage
from qorp.nodes import Neighbour
from qorp.router import Router
from qorp.routing import MessagesForwarder
from qorp.transports import Protocol, Connection, Server


def echo(message: FrontendData) -> FrontendData:
    echo = FrontendData(
        message.destination,
        message.source,
        message.payload
    )
    return echo


class NeignbourMock(Neighbour):

    received: List[NetworkMessage]

    def __init__(self, public_key: Ed25519PublicKey = None):
        if public_key is None:
            private_key = Ed25519PrivateKey.generate()
            public_key = private_key.public_key()
        super().__init__(public_key)

    def send(self, message: NetworkMessage) -> None:
        self.received.append(message)


class RouterMock(Router):

    received: List[Union[NetworkMessage, FrontendData]]

    def __init__(
        self,
        private_key: Ed25519PrivateKey,
        frontend: Frontend = None,
        frontend_factory: Callable[[Router], Frontend] = None,
        forwarder_factory: Callable[[Router], MessagesForwarder] = MessagesForwarder
    ) -> None:
        super().__init__(private_key, frontend, frontend_factory, forwarder_factory)

    def send(self, message: Union[NetworkMessage, FrontendData]) -> None:
        self.received.append(message)


class RecorderFrontend(Frontend):

    received: List[FrontendData]

    def __init__(self, router: Router) -> None:
        self.router = router
        self.received = []

    def message_callback(self, message: FrontendData) -> None:
        self.received.append(message)


class EchoFrontend(RecorderFrontend):

    received: List[FrontendData]

    def message_callback(self, message: FrontendData) -> None:
        super().message_callback(message)
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

    def connection_callback(
        self,
        address: TestConnection,
        connection: Connection[TestProtocol, bytes]
    ) -> None:
        self.callback(address, connection)
