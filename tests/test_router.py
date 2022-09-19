import asyncio
from functools import wraps
from unittest import TestCase

from typing import Awaitable, Callable, TypeVar

from qorp.codecs import CHACHA_NONCE_LENGTH, DEFAULT_CODEC
from qorp.messages import NetworkData, RouteRequest, RouteError
from qorp.nodes import Neighbour
from qorp.router import Router
from qorp.encryption import Ed25519PrivateKey, X25519PrivateKey

from tests.utils import RecorderFrontend, TestConnection, TestProtocol
from tests.utils import NeignbourMock, RouterMock


T = TypeVar("T")


def as_sync(async_fn: Callable[..., Awaitable[T]]) -> Callable[..., T]:
    @wraps(async_fn)
    def synced(*args, **kwargs) -> T:
        return asyncio.run(async_fn(*args, **kwargs))
    return synced


class TestMessagesForwarder(TestCase):

    def setUp(self) -> None:
        private_key = Ed25519PrivateKey.generate()
        self.router = RouterMock(private_key, frontend_factory=RecorderFrontend)
        self.forwarder = self.router.forwarder
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)

    def tearDown(self) -> None:
        self.loop.stop()
        self.loop.close()

    def test_networkdata_forwarding(self) -> None:
        source = NeignbourMock()
        destination = NeignbourMock()
        self.forwarder.routes[(source, destination)] = (source, destination)
        self.forwarder.routes[(source, self.router)] = (source, self.router)
        nonce = b"\x00"*CHACHA_NONCE_LENGTH
        destinations = destination, self.router
        signed = [
            NetworkData(source, dst, nonce, 1, b"\x00")
            for dst in destinations
        ]
        unsigned = [
            NetworkData(source, dst, nonce, 1, b"\x01")
            for dst in destinations
        ]
        for msg in signed:
            msg.sign(source.private_key)
            self.forwarder.message_callback(source, msg)
            self.assertIn(
                msg, msg.destination.received,
                "Message did not forwarded to next hop"
            )
        for msg in unsigned:
            self.forwarder.message_callback(source, msg)
            self.assertNotIn(
                msg, msg.destination.received,
                "Unsingned message forwarded to next hop"
            )

    def test_routeerror_emit(self) -> None:
        source = NeignbourMock()
        destination = NeignbourMock()
        nonce = b"\x00"*CHACHA_NONCE_LENGTH
        destinations = destination, self.router
        for dst in destinations:
            msg = NetworkData(source, dst, nonce, 1, b"\x00")
            msg.sign(source.private_key)
            self.forwarder.message_callback(source, msg)
            rerr = RouteError(self.router, source, source, dst)
            rerr.sign(self.router.private_key)
            self.assertIn(
                rerr, source.received,
                "Forwarder does not reply with RouteError to message with "
                "unknown source-destination pair."
            )

    @as_sync
    async def test_routerequest_propagation(self) -> None:
        source = NeignbourMock()
        destination = NeignbourMock()
        neighbours = [NeignbourMock() for _ in range(5)]
        self.forwarder.neighbours.update(neighbours)
        rreq_direction, *neighbours = neighbours
        privkey = X25519PrivateKey.generate()
        rreq_pubkey = privkey.public_key()
        rreq = RouteRequest(source, destination, rreq_pubkey)
        rreq.sign(source.private_key)
        self.forwarder.message_callback(rreq_direction, rreq)
        for neighbour in neighbours:
            self.assertIn(
                rreq, neighbour.received,
                "Forwarder does not relay RouteRequest to neighbour"
            )
        self.assertNotIn(
            rreq, rreq_direction.received,
            "Forwarder sends RouteRequest back to source"
        )
