import asyncio
from functools import wraps
from unittest import TestCase

from typing import Callable, Coroutine, TypeVar
from typing_extensions import ParamSpec

from qorp.codecs import CHACHA_NONCE_LENGTH, DEFAULT_CODEC
from qorp.messages import NetworkData, RouteRequest, RouteError, RouteResponse
from qorp.nodes import Neighbour
from qorp.router import Router
from qorp.encryption import Ed25519PrivateKey
from qorp.encryption import X25519PrivateKey

from tests.utils import RecorderFrontend, TestConnection, TestProtocol
from tests.utils import NeignbourMock, RouterMock


T = TypeVar("T")
P = ParamSpec("P")


def as_sync(async_fn: Callable[P, Coroutine[None, None, T]]) -> Callable[P, T]:
    @wraps(async_fn)
    def synced(*args: P.args, **kwargs: P.kwargs) -> T:
        return asyncio.run(async_fn(*args, **kwargs))
    return synced


def get_test_router() -> Router:
    private_key = Ed25519PrivateKey.generate()
    router = Router(private_key, frontend_factory=RecorderFrontend)
    return router


def link_routers(first: Router, second: Router) -> None:
    first_neighbour = Neighbour(first.public_key)
    first_proto = TestProtocol()
    first_neighbour_conn = TestConnection(first_proto, DEFAULT_CODEC, 0.01)
    first_neighbour.connections.append(first_neighbour_conn)
    second_neighbour = Neighbour(second.public_key)
    second_proto = TestProtocol()
    second_neighbour_conn = TestConnection(second_proto, DEFAULT_CODEC, 0.01)
    second_neighbour.connections.append(second_neighbour_conn)
    first_proto.address = second_neighbour_conn
    second_proto.address = first_neighbour_conn
    first.forwarder.neighbours.add(second_neighbour)
    second.forwarder.neighbours.add(first_neighbour)


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
        # TODO: Add special case - RReq to end of known route
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

    @as_sync
    async def test_routerequest_deduplication(self) -> None:
        source = NeignbourMock()
        destination = NeignbourMock()
        neighbours = [NeignbourMock() for _ in range(5)]
        self.forwarder.neighbours.update(neighbours)
        rreq_direction, rreq_other_direction, *neighbours = neighbours
        privkey = X25519PrivateKey.generate()
        rreq_pubkey = privkey.public_key()
        rreq = RouteRequest(source, destination, rreq_pubkey)
        rreq.sign(source.private_key)
        self.forwarder.message_callback(rreq_direction, rreq)
        self.forwarder.message_callback(rreq_other_direction, rreq)
        for neighbour in neighbours:
            self.assertEqual(
                neighbour.received.count(rreq), 1,
                "Forwarder duplicates RouteRequest"
            )
        # TODO: Decide is this normal that rreq_other_directions handles RReq
        #       coming from rreq_direction

    @as_sync
    async def test_routerequest_responding(self) -> None:
        source = NeignbourMock()
        destination = NeignbourMock()
        neighbours = [NeignbourMock() for _ in range(2)]
        self.forwarder.neighbours.update(neighbours)
        rreq_direction, rrep_direction = neighbours
        rreq_privkey = X25519PrivateKey.generate()
        rreq_pubkey = rreq_privkey.public_key()
        rrep_privkey = X25519PrivateKey.generate()
        rrep_pubkey = rrep_privkey.public_key()
        # TODO: Add special case - RReq to end of known route
        rreq = RouteRequest(source, destination, rreq_pubkey)
        rreq.sign(source.private_key)
        self.forwarder.message_callback(rreq_direction, rreq)
        rrep = RouteResponse(destination, source, rreq_pubkey, rrep_pubkey)
        rrep.sign(destination.private_key)
        self.forwarder.message_callback(rrep_direction, rrep)
        await asyncio.sleep(0.5)
        self.assertIn(
            rrep, rreq_direction.received,
            "Forwarder does not relay RouteResponse to requester"
        )

    @as_sync
    async def test_routeresponse_propagation(self) -> None:
        source = NeignbourMock()
        destination = NeignbourMock()
        neighbours = [NeignbourMock() for _ in range(5)]
        self.forwarder.neighbours.update(neighbours)
        rreq_direction, *neighbours = neighbours
        rrep_direction, *rrep_receivers = neighbours
        rreq_privkey = X25519PrivateKey.generate()
        rreq_pubkey = rreq_privkey.public_key()
        rrep_privkey = X25519PrivateKey.generate()
        rrep_pubkey = rrep_privkey.public_key()
        # TODO: Add special case - RReq to end of known route
        rreq = RouteRequest(source, destination, rreq_pubkey)
        rreq.sign(source.private_key)
        self.forwarder.message_callback(rreq_direction, rreq)
        rrep = RouteResponse(destination, source, rreq_pubkey, rrep_pubkey)
        rrep.sign(destination.private_key)
        self.forwarder.message_callback(rrep_direction, rrep)
        await asyncio.sleep(0.5)
        for receiver in rrep_receivers:
            self.assertIn(
                rrep, receiver.received,
                "Forwarder does not relay RouteResponse to requester"
            )
        self.assertNotIn(
            rrep, rrep_direction.received,
            "RouteResponse forwarded back to sender"
        )

    def test_routeerror_fetch(self) -> None:
        source = NeignbourMock()
        destination = NeignbourMock()
        src_direction = NeignbourMock()
        dst_direction = NeignbourMock()
        rnd_source = NeignbourMock()
        rnd_destination = NeignbourMock()
        forward_directions = (src_direction, dst_direction)
        backward_directions = (dst_direction, src_direction)
        self.forwarder.routes[(source, destination)] = forward_directions
        self.forwarder.routes[(destination, source)] = backward_directions
        ignored = [
            RouteError(rnd_source, rnd_destination, rnd_source, destination),
            RouteError(rnd_source, destination, source, destination)
            # TODO: add all cases of ignored RouteError messages
        ]
        for msg in ignored:
            msg.sign(rnd_source.private_key)
            self.forwarder.message_callback(rnd_source, msg)
        routes = (source, destination), (destination, source)
        for route in routes:
            self.assertIn(
                route, self.forwarder.routes,
                "Forwarder removes route after handles RouteError from node "
                "which is not a route participant."
            )
        rerr = RouteError(dst_direction, src_direction, source, destination)
        rerr.sign(dst_direction.private_key)
        self.forwarder.message_callback(dst_direction, rerr)
        for route in routes:
            self.assertNotIn(
                route, self.forwarder.routes,
                "Forwarder does not remove route after handles RouteError "
                "from a route participant."
            )

    def test_routeerror_propagation(self) -> None:
        pass

    @as_sync
    async def test_rreq_ttl_kill(self) -> None:
        TEST_TIMEOUT = 0.1
        self.forwarder.RREQ_TIMEOUT = TEST_TIMEOUT
        source = NeignbourMock()
        destination = NeignbourMock()
        neighbours = [NeignbourMock() for _ in range(5)]
        self.forwarder.neighbours.update(neighbours)
        rreq_direction, *neighbours = neighbours
        privkey = X25519PrivateKey.generate()
        rreq_pubkey = privkey.public_key()
        # TODO: Add special case - RReq to end of known route
        rreq = RouteRequest(source, destination, rreq_pubkey)
        rreq.sign(source.private_key)
        self.forwarder.message_callback(rreq_direction, rreq)
        await asyncio.sleep(TEST_TIMEOUT*10)
        self.assertNotIn(
            destination, self.forwarder.pending_requests,
            "Forwader does not delete RouteRequest"
        )


class TestRouter(TestCase):

    def setUp(self) -> None:
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)

    def tearDown(self) -> None:
        self.loop.stop()
        self.loop.close()

    def test_init_network(self) -> None:
        pass
