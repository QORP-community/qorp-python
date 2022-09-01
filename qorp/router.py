import asyncio
from asyncio import Future
from contextlib import contextmanager
from dataclasses import dataclass
from weakref import WeakKeyDictionary

from typing import Callable, Dict, Optional, Set, Tuple, Union

from .encryption import Ed25519PrivateKey, Ed25519PublicKey
from .encryption import X25519PrivateKey
from .encryption import ChaCha20Poly1305
from .frontend import Frontend
from .messages import FrontendData, NetworkMessage
from .messages import NetworkData, RouteRequest, RouteResponse, RouteError
from .nodes import KnownNode, Node, Neighbour
from .transports import Listener


RREQ_TIMEOUT = 10
EMPTY_SET: Set = set()


@dataclass
class RouteInfo:

    direction: Neighbour
    encryption_key: ChaCha20Poly1305
    counter: int = 0

    def get_nonce(self):
        self.counter += 1
        return self.counter


class Router(KnownNode):

    private_key: Ed25519PrivateKey
    public_key: Ed25519PublicKey
    broadcast_listeners: Set[Listener]
    frontend: Frontend
    neighbours: Set[Neighbour]
    directions: Dict[Node, Neighbour]
    pending_requests: Dict[Node, Set["Future[Neighbour]"]]
    _requesters: WeakKeyDictionary["Future[Neighbour]", Tuple[Node, Node]]

    def __init__(self, private_key: bytes, frontend: Frontend) -> None:
        super().__init__()
        self.private_key = Ed25519PrivateKey.from_private_bytes(private_key)
        self.public_key = self.private_key.public_key()
        self.frontend = frontend
        self.broadcast_listeners = set()
        self.neighbours = set()
        self.pending_requests = {}
        self._requesters = WeakKeyDictionary()

    async def find_direction(self, target: Node, timeout: Optional[float] = RREQ_TIMEOUT) -> Neighbour:
        if target in self.directions:
            return self.directions[target]
        exchange_private_key = X25519PrivateKey.generate()
        exchange_public_key = exchange_private_key.public_key()
        # TODO: store a private key for further secret generation
        request = RouteRequest(self, target, exchange_public_key)
        with self._track_request(target) as future:
            for neighbour in self.neighbours:
                neighbour.send(request)
            response = await asyncio.wait_for(future, timeout)
        return response

    @contextmanager
    def _track_request(self, target: Node):
        future: Future[Neighbour] = Future()
        requests = self.pending_requests.setdefault(target, set())
        requests.add(future)
        try:
            yield future
        finally:
            requests.remove(future)

    def network_message_callback(self, source: Neighbour, message: NetworkMessage):
        if not message.verify():
            return
        if isinstance(message, NetworkData):
            self.handle_data(source, message)
        elif isinstance(message, RouteRequest):
            self.handle_rreq(source, message)
        elif isinstance(message, RouteResponse):
            self.handle_rrep(source, message)
        elif isinstance(message, RouteError):
            self.handle_rerr(source, message)
        else:
            raise TypeError

    def handle_data(self, source: Neighbour, data: NetworkData):
        target = data.destination
        if target == self:
            self.frontend.send(data)
        elif target in self.directions:
            direction = self.directions[target]
            direction.send(data)
        else:
            rerr = RouteError(self, source, target)
            source.send(rerr)

    def handle_rreq(self, source: Neighbour, request: RouteRequest):
        target = request.destination
        if target == self:
            exchange_private_key = X25519PrivateKey.generate()
            exchange_public_key = exchange_private_key.public_key()
            # TODO: make exchange and store generated key
            response = RouteResponse(self, request.source, exchange_public_key)
            source.send(response)
        elif target in self.directions:
            direction = self.directions[target]
            direction.send(request)
        else:
            requests = self.pending_requests.setdefault(target, set())
            loop = asyncio.get_running_loop()
            future: Future[Neighbour] = loop.create_future()
            future.add_done_callback(self._done_request(target))
            ttl_kill = self._rreq_ttl_killer(target, future)
            loop.call_later(RREQ_TIMEOUT, ttl_kill)
            requests.add(future)
            if self.is_unique_rreq(request, exclude=future):
                for neighbour in self.neighbours:
                    if neighbour == source:
                        continue
                    neighbour.send(request)

    def handle_rrep(self, source: Neighbour, response: RouteResponse):
        target = response.destination
        direction = self.directions.get(target)
        if direction is not None:
            direction.send(response)

    def handle_rerr(self, source: Neighbour, error: RouteError):
        if self.directions.get(error.route_destination) == source:
            self.directions.pop(error.route_destination)
        # TODO: ?? resend RErr message 

    def is_unique_rreq(self, rreq: RouteRequest, exclude: Optional[Future] = None) -> bool:
        target = rreq.destination
        requests = self.pending_requests.get(target)
        if not requests:
            # there is no requests for target
            return True
        elif exclude in requests and len(requests) == 1:
            # there is exactly one request and it is excluded request
            return True
        return False

    def frontend_message_callback(self, message: FrontendData):
        # TODO: write frontend-originated data message processing code
        pass

    def _rreq_ttl_killer(self, target: Node, future: Future):
        def callback():
            futures = self.pending_requests.get(target, EMPTY_SET)
            if future in futures:
                futures.remove(future)
            if not future.done():
                future.cancel()
        return callback

    def _done_request(self, target: Node) -> Callable[["Future[Neighbour]"], None]:
        def callback(future: "Future[Neighbour]"):
            futures = self.pending_requests.get(target, EMPTY_SET)
            if future in futures:
                futures.remove(future)
            if future.done() and not (future.cancelled() or future.exception()):
                direction = future.result()
                self.directions.setdefault(target, direction)
                for future in futures:
                    future.set_result(direction)
        return callback
