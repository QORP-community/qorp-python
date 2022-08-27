import asyncio
from asyncio import Future
from contextlib import contextmanager
from weakref import WeakKeyDictionary

from typing import Callable, Dict, Optional, Set, Tuple

from .encryption import Ed25519PrivateKey, Ed25519PublicKey
from .frontend import Frontend
from .messages import Message
from .messages import Data, RouteRequest, RouteResponse, RouteError
from .nodes import Node, Neighbour
from .transports import Listener


RREQ_TIMEOUT = 10
EMPTY_SET: Set = set()


class Router(Node):

    private_key: Ed25519PrivateKey
    public_key: Ed25519PublicKey
    broadcast_listeners: Set[Listener]
    frontend: Frontend
    neighbours: Set[Neighbour]
    directions: Dict[Node, Neighbour]
    pending_requests: Dict[Node, Set["Future[Neighbour]"]]
    _requesters: WeakKeyDictionary["Future[Neighbour]", Tuple[Node, Node]]

    async def find_direction(self, target: Node, timeout: Optional[float] = RREQ_TIMEOUT) -> Neighbour:
        if target in self.directions:
            return self.directions[target]
        request = RouteRequest(self, target)
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

    def network_message_callback(self, source: Neighbour, message: Message):
        direction: Optional[Neighbour]
        if isinstance(message, Data):
            target = message.destination
            if target == self:
                self.frontend.send(message)
            elif target in self.directions:
                direction = self.directions[target]
                direction.send(message)
            else:
                rerr = RouteError(self, source)
                source.send(rerr)
        elif isinstance(message, RouteRequest):
            target = message.destination
            if target == self:
                response = RouteResponse(self, message.source)
                source.send(response)
            elif target in self.directions:
                direction = self.directions[target]
                direction.send(message)
            else:
                requests = self.pending_requests.setdefault(target, set())
                loop = asyncio.get_running_loop()
                future: Future[Neighbour] = loop.create_future()
                future.add_done_callback(self._done_request(target))
                ttl_kill = self._rreq_ttl_killer(target, future)
                loop.call_later(RREQ_TIMEOUT, ttl_kill)
                requests.add(future)
                if self.is_unique_rreq(message, exclude=future):
                    for neighbour in self.neighbours:
                        if neighbour == source:
                            continue
                        neighbour.send(message)
        elif isinstance(message, RouteResponse):
            target = message.destination
            direction = self.directions.get(target)
            if direction is not None:
                direction.send(message)
        elif isinstance(message, RouteError):
            # TODO: remove direction from directions
            pass
        else:
            raise TypeError

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

    def frontend_message_callback(self, message: Data):
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
