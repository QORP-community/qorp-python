from __future__ import annotations

import asyncio
from asyncio import Future
from weakref import WeakKeyDictionary

from typing import Callable, Dict, Optional, Set, Tuple
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from .router import Router

from .messages import NetworkMessage
from .messages import NetworkData, RouteRequest, RouteResponse, RouteError
from .nodes import KnownNode, Node, Neighbour
from .transports import Listener


RRepInfo = Tuple[Neighbour, RouteResponse]

RREQ_TIMEOUT = 10
EMPTY_SET: Set["Future[RRepInfo]"] = set()


class MessagesForwarder:

    router: Router
    broadcast_listeners: Set[Listener]
    neighbours: Set[Neighbour]
    routes: Dict[Tuple[KnownNode, KnownNode], Tuple[Neighbour, Neighbour]]
    directions: Dict[KnownNode, Neighbour]
    pending_requests: Dict[Node, Set["Future[RRepInfo]"]]
    _requests_details: "WeakKeyDictionary[Future[RRepInfo], RouteRequest]"

    def __init__(self, router: Router) -> None:
        self.router = router
        self.broadcast_listeners = set()
        self.neighbours = {router}
        self.routes = {(router, router): (router, router)}
        self.directions = {router: router}
        self.pending_requests = {}
        self._requests_details = WeakKeyDictionary()

    def message_callback(self, source: Neighbour, msg: NetworkMessage) -> None:
        if source != self.router and not msg.verify():
            return
        if isinstance(msg, NetworkData):
            self.handle_data(source, msg)
        elif isinstance(msg, RouteRequest):
            self.handle_rreq(source, msg)
        elif isinstance(msg, RouteResponse):
            self.handle_rrep(source, msg)
        elif isinstance(msg, RouteError):
            self.handle_rerr(source, msg)
        else:
            raise TypeError

    def handle_data(self, source: Neighbour, data: NetworkData) -> None:
        route_pair = data.source, data.destination
        directions = self.routes.get(route_pair)
        if directions is None:
            rerr = RouteError(self.router, source, *route_pair)
            source.send(rerr)
            return
        source_direction, destination_direction = directions
        if source_direction == source:
            destination_direction.send(data)

    def handle_rreq(self, source: Neighbour, request: RouteRequest) -> None:
        target = request.destination
        if target in self.directions:
            direction = self.directions[target]
            direction.send(request)
        else:
            requests = self.pending_requests.setdefault(target, set())
            loop = asyncio.get_running_loop()
            future: Future[RRepInfo] = loop.create_future()
            future.add_done_callback(self._done_request(target))
            ttl_kill = self._rreq_ttl_killer(target, future)
            loop.call_later(RREQ_TIMEOUT, ttl_kill)
            self._requests_details[future] = request
            requests.add(future)
            if self.is_unique_rreq(request, exclude=future):
                for neighbour in self.neighbours:
                    if neighbour == source:
                        continue
                    neighbour.send(request)

    def handle_rrep(self, source: Neighbour, response: RouteResponse) -> None:
        futures = self.pending_requests.get(response.source, EMPTY_SET)
        for future in futures:
            rreq = self._requests_details.get(future)
            if rreq is None or rreq.public_key != response.requester_key:
                # response not for this request
                continue
            futures.remove(future)
            future.set_result((source, response))

    def handle_rerr(self, source: Neighbour, error: RouteError) -> None:
        route_pair = error.route_source, error.route_destination
        directions = self.routes.get(route_pair)
        if not directions or directions[1] != source:
            return
        self.routes.pop(route_pair)
        source_direction = directions[0]
        source_direction.send(error)

    def is_unique_rreq(self, rreq: RouteRequest, exclude: Optional["Future[RRepInfo]"] = None) -> bool:
        target = rreq.destination
        requests = self.pending_requests.get(target)
        if not requests:
            # there is no requests for target
            return True
        elif exclude in requests and len(requests) == 1:
            # there is exactly one request and it is excluded request
            return True
        return False

    def _rreq_ttl_killer(self, target: Node, future: "Future[RRepInfo]") -> Callable[[], None]:
        def callback() -> None:
            futures = self.pending_requests.get(target, EMPTY_SET)
            if future in futures:
                futures.remove(future)
            if not future.done():
                future.set_exception(TimeoutError)
        return callback

    def _done_request(self, target: Node) -> Callable[["Future[RRepInfo]"], None]:
        def callback(future: "Future[RRepInfo]") -> None:
            futures = self.pending_requests.get(target, EMPTY_SET)
            if future in futures:
                futures.remove(future)
            if future.cancelled() or future.exception():
                return
            result = future.result()
            direction, response = result
            directions = (direction, direction)
            self.routes[(response.destination, response.source)] = directions
            self.routes[(response.source, response.destination)] = directions
            self.directions.setdefault(response.source, direction)
            for future in futures:
                future.set_result(result)
            for neighbour in self.neighbours:
                if neighbour != direction:
                    neighbour.send(response)
        return callback
