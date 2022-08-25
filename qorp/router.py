from asyncio import Future
from typing import Dict, Set

from .encryption import X25519PrivateKey, X25519PublicKey
from .frontend import Frontend
from .nodes import Node, Neighbour
from .transports import Listener


RREQ_TIMEOUT = 10


class Router(Node):

    private_key: X25519PrivateKey
    public_key: X25519PublicKey
    broadcast_listeners: Set[Listener]
    frontend: Frontend
    neighbours: Set[Neighbour]
    directions: Dict[Node, Neighbour]
    pending_requests: Dict[Node, Set["Future[Neighbour]"]]
