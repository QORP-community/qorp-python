from __future__ import annotations

from typing import Dict, List, Tuple, Type, Union
from typing import overload
from typing_extensions import Literal, Protocol

from .encryption import Ed25519PublicKey, X25519PublicKey, pubkey_to_bytes
from .messages import NetworkData, RouteError, RouteRequest, RouteResponse
from .nodes import Node, KnownNode, NodeAddress

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from .messages import NetworkMessage


CHACHA_NONCE_LENGTH = 12
PUBKEY_LENGTH = 32
SIGNATURE_LENGTH = 64

TYPE_TO_LABEL: Dict[Type[NetworkMessage], bytes] = {
    NetworkData: b"\x01",
    RouteRequest: b"\x02",
    RouteResponse: b"\x03",
    RouteError: b"\x04"
}
LABEL_TO_TYPE: Dict[bytes, Type[NetworkMessage]] = {
    label: type for type, label in TYPE_TO_LABEL.items()
}


class Encoder(Protocol):
    """
    Base class for messages encoders.
    """

    def __call__(self, message: NetworkMessage) -> bytes:
        pass


class Decoder(Protocol):
    """
    Base class for messages decoders.
    """

    def __call__(self, data: bytes) -> NetworkMessage:
        pass


def split(source: bytes, *lengths: int) -> List[bytes]:
    start = 0
    chunks = []
    for length in lengths:
        end = start + length
        chunk = source[start:end]
        chunks.append(chunk)
        start = end
    if start < len(source):
        chunk = source[start:]
        chunks.append(chunk)
    return chunks


def default_encoder(message: NetworkMessage) -> bytes:
    fields: List[bytes]
    message_type = type(message)
    if isinstance(message, NetworkData):
        fields = [
            pubkey_to_bytes(message.source.public_key),
            pubkey_to_bytes(message.destination.public_key),
            TYPE_TO_LABEL[message_type],
            message.nonce,
            message.length.to_bytes(2, "big"),
            message.signature,
            message.payload,
        ]
    elif isinstance(message, RouteRequest):
        if isinstance(message.destination, KnownNode):
            dst_field = pubkey_to_bytes(message.destination.public_key)
            dst_type = b"\x00"
        else:
            dst_field = message.destination.address
            dst_type = b"\x01"
        fields = [
            pubkey_to_bytes(message.source.public_key),
            dst_field,
            TYPE_TO_LABEL[message_type],
            dst_type,
            pubkey_to_bytes(message.public_key),
            message.signature,
        ]
    elif isinstance(message, RouteResponse):
        fields = [
            pubkey_to_bytes(message.source.public_key),
            pubkey_to_bytes(message.destination.public_key),
            TYPE_TO_LABEL[message_type],
            pubkey_to_bytes(message.requester_key),
            pubkey_to_bytes(message.public_key),
            message.signature,
        ]
    elif isinstance(message, RouteError):
        fields = [
            pubkey_to_bytes(message.source.public_key),
            pubkey_to_bytes(message.destination.public_key),
            TYPE_TO_LABEL[message_type],
            pubkey_to_bytes(message.route_source.public_key),
            pubkey_to_bytes(message.route_destination.public_key),
            message.signature,
        ]
    else:
        raise TypeError(f"Unknown message type: {message_type.__name__}")
    raw = b"".join(fields)
    return raw


def default_decoder(data: bytes) -> NetworkMessage:
    message: NetworkMessage
    head_scheme = PUBKEY_LENGTH, PUBKEY_LENGTH, 1
    source_, destination_, type_label, body = split(data, *head_scheme)
    message_type = LABEL_TO_TYPE.get(type_label)
    if message_type is None:
        raise ValueError(f"Incorrect message type label: {type_label!r}")
    if message_type is NetworkData:
        source, destination = _decode_sorce_destination(source_, destination_)
        data_scheme = CHACHA_NONCE_LENGTH, 2, SIGNATURE_LENGTH
        nonce, length_, signature, payload = split(body, *data_scheme)
        length = int.from_bytes(length_, "big")
        message = NetworkData(source, destination, nonce, length, payload)
    elif message_type is RouteRequest:
        rreq_scheme = 1, PUBKEY_LENGTH, SIGNATURE_LENGTH
        dst_type, pubkey_, signature = split(body, *rreq_scheme)
        unknown_dst = bool(dst_type[0])
        source, rdestination = _decode_sorce_destination(source_, destination_, unknown_dst)  # noqa
        pubkey = X25519PublicKey.from_public_bytes(pubkey_)
        message = RouteRequest(source, rdestination, pubkey)
    elif message_type is RouteResponse:
        source, destination = _decode_sorce_destination(source_, destination_)
        rrep_scheme = PUBKEY_LENGTH, PUBKEY_LENGTH, SIGNATURE_LENGTH
        requester_pubkey_, pubkey_, signature = split(body, *rrep_scheme)
        requester_pubkey = X25519PublicKey.from_public_bytes(requester_pubkey_)
        pubkey = X25519PublicKey.from_public_bytes(pubkey_)
        message = RouteResponse(source, destination, requester_pubkey, pubkey)
    elif message_type is RouteError:
        source, destination = _decode_sorce_destination(source_, destination_)
        rerr_scheme = PUBKEY_LENGTH, PUBKEY_LENGTH, SIGNATURE_LENGTH
        route_src_, route_dst_, signature = split(body, *rerr_scheme)
        route_src_key = Ed25519PublicKey.from_public_bytes(route_src_)
        route_dst_key = Ed25519PublicKey.from_public_bytes(route_dst_)
        route_src = KnownNode(route_src_key)
        route_dst = KnownNode(route_dst_key)
        message = RouteError(source, destination, route_src, route_dst)
    else:
        raise ValueError(f"Unknown message type: {message_type.__name__}")
    message.set_signature(signature)
    return message


@overload
def _decode_sorce_destination(
    src: bytes, dst: bytes
) -> Tuple[KnownNode, KnownNode]: ...
@overload
def _decode_sorce_destination(
    src: bytes, dst: bytes, unknown_dst: Literal[False] = False
) -> Tuple[KnownNode, KnownNode]: ...
@overload
def _decode_sorce_destination(
    src: bytes, dst: bytes, unknown_dst: Literal[True] = True
) -> Tuple[KnownNode, Node]: ...
@overload
def _decode_sorce_destination(
    src: bytes, dst: bytes, unknown_dst: bool = False
) -> Union[Tuple[KnownNode, Node], Tuple[KnownNode, KnownNode]]: ...
def _decode_sorce_destination(
    src: bytes, dst: bytes, unknown_dst: bool = False
) -> Union[Tuple[KnownNode, Node], Tuple[KnownNode, KnownNode]]:
    src_key = Ed25519PublicKey.from_public_bytes(src)
    source = KnownNode(src_key)
    if unknown_dst:
        destination = Node(NodeAddress(dst))
    else:
        dst_key = Ed25519PublicKey.from_public_bytes(dst)
        destination = KnownNode(dst_key)
    return source, destination
