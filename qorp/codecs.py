from __future__ import annotations
from abc import ABC, abstractmethod

from typing import ClassVar, Dict, Generic, List, Tuple, Type, TypeVar, Union
from typing import overload
from typing_extensions import Literal

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

Encoded = TypeVar("Encoded")


class MessagesCodec(ABC, Generic[Encoded]):

    @abstractmethod
    def encode(self, message: NetworkMessage) -> Encoded:
        pass

    @abstractmethod
    def decode(self, input: Encoded) -> NetworkMessage:
        pass


class DefaultCodec(MessagesCodec[bytes]):

    head_scheme: ClassVar[Tuple[int, ...]] = (PUBKEY_LENGTH, PUBKEY_LENGTH, 1)
    body_schemes: ClassVar[Dict[Type[NetworkMessage], Tuple[int, ...]]] = {
        NetworkData: (CHACHA_NONCE_LENGTH, 2, SIGNATURE_LENGTH),
        RouteRequest: (1, PUBKEY_LENGTH, SIGNATURE_LENGTH),
        RouteResponse: (PUBKEY_LENGTH, PUBKEY_LENGTH, SIGNATURE_LENGTH),
        RouteError: (PUBKEY_LENGTH, PUBKEY_LENGTH, SIGNATURE_LENGTH)
    }
    type_label: ClassVar[Dict[Type[NetworkMessage], bytes]] = {
        NetworkData: b"\x01",
        RouteRequest: b"\x02",
        RouteResponse: b"\x03",
        RouteError: b"\x04"
    }
    label_type: ClassVar[Dict[bytes, Type[NetworkMessage]]] = {
        label: type for type, label in type_label.items()
    }

    def encode(self, message: NetworkMessage) -> bytes:
        fields: List[bytes]
        MessageType = type(message)
        if isinstance(message, NetworkData):
            fields = [
                pubkey_to_bytes(message.source.public_key),
                pubkey_to_bytes(message.destination.public_key),
                self.type_label[MessageType],
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
                self.type_label[MessageType],
                dst_type,
                pubkey_to_bytes(message.public_key),
                message.signature,
            ]
        elif isinstance(message, RouteResponse):
            fields = [
                pubkey_to_bytes(message.source.public_key),
                pubkey_to_bytes(message.destination.public_key),
                self.type_label[MessageType],
                pubkey_to_bytes(message.requester_key),
                pubkey_to_bytes(message.public_key),
                message.signature,
            ]
        elif isinstance(message, RouteError):
            fields = [
                pubkey_to_bytes(message.source.public_key),
                pubkey_to_bytes(message.destination.public_key),
                self.type_label[MessageType],
                pubkey_to_bytes(message.route_source.public_key),
                pubkey_to_bytes(message.route_destination.public_key),
                message.signature,
            ]
        else:
            raise TypeError(f"Unknown message type: {MessageType.__name__}")
        raw = b"".join(fields)
        return raw

    def decode(self, encoded: bytes) -> NetworkMessage:
        message: NetworkMessage
        fields: Union[
            Tuple[KnownNode, KnownNode, bytes, int, bytes],
            Tuple[KnownNode, Union[Node, KnownNode], X25519PublicKey],
            Tuple[KnownNode, KnownNode, X25519PublicKey, X25519PublicKey],
            Tuple[KnownNode, KnownNode, KnownNode, KnownNode],
        ]
        source_, destination_, type_label, body = split(encoded, *self.head_scheme)
        MessageType = self.label_type.get(type_label)
        if MessageType is None:
            raise ValueError(f"Unknown message type label: {type_label!r}")
        body_scheme = self.body_schemes[MessageType]
        raw_fields = split(body, *body_scheme)
        if MessageType is NetworkData:
            source, destination = _decode_sorce_destination(source_, destination_)
            nonce, length_, signature, payload = raw_fields
            length = int.from_bytes(length_, "big")
            fields = source, destination, nonce, length, payload
        elif MessageType is RouteRequest:
            dst_type, pubkey_, signature = raw_fields
            unknown_dst = bool(dst_type[0])
            source, rdestination = _decode_sorce_destination(source_, destination_, unknown_dst)  # noqa
            pubkey = X25519PublicKey.from_public_bytes(pubkey_)
            fields = source, rdestination, pubkey
        elif MessageType is RouteResponse:
            source, destination = _decode_sorce_destination(source_, destination_)
            requester_pubkey_, pubkey_, signature = raw_fields
            requester_pubkey = X25519PublicKey.from_public_bytes(requester_pubkey_)
            pubkey = X25519PublicKey.from_public_bytes(pubkey_)
            fields = source, destination, requester_pubkey, pubkey
        elif MessageType is RouteError:
            source, destination = _decode_sorce_destination(source_, destination_)
            route_src_, route_dst_, signature = raw_fields
            route_src_key = Ed25519PublicKey.from_public_bytes(route_src_)
            route_dst_key = Ed25519PublicKey.from_public_bytes(route_dst_)
            route_src = KnownNode(route_src_key)
            route_dst = KnownNode(route_dst_key)
            fields = source, destination, route_src, route_dst
        else:
            raise ValueError(f"Unknown message type: {MessageType.__name__}")
        message = MessageType(*fields)
        message.set_signature(signature)
        return message


DEFAULT_CODEC = DefaultCodec()


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


@overload
def _decode_sorce_destination(
    src: bytes, dst: bytes
) -> Tuple[KnownNode, KnownNode]: ...
@overload  # noqa: E302
def _decode_sorce_destination(
    src: bytes, dst: bytes, unknown_dst: Literal[False] = False
) -> Tuple[KnownNode, KnownNode]: ...
@overload  # noqa: E302
def _decode_sorce_destination(
    src: bytes, dst: bytes, unknown_dst: Literal[True] = True
) -> Tuple[KnownNode, Node]: ...
@overload  # noqa: E302
def _decode_sorce_destination(
    src: bytes, dst: bytes, unknown_dst: bool = False
) -> Union[Tuple[KnownNode, Node], Tuple[KnownNode, KnownNode]]: ...
def _decode_sorce_destination(    # noqa: E302
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
