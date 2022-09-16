from unittest import TestCase

from qorp.encoding import DefaultCodec
from qorp.encryption import Ed25519PrivateKey, X25519PrivateKey
from qorp.messages import NetworkData, RouteRequest, RouteResponse, RouteError
from qorp.nodes import KnownNode


src_privkey = Ed25519PrivateKey.generate()
src_pubkey = src_privkey.public_key()
src = KnownNode(src_pubkey)

dst_privkey = Ed25519PrivateKey.generate()
dst_pubkey = dst_privkey.public_key()
dst = KnownNode(dst_pubkey)

exchange_privkey = X25519PrivateKey.generate()
exchange_pubkey = exchange_privkey.public_key()


class TestMessageSignVerify(TestCase):

    def setUp(self) -> None:
        self.data = NetworkData(src, dst, b"\x00"*12, 1, b"\x00")
        self.rreq = RouteRequest(src, dst, exchange_pubkey)
        self.rrep = RouteResponse(src, dst, exchange_pubkey, exchange_pubkey)
        self.rerr = RouteError(src, dst, src, dst)

    def test_signverify_networkdata(self) -> None:
        self.data.sign(src_privkey)
        self.assertTrue(self.data.verify())

    def test_signverify_routerequest(self) -> None:
        self.rreq.sign(src_privkey)
        self.assertTrue(self.rreq.verify())

    def test_signverify_routeresponse(self) -> None:
        self.rrep.sign(src_privkey)
        self.assertTrue(self.rrep.verify())

    def test_signverify_routeerror(self) -> None:
        self.rerr.sign(src_privkey)
        self.assertTrue(self.rerr.verify())


class TestDefaultCodec(TestCase):

    def setUp(self) -> None:
        self.codec = DefaultCodec()
        self.data = NetworkData(src, dst, b"\x00"*12, 1, b"\x00")
        self.rreq = RouteRequest(src, dst, exchange_pubkey)
        self.rrep = RouteResponse(src, dst, exchange_pubkey, exchange_pubkey)
        self.rerr = RouteError(src, dst, src, dst)
        for msg in self.data, self.rreq, self.rrep, self.rerr:
            msg.sign(src_privkey)

    def test_default_encodedecode_networkdata(self) -> None:
        encoded = self.codec.encode(self.data)
        decoded = self.codec.decode(encoded)
        self.assertEqual(self.data, decoded)

    def test_default_encodedecode_routerequest(self) -> None:
        encoded = self.codec.encode(self.rreq)
        decoded = self.codec.decode(encoded)
        self.assertEqual(self.rreq, decoded)

    def test_default_encodedecode_routeresponse(self) -> None:
        encoded = self.codec.encode(self.rrep)
        decoded = self.codec.decode(encoded)
        self.assertEqual(self.rrep, decoded)

    def test_default_encodedecode_routeerror(self) -> None:
        encoded = self.codec.encode(self.rerr)
        decoded = self.codec.decode(encoded)
        self.assertEqual(self.rerr, decoded)
