import unittest

from .test_messages import TestMessageSignVerify
from .test_messages import TestDefaultCodec
from .test_router import TestMessagesForwarder


tests = unittest.TestSuite()
tests.addTest(unittest.makeSuite(TestMessageSignVerify))
tests.addTest(unittest.makeSuite(TestDefaultCodec))
tests.addTest(unittest.makeSuite(TestMessagesForwarder))
