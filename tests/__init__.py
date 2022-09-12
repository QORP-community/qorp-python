import unittest

from .test_messages import TestMessageSignVerify
from .test_messages import TestMessageDefaultEncodingDecoding


tests = unittest.TestSuite()
tests.addTest(unittest.makeSuite(TestMessageSignVerify))
tests.addTest(unittest.makeSuite(TestMessageDefaultEncodingDecoding))
