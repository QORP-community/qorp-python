import unittest

from . import tests


runner = unittest.TextTestRunner(verbosity=2)
runner.run(tests)
