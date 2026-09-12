import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

import unittest
from engine import FailClosedEngine, TurkashEngine

class TestFailClosedEngine(unittest.TestCase):
    
    def setUp(self):
        self.engine = FailClosedEngine()

    def test_engine_initialization(self):
        self.assertFalse(self.engine.is_zeroized)
        self.assertEqual(self.engine.secure_ram_key_status, "SECURELY_MANAGED_READ_ONLY")

    def test_zeroization_process(self):
        self.engine.zeroize()
        self.assertTrue(self.engine.is_zeroized)
        self.assertEqual(self.engine.secure_ram_key_status, "ZEROIZED_TERMINAL_LOCKED")

    def test_unauthorized_operations_after_zeroize(self):
        self.engine.zeroize()
        with self.assertRaises(PermissionError):
            self.engine.add_signature("admin_1")

if __name__ == "__main__":
    unittest.main()
