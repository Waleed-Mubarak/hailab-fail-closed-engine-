import unittest
from src.engine import TurkashEngine

class TestTurkashEngineHardening(unittest.TestCase):
    def test_p0_03_encapsulation_and_terminal_state(self):
        engine = TurkashEngine()
        # Verify initial active state
        self.assertFalse(engine.is_zeroized)
        self.assertFalse(engine.system_locked)
        
        # Verify read-only status property is accessible and secure
        status = engine.secure_ram_key_status
        self.assertEqual(status, "SECURELY_MANAGED_READ_ONLY")

    def test_p0_04_zeroization_idempotence_strength(self):
        engine = TurkashEngine()
        
        # Execute first zeroization (Destructive transition)
        res_first = engine.execute_zeroization()
        self.assertTrue(res_first)
        self.assertTrue(engine.is_zeroized)
        self.assertTrue(engine.system_locked)
        
        # Subsequent zeroization calls must remain strictly idempotent without state drift (Z^2 = Z)
        res_second = engine.execute_zeroization()
        self.assertTrue(res_second)
        self.assertTrue(engine.is_zeroized)
        self.assertTrue(engine.system_locked)

if __name__ == "__main__":
    unittest.main()
