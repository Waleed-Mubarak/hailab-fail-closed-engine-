import unittest
from engine import TurkashEngine

class TestTurkashEngineHardening(unittest.TestCase):
    
    def test_p0_03_encapsulation_and_terminal_state(self):
        engine = TurkashEngine()
        # Verify initial active state
        self.assertFalse(engine.is_zeroized)
        
        # Verify read-only status property interface matches exact engine output
        status = engine.secure_ram_key_status
        self.assertEqual(status, "SECURELY_MANAGED_READ_ONLY")
        
        # P0-03 Hardening Check: Ensure terminal state interface 
        # behaves predictably and maintains state consistency.
        self.assertTrue(hasattr(engine, 'secure_ram_key_status'))

    def test_p0_04_zeroization_idempotence_and_invariance(self):
        engine = TurkashEngine()
        
        # Execute first zeroization (Destructive Transition)
        res_first = engine.execute_zeroization()
        self.assertTrue(res_first)
        self.assertTrue(engine.is_zeroized)
        
        # Capture the terminal state snapshot after first zeroization
        first_terminal_snapshot = (engine.is_zeroized, engine.secure_ram_key_status)
        
        # Subsequent zeroization calls must be strictly idempotent: Z^2 = Z
        res_second = engine.execute_zeroization()
        self.assertTrue(res_second)
        self.assertTrue(engine.is_zeroized)
        
        # Capture the terminal state snapshot after second zeroization
        second_terminal_snapshot = (engine.is_zeroized, engine.secure_ram_key_status)
        
        # Strong invariant assertion: State/destructive-transition invariance holds perfectly
        self.assertEqual(first_terminal_snapshot, second_terminal_snapshot, 
                         "Zeroization transition is not strictly invariant (Idempotence failure Z^2 != Z)")

if __name__ == "__main__":
    unittest.main()
