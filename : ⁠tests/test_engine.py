import unittest
from engine import TurkashEngine

class TestTurkashEngineFinalAuditing(unittest.TestCase):
    
    def test_p0_03_strict_encapsulation_and_no_resurrection(self):
        engine = TurkashEngine()
        self.assertFalse(engine.is_zeroized)
        
        # Execute terminal state
        engine.execute_zeroization()
        
        # P0-03 Evidence: Verify terminal state and zeroed memory payload
        self.assertTrue(engine.is_zeroized)
        self.assertTrue(engine.system_locked)
        self.assertTrue(all(b == 0 for b in engine.inspect_raw_memory_snapshot()))
        
        # Verify name mangling blocks external direct mutation/access
        with self.assertRaises(AttributeError):
            _ = engine.__secure_ram_key

    def test_p0_04_zeroization_idempotence_invariance_z_squared_equals_z(self):
        engine = TurkashEngine()
        
        # First destructive transition
        engine.execute_zeroization()
        snapshot_first = (
            engine.is_zeroized,
            engine.system_locked,
            engine.inspect_raw_memory_snapshot(),
            engine.secure_ram_key_status,
            len(engine.audit_trail)
        )
        
        # Second destructive transition (Z^2 = Z)
        engine.execute_zeroization()
        snapshot_second = (
            engine.is_zeroized,
            engine.system_locked,
            engine.inspect_raw_memory_snapshot(),
            engine.secure_ram_key_status,
            len(engine.audit_trail)
        )
        
        # P0-04 Evidence: Strict state invariance on core memory and terminal flags
        self.assertEqual(snapshot_first[0], snapshot_second[0])
        self.assertEqual(snapshot_first[1], snapshot_second[1])
        self.assertEqual(snapshot_first[2], snapshot_second[2])  # Raw memory bytes remain identically zeroed
        self.assertEqual(snapshot_first[3], snapshot_second[3])

if __name__ == "__main__":
    unittest.main()
