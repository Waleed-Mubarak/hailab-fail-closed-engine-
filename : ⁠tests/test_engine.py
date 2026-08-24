import unittest
from engine import TurkashEngine

class TestTurkashEngineDescriptorAuditing(unittest.TestCase):
    
    def test_descriptor_irreversible_state_lock(self):
        """
        Tests that once terminal states are locked via Descriptors, 
        any adversarial attempt to reset them to False raises a PermissionError.
        """
        engine = TurkashEngine()
        
        # 1. Execute zeroization to trigger immutable descriptor locks
        engine.execute_zeroization()
        self.assertTrue(engine.is_zeroized)
        
        # 2. Adversarial attempt to mutate/reset descriptor states back to False must fail
        with self.assertRaises(PermissionError):
            engine._is_zeroized = False
            
        with self.assertRaises(PermissionError):
            engine._terminal_state_locked = False

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
        
        # Strict state invariance on core memory and terminal flags
        self.assertEqual(snapshot_first[0], snapshot_second[0])
        self.assertEqual(snapshot_first[1], snapshot_second[1])
        self.assertEqual(snapshot_first[2], snapshot_second[2])
        self.assertEqual(snapshot_first[3], snapshot_second[3])

if __name__ == "__main__":
    unittest.main()
