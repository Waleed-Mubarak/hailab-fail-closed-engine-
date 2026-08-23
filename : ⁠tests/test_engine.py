import unittest
from engine import TurkashEngine

class TestTurkashEngineFinalAuditing(unittest.TestCase):
    
    def test_p0_03_adversarial_state_resurrection_denial(self):
        """
        Adversarial Regression Test for P0-03 (as requested by Dr. Hikmat Karimov):
        Verifies the exact flow:
        ZEROIZE -> attempted internal-state resurrection -> critical operation -> DENY
        """
        engine = TurkashEngine()
        self.assertFalse(engine.is_zeroized)
        
        # Step 1: Trigger secure zeroization (Terminal state)
        engine.execute_zeroization()
        self.assertTrue(engine.is_zeroized)
        self.assertTrue(engine.system_locked)
        self.assertTrue(all(b == 0 for b in engine.inspect_raw_memory_snapshot()))
        
        # Step 2: Attempt adversarial internal-state resurrection via name-mangling manipulation
        try:
            if hasattr(engine, '_TurkashEngine__is_zeroized'):
                engine._TurkashEngine__is_zeroized = False
            if hasattr(engine, '_TurkashEngine__system_locked'):
                engine._TurkashEngine__system_locked = False
            if hasattr(engine, '_TurkashEngine__secure_ram_key'):
                for i in range(len(engine._TurkashEngine__secure_ram_key)):
                    engine._TurkashEngine__secure_ram_key[i] = 0xFF
        except Exception:
            pass  # Even if tampering is attempted, fail-closed must hold

        # Step 3 & 4: Attempt recovery/critical operation and verify strict DENY (Exec(T) != 1)
        auth_result = engine.authorize_recovery("Adversary_Admin")
        self.assertFalse(auth_result, "Security violation: Recovery authorized on zeroized/resurrected engine!")

        operation_result = engine.execute_critical_operation_mpa(required_count=1)
        self.assertIn("OPERATION_DENIED", operation_result, f"Security invariant violated! Result: {operation_result}")
        self.assertFalse(engine.check_admissibility(), "Admissibility boundary failed post-resurrection.")

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
