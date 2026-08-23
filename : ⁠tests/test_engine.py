import unittest
from engine import TurkashEngine

class TestTurkashEngineFinalAuditing(unittest.TestCase):
    
    def test_p0_03_exact_adversarial_flow_denial(self):
        """
        Narrowly scoped regression test for P0-03 (Requested by Dr. Hikmat Kerimov):
        Flow: ZEROIZE -> attempted direct internal-state tampering/bypass -> valid quorum -> critical operation -> DENY
        """
        engine = TurkashEngine()
        
        # 1. ZEROIZE
        engine.execute_zeroization()
        self.assertTrue(engine.is_zeroized)
        
        # 2. attempted direct internal-state tampering/bypass
        try:
            engine._TurkashEngine__terminal_state_locked = False
            engine._TurkashEngine__is_zeroized = False
            engine._TurkashEngine__system_locked = False
            # Attempt to refill the raw memory with non-zero bytes to try bypassing memory-check
            if hasattr(engine, '_TurkashEngine__secure_ram_key'):
                for i in range(len(engine._TurkashEngine__secure_ram_key)):
                    engine._TurkashEngine__secure_ram_key[i] = 0xAA
        except Exception:
            pass  # Even if blocked or caught, proceed to test quorum and critical operation
            
        # 3. valid quorum (injecting valid admin signatures/quorum)
        engine.authorized_admins.add("admin_1")
        engine.authorized_admins.add("admin_2")
        self.assertTrue(engine.check_quorum(2))
        
        # 4. critical operation -> must result in DENY
        operation_result = engine.execute_critical_operation_mpa(required_count=2)
        
        # 5. Verify DENY
        self.assertIn("OPERATION_DENIED", operation_result, f"Security invariant violated! Critical operation succeeded after zeroization/tampering: {operation_result}")

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
