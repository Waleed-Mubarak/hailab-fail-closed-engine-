import unittest
from engine import TurkashEngine

class TestTurkashEngineFinalAuditing(unittest.TestCase):
    
    def test_p0_03_stub_deletion_fallback_bypass_denies_operation(self):
        """
        P0-03 Regression Test (Requested by Dr. Hikmat Kerimov):
        Ensures that restoring state flags AND explicitly deleting instance-level stubs 
        from __dict__ does not allow fallback execution of base class methods.
        """
        engine = TurkashEngine()
        
        # 1. Execute zeroization to trigger initial stub-replacement and terminal locks
        engine.execute_zeroization()
        self.assertTrue(engine.is_zeroized)
        
        # 2. Adversarial State Mutation & Flag Restoration attempt
        object.__setattr__(engine, "_TurkashEngine__is_zeroized", False)
        object.__setattr__(engine, "_TurkashEngine__terminal_state_locked", False)
        object.__setattr__(engine, "_TurkashEngine__system_locked", False)
        
        # 3. Explicitly delete instance-level stub overrides from instance __dict__ to test fallback vector
        raw_dict = object.__getattribute__(engine, "__dict__")
        raw_dict.pop("execute_critical_operation_mpa", None)
        raw_dict.pop("check_admissibility", None)
        
        # 4. Provide valid quorum to simulate a sophisticated bypass attempt
        engine.authorized_admins.add("node_1")
        engine.authorized_admins.add("node_2")
        engine.authorized_admins.add("node_3")
        
        # 5. Execution attempt must still raise PermissionError via base-class dictionary inspection
        with self.assertRaises(PermissionError):
            engine.execute_critical_operation_mpa(required_count=2)

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
