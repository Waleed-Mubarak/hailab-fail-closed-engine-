import unittest
import pytest
from engine import FailClosedEngine, TurkashEngine

class TestTurkashEngineDescriptorAuditing(unittest.TestCase):
    
    def test_p0_03_stub_deletion_fallback_bypass_denies_operation(self):
        """
        P0-03 Regression Test:
        Ensures that restoring state flags AND deleting instance-level stubs
        does not allow fallback execution of base class methods.
        """
        engine = FailClosedEngine()
        engine.zeroize()
        
        # 1. Adversarial Flag Restoration via object.__setattr__
        object.__setattr__(engine, "_FailClosedEngine__is_zeroized", False)
        object.__setattr__(engine, "_FailClosedEngine__terminal_state_locked", False)
        
        # 2. Delete instance-level stub overrides from instance __dict__ if any exist
        engine.__dict__.pop("execute_critical_operation", None)
        engine.__dict__.pop("check_admissibility", None)
        
        # 3. Must still raise PermissionError on execution attempt due to base class dict inspection
        with pytest.raises(PermissionError, match=".*CRITICAL_BLOCK.*"):
            engine.execute_critical_operation(
                action="CRITICAL_TRANSFER",
                quorum=["node_1", "node_2", "node_3"]
            )

    def test_p0_04_zeroization_idempotence_invariance_z_squared_equals_z(self):
        engine = FailClosedEngine()
        
        engine.zeroize()
        snapshot_first = (
            engine.is_zeroized,
            engine.system_locked,
            engine.inspect_raw_memory_snapshot(),
            engine.secure_ram_key_status,
            len(engine.audit_trail)
        )
        
        engine.zeroize()
        snapshot_second = (
            engine.is_zeroized,
            engine.system_locked,
            engine.inspect_raw_memory_snapshot(),
            engine.secure_ram_key_status,
            len(engine.audit_trail)
        )
        
        self.assertEqual(snapshot_first[0], snapshot_second[0])
        self.assertEqual(snapshot_first[1], snapshot_second[1])
        self.assertEqual(snapshot_first[2], snapshot_second[2])
        self.assertEqual(snapshot_first[3], snapshot_second[3])

if __name__ == "__main__":
    unittest.main()
