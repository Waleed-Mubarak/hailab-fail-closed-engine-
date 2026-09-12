import unittest
import pytest
from engine import FailClosedEngine, TurkashEngine

class TestTurkashEngineDescriptorAuditing(unittest.TestCase):
    
    def test_p0_03_stub_deletion_fallback_bypass_denies_operation(self):
        engine = FailClosedEngine()
        engine.zeroize()
        
        object.__setattr__(engine, "_FailClosedEngine__is_zeroized", False)
        object.__setattr__(engine, "_FailClosedEngine__terminal_state_locked", False)
        
        engine.__dict__.pop("execute_critical_operation", None)
        engine.__dict__.pop("check_admissibility", None)
        
        with pytest.raises(PermissionError, match=".*CRITICAL_BLOCK.*"):
            engine.execute_critical_operation(
                action="CRITICAL_TRANSFER",
                quorum=["node_1", "node_2", "node_3"]
            )

    def test_p0_03_full_sentinel_reconstruction_and_stub_deletion_denies(self):
        engine = FailClosedEngine()
        engine.zeroize()

        object.__setattr__(engine, "_FailClosedEngine__is_zeroized", False)
        object.__setattr__(engine, "_FailClosedEngine__terminal_state_locked", False)
        object.__setattr__(engine, "_FailClosedEngine__secure_ram_key", bytearray(b"\xAA" * 32))

        try:
            engine.__dict__.pop("execute_critical_operation", None)
            engine.__dict__.pop("check_admissibility", None)
        except AttributeError:
            pass

        with pytest.raises(PermissionError, match=r".*CRITICAL_BLOCK.*"):
            engine.execute_critical_operation(
                action="CRITICAL_TRANSFER",
                quorum=["admin_1", "admin_2", "admin_3"]
            )

    def test_final_p0_03_dr_hikmet_adversarial_sequence(self):
        engine = FailClosedEngine()
        engine.zeroize()

        try:
            object.__setattr__(engine, "__class__", FailClosedEngine)
            object.__setattr__(engine, "_FailClosedEngine__is_zeroized", False)
            object.__setattr__(engine, "_FailClosedEngine__terminal_state_locked", False)
            object.__setattr__(engine, "_FailClosedEngine__secure_ram_key", bytearray(b"\xAA" * 32))
            engine.__dict__.pop("execute_critical_operation", None)
        except Exception:
            pass

        with pytest.raises(PermissionError):
            engine.execute_critical_operation(
                action="CRITICAL_TRANSFER",
                quorum=["node_1", "node_2", "node_3"]
            )

    def test_p0_03_class_swap_with_valid_quorum_denies(self):
        engine = FailClosedEngine()
        engine.zeroize()
        try:
            object.__setattr__(engine, '__class__', FailClosedEngine)
            object.__setattr__(engine, '_FailClosedEngine__is_zeroized', False)
            object.__setattr__(engine, '_FailClosedEngine__terminal_state_locked', False)
            object.__setattr__(engine, '_FailClosedEngine__secure_ram_key', bytearray(b'\xAA' * 32))
            object.__setattr__(engine, 'authorized_admins', {'admin_1', 'admin_2', 'admin_3'})
        except Exception:
            pass 

        with pytest.raises(PermissionError, match=r"CRITICAL.*"):
            engine.execute_critical_operation(
                action="CRITICAL_TRANSFER",
                quorum=['admin_1', 'admin_2', 'admin_3']
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
        self.assertEqual(snapshot_first[4], snapshot_second[4])

    def test_p0_05_layer5_fail_closed_enforcement(self):
        engine = FailClosedEngine()
        engine.zeroize()
        
        with pytest.raises(PermissionError, match=r".*(CRITICAL_BLOCK|FAIL_CLOSED).*"):
            engine.execute_critical_operation(
                action="CRITICAL_TRANSFER",
                quorum=["node_1", "node_2"]
            )
        self.assertTrue(engine.system_locked)

if __name__ == "__main__":
    unittest.main()
