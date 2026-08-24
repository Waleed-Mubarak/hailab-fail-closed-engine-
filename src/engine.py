import pytest
from engine import FailClosedEngine

def test_p0_03_state_resurrection_via_object_setattr_is_blocked(engine_fixture=None):
    """
    P0-03 Regression Test (Requested by Dr. Hikmat Kerimov):
    Ensures that even if an attacker uses object.__setattr__ and modifies __dict__
    to restore is_zeroized=False, system_locked=False, and raw_memory,
    the operational paths remain dead and critical operations result in DENY.
    """
    engine = FailClosedEngine() if engine_fixture is None else engine_fixture
    
    # 1. Trigger zeroization
    engine.zeroize()
    
    # 2. Adversarial State Resurrection Attempt via object level
    try:
        object.__setattr__(engine, "_FailClosedEngine__is_zeroized", False)
        object.__setattr__(engine, "_FailClosedEngine__system_locked", False)
        engine.__dict__["_FailClosedEngine__raw_memory"] = {"restored": True}
    except Exception:
        pass

    # 3. Assert Admissibility fails
    assert engine.check_admissibility() is False

    # 4. Assert Critical Operation strictly DENIES and raises PermissionError
    with pytest.raises(PermissionError, match=r".*CRITICAL_BLOCK.*"):
        engine.execute_critical_operation(
            action="CRITICAL_TRANSFER",
            quorum=["node_1", "node_2", "node_3"]
        )
