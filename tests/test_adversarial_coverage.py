import pytest
import ctypes
from src.security_kernel import (
    SecureRegistrySet,
    ZeroizationKernel,
    ProductionPanicHandler,
    LockedRegistryMeta,
    verify_and_integrate
)

# --- E-02 / E-03 Tests ---
def test_e02_prevent_direct_attribute_tampering():
    s_set = SecureRegistrySet(["op1"])
    s_set.seal()
    
    # Attempt direct attribute modification via standard assignment
    with pytest.raises(PermissionError, match="E-02/E-03 Violation"):
        s_set._entries = set()

    # Attempt attribute tampering via object.__setattr__
    with pytest.raises(PermissionError, match="E-02/E-03 Violation"):
        object.__setattr__(s_set, "_entries", set())


def test_e03_terminal_state_lockdown():
    s_set = SecureRegistrySet(["op1"])
    ZeroizationKernel.force_zeroize_all()

    # Ensure no operations are accepted after zeroization
    with pytest.raises(PermissionError, match="E-03 Violation"):
        s_set.register("op2")

    with pytest.raises(SystemExit) as exc_info:
        verify_and_integrate("op3", s_set)
    assert exc_info.value.code == 101


# --- E-05 Tests ---
def test_e05_raw_memory_zeroization():
    buf = ctypes.create_string_buffer(b"SECRET_KEY_12345")
    ptr = ctypes.addressof(buf)
    
    # Verify buffer holds content
    assert buf.value == b"SECRET_KEY_12345"
    
    # Zeroize memory
    ZeroizationKernel.zeroize_buffer(ptr, len(buf))
    assert buf.value == b""


# --- E-06 Tests ---
def test_e06_production_panic_handler():
    with pytest.raises(SystemExit) as exc:
        ProductionPanicHandler.trigger_panic("Test Fault Injection")
    assert exc.value.code == 101
