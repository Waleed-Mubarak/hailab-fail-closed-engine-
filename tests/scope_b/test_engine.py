"""
Real OS-level integration and unit tests for Scope B Engine (B1-B7).
Exercises actual kernel mechanisms, IPC channels, watchdog liveness, and fail-closed behavior.
"""

import pytest
import os
import time
from src.scope_b.engine import ScopeBEngine

def test_engine_initialization_and_isolation():
    """Tests B1, B2, B5, and B6: Engine initializes with real OS protections."""
    engine = ScopeBEngine()
    assert engine.isolated is True
    assert engine.enforce_process_isolation(pid=100) is True
    engine.zeroize_state()

def test_syscall_policy_validation():
    """Tests B3: Syscall policy enforcement under sandbox baseline."""
    engine = ScopeBEngine()
    
    # Allowed syscalls
    assert engine.validate_syscall_policy("read") is True
    assert engine.validate_syscall_policy("write") is True
    
    # Unauthorized syscall must trigger Fail-Closed
    with pytest.raises(RuntimeError, match="FAIL-CLOSED: Unauthorized syscall"):
        engine.validate_syscall_policy("ptrace_unauthorized_fake")
        
    engine.zeroize_state()

def test_watchdog_and_ipc_liveness():
    """Tests B4 & B7: Dedicated watchdog and live IPC process verification."""
    engine = ScopeBEngine()
    
    # Normal watchdog check
    assert engine.check_watchdog_signal(signal_active=True) is True
    
    # Watchdog signal lost
    with pytest.raises(RuntimeError, match="FAIL-CLOSED: Dedicated watchdog signal lost"):
        engine.check_watchdog_signal(signal_active=False)
        
    engine.zeroize_state()

def test_worker_process_unexpected_termination():
    """Tests B4: Watchdog detects and fails closed if the worker process dies unexpectedly."""
    engine = ScopeBEngine()
    
    # Kill the worker process forcefully from the test (simulating a crash or attack)
    if engine.worker_pid:
        try:
            os.kill(engine.worker_pid, 9)  # SIGKILL
            # Give a tiny moment for the OS to update process status
            time.sleep(0.1)
        except ProcessLookupError:
            pass
            
    # Watchdog check must now catch the dead worker and raise FAIL-CLOSED
    with pytest.raises(RuntimeError, match="FAIL-CLOSED: Worker process"):
        engine.check_watchdog_signal(signal_active=True)
        
    engine.zeroize_state()

def test_zeroization_refusal():
    """Tests B1: Strict post-zeroization refusal mechanism."""
    engine = ScopeBEngine()
    engine.zeroize_state()
    
    with pytest.raises(RuntimeError):
        engine.enforce_process_isolation(pid=100)
        
    with pytest.raises(RuntimeError):
        engine.check_watchdog_signal(signal_active=True)
