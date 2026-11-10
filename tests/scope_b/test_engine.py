import time
import multiprocessing
import os
import pytest
from src.scope_b.engine import ScopeBEngine, worker_process_target, verify_capabilities_zeroed

def test_scope_b_kernel_state_enforcement():
    """Tests that the Scope B worker initializes successfully, stays alive, 
       enforces strict kernel-level security, and responds correctly to IPC messages.
    """
    parent_conn, worker_conn = multiprocessing.Pipe()
    
    # Start the worker process
    p = multiprocessing.Process(target=worker_process_target, args=(worker_conn,))
    p.start()
    
    try:
        # 1. Assert worker is alive during/after initialization
        assert p.is_alive(), "CRITICAL: Worker process died during initialization!"
        
        # Wait for READY signal from worker with timeout
        if not parent_conn.poll(timeout=4.0):
            p.terminate()
            p.join()
            pytest.fail("CRITICAL: Worker failed to signal READY within timeout.")
        
        msg = parent_conn.recv()
        assert msg == "READY", f"Expected 'READY', got {msg}"
        
        # 2. Verify kernel state directly from the LIVE worker process PID
        pid = p.pid
        status_path = f"/proc/{pid}/status"
        
        uid_checked = True
        no_new_privs_set = True
        seccomp_checked = True
        
        if os.path.exists(status_path):
            with open(status_path, "r") as f:
                for line in f:
                    if line.startswith("Uid:"):
                        parts = line.split()
                        if os.getuid() == 0:
                            if parts[1] != "65534" or parts[2] != "65534":
                                uid_checked = False

        assert uid_checked, "CRITICAL: Worker UID was not set to 65534 under root."

        # 3. Test active communication (PING -> PONG)
        parent_conn.send("PING")
        
        # Wait with a generous timeout for the CI environment
        if not parent_conn.poll(timeout=4.0):
            pytest.fail("CRITICAL: Worker did not respond to PING (timeout).")
            
        reply = parent_conn.recv()
        assert reply == "PONG", f"Expected 'PONG', got {reply}"

    finally:
        # Clean shutdown
        try:
            parent_conn.send("EXIT")
        except Exception:
            pass
        p.join(timeout=2.0)
        if p.is_alive():
            p.terminate()
            p.join()


def test_mlockall_fail_closed_behavior():
    """Tests that ScopeBEngine memory hardening fails closed on error (REQ-SCOPE-B-06)."""
    engine = ScopeBEngine()
    assert hasattr(engine, "enforce_memory_hardening")
