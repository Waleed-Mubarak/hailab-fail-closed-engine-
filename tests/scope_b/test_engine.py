import os
import time
import pytest
import multiprocessing
from src.scope_b.engine import ScopeBEngine, worker_process_target


def read_proc_status(pid):
    """Parses /proc/<pid>/status to extract kernel-level state attributes."""
    status_data = {}
    try:
        with open(f"/proc/{pid}/status", "r") as f:
            for line in f:
                parts = line.split(":", 1)
                if len(parts) == 2:
                    status_data[parts[0].strip()] = parts[1].strip()
    except FileNotFoundError:
        pass
    return status_data


def test_scope_b_kernel_state_enforcement():
    """Verifies actual kernel states via /proc/<pid>/status for the worker process
    in strict alignment with Dr. Hikmet's requirements (Uid, CapEff, CapBnd, NoNewPrivs).
    """
    parent_conn, child_conn = multiprocessing.Pipe()
    
    # Start worker process
    p = multiprocessing.Process(target=worker_process_target, args=(child_conn,))
    p.start()
    
    try:
        # Give a brief moment for the worker to initialize its strict security posture
        time.sleep(0.5)
        worker_pid = p.pid
        
        # Read kernel status of the worker process directly from /proc
        status = read_proc_status(worker_pid)
        assert status, f"Failed to read /proc/{worker_pid}/status"
        
        # 1. Verify UID has dropped to the dedicated restricted user (e.g., 65534 / nobody)
        uid_line = status.get("Uid", "")
        uids = [int(x) for x in uid_line.split() if x.isdigit()]
        assert len(uids) >= 1, "Uid line malformed in /proc status"
        # Real-world check: worker should have dropped privileges (UID != 0 or matches target_uid 65534)
        assert uids[0] == 65534 or uids[0] != 0, f"Worker failed to drop UID, current Uid: {uid_line}"

        # 2. Verify Capabilities are dropped (CapEff and CapBnd must be zeroized)
        cap_eff = status.get("CapEff", "0")
        cap_bnd = status.get("CapBnd", "0")
        
        # Convert hex strings from proc to integers for strict comparison
        assert int(cap_eff, 16) == 0, f"CapEff is not zeroed: {cap_eff}"
        assert int(cap_bnd, 16) == 0, f"CapBnd is not zeroed: {cap_bnd}"

        # 3. Verify NoNewPrivs is set to 1
        no_new_privs = status.get("NoNewPrivs", "0")
        assert no_new_privs == "1", f"NoNewPrivs is not enabled, got: {no_new_privs}"

        # Test communication flow (PING/PONG)
        parent_conn.send("PING")
        response = parent_conn.recv()
        assert response == "PONG"

        # Clean shutdown
        parent_conn.send("EXIT")
        p.join(timeout=2)
        
    finally:
        if p.is_alive():
            p.terminate()
            p.join()


def test_mlockall_fail_closed_behavior(monkeypatch):
    """Verifies that engine halts startup (raises RuntimeError) if mlockall fails."""
    engine = ScopeBEngine()
    
    # Mock libc.mlockall to simulate a hard kernel failure (returns -1)
    import src.scope_b.engine as eng_module
    monkeypatch.setattr(eng_module.libc, "mlockall", lambda flags: -1)
    
    # Verify fail-closed behavior: engine must raise RuntimeError and halt startup
    with pytest.raises(RuntimeError, match="CRITICAL: mlockall failed"):
        engine.enforce_memory_hardening()
