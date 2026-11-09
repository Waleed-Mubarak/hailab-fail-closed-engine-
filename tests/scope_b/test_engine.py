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
    in strict compliance with Dr. Hikmet's frozen baseline requirements.
    """
    parent_conn, child_conn = multiprocessing.Pipe()
    
    # Start worker process enforcing the strict frozen initialization order
    p = multiprocessing.Process(target=worker_process_target, args=(child_conn,))
    p.start()
    
    try:
        # Give a brief moment for the worker to initialize its strict security posture
        time.sleep(0.5)
        worker_pid = p.pid
        
        # Read kernel status of the worker process directly from /proc
        status = read_proc_status(worker_pid)
        assert status, f"Failed to read /proc/{worker_pid}/status"
        
        # 1. Verify UID has dropped strictly to the dedicated restricted user (65534 / nobody)
        uid_line = status.get("Uid", "")
        uids = [int(x) for x in uid_line.split() if x.isdigit()]
        assert len(uids) >= 1, "Uid line malformed in /proc status"
        assert uids[0] == 65534, f"Worker failed to drop UID to 65534 (nobody), current Uid: {uid_line}"

        # 2. Verify CapEff (Effective Capabilities) is completely zeroized
        cap_eff = status.get("CapEff", "0")
        assert int(cap_eff, 16) == 0, f"CapEff is not zeroed: {cap_eff}"

        # 3. Verify NoNewPrivs is strictly set to 1
        no_new_privs = status.get("NoNewPrivs", "0")
        assert no_new_privs == "1", f"NoNewPrivs is not enabled, got: {no_new_privs}"

        # Safe non-blocking communication test
        try:
            if parent_conn.poll(timeout=1.0):
                parent_conn.send("PING")
                if parent_conn.poll(timeout=1.0):
                    parent_conn.recv()
            parent_conn.send("EXIT")
        except Exception:
            pass
            
        p.join(timeout=1.0)
        
    finally:
        if p.is_alive():
            p.terminate()
            p.join(timeout=1.0)
        try:
            parent_conn.close()
            child_conn.close()
        except Exception:
            pass


def test_mlockall_fail_closed_behavior(monkeypatch):
    """Verifies that engine halts startup (raises RuntimeError) if mlockall fails (REQ-SCOPE-B-06)."""
    engine = ScopeBEngine()
    import src.scope_b.engine as eng_module
    monkeypatch.setattr(eng_module.libc, "mlockall", lambda flags: -1)
    
    with pytest.raises(RuntimeError, match="CRITICAL: mlockall failed"):
        engine.enforce_memory_hardening()
