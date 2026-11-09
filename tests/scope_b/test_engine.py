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
    """Verifies actual kernel states via /proc/<pid>/status for the worker process (REQ-SCOPE-B-05, REQ-SCOPE-B-03)."""
    parent_conn, child_conn = multiprocessing.Pipe()
    
    p = multiprocessing.Process(target=worker_process_target, args=(child_conn,))
    p.start()
    
    try:
        time.sleep(0.5)
        worker_pid = p.pid
        
        status = read_proc_status(worker_pid)
        assert status, f"Failed to read /proc/{worker_pid}/status"
        
        # 1. Verify UID / GID isolation (REQ-SCOPE-B-02)
        # Handle both Root environment (expects 65534) and CI non-root environment (expects non-zero unprivileged UID)
        uid_line = status.get("Uid", "")
        uids = [int(x) for x in uid_line.split() if x.isdigit()]
        assert len(uids) >= 1, "Uid line malformed in /proc status"
        
        if os.getuid() == 0:
            assert uids[0] == 65534, f"Worker running with unsafe UID in root mode: {uid_line}"
        else:
            assert uids[0] != 0, f"Worker running with root UID in unprivileged environment: {uid_line}"

        # 2. Verify Capabilities are fully dropped (CapEff and CapBnd = 0) (REQ-SCOPE-B-05)
        cap_eff = status.get("CapEff", "0000000000000000")
        cap_bnd = status.get("CapBnd", "0000000000000000")
        
        assert int(cap_eff, 16) == 0, f"Critical: CapEff is not zeroed: {cap_eff}"
        assert int(cap_bnd, 16) == 0, f"Critical: CapBnd is not zeroed: {cap_bnd}"

        # 3. Verify NoNewPrivs is active (= 1)
        no_new_privs = status.get("NoNewPrivs", "0")
        assert no_new_privs == "1", f"NoNewPrivs is not enforced: {no_new_privs}"

        # 4. Verify Seccomp filter status is active (> 0) (REQ-SCOPE-B-03)
        seccomp_status = status.get("Seccomp", "0")
        assert int(seccomp_status) > 0, f"Seccomp filter is not active: {seccomp_status}"

        # Clean shutdown sequence over pipe
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
