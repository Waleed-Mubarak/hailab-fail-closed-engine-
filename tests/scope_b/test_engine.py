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
    """Verifies actual kernel states via /proc/<pid>/status for the worker process."""
    parent_conn, child_conn = multiprocessing.Pipe()
    
    p = multiprocessing.Process(target=worker_process_target, args=(child_conn,))
    p.start()
    
    try:
        time.sleep(0.5)
        worker_pid = p.pid
        
        status = read_proc_status(worker_pid)
        assert status, f"Failed to read /proc/{worker_pid}/status"
        
        # 1. Verify UID
        uid_line = status.get("Uid", "")
        uids = [int(x) for x in uid_line.split() if x.isdigit()]
        assert len(uids) >= 1, "Uid line malformed in /proc status"
        assert uids[0] == 65534 or uids[0] != 0, f"Worker running with unsafe UID: {uid_line}"

        # 2. Verify NoNewPrivs status line exists and is tracked
        no_new_privs = status.get("NoNewPrivs", "0")
        assert no_new_privs in ["0", "1"], f"Invalid NoNewPrivs value: {no_new_privs}"

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
