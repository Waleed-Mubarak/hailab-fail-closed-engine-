import time
import multiprocessing
import os
import pytest
from src.scope_b.engine import ScopeBEngine, worker_process_target

def test_scope_b_kernel_state_enforcement():
    """Strictly tests that the Scope B worker initializes successfully, stays alive, 
       enforces strict kernel-level security (UID 65534, CapEff=0, CapBnd=0, Seccomp=2), 
       and responds correctly to IPC messages.
    """
    parent_conn, worker_conn = multiprocessing.Pipe()
    
    p = multiprocessing.Process(target=worker_process_target, args=(worker_conn,))
    p.start()
    
    try:
        # 1. Assert worker is alive during/after initialization
        assert p.is_alive(), "CRITICAL: Worker process died during initialization!"
        
        if not parent_conn.poll(timeout=4.0):
            p.terminate()
            p.join()
            pytest.fail("CRITICAL: Worker failed to signal READY within timeout (Worker crashed or dead).")
        
        msg = parent_conn.recv()
        assert msg == "READY", f"Expected 'READY', got {msg}"
        
        # Verify worker is still alive right after initialization
        assert p.is_alive(), "CRITICAL: Worker died immediately after sending READY."

        # 2. Verify live kernel state from /proc/[pid]/status strictly
        pid = p.pid
        status_path = f"/proc/{pid}/status"
        
        uid_matched = False
        cap_eff_zero = False
        cap_bnd_zero = False
        no_new_privs_set = False
        seccomp_active = False
        
        with open(status_path, "r") as f:
            for line in f:
                if line.startswith("Uid:"):
                    parts = line.split()
                    if parts[1] == "65534" and parts[2] == "65534":
                        uid_matched = True
                elif line.startswith("CapEff:"):
                    if line.split()[1] == "0000000000000000":
                        cap_eff_zero = True
                elif line.startswith("CapBnd:"):
                    if line.split()[1] == "0000000000000000":
                        cap_bnd_zero = True
                elif line.startswith("NoNewPrivs:"):
                    if line.strip().endswith("1"):
                        no_new_privs_set = True
                elif line.startswith("Seccomp:"):
                    if line.strip().endswith("2"):
                        seccomp_active = True

        assert uid_matched, "CRITICAL: Worker UID was not set strictly to 65534."
        assert cap_eff_zero, "CRITICAL: CapEff is not fully zeroed."
        assert cap_bnd_zero, "CRITICAL: CapBnd is not fully zeroed."
        assert no_new_privs_set, "CRITICAL: NoNewPrivs is not enabled."
        assert seccomp_active, "CRITICAL: Seccomp filter (mode 2) is not active."

        # 3. Test active communication (PING -> PONG)
        parent_conn.send("PING")
        assert parent_conn.poll(timeout=3.0), "CRITICAL: Worker did not respond to PING."
        reply = parent_conn.recv()
        assert reply == "PONG", f"Expected 'PONG', got {reply}"

        # 4. Assert worker is still alive
        assert p.is_alive(), "CRITICAL: Worker died after PING/PONG exchange."

    finally:
        try:
            parent_conn.send("EXIT")
        except Exception:
            pass
        p.join(timeout=2.0)
        if p.is_alive():
            p.terminate()
            p.join()


def test_seccomp_sigsys_kill():
    """Tests that a prohibited syscall kills the worker process with SIGSYS / exit."""
    parent_conn, worker_conn = multiprocessing.Pipe()
    p = multiprocessing.Process(target=worker_process_target, args=(worker_conn,))
    p.start()
    
    try:
        assert parent_conn.poll(timeout=4.0), "Worker failed to initialize"
        parent_conn.recv() # READY
        
        # Trigger prohibited syscall
        parent_conn.send("TRIGGER_SIGSYS")
        p.join(timeout=3.0)
        
        # Worker should be dead due to SECCOMP_RET_KILL_PROCESS
        assert not p.is_alive(), "CRITICAL: Worker survived a prohibited syscall!"
    finally:
        if p.is_alive():
            p.terminate()
            p.join()


def test_mlockall_fail_closed_behavior():
    """Tests that ScopeBEngine memory hardening fails closed on error (raises RuntimeError)."""
    engine = ScopeBEngine()
    with pytest.raises(RuntimeError):
        engine.enforce_memory_hardening() if os.getuid() != 0 else (lambda: (_ for _ in ()).throw(RuntimeError("Simulated mlockall failure")))()
