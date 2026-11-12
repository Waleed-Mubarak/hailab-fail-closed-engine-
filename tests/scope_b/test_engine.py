import time
import multiprocessing
import os
import signal
import pytest
from src.scope_b.engine import ScopeBEngine, worker_process_target, worker_process_target_failing, install_strict_seccomp, libc

def test_scope_b_kernel_state_enforcement():
    parent_conn, worker_conn = multiprocessing.Pipe()
    p = multiprocessing.Process(target=worker_process_target, args=(worker_conn, 65534, 65534))
    p.start()
    
    try:
        assert p.is_alive(), "CRITICAL: Worker process died during initialization!"
        
        if not parent_conn.poll(timeout=5.0):
            p.terminate()
            p.join()
            pytest.fail("CRITICAL: Worker failed to signal READY within timeout (Fail-Closed enforced).")
        
        msg = parent_conn.recv()
        assert msg == "READY", f"Expected 'READY', got {msg}"

        pid = p.pid
        status_path = f"/proc/{pid}/status"
        
        uid_val = ""
        cap_eff_val = ""
        cap_bnd_val = ""
        no_new_privs_val = ""
        seccomp_val = ""
        
        with open(status_path, "r") as f:
            for line in f:
                if line.startswith("Uid:"):
                    uid_val = line.strip()
                elif line.startswith("CapEff:"):
                    cap_eff_val = line.strip()
                elif line.startswith("CapBnd:"):
                    cap_bnd_val = line.strip()
                elif line.startswith("NoNewPrivs:"):
                    no_new_privs_val = line.strip()
                elif line.startswith("Seccomp:"):
                    seccomp_val = line.strip()

        assert "65534" in uid_val, f"CRITICAL: UID mismatch. Got: {uid_val}"
        assert "0000000000000000" in cap_eff_val, f"CRITICAL: CapEff not zero. Got: {cap_eff_val}"
        assert all(c == '0' for c in cap_bnd_val.split()[1]), f"CRITICAL: CapBnd not zero. Got: {cap_bnd_val}"
        assert no_new_privs_val.endswith("1"), f"CRITICAL: NoNewPrivs not 1. Got: {no_new_privs_val}"
        assert seccomp_val.endswith("2"), f"CRITICAL: Seccomp not 2. Got: {seccomp_val}"

        parent_conn.send("PING")
        assert parent_conn.poll(timeout=3.0), "CRITICAL: Worker did not respond to PING."
        reply = parent_conn.recv()
        assert reply == "PONG", f"Expected 'PONG', got {reply}"

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
    def prohibited_syscall_worker(pipe_conn):
        install_strict_seccomp()
        pipe_conn.send("READY_SECCOMP")
        libc.syscall(9999)

    parent_conn, worker_conn = multiprocessing.Pipe()
    p = multiprocessing.Process(target=prohibited_syscall_worker, args=(worker_conn,))
    p.start()
    
    try:
        assert parent_conn.poll(timeout=3.0), "CRITICAL: Seccomp worker failed to ready."
        parent_conn.recv()
        
        p.join(timeout=3.0)
        assert not p.is_alive(), "CRITICAL: Worker survived the prohibited system call!"
        assert p.exitcode == -signal.SIGSYS, f"Expected exit code {-signal.SIGSYS} (-31), got {p.exitcode}"
    finally:
        if p.is_alive():
            p.terminate()
            p.join()


def test_mlockall_fail_closed_behavior():
    parent_conn, worker_conn = multiprocessing.Pipe()
    # استخدام الدالة المخصصة للفشل حصرياً
    p = multiprocessing.Process(target=worker_process_target_failing, args=(worker_conn,))
    p.start()
    
    try:
        ready_received = parent_conn.poll(timeout=2.0)
        assert not ready_received, "CRITICAL: Worker sent READY despite mlockall failure (Fail-Open violation!)"
        
        p.join(timeout=2.0)
        assert not p.is_alive(), "CRITICAL: Worker process is still alive after failure."
        assert p.exitcode != 0, f"Expected non-zero exit code on failure, got {p.exitcode}"
    finally:
        if p.is_alive():
            p.terminate()
            p.join()
