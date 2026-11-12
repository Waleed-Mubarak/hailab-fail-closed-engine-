import time
import multiprocessing
import os
import signal
import pytest
from src.scope_b.engine import ScopeBEngine, worker_process_target, install_strict_seccomp, libc

def test_scope_b_kernel_state_enforcement():
    parent_conn, worker_conn = multiprocessing.Pipe()
    p = multiprocessing.Process(target=worker_process_target, args=(worker_conn,))
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
        
        uid_matched = False
        cap_eff_zero = False
        cap_bnd_zero = False
        no_new_privs_set = False
        seccomp_active = False
        
        with open(status_path, "r") as f:
            for line in f:
                if line.startswith("Uid:"):
                    parts = line.split()
                    if len(parts) > 2 and parts[1] == "65534" and parts[2] == "65534":
                        uid_matched = True
                elif line.startswith("CapEff:"):
                    if line.split()[1] == "0000000000000000":
                        cap_eff_zero = True
                elif line.startswith("CapBnd:"):
                    parts = line.split()
                    if len(parts) > 1 and all(c == '0' for c in parts[1]):
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
    """اختبار أن استدعاء نظام محظور يُنهي العملية بـ SIGSYS وكود الخروج -31 بدقة"""
    def prohibited_syscall_worker(pipe_conn):
        install_strict_seccomp()
        pipe_conn.send("READY_SECCOMP")
        # استدعاء نظام محظور غير موجود (9999) لتقوم النواة بقتل العملية فوراً بـ SIGSYS (-31)
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
    
    os.environ["SIMULATE_MLOCKALL_FAILURE"] = "1"
    p = multiprocessing.Process(target=worker_process_target, args=(worker_conn,))
    p.start()
    
    try:
        ready_received = parent_conn.poll(timeout=2.0)
        assert not ready_received, "CRITICAL: Worker sent READY despite mlockall failure (Fail-Open violation!)"
        
        p.join(timeout=2.0)
        assert not p.is_alive(), "CRITICAL: Worker process is still alive after failure."
        assert p.exitcode != 0, f"Expected non-zero exit code on failure, got {p.exitcode}"
    finally:
        os.environ.pop("SIMULATE_MLOCKALL_FAILURE", None)
        if p.is_alive():
            p.terminate()
            p.join()
