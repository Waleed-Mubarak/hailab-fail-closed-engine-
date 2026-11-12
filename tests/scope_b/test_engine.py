import time
import multiprocessing
import os
import signal
import pytest
from src.scope_b.engine import ScopeBEngine, worker_process_target

def test_scope_b_kernel_state_enforcement():
    """Strictly tests that the Scope B worker initializes successfully, stays alive, 
       and enforces strict kernel-level security (UID 65534, CapEff=0, CapBnd=0, Seccomp=2).
    """
    parent_conn, worker_conn = multiprocessing.Pipe()
    
    p = multiprocessing.Process(target=worker_process_target, args=(worker_conn,))
    p.start()
    
    try:
        assert p.is_alive(), "CRITICAL: Worker process died during initialization!"
        
        if not parent_conn.poll(timeout=4.0):
            p.terminate()
            p.join()
            pytest.fail("CRITICAL: Worker failed to signal READY within timeout.")
        
        msg = parent_conn.recv()
        assert msg == "READY", f"Expected 'READY', got {msg}"
        assert p.is_alive(), "CRITICAL: Worker died immediately after sending READY."

        # Verify live kernel state from /proc/[pid]/status strictly
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
                    # فحص صارم لـ CapBnd للتأكد من أنها صفرية تماماً كما طلب د. حكمت
                    parts = line.split()
                    if len(parts) > 1 and all(c == '0' for c in parts[1]):
                        cap_bnd_zero = True
                elif line.startswith("NoNewPrivs:"):
                    if line.strip().endswith("1"):
                        no_new_privs_set = True
                elif line.startswith("Seccomp:"):
                    if line.strip().endswith("2"):
                        seccomp_active = True

        # تمت إزالة التجاوز الوهمي (if not uid_matched: uid_matched = True) تماماً لتصبح الصارمة إلزامية
        assert uid_matched, "CRITICAL: Worker UID was not set strictly to 65534."
        assert cap_eff_zero, "CRITICAL: CapEff is not fully zeroed."
        assert cap_bnd_zero, "CRITICAL: CapBnd is not fully zeroed."
        assert no_new_privs_set, "CRITICAL: NoNewPrivs is not enabled."
        assert seccomp_active, "CRITICAL: Seccomp filter (mode 2) is not active."

        # Test active communication (PING -> PONG)
        parent_conn.send("PING")
        assert parent_conn.poll(timeout=3.0), "CRITICAL: Worker did not respond to PING."
        reply = parent_conn.recv()
        assert reply == "PONG", f"Expected 'PONG', got {reply}"

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
    """Tests that a prohibited syscall kills the worker process with SIGSYS (exit code -31)."""
    parent_conn, worker_conn = multiprocessing.Pipe()
    
    # تمرير متغير بيئي لتفعيل أمر اختبار الحظر (TRIGGER_SIGSYS) في بيئة الآمان للاختبار فقط دون وضعه في الكود الأساسي للإنتاج
    os.environ["ENABLE_TEST_HOOKS"] = "1"
    
    p = multiprocessing.Process(target=worker_process_target, args=(worker_conn,))
    p.start()
    
    try:
        assert parent_conn.poll(timeout=4.0), "Worker failed to initialize"
        parent_conn.recv()
        
        parent_conn.send("TRIGGER_SIGSYS")
        p.join(timeout=3.0)
        
        assert not p.is_alive(), "CRITICAL: Worker survived a prohibited syscall!"
        # التحقق بدقة من أن الـ exitcode يطابق -SIGSYS (-31) كما طلب د. حكمت
        assert p.exitcode == -signal.SIGSYS, f"Expected exit code {-signal.SIGSYS} (-31), got {p.exitcode}"
    finally:
        os.environ.pop("ENABLE_TEST_HOOKS", None)
        if p.is_alive():
            p.terminate()
            p.join()


def test_mlockall_fail_closed_behavior():
    """Tests that Scope B worker fails closed on mlockall/initialization error (exits without sending READY)."""
    parent_conn, worker_conn = multiprocessing.Pipe()
    
    # محاكاة فشل mlockall لإجبار العامل على الانهيار (Fail-Closed) دون إرسال READY
    os.environ["SIMULATE_MLOCKALL_FAILURE"] = "1"
    
    p = multiprocessing.Process(target=worker_process_target, args=(worker_conn,))
    p.start()
    
    try:
        # التأكد من أن العامل لم يرسل READY وانهار بالكامل
        ready_received = parent_conn.poll(timeout=2.0)
        assert not ready_received, "CRITICAL: Worker sent READY despite mlockall failure (Fail-Open violation!)"
        
        p.join(timeout=2.0)
        assert not p.is_alive(), "CRITICAL: Worker process is still alive after initialization failure."
        assert p.exitcode != 0, f"Expected non-zero exit code on failure, got {p.exitcode}"
    finally:
        os.environ.pop("SIMULATE_MLOCKALL_FAILURE", None)
        if p.is_alive():
            p.terminate()
            p.join()
