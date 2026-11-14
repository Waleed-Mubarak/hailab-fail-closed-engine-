import time
import multiprocessing
import os
import signal
import resource
import ctypes
import pytest

try:
    multiprocessing.set_start_method('spawn', force=True)
except RuntimeError:
    pass

from src.scope_b.engine import (
    worker_process_target,
    watchdog_process_target,
    install_strict_seccomp,
    libc,
    MCL_CURRENT,
    MCL_FUTURE,
)


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
        if isinstance(msg, dict) and "ERROR" in msg:
            pytest.fail(f"CRITICAL: Worker crashed with exception:\n{msg['ERROR']}")
        
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
                    if len(parts) > 1 and all(c == '0' for c in parts[1]) and len(parts[1]) >= 16:
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

        time.sleep(1.2)
        assert p.is_alive(), "CRITICAL: Worker died prematurely after initialization."

        for _ in range(2):
            parent_conn.send("PING")
            assert parent_conn.poll(timeout=3.0), "CRITICAL: Worker did not respond to PING."
            reply = parent_conn.recv()
            assert reply == "PONG", f"Expected 'PONG', got {reply}"

        parent_conn.send("EXIT")
        p.join(timeout=3.0)
        assert not p.is_alive(), "CRITICAL: Worker process did not exit after EXIT."
        assert p.exitcode == 0, f"Expected clean exit code 0, got {p.exitcode}"

    finally:
        if p.is_alive():
            p.terminate()
            p.join()


def test_scope_b_01_zeroization_lifecycle():
    parent_conn, worker_conn = multiprocessing.Pipe()
    p = multiprocessing.Process(target=worker_process_target, args=(worker_conn,))
    p.start()
    
    try:
        assert parent_conn.poll(timeout=5.0), "CRITICAL: Worker failed to start"
        assert parent_conn.recv() == "READY"

        parent_conn.send("COMPUTE")
        assert parent_conn.poll(timeout=2.0), "CRITICAL: Worker did not respond to COMPUTE."
        resp = parent_conn.recv()
        assert isinstance(resp, dict) and resp.get("STATUS") == "OK", f"Compute failed before zeroization: {resp}"

        parent_conn.send("MALFORMED_COMMAND")
        assert parent_conn.poll(timeout=2.0)
        assert parent_conn.recv() == "OPERATION_REFUSED"

        parent_conn.send("ZEROIZE")
        assert parent_conn.poll(timeout=2.0)
        assert parent_conn.recv() == "OK_ZEROIZED"

        parent_conn.send("COMPUTE")
        assert parent_conn.poll(timeout=2.0)
        assert parent_conn.recv() == "OPERATION_REFUSED"

        parent_conn.send("PING")
        assert parent_conn.poll(timeout=2.0)
        assert parent_conn.recv() == "OPERATION_REFUSED"

        parent_conn.send("EXIT")
        p.join(timeout=3.0)
        assert p.exitcode == 0

    finally:
        if p.is_alive():
            p.terminate()
            p.join()


def test_scope_b_02_mem_access_denied():
    parent_conn, worker_conn = multiprocessing.Pipe()
    p = multiprocessing.Process(target=worker_process_target, args=(worker_conn,))
    p.start()
    
    try:
        assert parent_conn.poll(timeout=5.0)
        assert parent_conn.recv() == "READY"
        
        pid = p.pid
        mem_path = f"/proc/{pid}/mem"
        
        access_denied = False
        try:
            with open(mem_path, "rb") as mem_file:
                mem_file.read(100)
        except (PermissionError, OSError):
            access_denied = True

        assert access_denied, "CRITICAL: Successfully read /proc/<pid>/mem of isolated worker! Dump isolation failed (B-02)."

        parent_conn.send("EXIT")
        p.join(timeout=3.0)
        assert p.exitcode == 0
    finally:
        if p.is_alive():
            p.terminate()
            p.join()


def prohibited_syscall_worker(pipe_conn):
    pipe_conn.send("READY_SECCOMP")
    install_strict_seccomp()
    libc.syscall(9999)


def test_seccomp_sigsys_kill():
    parent_conn, worker_conn = multiprocessing.Pipe()
    p = multiprocessing.Process(target=prohibited_syscall_worker, args=(worker_conn,))
    p.start()
    
    try:
        assert parent_conn.poll(timeout=5.0), "CRITICAL: Seccomp worker failed to ready."
        msg = parent_conn.recv()
        assert msg == "READY_SECCOMP"
        
        p.join(timeout=3.0)
        assert not p.is_alive(), "CRITICAL: Worker survived the prohibited system call!"
        assert p.exitcode == -signal.SIGSYS, f"Expected exit code {-signal.SIGSYS} (-31), got {p.exitcode}"
    finally:
        if p.is_alive():
            p.terminate()
            p.join()


def mlockall_failure_worker(pipe_conn):
    try:
        resource.setrlimit(resource.RLIMIT_MEMLOCK, (0, 0))
        os.setgroups([])
        os.setgid(65534)
        os.setuid(65534)
        
        if libc.mlockall(MCL_CURRENT | MCL_FUTURE) != 0:
            err = ctypes.get_errno()
            raise RuntimeError(f"CRITICAL: mlockall failed strictly with errno {err}")
        pipe_conn.send("READY")
    except Exception as e:
        import sys as _sys
        try:
            pipe_conn.send({"ERROR": str(e)})
        except Exception:
            pass
        _sys.exit(77)


def test_mlockall_failure():
    parent_conn, worker_conn = multiprocessing.Pipe()
    p = multiprocessing.Process(target=mlockall_failure_worker, args=(worker_conn,))
    p.start()
    
    try:
        has_data = parent_conn.poll(timeout=2.0)
        if has_data:
            msg = parent_conn.recv()
            if msg == "READY":
                pytest.fail("CRITICAL: Worker unexpectedly succeeded mlockall without CAP_IPC_LOCK!")
        
        p.join(timeout=3.0)
        assert not p.is_alive(), "CRITICAL: Worker process did not exit after mlockall failure."
        assert p.exitcode != 0, f"Expected non-zero exit code, got {p.exitcode}"
    finally:
        if p.is_alive():
            p.terminate()
            p.join()


def _parent_spawner_for_pdeathsig(child_pid_conn):
    _, worker_conn = multiprocessing.Pipe()
    w = multiprocessing.Process(target=worker_process_target, args=(worker_conn,))
    w.start()
    child_pid_conn.send(w.pid)
    time.sleep(10)


def test_worker_process_unexpected_termination():
    """REQ-SCOPE-B-04: التحقق من أن PR_SET_PDEATHSIG يقتل العامل فوراً بـ SIGKILL عند موت العملية الأب."""
    parent_info_conn, child_info_conn = multiprocessing.Pipe()
    intermediate_parent = multiprocessing.Process(target=_parent_spawner_for_pdeathsig, args=(child_info_conn,))
    intermediate_parent.start()
    
    worker_pid = None
    try:
        assert parent_info_conn.poll(timeout=5.0), "Failed to receive worker PID"
        worker_pid = parent_info_conn.recv()
        time.sleep(0.5)

        # قتل العملية الأبوية الوسيطة فجأة بـ SIGKILL
        os.kill(intermediate_parent.pid, signal.SIGKILL)
        intermediate_parent.join(timeout=3.0)

        # التحقق من أن العامل الفرعي قد قُتل تلقائياً بواسطة النواة (PR_SET_PDEATHSIG)
        time.sleep(0.3)
        worker_alive = True
        try:
            os.kill(worker_pid, 0)
        except OSError:
            worker_alive = False

        assert not worker_alive, f"CRITICAL: Worker (PID {worker_pid}) survived parent death!"
    finally:
        if intermediate_parent.is_alive():
            intermediate_parent.terminate()
            intermediate_parent.join()
        if worker_pid:
            try:
                os.kill(worker_pid, signal.SIGKILL)
            except OSError:
                pass


def test_scope_b_07_watchdog_monitoring():
    """REQ-SCOPE-B-07: اختبار عملية المراقبة المستقلة Watchdog واكتشافها لموت أو توقف العامل."""
    parent_conn, worker_conn = multiprocessing.Pipe()
    w = multiprocessing.Process(target=worker_process_target, args=(worker_conn,))
    w.start()
    
    wd_alert_parent, wd_alert_child = multiprocessing.Pipe()
    wd = None
    try:
        assert parent_conn.poll(timeout=5.0)
        assert parent_conn.recv() == "READY"

        wd = multiprocessing.Process(
            target=watchdog_process_target,
            args=(w.pid, parent_conn, wd_alert_child, 0.2),
        )
        wd.start()

        # السماح للـ Watchdog بإجراء عدة دورات فحص PING/PONG ناجحة
        time.sleep(0.7)
        assert wd.is_alive(), "CRITICAL: Watchdog died unexpectedly while worker is healthy."

        # إيقاف المراقب بأمان ثم إغلاق العامل
        wd_alert_parent.send("STOP_WATCHDOG")
        assert wd_alert_parent.poll(timeout=2.0)
        assert wd_alert_parent.recv() == "WATCHDOG_STOPPED"
        wd.join(timeout=2.0)

        parent_conn.send("EXIT")
        w.join(timeout=3.0)
        assert w.exitcode == 0
    finally:
        if wd and wd.is_alive():
            wd.terminate()
            wd.join()
        if w.is_alive():
            w.terminate()
            w.join()
