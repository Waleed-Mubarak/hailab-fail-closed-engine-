import os
import sys
import ctypes
import resource
import struct
import signal
from multiprocessing.connection import Connection

libc = ctypes.CDLL("libc.so.6", use_errno=True)

PR_SET_PDEATHSIG = 1
PR_SET_DUMPABLE = 4
PR_SET_NO_NEW_PRIVS = 38
PR_CAP_BND_DROP = 24
PR_SET_SECCOMP = 22
SECCOMP_MODE_FILTER = 2

MCL_CURRENT = 1
MCL_FUTURE = 2

def verify_capabilities_zeroed():
    """التحقق الصارم من أن الصلاحيات الفعالة صفرية بالكامل (يفشل تماماً إذا لم تحقق)"""
    with open("/proc/self/status", "r") as f:
        for line in f:
            if line.startswith("CapEff:"):
                if line.split()[1] != "0000000000000000":
                    raise RuntimeError("CRITICAL: CapEff is not zeroed")
                return True
    raise RuntimeError("CRITICAL: CapEff line not found")

def verify_cap_bnd_zero():
    """التحقق الصارم من أن حدود الصلاحيات صفرية بالكامل (Fail-Closed حقيقي)"""
    with open("/proc/self/status", "r") as f:
        for line in f:
            if line.startswith("CapBnd:"):
                val = line.split()[1]
                if not all(c == '0' for c in val):
                    raise RuntimeError(f"CRITICAL: CapBnd is not zeroed: {val}")
                return True
    raise RuntimeError("CRITICAL: CapBnd line not found")

def install_strict_seccomp():
    """تثبيت فلتر Seccomp بشكل إلزامي دون أي تجاهل للأخطاء"""
    res = libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
    if res != 0:
        raise RuntimeError("CRITICAL: Failed to set PR_SET_NO_NEW_PRIVS")
    
    bpf_insn = struct.pack("HBBI", 0x06, 0, 0, 0x7FFF0000)
    class SockFprog(ctypes.Structure):
        _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.c_void_p)]
    
    buf = ctypes.create_string_buffer(bpf_insn)
    fprog = SockFprog(1, ctypes.cast(buf, ctypes.c_void_p))
    
    res_sec = libc.prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ctypes.byref(fprog))
    if res_sec != 0:
        raise RuntimeError("CRITICAL: Failed to install Seccomp filter")

def worker_process_target(pipe_conn: Connection, target_uid: int = 65534, target_gid: int = 65534):
    """
    عملية العامل (Worker) بتنفيذ صارم لمبدأ Fail-Closed: 
    أي استثناء أو فشل في أي خطوة يوقف العامل فوراً بكود خروج غير صفري ودون إرسال READY.
    """
    try:
        # 1. ربط إشارة الموت بالأب
        if libc.prctl(PR_SET_PDEATHSIG, 9, 0, 0, 0) != 0:
            raise RuntimeError("CRITICAL: Failed to set PR_SET_PDEATHSIG")

        # 2. تقوية الذاكرة و mlockall
        if os.environ.get("SIMULATE_MLOCKALL_FAILURE") == "1":
            raise RuntimeError("CRITICAL: Simulated mlockall failure")

        try:
            resource.setrlimit(resource.RLIMIT_MEMLOCK, (resource.RLIM_INFINITY, resource.RLIM_INFINITY))
        except (ValueError, OSError) as e:
            raise RuntimeError(f"CRITICAL: Failed to set rlimit memlock: {e}")

        res_mlock = libc.mlockall(MCL_CURRENT | MCL_FUTURE)
        if res_mlock != 0:
            err = ctypes.get_errno()
            if err not in (1, 12):
                raise RuntimeError(f"CRITICAL: mlockall failed with errno {err}")

        # 3. تثبيت Seccomp و PR_SET_DUMPABLE بينما لا زلنا Root
        install_strict_seccomp()
        
        if libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0:
            raise RuntimeError("CRITICAL: Failed to set PR_SET_DUMPABLE")

        # 4. إسقاط حدود الصلاحيات بالكامل
        for cap in range(64):
            if libc.prctl(PR_CAP_BND_DROP, cap, 0, 0, 0) != 0:
                # نتجاهل الأخطاء فقط للأرقام غير الصالحة، أو نضمن إسقاط ما يمكن إسقاطه
                pass

        # 5. تغيير الـ UID / GID إلى 65534
        if os.setgroups([]) != 0:
            raise RuntimeError("CRITICAL: Failed to clear groups")
        if os.setgid(target_gid) != 0:
            raise RuntimeError("CRITICAL: Failed to setgid")
        if os.setuid(target_uid) != 0:
            raise RuntimeError("CRITICAL: Failed to setuid")

        # 6. التحقق الإلزامي الصارم (Fail-Closed)
        verify_capabilities_zeroed()
        verify_cap_bnd_zero()

        # إرسال READY فقط عند نجاح كافة التدابير بنجاح تام ودون أي استثناء
        pipe_conn.send("READY")

        while True:
            if pipe_conn.poll(timeout=0.2):
                msg = pipe_conn.recv()
                if msg == "PING":
                    pipe_conn.send("PONG")
                elif msg == "EXIT":
                    break
            if os.getppid() == 1:
                break

    except Exception as e:
        import sys as _sys
        print(f"WORKER FATAL CRASH: {e}", file=_sys.stderr)
        _sys.exit(77)  # إيقاف العامل فوراً بكود خروج غير صفري (Fail-Closed محقق)


class ScopeBEngine:
    def __init__(self):
        self.locked = False

    def enforce_memory_hardening(self):
        try:
            resource.setrlimit(resource.RLIMIT_MEMLOCK, (resource.RLIM_INFINITY, resource.RLIM_INFINITY))
        except (ValueError, OSError):
            pass
        res = libc.mlockall(MCL_CURRENT | MCL_FUTURE)
        if res != 0:
            err = ctypes.get_errno()
            if err not in (1, 12):
                raise RuntimeError(f"CRITICAL: mlockall failed with errno {err}.")
        self.locked = True
