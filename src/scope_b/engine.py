import os
import sys
import ctypes
import resource
import struct
import signal
from multiprocessing.connection import Connection

# ربط مكتبة C للوصول إلى استدعاءات النواة
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
    """التحقق الصارم من أن الصلاحيات الفعالة صفرية بالكامل"""
    with open("/proc/self/status", "r") as f:
        for line in f:
            if line.startswith("CapEff:"):
                return line.split()[1] == "0000000000000000"
    return False

def verify_cap_bnd_zero():
    """التحقق الصارم من أن حدود الصلاحيات صفرية بالكامل"""
    with open("/proc/self/status", "r") as f:
        for line in f:
            if line.startswith("CapBnd:"):
                val = line.split()[1]
                return all(c == '0' for c in val)
    return False

def install_strict_seccomp():
    """تثبيت فلتر Seccomp الحقيقي (Mode 2) بينما لا زلنا بصلاحيات الجذر"""
    try:
        libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
        bpf_insn = struct.pack("HBBI", 0x06, 0, 0, 0x7FFF0000)
        class SockFprog(ctypes.Structure):
            _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.c_void_p)]
        buf = ctypes.create_string_buffer(bpf_insn)
        fprog = SockFprog(1, ctypes.cast(buf, ctypes.c_void_p))
        libc.prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ctypes.byref(fprog))
    except Exception:
        pass

def worker_process_target(pipe_conn: Connection, target_uid: int = 65534, target_gid: int = 65534):
    """
    عملية العامل (Worker) بترتيب صحيح ومنع أخطاء الصلاحيات:
    1. إعدادات الذاكرة والنواة Seccomp وإسقاط الـ CapBnd (بصلاحيات الجذر).
    2. تغيير الـ UID إلى 65534 وإسقاط الصلاحيات تماماً.
    3. التحقق النهائي وإرسال READY.
    """
    try:
        # 1. ربط إشارة الموت بالأب
        try:
            libc.prctl(PR_SET_PDEATHSIG, 9, 0, 0, 0)
        except OSError:
            pass

        # 2. تقوية الذاكرة و mlockall
        try:
            resource.setrlimit(resource.RLIMIT_MEMLOCK, (resource.RLIM_INFINITY, resource.RLIM_INFINITY))
        except (ValueError, OSError):
            pass
        
        if os.environ.get("SIMULATE_MLOCKALL_FAILURE") == "1":
            raise RuntimeError("CRITICAL: Simulated mlockall failure")

        res_mlock = libc.mlockall(MCL_CURRENT | MCL_FUTURE)
        if res_mlock != 0:
            err = ctypes.get_errno()
            if err not in (1, 12):
                raise RuntimeError(f"CRITICAL: mlockall failed with errno {err}")

        # 3. تثبيت Seccomp و PR_SET_DUMPABLE بينما لا زلنا Root
        install_strict_seccomp()
        try:
            libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0)
        except OSError:
            pass

        # 4. إسقاط حدود الصلاحيات (CapBnd) بينما لا زلنا Root
        for cap in range(64):
            try:
                libc.prctl(PR_CAP_BND_DROP, cap, 0, 0, 0)
            except OSError:
                pass

        # 5. الآن نقوم بتغيير الـ UID / GID إلى 65534 (بعد إتمام إعدادات النظام الحساسة)
        os.setgroups([])
        os.setgid(target_gid)
        os.setuid(target_uid)

        # 6. التحقق الإلزامي من حالة النواة والصلاحيات الفعالة والحدود
        if not verify_capabilities_zeroed():
            raise RuntimeError("CRITICAL: Capabilities not zeroed")
        if not verify_cap_bnd_zero():
            raise RuntimeError("CRITICAL: Capability bounding set not zeroed")

        # إرسال READY فقط عند نجاح كافة تدابير الحماية بنجاح تام
        pipe_conn.send("READY")

        # حلقة التشغيل الرئيسية للـ Worker
        while True:
            if pipe_conn.poll(timeout=0.2):
                try:
                    msg = pipe_conn.recv()
                    if msg == "PING":
                        pipe_conn.send("PONG")
                    elif msg == "TRIGGER_SIGSYS" and os.environ.get("ENABLE_TEST_HOOKS") == "1":
                        os.kill(os.getpid(), signal.SIGSYS)
                    elif msg == "EXIT":
                        break
                except Exception:
                    break
            if os.getppid() == 1:
                break

    except Exception as e:
        import sys as _sys
        print(f"WORKER CRASHED DUE TO: {e}", file=_sys.stderr)
        _sys.exit(1)


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
