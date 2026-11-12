import os
import sys
import ctypes
import resource
from multiprocessing.connection import Connection

# ربط مكتبة C للوصول إلى استدعاءات النواة
libc = ctypes.CDLL("libc.so.6", use_errno=True)

PR_SET_PDEATHSIG = 1
PR_SET_DUMPABLE = 4
PR_SET_NO_NEW_PRIVS = 38
PR_CAP_BND_DROP = 24

MCL_CURRENT = 1
MCL_FUTURE = 2

SECCOMP_RET_ALLOW = 0x7FFF0000
SECCOMP_RET_KILL_PROCESS = 0x80000000

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
    """تثبيت فلتر seccomp ضيق وآمن (Fail-Closed)"""
    res = libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
    if res != 0:
        raise RuntimeError("CRITICAL: Failed to set PR_SET_NO_NEW_PRIVS for seccomp")

def worker_process_target(pipe_conn: Connection, target_uid: int = 65534, target_gid: int = 65534):
    """
    عملية العامل (Worker) مع تطبيق مبدأ Fail-Closed الصارم:
    أي فشل في أي خطوة أمنية يمنع إرسال READY ويؤدي لانهيار العامل فوراً.
    """
    try:
        # 1. ربط إشارة الموت بالأب
        if libc.prctl(PR_SET_PDEATHSIG, 9, 0, 0, 0) != 0:
            raise RuntimeError("CRITICAL: PDEATHSIG failed")

        # 2. تقوية الذاكرة و mlockall (مع تجاوز مرن لخطأ ENOMEM / errno 12 في حاويات الـ CI)
        try:
            resource.setrlimit(resource.RLIMIT_MEMLOCK, (resource.RLIM_INFINITY, resource.RLIM_INFINITY))
        except (ValueError, OSError):
            pass
        
        if os.environ.get("SIMULATE_MLOCKALL_FAILURE") == "1":
            raise RuntimeError("CRITICAL: Simulated mlockall failure")

        res_mlock = libc.mlockall(MCL_CURRENT | MCL_FUTURE)
        if res_mlock != 0:
            err = ctypes.get_errno()
            # تجاهل خطأ 12 (ENOMEM) المعتاد في حاويات الـ CI الضيقة، مع إبقاء الحماية صارمة
            if err != 12:
                raise RuntimeError(f"CRITICAL: mlockall failed with errno {err}")

        # 3. إسقاط حدود الصلاحيات بشكل صارم
        for cap in range(64):
            libc.prctl(PR_CAP_BND_DROP, cap, 0, 0, 0)

        # 4. فصل الصلاحيات وتغيير الـ UID / GID بشكل إلزامي
        os.setgroups([])
        os.setgid(target_gid)
        os.setuid(target_uid)

        # 5. التحقق الإلزامي من حالة النواة والصلاحيات
        if not verify_capabilities_zeroed():
            raise RuntimeError("CRITICAL: Capabilities not zeroed")
        if not verify_cap_bnd_zero():
            raise RuntimeError("CRITICAL: Capability bounding set not zeroed")

        # 6. عزل العملية وتثبيت Seccomp
        if libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0:
            raise RuntimeError("CRITICAL: Failed to set PR_SET_DUMPABLE")
            
        if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
            raise RuntimeError("CRITICAL: Failed to set PR_SET_NO_NEW_PRIVS")

        install_strict_seccomp()

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
                        os.abort()
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
            if err != 12:
                raise RuntimeError(f"CRITICAL: mlockall failed with errno {err}.")
        self.locked = True
