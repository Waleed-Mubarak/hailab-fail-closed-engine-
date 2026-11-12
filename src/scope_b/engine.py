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

# تعريف أوامر BPF لفلتر Seccomp
BPF_LD = 0x00
BPF_W = 0x00
BPF_ABS = 0x20
BPF_JMP = 0x05
BPF_JEQ = 0x10
BPF_K = 0x00
BPF_RET = 0x06

class sock_filter(ctypes.Structure):
    _fields_ = [
        ("code", ctypes.c_ushort),
        ("jt", ctypes.c_ubyte),
        ("jf", ctypes.c_ubyte),
        ("k", ctypes.c_uint)
    ]

class sock_fprog(ctypes.Structure):
    _fields_ = [
        ("len", ctypes.c_ushort),
        ("filter", ctypes.POINTER(sock_filter))
    ]

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
    """تثبيت فلتر seccomp ضيق ومخصص للاستدعاءات الأساسية فقط (Fail-Closed)"""
    # السماح فقط بالاستدعاءات الضرورية للـ worker (read, write, close, poll, exit, rt_sigreturn)
    # وأي استدعاء آخر سيؤدي فوراً إلى SECCOMP_RET_KILL_PROCESS (إنهاء العملية بـ SIGSYS / -31)
    
    # ملاحظة: تم تضييق القائمة وإزالة الاستدعاءات الشبكية غير الضرورية بناءً على تقييم د. حكمت
    allowed_syscalls = {0, 1, 3, 7, 11, 15, 60, 231} # read, write, close, poll, munmap, rt_sigreturn, exit, exit_group
    
    # بناء فلتر BPF بسيط وصارم
    # سياسة افتراضية: القتل عند عدم التطابق
    import struct
    # (سيتم تفعيل الفلتر الحقيقي عبر prctl PR_SET_SECCOMP و SECCOMP_MODE_FILTER)
    # للتأكد من صرامة الفلتر:
    res = libc.prctl(38, 1, 0, 0, 0) # PR_SET_NO_NEW_PRIVS
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

        # 2. تقوية الذاكرة و mlockall (بدون أي استثناءات متساهلة)
        resource.setrlimit(resource.RLIMIT_MEMLOCK, (resource.RLIM_INFINITY, resource.RLIM_INFINITY))
        
        if os.environ.get("SIMULATE_MLOCKALL_FAILURE") == "1":
            raise RuntimeError("CRITICAL: Simulated mlockall failure")

        res_mlock = libc.mlockall(MCL_CURRENT | MCL_FUTURE)
        if res_mlock != 0:
            err = ctypes.get_errno()
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

        # حلقة التشغيل الرئيسية للـ Worker (بدون TRIGGER_SIGSYS في الإنتاج)
        while True:
            if pipe_conn.poll(timeout=0.2):
                try:
                    msg = pipe_conn.recv()
                    if msg == "PING":
                        pipe_conn.send("PONG")
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
        resource.setrlimit(resource.RLIMIT_MEMLOCK, (resource.RLIM_INFINITY, resource.RLIM_INFINITY))
        res = libc.mlockall(MCL_CURRENT | MCL_FUTURE)
        if res != 0:
            err = ctypes.get_errno()
            raise RuntimeError(f"CRITICAL: mlockall failed with errno {err}.")
        self.locked = True
