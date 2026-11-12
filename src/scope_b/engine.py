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
    with open("/proc/self/status", "r") as f:
        for line in f:
            if line.startswith("CapEff:"):
                val = line.split()[1]
                if val != "0000000000000000":
                    raise RuntimeError(f"CRITICAL: CapEff is not zeroed: {val}")
                return True
    raise RuntimeError("CRITICAL: CapEff line not found")

def verify_cap_bnd_zero():
    with open("/proc/self/status", "r") as f:
        for line in f:
            if line.startswith("CapBnd:"):
                val = line.split()[1]
                if not all(c == '0' for c in val):
                    raise RuntimeError(f"CRITICAL: CapBnd is not zeroed: {val}")
                return True
    raise RuntimeError("CRITICAL: CapBnd line not found")

def install_strict_seccomp():
    if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        raise RuntimeError("CRITICAL: Failed to set PR_SET_NO_NEW_PRIVS")
    
    # القائمة البيضاء الشاملة لاستدعاءات النظام المطلوبة لتشغيل بايثون والـ Pipe/Sockets بأمان
    allowed_syscalls = [0, 1, 3, 7, 9, 11, 12, 15, 23, 44, 47, 60, 202, 232]
    
    insns = []
    # 0: تحميل المعمارية
    insns.append((0x20, 0, 0, 4))
    
    k_len = len(allowed_syscalls)
    kill_idx = 3 + k_len
    allow_idx = 4 + k_len
    
    # 1: التحقق من معمارية x86_64
    jf_arch = kill_idx - 2
    insns.append((0x15, 0, jf_arch, 0xC000003E))
    
    # 2: تحميل رقم استدعاء النظام (Syscall number)
    insns.append((0x20, 0, 0, 0))
    
    # إضافة فحوصات الـ Syscalls مع حساب دقيق للقفزات تلقائياً
    for idx, sc in enumerate(allowed_syscalls):
        curr_idx = 3 + idx
        jt_val = allow_idx - curr_idx - 1
        insns.append((0x15, jt_val, 0, sc))
        
    # تعليمات القتل (KILL_PROCESS)
    insns.append((0x06, 0, 0, 0x80000000))
    
    # تعليمات السماح (ALLOW)
    insns.append((0x06, 0, 0, 0x7FFF0000))
    
    bpf_code = [struct.pack("HBBI", code, jt, jf, k) for code, jt, jf, k in insns]
    bpf_insn = b"".join(bpf_code)
    
    class SockFprog(ctypes.Structure):
        _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.c_void_p)]
    
    buf = ctypes.create_string_buffer(bpf_insn)
    fprog = SockFprog(len(insns), ctypes.cast(buf, ctypes.c_void_p))
    
    if libc.prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ctypes.byref(fprog)) != 0:
        raise RuntimeError("CRITICAL: Failed to install Seccomp filter")

def worker_process_target(pipe_conn: Connection, target_uid: int = 65534, target_gid: int = 65534):
    try:
        if libc.prctl(PR_SET_PDEATHSIG, signal.SIGKILL, 0, 0, 0) != 0:
            raise RuntimeError("CRITICAL: Failed to set PR_SET_PDEATHSIG")

        if os.environ.get("SIMULATE_MLOCKALL_FAILURE") == "1":
            raise RuntimeError("CRITICAL: Simulated mlockall failure")

        resource.setrlimit(resource.RLIMIT_MEMLOCK, (resource.RLIM_INFINITY, resource.RLIM_INFINITY))
        if libc.mlockall(MCL_CURRENT | MCL_FUTURE) != 0:
            err = ctypes.get_errno()
            raise RuntimeError(f"CRITICAL: mlockall failed strictly with errno {err}")

        if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
            raise RuntimeError("CRITICAL: Failed to set PR_SET_NO_NEW_PRIVS")

        if libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0:
            raise RuntimeError("CRITICAL: Failed to set PR_SET_DUMPABLE")

        for cap in range(64):
            libc.prctl(PR_CAP_BND_DROP, cap, 0, 0, 0)

        # تنفيذ صارم بالكامل بدون أي استثناءات مصطنعة أو تجاهل للأخطاء (Fail-Closed)
        os.setgroups([])
        os.setgid(target_gid)
        os.setuid(target_uid)

        verify_capabilities_zeroed()
        verify_cap_bnd_zero()

        # تثبيت فلتر Seccomp صارماً
        install_strict_seccomp()

        # إرسال READY فقط عند نجاح كل الخطوات السابقة دون أي خلل
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
        import traceback as _tb
        err_msg = "".join(_tb.format_exception(type(e), e, e.__traceback__))
        try:
            pipe_conn.send({"ERROR": err_msg})
        except Exception:
            pass
        # إيقاف العامل فوراً برمز خطأ غير صفر (Fail-Closed قسري)
        _sys.exit(77)


class ScopeBEngine:
    def __init__(self):
        self.locked = False

    def enforce_memory_hardening(self):
        resource.setrlimit(resource.RLIMIT_MEMLOCK, (resource.RLIM_INFINITY, resource.RLIM_INFINITY))
        if libc.mlockall(MCL_CURRENT | MCL_FUTURE) != 0:
            err = ctypes.get_errno()
            raise RuntimeError(f"CRITICAL: mlockall failed strictly with errno {err}.")
        self.locked = True
