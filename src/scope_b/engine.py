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
    """التحقق الصارم من تصفير الصلاحيات الفعالة (Fail-Closed إلزامي)"""
    with open("/proc/self/status", "r") as f:
        for line in f:
            if line.startswith("CapEff:"):
                val = line.split()[1]
                if val != "0000000000000000":
                    raise RuntimeError(f"CRITICAL: CapEff is not zeroed: {val}")
                return True
    raise RuntimeError("CRITICAL: CapEff line not found")

def verify_cap_bnd_zero():
    """التحقق الصارم من تصفير حدود الصلاحيات (Fail-Closed إلزامي)"""
    with open("/proc/self/status", "r") as f:
        for line in f:
            if line.startswith("CapBnd:"):
                val = line.split()[1]
                if not all(c == '0' for c in val):
                    raise RuntimeError(f"CRITICAL: CapBnd is not zeroed: {val}")
                return True
    raise RuntimeError("CRITICAL: CapBnd line not found")

def install_strict_seccomp():
    """تثبيت فلتر Seccomp الصارم دون أي تجاهل للأخطاء"""
    if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        raise RuntimeError("CRITICAL: Failed to set PR_SET_NO_NEW_PRIVS")
    
    bpf_code = [
        struct.pack("HBBI", 0x20, 0, 0, 4),          # Load architecture
        struct.pack("HBBI", 0x15, 0, 6, 0xC000003E), # Check x86_64
        struct.pack("HBBI", 0x20, 0, 0, 0),          # Load syscall number
        struct.pack("HBBI", 0x15, 0, 0, 60),         # sys_exit
        struct.pack("HBBI", 0x15, 0, 0, 15),         # sys_rt_sigreturn
        struct.pack("HBBI", 0x15, 0, 0, 0),          # sys_read
        struct.pack("HBBI", 0x15, 0, 0, 1),          # sys_write
        struct.pack("HBBI", 0x15, 0, 0, 11),         # sys_munmap (ضروري للاختبارات)
        struct.pack("HBBI", 0x06, 0, 0, 0x7FFF0000), # ALLOW
        struct.pack("HBBI", 0x06, 0, 0, 0x80000000)  # KILL_PROCESS (SIGSYS)
    ]
    bpf_insn = b"".join(bpf_code)
    
    class SockFprog(ctypes.Structure):
        _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.c_void_p)]
    
    buf = ctypes.create_string_buffer(bpf_insn)
    fprog = SockFprog(len(bpf_code), ctypes.cast(buf, ctypes.c_void_p))
    
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
            raise RuntimeError(f"CRITICAL: mlockall failed with errno {err}")

        install_strict_seccomp()
        
        if libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0:
            raise RuntimeError("CRITICAL: Failed to set PR_SET_DUMPABLE")

        for cap in range(64):
            libc.prctl(PR_CAP_BND_DROP, cap, 0, 0, 0)

        if os.setgroups([]) != 0:
            raise RuntimeError("CRITICAL: Failed to setgroups")
        if os.setgid(target_gid) != 0:
            raise RuntimeError("CRITICAL: Failed to setgid")
        if os.setuid(target_uid) != 0:
            raise RuntimeError("CRITICAL: Failed to setuid")

        verify_capabilities_zeroed()
        verify_cap_bnd_zero()

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
        _sys.exit(77)


class ScopeBEngine:
    def __init__(self):
        self.locked = False

    def enforce_memory_hardening(self):
        resource.setrlimit(resource.RLIMIT_MEMLOCK, (resource.RLIM_INFINITY, resource.RLIM_INFINITY))
        if libc.mlockall(MCL_CURRENT | MCL_FUTURE) != 0:
            err = ctypes.get_errno()
            raise RuntimeError(f"CRITICAL: mlockall failed with errno {err}.")
        self.locked = True
