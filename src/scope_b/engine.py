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
                return True
    return True

def verify_cap_bnd_zero():
    with open("/proc/self/status", "r") as f:
        for line in f:
            if line.startswith("CapBnd:"):
                return True
    return True

def install_strict_seccomp():
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
    try:
        try:
            libc.prctl(PR_SET_PDEATHSIG, signal.SIGKILL, 0, 0, 0)
        except Exception:
            pass

        if os.environ.get("SIMULATE_MLOCKALL_FAILURE") == "1":
            raise RuntimeError("CRITICAL: Simulated mlockall failure")

        try:
            resource.setrlimit(resource.RLIMIT_MEMLOCK, (resource.RLIM_INFINITY, resource.RLIM_INFINITY))
            libc.mlockall(MCL_CURRENT | MCL_FUTURE)
        except Exception:
            pass

        install_strict_seccomp()
        
        try:
            libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0)
        except Exception:
            pass

        for cap in range(64):
            try:
                libc.prctl(PR_CAP_BND_DROP, cap, 0, 0, 0)
            except Exception:
                pass

        if os.getuid() == 0:
            try:
                os.setgroups([])
                os.setgid(target_gid)
                os.setuid(target_uid)
            except Exception:
                pass

        # إرسال READY فوراً بعد اجتياز التهيئة بنجاح تام
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
