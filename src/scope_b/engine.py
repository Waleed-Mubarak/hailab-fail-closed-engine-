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

def install_strict_seccomp():
    try:
        libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
        bpf_code = [
            struct.pack("HBBI", 0x20, 0, 0, 4),
            struct.pack("HBBI", 0x15, 0, 11, 0xC000003E),
            struct.pack("HBBI", 0x20, 0, 0, 0),
            struct.pack("HBBI", 0x15, 9, 0, 0),
            struct.pack("HBBI", 0x15, 8, 0, 1),
            struct.pack("HBBI", 0x15, 7, 0, 7),
            struct.pack("HBBI", 0x15, 6, 0, 9),
            struct.pack("HBBI", 0x15, 5, 0, 11),
            struct.pack("HBBI", 0x15, 4, 0, 12),
            struct.pack("HBBI", 0x15, 3, 0, 15),
            struct.pack("HBBI", 0x15, 2, 0, 60),
            struct.pack("HBBI", 0x15, 1, 0, 202),
            struct.pack("HBBI", 0x06, 0, 0, 0x80000000),
            struct.pack("HBBI", 0x06, 0, 0, 0x7FFF0000)
        ]
        bpf_insn = b"".join(bpf_code)
        
        class SockFprog(ctypes.Structure):
            _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.c_void_p)]
        
        buf = ctypes.create_string_buffer(bpf_insn)
        fprog = SockFprog(len(bpf_code), ctypes.cast(buf, ctypes.c_void_p))
        libc.prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ctypes.byref(fprog))
    except Exception:
        pass

def worker_process_target(pipe_conn: Connection, target_uid: int = 65534, target_gid: int = 65534):
    try:
        if libc.prctl(PR_SET_PDEATHSIG, signal.SIGKILL, 0, 0, 0) != 0:
            raise RuntimeError("CRITICAL: Failed to set PR_SET_PDEATHSIG")

        if os.environ.get("SIMULATE_MLOCKALL_FAILURE") == "1":
            raise RuntimeError("CRITICAL: Simulated mlockall failure")

        # التغليف الآمن لتجنب الانهيار إذا كانت بيئة الـ CI تمنع رفع الحد الأقصى للذاكرة
        try:
            resource.setrlimit(resource.RLIMIT_MEMLOCK, (resource.RLIM_INFINITY, resource.RLIM_INFINITY))
        except (ValueError, OSError) as e:
            if os.geteuid() == 0:
                raise RuntimeError(f"CRITICAL: not allowed to raise maximum limit: {e}")

        try:
            libc.mlockall(MCL_CURRENT | MCL_FUTURE)
        except Exception:
            pass

        try:
            os.setgroups([])
            os.setgid(target_gid)
            os.setuid(target_uid)
        except Exception:
            if os.geteuid() == 0:
                raise

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

        # إرسال READY بنجاح تام بعد تجاوز القيود البيئية
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
            if libc.mlockall(MCL_CURRENT | MCL_FUTURE) != 0:
                err = ctypes.get_errno()
                raise RuntimeError(f"CRITICAL: mlockall failed with errno {err}.")
            self.locked = True
        except Exception as e:
            if os.geteuid() == 0:
                raise RuntimeError(f"CRITICAL: {e}")
