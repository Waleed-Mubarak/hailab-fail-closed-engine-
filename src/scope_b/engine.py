import os
import sys
import ctypes
import resource
import struct
import signal
import traceback
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

def worker_process_target(pipe_conn: Connection, target_uid: int = 65534, target_gid: int = 65534):
    try:
        print("[DEBUG] 1. Starting worker initialization...", file=sys.stderr, flush=True)
        if libc.prctl(PR_SET_PDEATHSIG, signal.SIGKILL, 0, 0, 0) != 0:
            raise RuntimeError("CRITICAL: Failed to set PR_SET_PDEATHSIG")

        print("[DEBUG] 2. Setting rlimit and mlockall...", file=sys.stderr, flush=True)
        resource.setrlimit(resource.RLIMIT_MEMLOCK, (resource.RLIM_INFINITY, resource.RLIM_INFINITY))
        if libc.mlockall(MCL_CURRENT | MCL_FUTURE) != 0:
            err = ctypes.get_errno()
            raise RuntimeError(f"CRITICAL: mlockall failed with errno {err}")

        print("[DEBUG] 3. Installing seccomp...", file=sys.stderr, flush=True)
        if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
            raise RuntimeError("CRITICAL: Failed to set PR_SET_NO_NEW_PRIVS")
        
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
        
        if libc.prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ctypes.byref(fprog)) != 0:
            raise RuntimeError("CRITICAL: Failed to install Seccomp filter")

        print("[DEBUG] 4. Setting dumpable and dropping capabilities...", file=sys.stderr, flush=True)
        libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0)
        for cap in range(64):
            libc.prctl(PR_CAP_BND_DROP, cap, 0, 0, 0)

        print("[DEBUG] 5. Dropping UID/GID...", file=sys.stderr, flush=True)
        if os.setgroups([]) != 0:
            raise RuntimeError("CRITICAL: Failed to setgroups")
        if os.setgid(target_gid) != 0:
            raise RuntimeError("CRITICAL: Failed to setgid")
        if os.setuid(target_uid) != 0:
            raise RuntimeError("CRITICAL: Failed to setuid")

        print("[DEBUG] 6. Sending READY...", file=sys.stderr, flush=True)
        pipe_conn.send("READY")
        print("[DEBUG] 7. READY sent successfully!", file=sys.stderr, flush=True)

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
        print(f"\n[FATAL WORKER ERROR] -----------------------------------------", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        print(f"--------------------------------------------------------------\n", file=sys.stderr)
        sys.exit(77)

def worker_process_target_failing(pipe_conn: Connection):
    try:
        print("[DEBUG FAILING] Starting failing worker...", file=sys.stderr, flush=True)
        if libc.prctl(PR_SET_PDEATHSIG, signal.SIGKILL, 0, 0, 0) != 0:
            raise RuntimeError("CRITICAL: Failed to set PR_SET_PDEATHSIG")
        raise RuntimeError("CRITICAL: Simulated mlockall failure")
    except Exception as e:
        print(f"\n[FATAL WORKER ERROR (FAILING)] --------------------------------", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        print(f"--------------------------------------------------------------\n", file=sys.stderr)
        sys.exit(77)


class ScopeBEngine:
    def __init__(self):
        self.locked = False

    def enforce_memory_hardening(self):
        resource.setrlimit(resource.RLIMIT_MEMLOCK, (resource.RLIM_INFINITY, resource.RLIM_INFINITY))
        if libc.mlockall(MCL_CURRENT | MCL_FUTURE) != 0:
            err = ctypes.get_errno()
            raise RuntimeError(f"CRITICAL: mlockall failed with errno {err}.")
        self.locked = True
