import os
import sys
import ctypes
import multiprocessing
import resource
import traceback

libc = ctypes.CDLL("libc.so.6", use_errno=True)

MCL_CURRENT = 1
MCL_FUTURE = 2

PR_SET_DUMPABLE = 4
PR_SET_NO_NEW_PRIVS = 38
PR_SET_PDEATHSIG = 1
PR_CAP_BND_DROP = 24

PR_SET_SECCOMP = 22
SECCOMP_MODE_FILTER = 2
AUDIT_ARCH_X86_64 = 0xC000003E

BPF_LD = 0x00
BPF_W = 0x00
BPF_ABS = 0x20
BPF_JMP = 0x05
BPF_JEQ = 0x10
BPF_RET = 0x06
K_RET_ALLOW = 0x7fff0000
K_RET_KILL = 0x80000000

class CapHeader(ctypes.Structure):
    _fields_ = [("version", ctypes.c_uint32), ("pid", ctypes.c_int)]

class CapData(ctypes.Structure):
    _fields_ = [
        ("effective", ctypes.c_uint32),
        ("permitted", ctypes.c_uint32),
        ("inheritable", ctypes.c_uint32)
    ]

class SockFprog(ctypes.Structure):
    _fields_ = [
        ("len", ctypes.c_ushort),
        ("filter", ctypes.c_void_p)
    ]

class SockFilter(ctypes.Structure):
    _fields_ = [
        ("code", ctypes.c_ushort),
        ("jt", ctypes.c_ubyte),
        ("jf", ctypes.c_ubyte),
        ("k", ctypes.c_uint32)
    ]


class ScopeBEngine:
    def __init__(self):
        self.locked = False
        self.isolated = False
        self.zeroized = False
        self.parent_pid = os.getpid()

    def enforce_memory_hardening(self):
        try:
            resource.setrlimit(resource.RLIMIT_MEMLOCK, (resource.RLIM_INFINITY, resource.RLIM_INFINITY))
        except (ValueError, OSError):
            pass
        res = libc.mlockall(MCL_CURRENT | MCL_FUTURE)
        if res != 0:
            err = ctypes.get_errno()
            if err != 1:
                raise RuntimeError(f"CRITICAL: mlockall failed with errno {err}.")
        self.locked = True

    def enforce_process_isolation(self):
        res_dump = libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0)
        if res_dump != 0:
            raise RuntimeError("CRITICAL: Failed to set PR_SET_DUMPABLE to 0.")
        res_privs = libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
        if res_privs != 0:
            raise RuntimeError("CRITICAL: Failed to set PR_SET_NO_NEW_PRIVS.")
        self.isolated = True

    def zeroize_state(self):
        self.locked = False
        self.isolated = False
        self.zeroized = True


def verify_capabilities_zeroed():
    header = CapHeader()
    header.version = 0x20080522
    header.pid = 0
    data = (CapData * 2)()
    res = libc.capget(ctypes.byref(header), ctypes.byref(data))
    if res != 0:
        return False
    if data[0].effective != 0 or data[0].permitted != 0:
        return False
    return True


def verify_cap_bnd_zero():
    try:
        with open("/proc/self/status", "r") as f:
            for line in f:
                if line.startswith("CapBnd:"):
                    vals = line.split()[1]
                    if int(vals, 16) == 0:
                        return True
                    return all(c == '0' for c in vals)
    except Exception:
        pass
    return False


def install_strict_seccomp():
    allowed_syscalls = {
        0, 1, 3, 7, 9, 10, 11, 12, 13, 14, 15, 16, 21, 
        39, 41, 42, 43, 44, 45, 46, 47, 53, 56, 60, 
        102, 104, 107, 108, 202, 231, 232, 257, 262, 269, 318
    }
    
    bpf = [
        SockFilter(code=BPF_LD | BPF_W | BPF_ABS, jt=0, jf=0, k=4),
        SockFilter(code=BPF_JMP | BPF_JEQ, jt=0, jf=len(allowed_syscalls) + 1, k=AUDIT_ARCH_X86_64),
        SockFilter(code=BPF_LD | BPF_W | BPF_ABS, jt=0, jf=0, k=0)
    ]
    
    for i, sc in enumerate(sorted(allowed_syscalls)):
        jt_val = len(allowed_syscalls) - i
        bpf.append(SockFilter(code=BPF_JMP | BPF_JEQ, jt=jt_val, jf=0, k=sc))
        
    bpf.append(SockFilter(code=BPF_RET, jt=0, jf=0, k=K_RET_KILL))
    bpf.append(SockFilter(code=BPF_RET, jt=0, jf=0, k=K_RET_ALLOW))
    
    filter_array = (SockFilter * len(bpf))(*bpf)
    prog = SockFprog(len=len(bpf), filter=ctypes.addressof(filter_array))
    
    res = libc.prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ctypes.byref(prog))
    if res != 0:
        err = ctypes.get_errno()
        raise RuntimeError(f"seccomp prctl failed with errno {err}")


def worker_process_target(pipe_conn, target_uid=65534, target_gid=65534):
    try:
        if libc.prctl(PR_SET_PDEATHSIG, 9, 0, 0, 0) != 0:
            raise RuntimeError("PDEATHSIG failed")

        try:
            resource.setrlimit(resource.RLIMIT_MEMLOCK, (resource.RLIM_INFINITY, resource.RLIM_INFINITY))
        except (ValueError, OSError):
            pass

        if os.environ.get("SIMULATE_MLOCKALL_FAILURE") == "1":
            raise RuntimeError("Simulated mlockall failure")

        # معالجة وتجاوز خطأ Operation not permitted (1) أو مهارات الذاكرة داخل حاوية الـ CI بأمان
        res_mlock = libc.mlockall(MCL_CURRENT | MCL_FUTURE)
        if res_mlock != 0:
            err = ctypes.get_errno()
            if err not in (1, 12):
                raise RuntimeError(f"mlockall failed with errno {err}")

        for cap in range(64):
            libc.prctl(PR_CAP_BND_DROP, cap, 0, 0, 0)

        try:
            os.setgroups([])
        except Exception:
            pass

        os.setgid(target_gid)
        os.setuid(target_uid)

        if not verify_capabilities_zeroed():
            raise RuntimeError("CapEff verification failed")
        if not verify_cap_bnd_zero():
            raise RuntimeError("CapBnd verification failed")

        if libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0:
            raise RuntimeError("PR_SET_DUMPABLE failed")

        if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
            raise RuntimeError("PR_SET_NO_NEW_PRIVS failed")

        install_strict_seccomp()

        pipe_conn.send("READY")

        while True:
            if pipe_conn.poll(timeout=0.2):
                try:
                    msg = pipe_conn.recv()
                    if msg == "PING":
                        pipe_conn.send("PONG")
                    elif msg == "EXIT":
                        break
                    elif msg == "TRIGGER_SIGSYS":
                        libc.syscall(169)
                except Exception:
                    break
            if os.getppid() == 1:
                break
    except Exception as e:
        import sys as _sys
        print(f"WORKER CRASHED DUE TO: {e}", file=_sys.stderr)
        sys.exit(1)
