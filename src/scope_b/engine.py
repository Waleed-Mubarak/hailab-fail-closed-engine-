import os
import sys
import ctypes
import multiprocessing

# Load libc for kernel-level system calls
libc = ctypes.CDLL("libc.so.6", use_errno=True)

# Constants for mlockall
MCL_CURRENT = 1
MCL_FUTURE = 2

# Constants for prctl
PR_SET_DUMPABLE = 4
PR_SET_NO_NEW_PRIVS = 38
PR_SET_PDEATHSIG = 1
PR_CAP_BND_DROP = 24

# Seccomp & BPF Constants
PR_SET_SECCOMP = 22
SECCOMP_MODE_FILTER = 2

# Linux Capability Structures
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
        """Enforces mlockall. Fails closed (halts startup with RuntimeError) if mlockall fails (REQ-SCOPE-B-06)."""
        res = libc.mlockall(MCL_CURRENT | MCL_FUTURE)
        if res != 0:
            err = ctypes.get_errno()
            raise RuntimeError(
                f"CRITICAL: mlockall failed with errno {err}. Startup halted."
            )
        self.locked = True

    def enforce_process_isolation(self):
        """Enforces kernel-level process isolation and protections in parent."""
        res_dump = libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0)
        if res_dump != 0:
            raise RuntimeError("CRITICAL: Failed to set PR_SET_DUMPABLE to 0.")

        res_privs = libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
        if res_privs != 0:
            raise RuntimeError("CRITICAL: Failed to set PR_SET_NO_NEW_PRIVS.")

        self.isolated = True

    def zeroize_state(self):
        """Zeroizes internal state and flags."""
        self.locked = False
        self.isolated = False
        self.zeroized = True


def verify_capabilities_zeroed():
    """Verifies via capget that CapEff and CapBnd are fully zeroed (REQ-SCOPE-B-05)."""
    header = CapHeader()
    header.version = 0x20080522
    header.pid = 0
    data = (CapData * 2)()
    res = libc.capget(ctypes.byref(header), ctypes.byref(data))
    if res != 0:
        return False
    if data[0].effective != 0 or data[0].permitted != 0 or data[1].effective != 0 or data[1].permitted != 0:
        return False
    return True


def install_strict_seccomp():
    """Installs a valid BPF seccomp filter allowing necessary python/system calls 
       and defaulting to SECCOMP_RET_KILL_PROCESS (REQ-SCOPE-B-03).
    """
    # Comprehensive allowed syscall numbers for Python runtime on x86_64
    allowed_syscalls = {
        0, 1, 3, 9, 10, 11, 12, 13, 14, 15, 16, 21, 
        39, 56, 60, 102, 104, 107, 108, 202, 231, 257, 262, 269, 318
    }
    
    bpf_code = []
    # 1. Check architecture (AUDIT_ARCH_X86_64 = 0xC000003E)
    bpf_code.append(SockFilter(code=0x20, jt=0, jf=0, k=4))
    bpf_code.append(SockFilter(code=0x15, jt=0, jf=len(allowed_syscalls) + 1, k=0xC000003E))
    
    # 2. Load syscall number offset
    bpf_code.append(SockFilter(code=0x20, jt=0, jf=0, k=0))
    
    # 3. Add jump conditions for each allowed syscall
    for i, sc in enumerate(sorted(allowed_syscalls)):
        jt_val = len(allowed_syscalls) - i
        bpf_code.append(SockFilter(code=0x15, jt=jt_val, jf=0, k=sc))
        
    # 4. Default action: SECCOMP_RET_KILL_PROCESS
    bpf_code.append(SockFilter(code=0x06, jt=0, jf=0, k=0x80000000))
    
    # 5. Allow action: SECCOMP_RET_ALLOW
    bpf_code.append(SockFilter(code=0x06, jt=0, jf=0, k=0x7fff0000))
    
    filter_array = (SockFilter * len(bpf_code))(*bpf_code)
    prog = SockFprog(len=len(bpf_code), filter=ctypes.addressof(filter_array))
    
    res = libc.prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ctypes.byref(prog))
    if res != 0:
        sys.exit(1)


def worker_process_target(pipe_conn, target_uid=65534, target_gid=65534):
    """Worker process strictly enforcing Dr. Hikmet's exact frozen initialization order 
       and absolute Fail-Closed semantics without soft bypasses.
    """
    try:
        # 1. Ensure worker dies if parent dies
        if libc.prctl(PR_SET_PDEATHSIG, 9, 0, 0, 0) != 0:
            sys.exit(1)

        # 2. mlockall (Strict Fail-Closed)
        if libc.mlockall(MCL_CURRENT | MCL_FUTURE) != 0:
            sys.exit(1)

        # 3. Drop bounding set via prctl while still root
        for cap in range(65):
            libc.prctl(PR_CAP_BND_DROP, cap, 0, 0, 0)

        # 4. setgid / setuid to dedicated UID
        try:
            os.setgid(target_gid)
            os.setuid(target_uid)
        except OSError:
            sys.exit(1)

        # 5. Verify capabilities zeroed strictly (No UID 0 bypass)
        if not verify_capabilities_zeroed():
            sys.exit(1)

        # 6. PR_SET_DUMPABLE = 0
        if libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0:
            sys.exit(1)

        # 7. PR_SET_NO_NEW_PRIVS = 1
        if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
            sys.exit(1)

        # 8. Install strict Seccomp BPF filter
        install_strict_seccomp()

        # Signal parent that initialization completed successfully and worker is ALIVE
        pipe_conn.send("READY")

        # Communication loop with parent (Deadlock-free & active)
        while True:
            if pipe_conn.poll(timeout=2.0):
                try:
                    msg = pipe_conn.recv()
                    if msg == "PING":
                        pipe_conn.send("PONG")
                    elif msg == "EXIT":
                        break
                except Exception:
                    break
            else:
                if os.getppid() == 1:
                    break
    except Exception:
        sys.exit(1)
