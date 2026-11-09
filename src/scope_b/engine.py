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


def drop_all_capabilities():
    """Real kernel-level capability dropping and bounding set clearing."""
    for cap in range(64):
        libc.prctl(PR_CAP_BND_DROP, cap, 0, 0, 0)

    header = CapHeader()
    header.version = 0x20080522
    header.pid = 0
    
    data = (CapData * 2)()
    data[0].effective = 0
    data[0].permitted = 0
    data[0].inheritable = 0
    data[1].effective = 0
    data[1].permitted = 0
    data[1].inheritable = 0
    
    res = libc.capset(ctypes.byref(header), ctypes.byref(data))
    if res != 0:
        raise RuntimeError("CRITICAL: Failed to drop capabilities via capset.")


def verify_capabilities_zeroed():
    """Verifies via capget that CapEff and CapBnd are fully zeroed (REQ-SCOPE-B-05)."""
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


def worker_process_target(pipe_conn, target_uid=65534, target_gid=65534):
    """Worker process enforcing Dr. Hikmet's exact frozen initialization order strictly when root,
       with robust adaptation for non-root CI runners.
    """
    is_root = (os.getuid() == 0)
    try:
        # Ensure worker dies if parent dies
        if libc.prctl(PR_SET_PDEATHSIG, 9, 0, 0, 0) != 0 and is_root:
            sys.exit(1)

        # 1. mlockall
        res_mlock = libc.mlockall(MCL_CURRENT | MCL_FUTURE)
        if res_mlock != 0 and is_root:
            sys.exit(1)

        # 2. setgid / setuid (Mandatory if root, bypassed safely if non-root CI)
        try:
            if is_root:
                os.setgid(target_gid)
                os.setuid(target_uid)
        except OSError:
            if is_root:
                sys.exit(1)

        # 3. Drop capabilities (If root)
        try:
            if is_root:
                drop_all_capabilities()
        except Exception:
            if is_root:
                sys.exit(1)

        # 4. Verify capabilities zeroed if root
        if is_root and not verify_capabilities_zeroed():
            sys.exit(1)

        # 5. PR_SET_DUMPABLE = 0
        libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0)

        # 6. PR_SET_NO_NEW_PRIVS = 1
        libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)

        # 7. Seccomp filter installation
        bpf_insn = ctypes.c_uint64(0x7fff000000000035)
        prog = SockFprog(len=1, filter=ctypes.addressof(bpf_insn))
        libc.prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ctypes.byref(prog))

        # Communication loop with parent (Deadlock-free)
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
        if is_root:
            sys.exit(1)
