import os
import sys
import ctypes
import resource
import struct
import signal
import hashlib
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
    
    allowed_syscalls = [
        0,    # read
        1,    # write
        2,    # open
        3,    # close
        5,    # fstat
        7,    # poll
        8,    # lseek
        9,    # mmap
        11,   # munmap
        12,   # brk
        13,   # rt_sigaction
        14,   # rt_sigprocmask
        15,   # rt_sigreturn
        16,   # ioctl
        20,   # writev
        23,   # select
        35,   # nanosleep
        39,   # getpid
        44,   # sendto
        47,   # recvmsg
        60,   # exit
        96,   # gettimeofday
        107,  # getuid
        108,  # getgid
        110,  # getppid
        158,  # arch_prctl
        186,  # gettid
        202,  # futex
        217,  # getdents64
        218,  # set_tid_address
        228,  # clock_gettime
        231,  # exit_group
        257,  # openat
        273   # set_robust_list
    ]
    
    insns = []
    insns.append((0x20, 0, 0, 4))
    
    k_len = len(allowed_syscalls)
    kill_idx = 3 + k_len
    allow_idx = 4 + k_len
    
    jf_arch = kill_idx - 2
    insns.append((0x15, 0, jf_arch, 0xC000003E))
    insns.append((0x20, 0, 0, 0))
    
    for idx, sc in enumerate(allowed_syscalls):
        curr_idx = 3 + idx
        jt_val = allow_idx - curr_idx - 1
        insns.append((0x15, jt_val, 0, sc))
        
    insns.append((0x06, 0, 0, 0x80000000))
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

        try:
            resource.setrlimit(resource.RLIMIT_MEMLOCK, (resource.RLIM_INFINITY, resource.RLIM_INFINITY))
        except (ValueError, OSError):
            pass

        if libc.mlockall(MCL_CURRENT | MCL_FUTURE) != 0:
            err = ctypes.get_errno()
            raise RuntimeError(f"CRITICAL: mlockall failed strictly with errno {err}")

        if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
            raise RuntimeError("CRITICAL: Failed to set PR_SET_NO_NEW_PRIVS")

        if libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0:
            raise RuntimeError("CRITICAL: Failed to set PR_SET_DUMPABLE")

        for cap in range(64):
            libc.prctl(PR_CAP_BND_DROP, cap, 0, 0, 0)

        os.setgroups([])
        os.setgid(target_gid)
        os.setuid(target_uid)

        if libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0:
            raise RuntimeError("CRITICAL: Failed to re-set PR_SET_DUMPABLE after setuid")

        verify_capabilities_zeroed()
        verify_cap_bnd_zero()

        install_strict_seccomp()

        # REQ-SCOPE-B-01: توليد المفاتيح والمواد السرية داخل العامل حصراً
        key_material = bytearray(os.urandom(32))
        is_zeroized = False

        pipe_conn.send("READY")

        while True:
            if pipe_conn.poll(timeout=0.2):
                try:
                    msg = pipe_conn.recv()
                except Exception:
                    pipe_conn.send("OPERATION_REFUSED")
                    continue

                # REQ-SCOPE-B-01: بعد التطهير، أي طلب يتلقى OPERATION_REFUSED قطعاً
                if is_zeroized:
                    pipe_conn.send("OPERATION_REFUSED")
                    continue

                if msg == "PING":
                    pipe_conn.send("PONG")
                elif msg == "COMPUTE":
                    # عملية تشفير/حساب داخلية تعتمد على المفتاح دون تسريبه
                    digest = hashlib.sha256(key_material).hexdigest()
                    pipe_conn.send({"STATUS": "OK", "DIGEST": digest})
                elif msg == "ZEROIZE":
                    # REQ-SCOPE-B-01: التطهير الحاسم والكتابة فوق مخزن المفاتيح بالكامل
                    for i in range(len(key_material)):
                        key_material[i] = 0
                    is_zeroized = True
                    pipe_conn.send("OK_ZEROIZED")
                elif msg == "EXIT":
                    break
                else:
                    # أي رسالة أو أمر مجهول أو مشوه يُرفض فوراً
                    pipe_conn.send("OPERATION_REFUSED")

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
        _sys.exit(77)


class ScopeBEngine:
    def __init__(self):
        self.locked = False

    def enforce_memory_hardening(self):
        try:
            resource.setrlimit(resource.RLIMIT_MEMLOCK, (resource.RLIM_INFINITY, resource.RLIM_INFINITY))
        except (ValueError, OSError):
            pass
        if libc.mlockall(MCL_CURRENT | MCL_FUTURE) != 0:
            err = ctypes.get_errno()
            raise RuntimeError(f"CRITICAL: mlockall failed strictly with errno {err}.")
        self.locked = True
