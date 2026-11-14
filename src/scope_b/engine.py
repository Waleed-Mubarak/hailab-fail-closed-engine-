import os
import sys
import time
import ctypes
import resource
import struct
import signal
import hashlib
from multiprocessing.connection import Connection

libc = ctypes.CDLL("libc.so.6", use_errno=True)

PR_SET_PDEATHSIG = 1
PR_GET_DUMPABLE = 3
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


def _drop_privileges_and_harden(target_uid: int, target_gid: int):
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

    if libc.prctl(PR_GET_DUMPABLE, 0, 0, 0, 0) != 0:
        raise RuntimeError("CRITICAL: PR_GET_DUMPABLE is not 0")

    verify_capabilities_zeroed()
    verify_cap_bnd_zero()


def worker_process_target(
    pipe_conn: Connection,
    wd_conn: Connection = None,
    target_uid: int = 65534,
    target_gid: int = 65534,
):
    try:
        # REQ-SCOPE-B-04: إنهاء العامل فوراً بـ SIGKILL عند موت العملية الأبوية
        if libc.prctl(PR_SET_PDEATHSIG, signal.SIGKILL, 0, 0, 0) != 0:
            raise RuntimeError("CRITICAL: Failed to set PR_SET_PDEATHSIG")

        # REQ-SCOPE-B-06: قفل الذاكرة ومنع التبديل للقرص (Fail-Closed)
        try:
            resource.setrlimit(resource.RLIMIT_MEMLOCK, (resource.RLIM_INFINITY, resource.RLIM_INFINITY))
        except (ValueError, OSError):
            pass

        if libc.mlockall(MCL_CURRENT | MCL_FUTURE) != 0:
            err = ctypes.get_errno()
            raise RuntimeError(f"CRITICAL: mlockall failed strictly with errno {err}")

        # REQ-SCOPE-B-05 & B-02: إسقاط الصلاحيات وتفعيل العزل
        _drop_privileges_and_harden(target_uid, target_gid)

        # REQ-SCOPE-B-01: توليد مادة المفتاح قبل تركيب Seccomp (لتجنب حظر getrandom #318)
        key_material = bytearray(os.urandom(32))
        is_zeroized = False

        # REQ-SCOPE-B-03: تركيب مرشح Seccomp الصارم
        install_strict_seccomp()

        pipe_conn.send("READY")

        while True:
            # 1. معالجة قناة مراقبة الـ Watchdog المستقلة (REQ-SCOPE-B-07)
            if wd_conn is not None and wd_conn.poll(timeout=0.05):
                try:
                    wd_msg = wd_conn.recv()
                    if wd_msg == "WD_PING":
                        wd_conn.send("WD_PONG")
                except Exception:
                    pass

            # 2. معالجة قناة الأوامر الرئيسية
            if pipe_conn.poll(timeout=0.1):
                try:
                    msg = pipe_conn.recv()
                except Exception:
                    pipe_conn.send("OPERATION_REFUSED")
                    continue

                if msg == "EXIT":
                    break

                if is_zeroized:
                    pipe_conn.send("OPERATION_REFUSED")
                    continue

                if msg == "PING":
                    pipe_conn.send("PONG")
                elif msg == "COMPUTE":
                    digest = hashlib.sha256(key_material).hexdigest()
                    pipe_conn.send({"STATUS": "OK", "DIGEST": digest})
                elif msg == "ZEROIZE":
                    for i in range(len(key_material)):
                        key_material[i] = 0
                    is_zeroized = True
                    pipe_conn.send("OK_ZEROIZED")
                else:
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


def watchdog_process_target(
    worker_pid: int,
    wd_conn: Connection,
    alert_conn: Connection,
    interval: float = 0.2,
    target_uid: int = 65534,
    target_gid: int = 65534,
):
    """
    REQ-SCOPE-B-07: عملية مراقبة مستقلة:
    - تعمل بصلاحيات مقيدة (UID 65534).
    - تستخدم قناة اتصال مستقلة تماماً عن العملية الرئيسية (wd_conn).
    - تتخذ إجراء احتواء فعلي (Fail-Closed Containment) بإنهاء العامل عند عدم الاستجابة.
    """
    try:
        if libc.prctl(PR_SET_PDEATHSIG, signal.SIGKILL, 0, 0, 0) != 0:
            raise RuntimeError("CRITICAL: Watchdog failed to set PR_SET_PDEATHSIG")

        _drop_privileges_and_harden(target_uid, target_gid)
        alert_conn.send("WATCHDOG_READY")

        while True:
            if alert_conn.poll(timeout=0.05):
                cmd = alert_conn.recv()
                if cmd == "STOP_WATCHDOG":
                    alert_conn.send("WATCHDOG_STOPPED")
                    break

            # فحص وجود العملية
            try:
                os.kill(worker_pid, 0)
            except OSError:
                alert_conn.send("FAIL_CLOSED_CONTAINED:WORKER_DEAD")
                break

            # فحص الاستجابة عبر القناة المستقلة
            try:
                wd_conn.send("WD_PING")
                if wd_conn.poll(timeout=0.8):
                    resp = wd_conn.recv()
                    if resp != "WD_PONG":
                        try:
                            os.kill(worker_pid, signal.SIGKILL)
                        except OSError:
                            pass
                        alert_conn.send("FAIL_CLOSED_CONTAINED:INVALID_RESPONSE")
                        break
                else:
                    try:
                        os.kill(worker_pid, signal.SIGKILL)
                    except OSError:
                        pass
                    alert_conn.send("FAIL_CLOSED_CONTAINED:TIMEOUT")
                    break
            except Exception:
                try:
                    os.kill(worker_pid, signal.SIGKILL)
                except OSError:
                    pass
                alert_conn.send("FAIL_CLOSED_CONTAINED:PIPE_ERROR")
                break

            time.sleep(interval)
    except Exception as e:
        try:
            os.kill(worker_pid, signal.SIGKILL)
        except OSError:
            pass
        try:
            alert_conn.send(f"WATCHDOG_ERROR:{e}")
        except Exception:
            pass


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
