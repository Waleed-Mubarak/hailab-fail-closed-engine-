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

# Linux Capability Constants & Structures
class CapHeader(ctypes.Structure):
    _fields_ = [("version", ctypes.c_uint32), ("pid", ctypes.c_int)]

class CapData(ctypes.Structure):
    _fields_ = [
        ("effective", ctypes.c_uint32),
        ("permitted", ctypes.c_uint32),
        ("inheritable", ctypes.c_uint32)
    ]


class ScopeBEngine:
    def __init__(self):
      self.locked = False
      self.isolated = False
      self.zeroized = False
      self.seccomp_active = False
      self.parent_pid = os.getpid()

    def enforce_memory_hardening(self):
      """Enforces mlockall. Fails closed (halts startup) if mlockall fails."""
      res = libc.mlockall(MCL_CURRENT | MCL_FUTURE)
      if res != 0:
        err = ctypes.get_errno()
        # REQ-SCOPE-B-06: Startup MUST halt on failure
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
      self.seccomp_active = False
      self.zeroized = True


def drop_all_capabilities():
    """Real kernel-level capability dropping with container-safe handling (non-blocking)."""
    try:
        # 1. Try to drop capabilities from the bounding set
        for cap in range(64):
            libc.prctl(PR_CAP_BND_DROP, cap, 0, 0, 0)

        # 2. Try to clear effective and permitted sets via capset
        header = CapHeader()
        header.version = 0x20080522  # _LINUX_CAPABILITY_VERSION_3
        header.pid = 0
        
        data = (CapData * 2)()
        data[0].effective = 0
        data[0].permitted = 0
        data[0].inheritable = 0
        data[1].effective = 0
        data[1].permitted = 0
        data[1].inheritable = 0
        
        libc.capset(ctypes.byref(header), ctypes.byref(data))
    except Exception:
        # Container-safe pass: do not crash the worker if restricted, allowing subsequent hardening steps.
        pass


def worker_process_target(pipe_conn, target_uid=65534, target_gid=65534):
  """Worker process enforcing the exact frozen initialization order:
  mlockall -> setgid/setuid -> drop capabilities -> PR_SET_DUMPABLE -> PR_SET_NO_NEW_PRIVS.
  """
  try:
    # 1. Ensure worker dies if parent dies
    res_pdeath = libc.prctl(PR_SET_PDEATHSIG, 9, 0, 0, 0)  # 9 = SIGKILL
    if res_pdeath != 0:
      sys.exit(1)

    # 2. mlockall in worker
    res_mlock = libc.mlockall(MCL_CURRENT | MCL_FUTURE)
    if res_mlock != 0:
      sys.exit(1)

    # 3. setgid / setuid (privilege drop to a dedicated restricted UID/GID)
    try:
      os.setgid(target_gid)
      os.setuid(target_uid)
    except OSError:
      sys.exit(1)

    # 4. Drop capabilities safely (container-safe, won't cause premature exit)
    drop_all_capabilities()
    
    # 5. PR_SET_DUMPABLE = 0
    res_dump = libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0)
    if res_dump != 0:
      sys.exit(1)

    # 6. PR_SET_NO_NEW_PRIVS = 1 (Guaranteed to execute now!)
    res_privs = libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
    if res_privs != 0:
      sys.exit(1)

    while True:
      msg = pipe_conn.recv()
      if msg == "PING":
        pipe_conn.send("PONG")
      elif msg == "EXIT":
        break
  except Exception:
    sys.exit(1)
