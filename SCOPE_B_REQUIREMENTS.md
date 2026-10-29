# SCOPE B TECHNICAL REQUIREMENTS & ACCEPTANCE SPECIFICATIONS (Revision 7)

## 1. Scope & System Dependencies
This document specifies the exact requirements for Phase 3 / Scope B implementation. Scope B is evaluated independently from Scope A certification and establishes process boundary isolation and privileged operations security.

---

## 2. Decision B1: Dedicated Process Isolation Architecture & B1 Adversary Boundaries
- Req-B1.1 (Process Boundary): The engine must spawn a dedicated worker daemon process (isolation worker) for handling sensitive key material and operations. Native C extensions within the main Python runtime process are explicitly non-compliant for B1 isolation.
- Req-B1.2 (Restricted IPC Protocol & Authentication): 
  - Communication between the main CPython runtime and the isolated process uses a secure request-response IPC channel over Unix Domain Sockets.
  - The protocol enforces strict peer authentication via SO_PEERCRED, explicit message framing, strict payload size limits, and robust rejection/termination upon receiving malformed or unauthorized requests.
- Req-B1.3 (B1 Adversary Coverage - Partial Scope & Trust Boundary): 
  - Threat B1 is classified as partially in scope. The security architecture provides explicit isolation of worker-held secrets from the main process and enforces the worker's operational allow-list.
  - However, it is explicitly acknowledged that absent an external cryptographic or hardware signing oracle, an adversary controlling the main process (B1) can execute permitted IPC operations while the worker remains active.
  - Guarantee against B1 is enforced via unconditional post-zeroization refusal, subject to stated trust assumptions and verification evidence. Residual risk from authorized operations initiated prior to terminal zeroization is managed via bounded allow-lists.

---

## 3. Worker Identity, Capability Drop, Memory Protection & Initialization Sequence
- Req-B2.1 (Dedicated Identity & Privilege Drop): The worker process must execute under a dedicated non-root User ID (UID) distinct from the main application process to prevent cross-process signaling/pkill attacks.
- Req-B2.2 (Memory Locking & Swap Policy): To prevent memory replicas and swap exposure of sensitive buffers, the worker process must invoke mlockall(MCL_CURRENT | MCL_FUTURE) during initialization. If mlockall fails (e.g., due to insufficient RLIMIT_MEMLOCK), the worker startup MUST halt immediately. Host deployment strictly requires swap to be disabled or verified encrypted at deployment.
- Req-B2.3 (Worker-Level Process Control & PR_SET_DUMPABLE): PR_SET_DUMPABLE=0 is enforced as an active worker-level process control (verified and re-verified during initialization) to prevent core dumps and process inspection.
- Req-B2.4 (Mandatory Worker Initialization & Privilege-Transition Sequence):
  The worker startup sequence must strictly execute in the following validated order:
  1. Memory Locking: Invoke mlockall to lock volatile buffers into RAM (halts startup immediately if failed).
  2. UID/GID Transition: Drop root privileges and transition to the dedicated non-root UID/GID.
  3. Capability Stripping: Completely clear capability bounding sets, ensuring strict verification of CapEff = 0 and CapBnd = 0 via /proc/self/status.
  4. Process Dumpable State: Set and verify PR_SET_DUMPABLE = 0.
  5. Privilege Restriction: Apply PR_SET_NO_NEW_PRIVS.
  6. Seccomp Policy: Apply the final restrictive seccomp system call allow-list.
- Req-B2.5 (Inter-Process Failure Mechanisms):
  - Main Process Death: Detected by worker via PR_SET_PDEATHSIG, Linux pidfd, or immediate EOF on the IPC socket.
  - Worker Process Death: Main CPython process must fail-closed immediately and never fall back to in-process key handling.

---

## 4. Execution Rules, Invariants & Seccomp Restrictions
- Controlled Anomaly Handling (INV-B-01): Under detected application errors or clean shutdown triggers, the worker MUST first execute deterministic volatile memory scrubbing/zeroization (0x00), and only then invoke sys_exit_group.
- Abrupt Signal Failure & Memory Faults (INV-B-02): Under abrupt failures (e.g., SIGKILL, or SIGSEGV/SIGBUS occurring directly within the scrubbing execution path), scrubbing is provided on a best-effort basis. Residual exposure and measured metrics must be logged to audit channels.
- Seccomp System Call Filtering:
  - Permitted Syscalls by Name: read, write, close, readv, writev, socketpair, epoll_wait, epoll_ctl, exit_group, futex, clock_gettime, sigreturn.
  - Enforcement Action: Any unauthorized system call triggers immediate kernel process termination via SECCOMP_RET_KILL_PROCESS.

---

## 5. Audit Trail & Cryptographic Separation
- Req-B-Audit (Audit Integrity vs. Git Versioning): 
  - Git Commit Identifiers: Tracked exclusively using SHA-1 commit hashes.
  - Audit Trail Integrity (PA-04 / INV-B-03): Audit logs and runtime integrity hashes must utilize SHA-256 (or stronger collision-resistant hashing algorithms) paired with external append-only sinks or asymmetric signatures inaccessible to the main process.
- Req-B-Async (Out-of-Loop Dedicated Watchdog): The asynchronous watchdog monitor operates as an **independent, dedicated watchdog process** (separate from the worker daemon) with restricted UID permissions and explicit signaling rights to monitor main-loop stalls or worker death, tracked via acceptance row (REQ-SCOPE-B-07).

---

## 6. Explicit Non-Coverage Declarations (Exclusions)
- Kernel-Level Vulnerabilities (Adversary B3): Excluded. Scope B assumes Linux kernel integrity.
- Physical, Hardware & Cold-Boot Attacks (Adversary B4): Excluded. Physical RAM extraction, bus sniffing, and cold-boot attacks are explicitly excluded from both Scope A and Scope B, requiring a separately specified hardware-security scope.

---

## 7. Unified Acceptance Criteria Matrix

| Requirement ID | Adversary Attack Vector | Expected System Reaction | Evidence Artifact / Proof |
| :--- | :--- | :--- | :--- |
| REQ-SCOPE-B-01 | Compromised main process attempts oracle decryption or unauthorized IPC calls | Worker enforces allow-list and unconditionally refuses requests post-zeroization | Execution test verifying OPERATION_REFUSED response |
| REQ-SCOPE-B-02 | Main process attempts signaling/inspecting worker under distinct UID (PR_SET_DUMPABLE=0) | OS denies signal transmission / memory read (EPERM) | Process signal isolation verification test logs |
| REQ-SCOPE-B-03 | Unauthorized system call execution inside worker process | Kernel terminates process immediately via SECCOMP_RET_KILL_PROCESS | Seccomp filter validation test logs |
| REQ-SCOPE-B-04 | Abrupt crash of main CPython interpreter process | Worker detects socket EOF/PDEATHSIG and zeroizes memory | Process crash integration test logs |
| REQ-SCOPE-B-05 | Privilege drop or capability verification bypass attempt | Startup halts immediately if CapEff > 0 or CapBnd > 0 | /proc/self/status capability audit log |
| REQ-SCOPE-B-06 | Memory swap exposure or replica leakage attempt | mlockall failure halts startup immediately; Swap disabled or encrypted | Memory lock verification and mlockall failure test logs |
| REQ-SCOPE-B-07 | Asynchronous worker stall or unresponsive loop | Independent watchdog process detects timeout and triggers containment | Watchdog isolation and termination test logs |
