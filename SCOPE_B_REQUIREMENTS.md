# SCOPE B TECHNICAL REQUIREMENTS & ACCEPTANCE SPECIFICATIONS (Revision 6)

## 1. Scope & System Dependencies
This document specifies the exact requirements for Phase 3 / Scope B implementation. Scope B is evaluated independently from Scope A certification and establishes process boundary isolation and privileged operations security[span_5](start_span)[span_5](end_span)[span_6](start_span)[span_6](end_span).

---

## 2. Decision B1: Dedicated Process Isolation Architecture & B1 Adversary Boundaries
- Req-B1.1 (Process Boundary): The engine must spawn a dedicated worker daemon process (isolation worker) for handling sensitive key material and operations[span_7](start_span)[span_7](end_span). Native C extensions within the main Python runtime process are explicitly non-compliant for B1 isolation.
- Req-B1.2 (Restricted IPC Protocol & Authentication): 
  - Communication between the main CPython runtime and the isolated process uses a secure request-response IPC channel over Unix Domain Sockets[span_8](start_span)[span_8](end_span).
  - The protocol enforces strict peer authentication via SO_PEERCRED, explicit message framing, strict payload size limits, and robust rejection/termination upon receiving malformed or unauthorized requests[span_9](start_span)[span_9](end_span).
- Req-B1.3 (B1 Adversary Coverage - Partial Scope & Trust Boundary): 
  - Threat B1 is classified as partially in scope[span_10](start_span)[span_10](end_span). The security architecture provides explicit isolation of worker-held secrets from the main process and enforces the worker's operational allow-list.
  - However, it is explicitly acknowledged that absent an external cryptographic or hardware signing oracle, an adversary controlling the main process (B1) can execute permitted IPC operations while the worker remains active[span_11](start_span)[span_11](end_span).
  - Guarantee against B1 is enforced via unconditional post-zeroization refusal, subject to stated trust assumptions and verification evidence[span_12](start_span)[span_12](end_span). Residual risk from authorized operations initiated prior to terminal zeroization is managed via bounded allow-lists[span_13](start_span)[span_13](end_span).

---

## 3. Worker Identity, Capability Drop, Memory Protection & Initialization Sequence
- Req-B2.1 (Dedicated Identity & Privilege Drop): The worker process must execute under a dedicated non-root User ID (UID) distinct from the main application process to prevent cross-process signaling/pkill attacks[span_14](start_span)[span_14](end_span)[span_15](start_span)[span_15](end_span).
- Req-B2.2 (Memory Locking & Swap Policy): To prevent memory replicas and swap exposure of sensitive buffers, the worker process must invoke mlockall(MCL_CURRENT | MCL_FUTURE) during initialization[span_16](start_span)[span_16](end_span)[span_17](start_span)[span_17](end_span). If mlockall fails (e.g., due to insufficient RLIMIT_MEMLOCK), the worker startup MUST halt immediately[span_18](start_span)[span_18](end_span). Host deployment strictly requires swap to be disabled or verified encrypted at deployment[span_19](start_span)[span_19](end_span).
- Req-B2.3 (Worker-Level Process Control & PR_SET_DUMPABLE): PR_SET_DUMPABLE=0 is enforced as an active worker-level process control (verified and re-verified during initialization) to prevent core dumps and process inspection[span_20](start_span)[span_20](end_span)[span_21](start_span)[span_21](end_span).
- Req-B2.4 (Mandatory Worker Initialization & Privilege-Transition Sequence):
  The worker startup sequence must strictly execute in the following validated order[span_22](start_span)[span_22](end_span):
  1. Memory Locking: Invoke mlockall to lock volatile buffers into RAM (halts startup immediately if failed)[span_23](start_span)[span_23](end_span)[span_24](start_span)[span_24](end_span).
  2. UID/GID Transition: Drop root privileges and transition to the dedicated non-root UID/GID[span_25](start_span)[span_25](end_span).
  3. Capability Stripping: Completely clear capability bounding sets, ensuring strict verification of CapEff = 0 and CapBnd = 0 via /proc/self/status[span_26](start_span)[span_26](end_span).
  4. Process Dumpable State: Set and verify PR_SET_DUMPABLE = 0[span_27](start_span)[span_27](end_span).
  5. Privilege Restriction: Apply PR_SET_NO_NEW_PRIVS[span_28](start_span)[span_28](end_span).
  6. Seccomp Policy: Apply the final restrictive seccomp system call allow-list[span_29](start_span)[span_29](end_span).
- Req-B2.5 (Inter-Process Failure Mechanisms):
  - Main Process Death: Detected by worker via PR_SET_PDEATHSIG, Linux pidfd, or immediate EOF on the IPC socket[span_30](start_span)[span_30](end_span).
  - Worker Process Death: Main CPython process must fail-closed immediately and never fall back to in-process key handling.

---

## 4. Execution Rules, Invariants & Seccomp Restrictions
- Controlled Anomaly Handling (INV-B-01): Under detected application errors or clean shutdown triggers, the worker MUST first execute deterministic volatile memory scrubbing/zeroization (0x00), and only then invoke sys_exit_group[span_31](start_span)[span_31](end_span).
- Abrupt Signal Failure & Memory Faults (INV-B-02): Under abrupt failures (e.g., SIGKILL, or SIGSEGV/SIGBUS occurring directly within the scrubbing execution path), scrubbing is provided on a best-effort basis[span_32](start_span)[span_32](end_span). Residual exposure and measured metrics must be logged to audit channels[span_33](start_span)[span_33](end_span).
- Seccomp System Call Filtering:
  - Permitted Syscalls by Name: read, write, close, readv, writev, socketpair, epoll_wait, epoll_ctl, exit_group, futex, clock_gettime, sigreturn[span_34](start_span)[span_34](end_span).
  - Enforcement Action: Any unauthorized system call triggers immediate kernel process termination via SECCOMP_RET_KILL_PROCESS[span_35](start_span)[span_35](end_span).

---

## 5. Audit Trail & Cryptographic Separation
- Req-B-Audit (Audit Integrity vs. Git Versioning): 
  - Git Commit Identifiers: Tracked exclusively using SHA-1 commit hashes.
  - Audit Trail Integrity (PA-04 / INV-B-03): Audit logs and runtime integrity hashes must utilize SHA-256 (or stronger collision-resistant hashing algorithms) paired with external append-only sinks or asymmetric signatures inaccessible to the main process.
- Req-B-Async (Out-of-Loop Watchdog): The asynchronous watchdog monitor operates as an independent containment and monitoring mechanism within the worker daemon process, tracked via a dedicated acceptance row (REQ-SCOPE-B-07)[span_36](start_span)[span_36](end_span)[span_37](start_span)[span_37](end_span).

---

## 6. Explicit Non-Coverage Declarations (Exclusions)
- Kernel-Level Vulnerabilities (Adversary B3): Excluded. Scope B assumes Linux kernel integrity.
- Physical, Hardware & Cold-Boot Attacks (Adversary B4): Excluded. Physical RAM extraction, bus sniffing, and cold-boot attacks are explicitly excluded from both Scope A and Scope B, requiring a separately specified hardware-security scope[span_38](start_span)[span_38](end_span).

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
| REQ-SCOPE-B-07 | Asynchronous worker stall or unresponsive loop | Independent watchdog detects timeout and triggers containment | Watchdog isolation and termination test logs |
