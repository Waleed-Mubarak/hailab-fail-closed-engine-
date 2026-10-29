# THREAT MODEL & SECURITY ARCHITECTURE: SCOPE B (Revision 7)

## 1. System Boundaries & Trust Assumptions
This document establishes the threat model and adversary coverage boundaries for Scope B implementation. Scope B introduces process-level isolation to safeguard cryptographic key material and privileged operations independently of Scope A CPython runtime checks.

### Trust Assumptions
- **Host Kernel Integrity:** Linux kernel integrity is assumed (Adversary B3 excluded).
- **Physical Boundary Exclusions:** Physical access, hardware bus sniffing, and RAM cold-boot extraction are strictly excluded from both Scope A and Scope B.

---

## 2. Adversary Definitions & Attack Vectors

| Adversary ID | Threat Description & Boundary Coverage | System Mitigation Strategy |
| :--- | :--- | :--- |
| **B1 (Main Process Compromise)** | Partially in scope. Adversary controls CPython main process and attempts oracle decryption or unauthorized worker IPC calls. | Enforces strict IPC message allow-listing and unconditional post-zeroization refusal. Residual operational risk prior to zeroization is managed via bounded allow-lists. |
| **B2 (Worker Process Inspection)** | In scope. Main process or unprivileged local actor attempts to inspect worker memory, pkill worker, or dump core. | Dedicated worker UID/GID, PR_SET_DUMPABLE=0 enforcement, and mlockall memory locking. |
| **B3 (Kernel Exploitation)** | Excluded. | Assumed out of scope; relies on OS kernel isolation. |
| **B4 (Physical / Cold-Boot)** | Excluded. | Strictly excluded from both Scope A and Scope B; requires dedicated hardware security boundary. |

---

## 3. Mandatory Worker Initialization & Privilege-Transition Sequence
To prevent privilege escalation or capability bypass, the worker startup sequence strictly enforces the following six-step initialization order:

1. **Memory Locking:** Invoke `mlockall(MCL_CURRENT | MCL_FUTURE)` to lock sensitive buffers into RAM. If `mlockall` fails (e.g., insufficient `RLIMIT_MEMLOCK`), worker startup **halts immediately**. Host swap must be disabled or verified encrypted.
2. **UID/GID Transition:** Drop root privileges and transition to a dedicated non-root User ID/Group ID distinct from the main application process.
3. **Capability Stripping:** Completely clear capability bounding sets, strictly verifying `CapEff = 0` and `CapBnd = 0` via `/proc/self/status`.
4. **Process Dumpable State:** Set and verify `PR_SET_DUMPABLE = 0` to block core dumps and ptrace inspection.
5. **Privilege Restriction:** Apply `PR_SET_NO_NEW_PRIVS` to prevent gaining privileges via execve.
6. **Seccomp Filtering:** Enforce the restrictive seccomp allow-list. Unauthorized system calls trigger immediate kernel termination via `SECCOMP_RET_KILL_PROCESS`.

---

## 4. Execution Invariants & Fault Domain Handling
- **Controlled Anomaly Handling (INV-B-01):** Under detected application errors or clean shutdown triggers, the worker MUST first execute deterministic volatile memory scrubbing/zeroization (0x00), followed by `sys_exit_group`.
- **Abrupt Signal Failure & Memory Faults (INV-B-02):** Under abrupt signal failures (e.g., `SIGKILL`, `SIGSEGV`, `SIGBUS`), scrubbing is provided on a best-effort basis. Audit records for `SIGKILL` or unhandled signals must be generated and preserved by an external, surviving parent monitor or dedicated logging sink.

---

## 5. Watchdog Architecture & Failure Domain (A3 Resolution)
- **Dedicated Watchdog Process:** The watchdog operates as an **independent, dedicated watchdog process** (completely separate from the worker daemon process).
- **Failure Domain & Detection:** It runs under a dedicated restricted UID to monitor worker main-loop stalls or unexpected worker termination.
- **Containment Action:** If a main-loop stall or heartbeat timeout is detected, the dedicated watchdog process issues explicit containment signals (`SIGKILL`) to terminate the stalled worker and notifies the main runtime to fail-closed.
- **Watchdog Failure:** If the watchdog process itself fails or dies, the worker detects parent/monitor disconnection on its control channel and immediately triggers zeroization and self-termination.

---

## 6. Unified Acceptance Criteria Matrix (A2 Restoration)

| Requirement ID | Adversary Attack Vector | Expected System Reaction | Evidence Artifact / Proof |
| :--- | :--- | :--- | :--- |
| REQ-SCOPE-B-01 | Compromised main process attempts oracle decryption or unauthorized IPC calls | Worker enforces allow-list and unconditionally refuses requests post-zeroization | Execution test verifying OPERATION_REFUSED response |
| REQ-SCOPE-B-02 | Main process attempts signaling/inspecting worker under distinct UID (PR_SET_DUMPABLE=0) | OS denies signal transmission / memory read (EPERM) | Process signal isolation verification test logs |
| REQ-SCOPE-B-03 | Unauthorized system call execution inside worker process | Kernel terminates process immediately via SECCOMP_RET_KILL_PROCESS | Seccomp filter validation test logs |
| REQ-SCOPE-B-04 | Abrupt crash of main CPython interpreter process | Worker detects socket EOF/PDEATHSIG and zeroizes memory | Process crash integration test logs |
| REQ-SCOPE-B-05 | Privilege drop or capability verification bypass attempt | Startup halts immediately if CapEff > 0 or CapBnd > 0 | /proc/self/status capability audit log |
| REQ-SCOPE-B-06 | Memory swap exposure or replica leakage attempt | mlockall failure halts startup immediately; Swap disabled or encrypted | Memory lock verification and mlockall failure test logs |
| REQ-SCOPE-B-07 | Asynchronous worker stall or unresponsive loop | Independent dedicated watchdog process detects timeout and triggers containment | Watchdog isolation and termination test logs |
