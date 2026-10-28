# SCOPE B TECHNICAL REQUIREMENTS & ACCEPTANCE SPECIFICATIONS (Revision 4)

## 1. Scope & System Dependencies
This document specifies the exact requirements for **Phase 3 / Scope B** implementation. Scope B is evaluated independently from Scope A certification and establishes process boundary isolation and privileged operations security.

---

## 2. Decision B1: Dedicated Process Isolation Architecture
- **Req-B1.1 (Process Boundary):** The engine must spawn a dedicated worker daemon process (`isolation worker`) for handling sensitive key material and operations. Native C extensions within the main Python runtime process are explicitly non-compliant for B1 isolation.
- **Req-B1.2 (Restricted IPC Protocol):** Communication between the main CPython runtime and the isolated process must use strict, unidirectional, or restricted POSIX IPC channels (Unix Domain Sockets).
- **Req-B1.3 (Oracle Attack & Quorum Boundary Design):** 
  - Since an adversary controlling the main process (Adversary B1) could theoretically transmit unverified quorum indicators across the IPC boundary, the worker acknowledges that it operates under B1 threat constraints: the worker enforces an operational allow-list and executes permitted requests while active. 
  - Independent cryptographic quorum verification requires keys held outside the main process; absent an external hardware/cryptographic oracle, B1 can trigger any operation the allow-list permits while the worker is active. Absolute guarantee against B1 is strictly enforced via **unconditional post-zeroization refusal**.

---

## 3. Worker Identity, Capability Drop & Failure Detection
- **Req-B2.1 (Dedicated Identity & Privilege Drop):** The worker process must execute under a dedicated non-root User ID (`UID`) distinct from the main application process to prevent cross-process signaling/pkill attacks.
- **Req-B2.2 (Rigorous Capability Stripping & Verification):** 
  - If the worker process initializes as root, it must completely clear all capabilities and bounding sets.
  - Prior to applying `seccomp` filters, the worker must inspect `/proc/self/status` to strictly verify that `CapEff = 0` and `CapBnd = 0`.
- **Req-B2.3 (Deployment Prerequisites):** Kernel settings such as `kernel.yama.ptrace_scope=3` and `PR_SET_DUMPABLE=0` are classified as mandatory host deployment prerequisites.
- **Req-B2.4 (Inter-Process Failure Mechanisms):**
  - **Main Process Death:** Detected by worker via `PR_SET_PDEATHSIG`, Linux `pidfd`, or immediate `EOF` on the IPC socket.
  - **Worker Process Death:** Main CPython process must fail-closed immediately and never fall back to in-process key handling.

---

## 4. Execution Rules, Invariants & Seccomp Restrictions
- **INV-B-01 & INV-B-02 Execution Order:** Upon anomaly detection, the worker MUST first execute deterministic volatile memory scrubbing/zeroization, and only then invoke `sys_exit_group`.
- **Seccomp System Call Filtering:**
  - Before applying filters, `PR_SET_NO_NEW_PRIVS` must be explicitly set.
  - Seccomp filters must be applied strictly AFTER privilege capability stripping (`CapEff = 0`, `CapBnd = 0`) and IPC channel initialization.
  - Seccomp profile must enforce a strict allow-list (restricting syscalls to essential IPC I/O and `sys_exit_group`; all unauthorized syscalls trigger immediate `SIGSYS`).

---

## 5. Audit Trail & Cryptographic Separation
- **Req-B-Audit (Audit Integrity vs. Git Versioning):** 
  - **Git Commit Identifiers:** Tracked exclusively using **SHA-1** commit hashes.
  - **Audit Trail Integrity (PA-04 / INV-B-03):** Audit logs and runtime integrity hashes must utilize **SHA-256** (or stronger collision-resistant hashing algorithms) paired with external append-only sinks or asymmetric signatures inaccessible to the main process.
- **Req-B-Async (Out-of-Loop Watchdog):** The asynchronous watchdog monitor must execute inside the worker daemon process to remain independent of the main Python interpreter state.

---

## 6. Explicit Non-Coverage Declarations (Exclusions)
- **Kernel-Level Vulnerabilities (Adversary B3):** Excluded. Scope B assumes Linux kernel integrity.
- **Physical & Hardware Attacks (Adversary B4):** Excluded. Physical RAM extraction, bus sniffing, and cold-boot attacks require TEE/HSM hardware modules not covered in Scope B.

---

## 7. Unified Acceptance Criteria Matrix

| Requirement ID | Adversary Attack Vector | Expected System Reaction | Evidence Artifact / Proof |
| :--- | :--- | :--- | :--- |
| **REQ-SCOPE-B-01** | Compromised main process attempts oracle decryption or unauthorized IPC calls | Worker enforces allow-list and unconditionally refuses requests post-zeroization | Execution test verifying `OPERATION_REFUSED` response |
| **REQ-SCOPE-B-02** | Main process attempts signaling/inspecting worker under distinct UID (`PR_SET_DUMPABLE=0`) | OS denies signal transmission / memory read (`EPERM`) | Process signal isolation verification test logs |
| **REQ-SCOPE-B-03** | Unauthorized system call execution inside worker process | Kernel terminates process immediately via `SIGSYS` | Seccomp filter validation test logs |
| **REQ-SCOPE-B-04** | Abrupt crash of main CPython interpreter process | Worker detects socket `EOF`/`PDEATHSIG` and zeroizes memory | Process crash integration test logs |
| **REQ-SCOPE-B-05** | Privilege drop bypass attempt prior to seccomp activation | Verification failure halts startup if `CapEff > 0` or `CapBnd > 0` | `/proc/self/status` capability audit log |
