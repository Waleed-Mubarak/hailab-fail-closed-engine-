# SCOPE B TECHNICAL REQUIREMENTS & ACCEPTANCE SPECIFICATIONS

## 1. Scope & System Dependencies
This document specifies the exact requirements for **Phase 3 / Scope B** implementation. Scope B is evaluated independently from Scope A certification and establishes process boundary isolation and privileged operations security.

---

## 2. Decision B1: Dedicated Process Isolation Architecture
- **Req-B1.1 (Process Boundary):** The engine must spawn a dedicated worker daemon process (`isolation worker`) for handling sensitive key material and operations. Native C extensions within the main Python runtime process are explicitly non-compliant for B1 isolation.
- **Req-B1.2 (Restricted IPC Protocol):** Communication between the main CPython runtime and the isolated process must use strict, unidirectional, or restricted POSIX IPC channels (Unix Domain Sockets).
- **Req-B1.3 (Oracle Attack & Authorization Guardrails):** 
  - Key confidentiality alone is insufficient. The worker process must enforce operation authorization internally.
  - The worker process maintains an explicit allow-list of IPC operations.
  - Quorum verification and terminal zeroization states must be managed and enforced strictly inside the worker process to prevent main-process tamper/oracle execution.
  - Once zeroization is triggered inside the worker, it must refuse all subsequent IPC requests unconditionally.

---

## 3. Worker Identity, Privilege Drop & Failure Detection
- **Req-B2.1 (Dedicated Identity & Privilege Drop):** The worker process must execute under a dedicated non-root User ID (`UID`) distinct from the main application process to prevent cross-process signaling/pkill attacks.
- **Req-B2.2 (Deployment Prerequisites):** Kernel settings such as `kernel.yama.ptrace_scope=3` and `PR_SET_DUMPABLE=0` are classified as mandatory host deployment prerequisites enforced during deployment.
- **Req-B2.3 (Inter-Process Failure Mechanisms):**
  - **Main Process Death:** Detected by worker via `PR_SET_PDEATHSIG`, Linux `pidfd`, or immediate `EOF` on the IPC socket.
  - **Worker Process Death:** Main CPython process must fail-closed immediately and never fall back to in-process key handling.
  - **SIGKILL Behavior:** Under SIGKILL, kernel immediate termination prevents zeroization code execution; residual memory pages are accepted under B3/B4 physical/kernel exclusions.

---

## 4. Execution Rules, Invariants & Seccomp Restrictions
- **INV-B-01 & INV-B-02 Execution Order:** Upon anomaly detection, the worker MUST first execute deterministic volatile memory scrubbing/zeroization, and only then invoke `sys_exit_group`.
- **Seccomp System Call Filtering:**
  - Before applying filters, `PR_SET_NO_NEW_PRIVS` must be explicitly set.
  - Seccomp filters must be applied strictly AFTER privilege drop and IPC channel initialization.
  - Seccomp profile must enforce a strict allow-list (restricting syscalls to essential IPC I/O and `sys_exit_group`; all unauthorized syscalls trigger immediate `SIGSYS`).

---

## 5. Audit Trail & Async Watchdog Requirements
- **Req-B-Audit (Audit Trail Integrity):** Hashes and audit metrics must be written to an external append-only sink or signed via an asymmetric key inaccessible to the main process.
- **Req-B-Async (Out-of-Loop Watchdog):** The asynchronous watchdog monitor must execute inside, or be strictly enforced by, the worker daemon process to remain independent of the main Python interpreter state.
- **Commit Binding:** Every implementation file in `src/isolation/` and `tests/test_scope_b.py` is bound to explicit SHA-1 Git commit hashes upon completion.

---

## 6. Explicit Non-Coverage Declarations (Exclusions)
- **Kernel-Level Vulnerabilities (Adversary B3):** Excluded. Scope B assumes Linux kernel integrity.
- **Physical & Hardware Attacks (Adversary B4):** Excluded. Physical RAM extraction, bus sniffing, and cold-boot attacks require TEE/HSM hardware modules not covered in Scope B.

---

## 7. Acceptance Criteria Matrix

| Requirement ID | Adversary Attack Vector | Expected System Reaction | Evidence Artifact / Proof |
| :--- | :--- | :--- | :--- |
| **REQ-SCOPE-B-01** | Compromised main process attempts oracle decryption on zeroized worker | Worker refuses request with authorization failure / terminal refusal | Execution test verifying `OPERATION_REFUSED` response |
| **REQ-SCOPE-B-02** | Main process attempts signaling worker under distinct UID | OS denies signal transmission (`EPERM`) | Process signal isolation verification test |
| **REQ-SCOPE-B-03** | Unauthorized system call execution inside worker process | Kernel terminates process immediately via `SIGSYS` | Seccomp filter validation test logs |
| **REQ-SCOPE-B-04** | Abrupt crash of main CPython interpreter process | Worker detects socket `EOF`/`PDEATHSIG` and zeroizes memory | Process crash integration test logs |
| **REQ-SCOPE-B-05** | Memory corruption trigger (`SIGSEGV` / `SIGBUS`) | Deterministic memory scrub prior to process termination | Memory non-leakage measurement report |
