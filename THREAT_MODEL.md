# THREAT MODEL: Scope B – OS-Level Privilege & Memory Boundary Isolation

## 1. System Overview & Scope Definition
This threat model defines the security boundaries, attack vectors, and operational invariants for **Scope B (OS-Level Privilege & Isolation Guarantee)** within the HAI Lab Fail-Closed & Zeroization Engine.

> **Scope A Boundary Disclaimer:**  
> Scope A guarantees are strictly limited to application-level managed buffer zeroization and process termination via `os._exit(101)` under commit `191928d0e5354d8686c664a9aaa20e7ca2d323df` (`REQ-SCOPE-A-01` through `REQ-SCOPE-A-04`). Scope B extends containment beyond the Python interpreter boundary to enforcing process privilege drop, kernel-enforced syscall filtering, and process boundary isolation.

---

## 2. Protected Assets & Adversary Profiles

### 2.1 Protected Assets
* **PA-01 (Primary Key Material & Derived Secrets):** Plaintext cryptographic keys, ephemeral seeds, and intermediate states.
* **PA-02 (Volatile Buffer Replicas):** Any copies or lingering representations of key material in process memory or swap space.
* **PA-03 (Zeroization State Registers):** Execution status and confirmation signals indicating successful memory scrubbing.
* **PA-04 (Audit Trails & Verification Logs):** Immutable, collision-resistant cryptographic hash logs (**SHA-256** or stronger) documenting privilege changes and fail-closed events.

### 2.2 Adversary Profiles & Scope Boundaries
* **Adversary B1 (In-Process Malicious/Compromised Code):** Code executing within the same CPython runtime attempting memory inspection, attribute tampering, or sending unverified IPC quorum flags.
  * *Status:* **IN-SCOPE** via Decision B1 (Dedicated privilege-separated worker daemon process; native C extensions in main process are explicitly disallowed). Absolute protection against B1 is strictly enforced via **unconditional post-zeroization refusal**.
* **Adversary B2 (Co-located Local Unprivileged Attacker):** Unprivileged local processes attempting memory reads via `/proc/<pid>/mem` or attachment via `ptrace`.
  * *Status:* **IN-SCOPE** (Mitigated via dedicated worker `UID`, `PR_SET_DUMPABLE=0`, and deployment prerequisite `yama.ptrace_scope=3`).
* **Adversary B3 (Kernel Exploit / Ring-0 Attacker):** Adversaries exploiting OS kernel vulnerabilities to subvert process boundaries.
  * *Status:* **EXCLUDED FROM SCOPE B** (Explicitly out of scope, kernel integrity assumed).
* **Adversary B4 (Physical / Cold-Boot / Hardware Attacker):** Physical probing, RAM freeze/cold-boot extraction, or hardware-level bus sniffing.
  * *Status:* **EXCLUDED FROM SCOPE B** (Requires dedicated TEE/HSM integration).
* **Adversary B5 (Runtime Invariant Manipulator):** Injecting asynchronous cancellations or unhandled exceptions to force a Fail-Open state.
  * *Status:* **IN-SCOPE** (Mitigated via out-of-event-loop watchdog monitoring executed inside the worker daemon process).

---

## 3. Trust Boundaries & Isolation Primitives

### 3.1 Decision B1: Process Isolation & Quorum Boundary Design
To eliminate vulnerabilities stemming from CPython immutable object behavior and in-process memory exposure:
1. All key handling, cryptographic operations, and zeroization enforcement are offloaded to a dedicated worker daemon process (`isolation worker`). Native C extensions sharing the main process memory space are disallowed.
2. The main application process communicates with the worker strictly via restricted POSIX IPC channels (Unix Domain Sockets).
3. The worker maintains an internal operation allow-list and unconditionally refuses all requests once a terminal zeroization state is reached.

### 3.2 System Call Filtering & Rigorous Capability Stripping
* **Capability Stripping & Verification Sequence:**
  1. Clear all process capabilities and bounding sets.
  2. Inspect `/proc/self/status` to strictly verify that `CapEff = 0` and `CapBnd = 0`. Startup halts immediately if verification fails.
  3. Set `PR_SET_NO_NEW_PRIVS`.
  4. Apply `seccomp-bpf` syscall filters strictly AFTER capability verification and IPC initialization.
* **Syscall Whitelisting (`seccomp-bpf`):** Restricts syscalls to essential IPC I/O and `sys_exit_group`. Any unauthorized syscall causes immediate kernel termination via `SIGSYS`.

---

## 4. Unified Compliance & Verification Matrix (`REQ-SCOPE-B-xx`)

| Requirement ID | Security Constraint | Verification Method | Audit Evidence |
| :--- | :--- | :--- | :--- |
| **REQ-SCOPE-B-01** | **Process Boundary & Oracle Isolation:** Worker enforces IPC allow-list and unconditionally refuses all requests post-zeroization. | Test inter-process isolation and verify post-zeroization refusal under induced main-process tampering. | `OPERATION_REFUSED` verification test logs. |
| **REQ-SCOPE-B-02** | **Ptrace, Memory Dump & UID Isolation:** Worker runs under distinct non-root UID with `PR_SET_DUMPABLE=0`, blocking cross-UID signaling and `/proc/<pid>/mem` access. | Attempt `ptrace(PTRACE_ATTACH)` and cross-UID signal transmission. | `EPERM` return code verification logs. |
| **REQ-SCOPE-B-03** | **Kernel Syscall Restriction:** Restrict available syscalls to an explicit allow-list via `seccomp-bpf` post-capability drop. | Trigger prohibited syscalls within test harness. | Kernel `SIGSYS` signal & `sys_exit_group` audit log. |
| **REQ-SCOPE-B-04** | **Inter-Process Failure Detection:** Abrupt crash/death of main CPython process triggers instant worker zeroization. | Simulate main process crash and test `PR_SET_PDEATHSIG` / socket `EOF`. | Process crash integration test logs. |
| **REQ-SCOPE-B-05** | **Privilege Drop Verification & Async Containment:** Startup halts if `CapEff > 0` or `CapBnd > 0`; watchdog runs inside worker process. | Attempt startup with retained capability; inject async delay to watchdog. | `/proc/self/status` audit log & watchdog termination log. |

---

## 5. Formal Execution Invariants & Versioning Standards
1. **INV-B-01 & INV-B-02 (Deterministic Memory Zeroization Sequence):** Upon anomaly detection, the worker MUST first execute deterministic volatile memory scrubbing/zeroization (`0x00`), and only then invoke `sys_exit_group`.
2. **INV-B-03 (Cryptographic vs. Versioning Separation):**
   - **Git Versioning:** Commit identifiers are tracked exclusively using **SHA-1** commit hashes.
   - **Audit Trail Integrity:** Log hashes are computed using **SHA-256** (or stronger) and written to an external append-only sink or signed via an asymmetric key inaccessible to the main process.

---

## 6. Audit & Acceptance Criteria
* **Automated Integration Suite:** Must verify `seccomp` violation termination (`SIGSYS`), cross-UID `ptrace`/signal blockage (`EPERM`), `CapEff=0`/`CapBnd=0` verification, socket EOF/PDEATHSIG failure detection, and memory non-leakage under induced `SIGSEGV`/`SIGBUS`.
* **Repository Placement:** Formally tracked under `THREAT_MODEL.md` and `SCOPE_B_REQUIREMENTS.md` in the repository root using explicit SHA-1 commit identifiers for code versioning and SHA-256 for audit trails.
