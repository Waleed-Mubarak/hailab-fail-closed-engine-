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
  * *Status:* **PARTIALLY IN-SCOPE** (with residual pre-termination risk acknowledged per Req-B1.3). Protection against B1 is strictly enforced via unconditional **post-zeroization refusal**, subject to stated trust assumptions and verification evidence.
* **Adversary B2 (Co-located Local Unprivileged Attacker):** Unprivileged local processes attempting memory reads via `/proc/<pid>/mem` or attachment via `ptrace`.
  * *Status:* **IN-SCOPE** (Mitigated via dedicated worker `UID`, `PR_SET_DUMPABLE=0`, and deployment prerequisite `yama.ptrace_scope=3`).
* **Adversary B3 (Kernel Exploit / Ring-0 Attacker):** Adversaries exploiting OS kernel vulnerabilities to subvert process boundaries.
  * *Status:* **EXCLUDED FROM SCOPE B** (Explicitly out of scope, kernel integrity assumed).
* **Adversary B4 (Physical / Cold-Boot / Hardware Attacker):** Physical probing, RAM freeze/cold-boot extraction, or hardware-level bus sniffing.
  * *Status:* **EXCLUDED FROM BOTH SCOPE A AND SCOPE B** (Requires dedicated TEE/HSM integration).
* **Adversary B5 (Runtime Invariant Manipulator):** Injecting asynchronous cancellations or unhandled exceptions to force a Fail-Open state.
  * *Status:* **IN-SCOPE** (Mitigated via out-of-event-loop watchdog monitoring executed inside the worker daemon process).

---

## 3. Trust Boundaries & Isolation Primitives

### 3.1 Decision B1: Process Isolation & IPC Design
1. Key handling and zeroization enforcement are offloaded to a dedicated worker daemon process (`isolation worker`).
2. The main process communicates with the worker over Unix domain sockets using `SO_PEERCRED` validation, structured message framing, length enforcement, and strict malformed request rejection.
3. Post-zeroization refusal is unconditionally enforced for any subsequent requests.

### 3.2 Initialization Sequence & System Call Filtering
* **Strict Worker Initialization Sequence:**
  1. **Memory Locking:** Invoke `mlockall(MCL_CURRENT | MCL_FUTURE)` (REQ-SCOPE-B-06). If `mlockall` fails (e.g., due to insufficient `RLIMIT_MEMLOCK`), worker startup **halts immediately**. Host deployment prerequisite strictly requires swap to be disabled or verified encrypted at deployment.
  2. **UID/GID Transition:** Drop privileges to a dedicated non-root UID/GID.
  3. **Capability Stripping:** Clear all process capabilities and verify `CapEff = 0` and `CapBnd = 0` via `/proc/self/status`. Startup halts immediately if non-zero.
  4. **Dumpability Control:** Set `PR_SET_DUMPABLE = 0`.
  5. **No New Privs:** Set `PR_SET_NO_NEW_PRIVS`.
  6. **Syscall Filtering:** Apply `seccomp-bpf` whitelist filters last.

* **Explicit Seccomp Syscall Allow-list:**
  * **Permitted Syscalls by Name:** `read`, `write`, `close`, `readv`, `writev`, `socketpair`, `epoll_wait`, `epoll_ctl`, `exit_group`, `futex`, `clock_gettime`, `sigreturn`.
  * **Enforcement Action:** Any syscall outside this list triggers immediate kernel process termination via `SECCOMP_RET_KILL_PROCESS`. Tested via non-whitelisted syscall invocation.

---

## 4. Unified Compliance & Verification Matrix (`REQ-SCOPE-B-xx`)

| Requirement ID | Security Constraint | Verification Method | Audit Evidence |
| :--- | :--- | :--- | :--- |
| **REQ-SCOPE-B-01** | **Process Boundary & Oracle Isolation:** Worker enforces IPC allow-list and unconditionally refuses post-zeroization requests. | Inter-process isolation test under induced tampering. | `OPERATION_REFUSED` verification logs. |
| **REQ-SCOPE-B-02** | **Ptrace, Memory Dump & UID Isolation:** Dedicated non-root UID with `PR_SET_DUMPABLE=0` blocks cross-UID ptrace and `/proc/<pid>/mem`. | Attempt `ptrace(PTRACE_ATTACH)` and cross-UID signaling. | `EPERM` return code logs. |
| **REQ-SCOPE-B-03** | **Kernel Syscall Restriction:** Seccomp allow-list enforced with `SECCOMP_RET_KILL_PROCESS`. | Trigger unauthorized syscalls in harness. | Kernel `SIGSYS` / `SECCOMP_RET_KILL_PROCESS` logs. |
| **REQ-SCOPE-B-04** | **Inter-Process Failure Detection:** Abrupt main process death triggers instant worker zeroization via `PR_SET_PDEATHSIG` / Socket EOF. | Simulate main process crash. | Crash integration test logs. |
| **REQ-SCOPE-B-05** | **Privilege Drop & Capability Check:** Startup halts if `CapEff > 0` or `CapBnd > 0`. | Attempt startup with retained privileges. | `/proc/self/status` audit logs. |
| **REQ-SCOPE-B-06** | **Memory Locking Guarantee:** `mlockall` failure halts worker startup immediately. Swap must be disabled or encrypted. | Simulate `RLIMIT_MEMLOCK` exhaustion. | Startup failure & mlockall audit logs. |
| **REQ-SCOPE-B-07** | **Independent Watchdog Monitor:** Dedicated watchdog process monitors worker health out-of-event-loop. | Inject watchdog heartbeat delays. | Watchdog kill audit logs. |

---

## 5. Execution Invariants & Fault Handling Boundaries

### 5.1 Controlled Anomaly Handling vs. Abrupt Signal Failure
* **Controlled Anomaly Handling (INV-B-01):** Under detected application errors or clean shutdown triggers, the worker executes deterministic volatile memory scrubbing/zeroization (`0x00`), followed by `sys_exit_group`.
* **Abrupt Failures & Memory Faults (INV-B-02):** Under abrupt failures (e.g., `SIGKILL`, or `SIGSEGV`/`SIGBUS` occurring directly within the scrubbing execution path itself), scrubbing is provided on a **best-effort** basis. Residual exposure includes unscrubbed RAM pages until OS process cleanup. Residual risks and measured metrics are logged to audit channels.

### 5.2 Versioning & Hash Standards
* **Git Versioning:** Versioning references rely exclusively on **SHA-1** commit identifiers.
* **Audit Trail Integrity:** Operational logs compute hashes using **SHA-256** (or stronger) to append-only sinks.

---

## 6. Audit & Acceptance Criteria
* **Automated Integration Suite:** Verifies `SECCOMP_RET_KILL_PROCESS` termination, cross-UID `ptrace` blockage (`EPERM`), capability zeroing verification, `mlockall` startup halts, watchdog timeouts, and measured residual exposure under induced `SIGSEGV`/`SIGBUS`.
* **Repository Synchronization:** Formally tracked in `THREAT_MODEL.md` in lockstep with `SCOPE_B_REQUIREMENTS.md` (Revision 5).
