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
* **PA-04 (Audit Trails & Verification Logs):** Immutable hash logs (`SHA-1`) documenting privilege changes and fail-closed events.

### 2.2 Adversary Profiles & Scope Boundaries
* **Adversary B1 (In-Process Malicious/Compromised Code):** Code executing within the same CPython runtime attempting memory inspection or attribute tampering (e.g., via `__object.__setattr__` or `ctypes`).
  * *Status:* **IN-SCOPE** via Decision B1 (Dedicated privilege-separated worker daemon process; native C extensions within the main runtime are explicitly excluded).
* **Adversary B2 (Co-located Local Unprivileged Attacker):** Unprivileged local processes attempting memory reads via `/proc/<pid>/mem` or attachment via `ptrace`.
  * *Status:* **IN-SCOPE** (Mitigated via dedicated worker `UID`, `PR_SET_DUMPABLE=0`, and deployment prerequisite `yama.ptrace_scope=3`).
* **Adversary B3 (Kernel Exploit / Ring-0 Attacker):** Adversaries exploiting OS kernel vulnerabilities to subvert process boundaries.
  * *Status:* **EXCLUDED FROM SCOPE B** (Explicitly out of scope, kernel integrity assumed).
* **Adversary B4 (Physical / Cold-Boot / Hardware Attacker):** Physical probing, RAM freeze/cold-boot extraction, or hardware-level bus sniffing.
  * *Status:* **EXCLUDED FROM SCOPE B** (Requires dedicated TEE/HSM integration).
* **Adversary B5 (Runtime Invariant Manipulator):** Injecting asynchronous cancellations or unhandled exceptions to force a Fail-Open state.
  * *Status:* **IN-SCOPE** (Mitigated via out-of-event-loop watchdog monitoring executed inside the worker process).

---

## 3. Trust Boundaries & Isolation Primitives

### 3.1 Decision B1: Process Isolation & Key Offloading Design
To eliminate vulnerabilities stemming from CPython immutable object behavior and in-process memory exposure:
1. All key handling, cryptographic operations, and quorum/zeroization state enforcement are offloaded to a dedicated worker daemon process (`isolation worker`). Native C extensions sharing the main process memory space are disallowed.
2. The main application process communicates with the worker strictly via restricted, unidirectional POSIX IPC channels (Unix Domain Sockets).
3. The worker maintains an internal allow-list of IPC operations and unconditionally refuses all requests once a terminal zeroization state is reached.

### 3.2 System Call Filtering & Capability Stripping
* **Syscall Whitelisting (`seccomp-bpf`):** The isolated worker process applies a strict `seccomp` filter restricting available syscalls to essential IPC I/O and `sys_exit_group` after initialization. Any unwhitelisted syscall triggers immediate kernel termination via `SIGSYS`.
* **Privilege Drop & Initialization Sequence:**
  1. Lock memory buffers (`mlockall` / `RLIMIT_MEMLOCK`).
  2. Set `PR_SET_NO_NEW_PRIVS`.
  3. Drop process privileges to a dedicated non-root User ID (`UID`) distinct from the main application.
  4. Apply `seccomp-bpf` filters strictly after IPC initialization and privilege drop.

---

## 4. Compliance & Verification Matrix (`REQ-SCOPE-B-xx`)

| Requirement ID | Security Constraint | Verification Method | Audit Evidence |
| :--- | :--- | :--- | :--- |
| **REQ-SCOPE-B-01** | **Process Boundary Isolation:** Cryptographic operations must execute in a separate worker process with internal quorum and zeroization enforcement. | Test inter-process memory isolation and attempt oracle attacks on zeroized worker. | Process tree status & IPC authorization boundary logs. |
| **REQ-SCOPE-B-02** | **Ptrace & Dump Protection:** Worker runs under dedicated UID, blocking cross-process signaling, `/proc/<pid>/mem` access, and `ptrace` attachment (`PR_SET_DUMPABLE=0`). | Attempt `ptrace(PTRACE_ATTACH)` and cross-UID signal transmission during execution. | `EPERM` return code verification logs. |
| **REQ-SCOPE-B-03** | **Memory Swapping Prevention:** Key buffers must be locked in RAM using `mlockall(MCL_CURRENT \| MCL_FUTURE)`. | Verify `VmLck` status field in `/proc/self/status` during key lifecycle. | Non-zero `VmLck` audit verification report. |
| **REQ-SCOPE-B-04** | **Kernel Syscall Restriction:** Restrict available syscalls to an explicit whitelist via `seccomp-bpf` post-initialization. | Trigger prohibited syscalls within test harness. | Kernel `SIGSYS` signal & `sys_exit_group` audit log. |
| **REQ-SCOPE-B-05** | **Async Boundary Containment:** Out-of-loop watchdog monitor executes within the worker process, independent of the CPython interpreter. | Inject uncaught asynchronous delays and observe worker-driven fail-closed termination. | Watchdog termination log independent of CPython event loop. |

---

## 5. Formal Execution Invariants
1. **INV-B-01 & INV-B-02 (Deterministic Sequence & Memory Zeroization):** Upon anomaly detection, the worker MUST first execute deterministic volatile memory scrubbing/zeroization (`0x00`), and only then invoke `sys_exit_group`.
2. **INV-B-03 (Audit Trail Integrity):** Immutable SHA-1 Git commit hashes and cryptographic audit metrics are written to an external append-only sink or signed via an asymmetric key inaccessible to the main process.

---

## 6. Audit & Acceptance Criteria
* **Automated Integration Suite:** Must verify `seccomp` violation termination (`SIGSYS`), cross-UID `ptrace`/signal blockage, `VmLck` verification, socket EOF/PDEATHSIG failure detection, and memory non-leakage under induced `SIGSEGV`/`SIGBUS`.
* **Repository Placement:** Formally tracked under `THREAT_MODEL.md` and `SCOPE_B_REQUIREMENTS.md` in the repository root using explicit SHA-1 commit identifiers.
