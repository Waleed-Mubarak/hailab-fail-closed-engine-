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
* **PA-04 (Audit Trails & Verification Logs):** Immutable hash logs (`SHA-256`) documenting privilege changes and fail-closed events.

### 2.2 Adversary Profiles & Scope Boundaries
* **Adversary B1 (In-Process Malicious/Compromised Code):** Code executing within the same CPython runtime attempting memory inspection or attribute tampering (e.g., via `__object.__setattr__` or `ctypes`).
  * *Status:* **IN-SCOPE** via Decision B1 (Dedicated privilege-separated process boundary).
* **Adversary B2 (Co-located Local Unprivileged Attacker):** Unprivileged local processes attempting memory reads via `/proc/<pid>/mem` or attachment via `ptrace`.
  * *Status:* **IN-SCOPE** (Mitigated via `PR_SET_DUMPABLE=0` and `yama.ptrace_scope=3`).
* **Adversary B3 (Kernel Exploit / Ring-0 Attacker):** Adversaries exploiting OS kernel vulnerabilities to subvert process boundaries.
  * *Status:* **EXCLUDED FROM SCOPE B** (Explicitly out of scope).
* **Adversary B4 (Physical / Cold-Boot / Hardware Attacker):** Physical probing, RAM freeze/cold-boot extraction, or hardware-level bus sniffing.
  * *Status:* **EXCLUDED FROM SCOPE B** (Requires dedicated TEE/HSM integration).
* **Adversary B5 (Runtime Invariant Manipulator):** Injecting asynchronous cancellations or unhandled exceptions to force a Fail-Open state.
  * *Status:* **IN-SCOPE** (Mitigated via out-of-event-loop watchdog monitoring).

---

## 3. Trust Boundaries & Isolation Primitives

### 3.1 Decision B1: Process Isolation & Key Offloading Design
To eliminate vulnerabilities stemming from CPython immutable object behavior (where `bytes`/`str` objects allocated by CPython cannot be guaranteed zeroed in-place due to interpreter free-lists), Scope B strictly enforces **Decision B1**:
1. All key handling and sensitive cryptography are offloaded to a dedicated, isolated worker process (Native C extension or privilege-dropped daemon).
2. The main application process communicates with the worker strictly via restricted IPC.
3. In-process CPython state tampering (`REQ-SCOPE-A-06`) cannot inspect or modify key buffers residing inside the isolated worker process memory space.

### 3.2 System Call Filtering & Capability Stripping
* **Syscall Whitelisting (`seccomp-bpf`):** The isolated engine process applies a strict `seccomp` filter allowing only essential I/O and `sys_exit_group`. Any unwhitelisted syscall (e.g., `execve`, `socket`) causes immediate kernel termination.
* **Capability Dropping Sequence:** Order of privilege stripping is strictly enforced:
  1. Lock memory buffers (`mlockall` / `RLIMIT_MEMLOCK`).
  2. Drop capabilities (`CAP_SYS_PTRACE`, `CAP_NET_RAW`, etc.).
  3. Drop `CAP_SETPCAP` last to prevent capability regaining.
  4. Audit capability status via `/proc/self/status` (`CapBnd`, `CapEff`).

---

## 4. Compliance & Verification Matrix (`REQ-SCOPE-B-xx`)

| Requirement ID | Security Constraint | Verification Method | Audit Evidence |
| :--- | :--- | :--- | :--- |
| **REQ-SCOPE-B-01** | **Process Boundary Isolation:** Cryptographic operations must execute in a separate process space isolated from the main CPython runtime. | Test inter-process memory isolation under induced CPython attribute tampering. | Process tree status & IPC boundary inspection logs. |
| **REQ-SCOPE-B-02** | **Ptrace & Dump Protection:** Process memory must block `/proc/<pid>/mem` access and `ptrace` attachment (`PR_SET_DUMPABLE=0`). | Attempt `ptrace(PTRACE_ATTACH)` and `/proc/self/mem` read operations during execution. | `EPERM` return code verification logs. |
| **REQ-SCOPE-B-03** | **Memory Swapping Prevention:** Key buffers must be locked in RAM using `mlockall(MCL_CURRENT \| MCL_FUTURE)`. | Verify `VmLck` status field in `/proc/self/status` during key lifecycle. | Non-zero `VmLck` audit verification report. |
| **REQ-SCOPE-B-04** | **Kernel Syscall Restriction:** Restrict available syscalls to an explicit whitelist via `seccomp-bpf`. | Trigger prohibited syscalls (`execve`, `socket`) within test harness. | Kernel SIGSYS signal & `sys_exit_group` audit log. |
| **REQ-SCOPE-B-05** | **Async Boundary Containment:** Asynchronous task timeouts or cancellations must trigger out-of-loop fail-closed sequence. | Inject uncaught `asyncio.CancelledError` and delay signals. | Watchdog termination log independent of CPython event loop. |

---

## 5. Formal Execution Invariants
1. **INV-B-01 (Kernel-Enforced Failure Termination):** Any breach of security invariants triggers immediate termination via `sys_exit_group`, bypassing CPython signal handlers.
2. **INV-B-02 (Zero Residual Memory Footprint in Isolated Process):** All native buffers in the isolated process are overwritten (`0x00`) before page release.
3. **INV-B-03 (Audit Trail Integrity):** Immutable SHA-256 hashes record all privilege drop states and execution transitions.

---

## 6. Audit & Acceptance Criteria
* **Automated Integration Suite:** Must verify `seccomp` violation termination, `ptrace` blockage, `VmLck` verification, and memory non-leakage under induced `SIGSEGV`/`SIGBUS`.
* **Repository Placement:** Formally tracked under `THREAT_MODEL.md` and `SCOPE_B_REQUIREMENTS.md` in the repository root.
