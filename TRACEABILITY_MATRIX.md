# Scope B Traceability Matrix (Frozen Baseline vs Implementation)

| Requirement ID | Frozen Baseline Definition | Implementation Status | Corresponding Real OS Mechanism | Verified by Test |
| :--- | :--- | :--- | :--- | :--- |
| **REQ-SCOPE-B-01** | Oracle isolation; refusal after zeroization | **IMPLEMENTED** | Key material generated exclusively inside worker via `os.urandom(32)`, strict pipe protocol, complete buffer zeroization, and unconditional `OPERATION_REFUSED` post-zeroization | `test_scope_b_01_zeroization_lifecycle` |
| **REQ-SCOPE-B-02** | ptrace / dump / UID isolation | **NOT IMPLEMENTED** | Worker runs under UID 65534 with `PR_SET_DUMPABLE(0)`; `EPERM` test on `/proc/<pid>/mem` pending | Pending `EPERM` test on `/proc/<pid>/mem` |
| **REQ-SCOPE-B-03** | seccomp, SECCOMP_RET_KILL_PROCESS | **IMPLEMENTED** | Strict BPF seccomp filter installed via `prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER)` with `SECCOMP_RET_KILL_PROCESS` on violations | `test_seccomp_sigsys_kill` |
| **REQ-SCOPE-B-04** | Fail-Closed Mechanism on Security Breach | **PARTIAL** | `PR_SET_PDEATHSIG(SIGKILL)` terminates worker on parent death | Pending dedicated termination test |
| **REQ-SCOPE-B-05** | Privilege Separation & UID isolation | **IMPLEMENTED** | Strict UID/GID drop to 65534, capability bounding set zeroing, `CapEff/CapBnd` zeroed, `PR_SET_NO_NEW_PRIVS`, and `PR_SET_DUMPABLE(0)` re-verified post-setuid | `test_scope_b_kernel_state_enforcement` |
| **REQ-SCOPE-B-06** | Memory Locking & Hardening | **IMPLEMENTED** | Strict `mlockall(MCL_CURRENT | MCL_FUTURE)` with strict startup halt (Fail-Closed) on failure | `test_scope_b_kernel_state_enforcement`, `test_mlockall_failure` |
| **REQ-SCOPE-B-07** | Dedicated watchdog process | **NOT IMPLEMENTED** | IPC pipe with PING/PONG in main process, no separate timer/UID | Pending dedicated watchdog process with separate failure domain |
