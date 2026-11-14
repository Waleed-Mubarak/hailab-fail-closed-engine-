# Scope B Traceability Matrix (Frozen Baseline vs Implementation)

| Requirement ID | Frozen Baseline Definition | Implementation Status | Corresponding Real OS Mechanism | Verified by Test |
| :--- | :--- | :--- | :--- | :--- |
| **REQ-SCOPE-B-01** | Oracle isolation; refusal after zeroization | **IMPLEMENTED** | Key material generated exclusively inside worker via `os.urandom(32)`, strict pipe protocol, complete buffer zeroization, and unconditional `OPERATION_REFUSED` post-zeroization | `test_scope_b_01_zeroization_lifecycle` |
| **REQ-SCOPE-B-02** | ptrace / dump / UID isolation | **IMPLEMENTED** | UID separation (65534), `PR_SET_DUMPABLE(0)` with verified `PR_GET_DUMPABLE == 0`, preventing external memory inspection via `/proc/<pid>/mem` | `test_scope_b_02_mem_access_denied`, `test_scope_b_kernel_state_enforcement` |
| **REQ-SCOPE-B-03** | seccomp, SECCOMP_RET_KILL_PROCESS | **IMPLEMENTED** | Strict BPF seccomp filter installed via `prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER)` with `SECCOMP_RET_KILL_PROCESS` on violations | `test_seccomp_sigsys_kill` |
| **REQ-SCOPE-B-04** | Fail-Closed Mechanism on Security Breach | **IMPLEMENTED** | `PR_SET_PDEATHSIG(SIGKILL)` terminates worker immediately upon unexpected parent termination | `test_worker_process_unexpected_termination` |
| **REQ-SCOPE-B-05** | Privilege Separation & UID isolation | **IMPLEMENTED** | Strict UID/GID drop to 65534, capability bounding set zeroing, `CapEff/CapBnd` zeroed, `PR_SET_NO_NEW_PRIVS`, and `PR_SET_DUMPABLE(0)` re-verified post-setuid | `test_scope_b_kernel_state_enforcement` |
| **REQ-SCOPE-B-06** | Memory Locking & Hardening | **IMPLEMENTED** | Strict `mlockall(MCL_CURRENT | MCL_FUTURE)` with strict startup halt (Fail-Closed) on failure | `test_scope_b_kernel_state_enforcement`, `test_mlockall_failure` |
| **REQ-SCOPE-B-07** | Dedicated watchdog process | **IMPLEMENTED** | Dedicated independent watchdog process (`watchdog_process_target`) monitoring worker liveness and responsiveness over isolated IPC | `test_scope_b_07_watchdog_monitoring` |
