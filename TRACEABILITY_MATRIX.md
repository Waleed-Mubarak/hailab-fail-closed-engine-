# Scope B Traceability Matrix (Frozen Baseline vs Implementation)

| Requirement ID | Frozen Baseline Definition | Implementation Status | Corresponding Real OS Mechanism | Verified by Test |
| :--- | :--- | :--- | :--- | :--- |
| **REQ-SCOPE-B-01** | Oracle isolation; refusal after zeroization | **IMPLEMENTED** | Separate worker process (`os.fork`) & post-zeroization lock | `test_engine_initialization_and_isolation`, `test_zeroization_refusal` |
| **REQ-SCOPE-B-02** | ptrace / dump / UID isolation | **IMPLEMENTED** | `prctl(PR_SET_DUMPABLE, 0)` restriction | `test_engine_initialization_and_isolation` |
| **REQ-SCOPE-B-03** | seccomp, SECCOMP_RET_KILL_PROCESS | **IMPLEMENTED** | `prctl(PR_SET_NO_NEW_PRIVS)` & strict syscall allow-list policy | `test_syscall_policy_validation` |
| **REQ-SCOPE-B-04** | Fail-Closed Mechanism on Security Breach | **IMPLEMENTED** | `PR_SET_PDEATHSIG` & `os.waitpid` unexpected termination catch | `test_worker_process_unexpected_termination` |
| **REQ-SCOPE-B-05** | Privilege Separation & UID isolation | **IMPLEMENTED** | UID/GID privilege verification and process hardening | `test_engine_initialization_and_isolation` |
| **REQ-SCOPE-B-06** | Memory Locking & Hardening | **IMPLEMENTED** | `libc.mlockall(MCL_CURRENT \| MCL_FUTURE)` | `test_engine_initialization_and_isolation` |
| **REQ-SCOPE-B-07** | Dedicated watchdog process | **IMPLEMENTED** | Live IPC pipe (`multiprocessing.Pipe`) with PING/PONG liveness check | `test_watchdog_and_ipc_liveness` |
