# Scope B Traceability Matrix (Frozen Baseline vs Implementation)

| Requirement ID | Frozen Baseline Definition | Implementation Status | Corresponding Real OS Mechanism | Verified by Test |
| :--- | :--- | :--- | :--- | :--- |
| **REQ-SCOPE-B-01** | Oracle isolation; refusal after zeroization | **NOT IMPLEMENTED** | Worker holds no key material; basic PING-PONG | Pending proper worker state |
| **REQ-SCOPE-B-02** | ptrace / dump / UID isolation | **NOT IMPLEMENTED** | Worker runs under same UID; no `EPERM` test on `/proc/<pid>/mem` | Pending UID/dumpable enforcement in worker |
| **REQ-SCOPE-B-03** | seccomp, SECCOMP_RET_KILL_PROCESS | **NOT IMPLEMENTED** | No seccomp filter installed (`Seccomp: 0`) | Pending real seccomp filter installation |
| **REQ-SCOPE-B-04** | Fail-Closed Mechanism on Security Breach | **PARTIAL** | `PR_SET_PDEATHSIG(SIGKILL)` terminates worker on parent death | `test_worker_process_unexpected_termination` |
| **REQ-SCOPE-B-05** | Privilege Separation & UID isolation | **NOT IMPLEMENTED** | Processes retain root UID and full capabilities | Pending UID drop & capability bounding set zeroing |
| **REQ-SCOPE-B-06** | Memory Locking & Hardening | **NOT IMPLEMENTED** | `mlockall` runs in parent only; failure caught with `pass` | Pending strict startup halt on `mlockall` failure |
| **REQ-SCOPE-B-07** | Dedicated watchdog process | **NOT IMPLEMENTED** | IPC pipe with PING/PONG in main process, no separate timer/UID | Pending dedicated watchdog process with separate failure domain |
