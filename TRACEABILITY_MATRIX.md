# Scope B Traceability Matrix

This document maintains strict traceability between the frozen Scope B requirements baseline and the actual implementation and test coverage.

| Requirement ID | Frozen Baseline Description | Implementation Status | Implemented Component | Verification Test |
| :--- | :--- | :--- | :--- | :--- |
| **REQ-SCOPE-B-01** | Oracle isolation & state initialization | **IMPLEMENTED** | `src/scope_b/engine.py` (`ScopeBEngine.__init__`) | `tests/scope_b/test_engine.py` (`test_engine_initialization`) |
| **REQ-SCOPE-B-02** | ptrace / dump restriction (PR_SET_DUMPABLE) | **IMPLEMENTED** | `src/scope_b/engine.py` (`prctl`) | `tests/scope_b/test_engine.py` (`test_process_isolation_*`) |
| **REQ-SCOPE-B-03** | Seccomp Syscall Filtering | **NOT IMPLEMENTED** | Pending kernel filter integration | Pending |
| **REQ-SCOPE-B-04** | Failure detection & Fail-Closed mechanism | **IMPLEMENTED** | `src/scope_b/engine.py` (`_fail_closed`) | `tests/scope_b/test_engine.py` (`test_watchdog_signal_lost`) |
| **REQ-SCOPE-B-05** | Privilege Separation & UID isolation | **IMPLEMENTED (Partial)** | `src/scope_b/engine.py` (`prctl`) | `tests/scope_b/test_engine.py` (`test_process_isolation_*`) |
| **REQ-SCOPE-B-06** | Memory Locking (`mlockall`) | **IMPLEMENTED** | `src/scope_b/engine.py` (`mlockall`) | `tests/scope_b/test_engine.py` (`test_memory_hardening_execution`) |
| **REQ-SCOPE-B-07** | Watchdog signal verification | **IMPLEMENTED** | `src/scope_b/engine.py` (`check_watchdog_signal`) | `tests/scope_b/test_engine.py` (`test_watchdog_signal_*`) |

## Verification Note
- Status values strictly reflect the physical reality of the code in the repository.
- Mechanisms relying on real Linux OS primitives (`mlockall`, `prctl`) are verified via automated pytest execution.
