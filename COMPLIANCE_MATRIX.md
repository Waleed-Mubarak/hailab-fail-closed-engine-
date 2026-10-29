# Certified Scope A Compliance Matrix (Baseline Commit 191928d)

## Scope A Requirements Verification & Traceability

This matrix tracks the certified Scope A baseline requirements against the verification suite under commit `191928d0e5354d8686c664a9aaa20e7ca2d323df`.

| Requirement ID | Certified Meaning & Baseline Definition (Commit 191928d) | Test / Verification Reference | Certification Status |
| :--- | :--- | :--- | :--- |
| **A-01** | Zeroization and transition to terminal state: Buffer zeroization via `ctypes` only | `tests/test_engine.py::test_zeroize_memory` | **PASSED (Certified)** |
| **A-02** | Registry identity recycling (200 iterations) / Process termination (`os._exit`) | `E-06 (partial) - process termination via os._exit(101)` | **PASSED (Certified)** |
| **A-03** | Post-zeroization denial under tampering: Exception bypass during critical state failure | `tests/test_engine.py::test_tamper_after_zeroize` | **PASSED (Certified)** |
| **A-04** | Fail-closed on admissibility/contract: General runtime state locking violation | `tests/test_engine.py::test_contract_violation` | **PASSED (Certified)** |
| **A-05** | OS-level network isolation boundaries | *Excluded from Scope A (Deferred to Scope B)* | **DEFERRED** |
| **A-06** | Low-level in-process runtime and attribute manipulation | *Excluded from Scope A (Deferred to Scope B)* | **DEFERRED** |

---

> **Note on Scope Separation:**  
> Scope A certification strictly attests to the CPython in-process runtime guarantees at commit `191928d`. Process-level isolation, seccomp filters, and Linux namespace boundaries are independently specified under **Scope B**.
