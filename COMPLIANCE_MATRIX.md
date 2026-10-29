| ID | Certified Requirement | Test / Verification Reference | Certification Status |
| :--- | :--- | :--- | :--- |
| **A-01** | Application-Level Zeroization & State Isolation | `tests/test_engine.py::test_zeroize_memory` | **PASSED (Certified)** |
| **A-02** | Registry Identity Recycling — Mandatory Finding | `tests/test_engine.py::test_registry_identity_recycling` | **PASSED (Certified)** |
| **A-03** | Adversarial Sentinel Reconstruction — P0-03 | `tests/test_engine.py::test_adversarial_sentinel` | **PASSED (Certified)** |
| **A-04** | Fail-Closed Layer 5 Enforcement | `tests/test_engine.py::test_fail_closed_layer5` | **PASSED (Certified)** |
| **A-05** | OS-level network isolation boundaries | *Excluded from Scope A (Deferred to Scope B)* | **DEFERRED** |
| **A-06** | Low-level in-process runtime and attribute manipulation | *Excluded from Scope A (Deferred to Scope B)* | **DEFERRED** |
