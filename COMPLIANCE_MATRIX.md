# Certified Scope A Compliance Matrix

| ID | Certified Requirement | Test / Verification Reference | Status |
| :--- | :--- | :--- | :--- |
| **A-01** | Application-Level Zeroization & State Isolation | *Certified in baseline 191928d* | **PASSED** |
| **A-02** | Registry Identity Recycling — Mandatory Finding | *Certified in baseline 191928d* | **PASSED** |
| **A-03** | Adversarial Sentinel Reconstruction — P0-03 | *Certified in baseline 191928d* | **PASSED** |
| **A-04** | Fail-Closed Layer 5 Enforcement | *Certified in baseline 191928d* | **PASSED** |
| **A-05** | OS Network Isolation Boundary Clarification — EXCLUDED FROM SCOPE A | *N/A* | **EXCLUDED** |
| **A-06** | Low-level object.__setattr__ on engine slots — EXCLUDED FROM SCOPE A | *N/A* | **EXCLUDED** |

---

> **Note on Baseline & Scope Separation:**  
> This matrix reflects the exact certified baseline from commit `191928d0e5354d8686c664a9aaa20e7ca2d323df`[span_5](start_span)[span_5](end_span). Process termination via `os._exit(101)` is recorded separately under **E-06 (partial)**[span_6](start_span)[span_6](end_span)[span_7](start_span)[span_7](end_span). OS-level network isolation and process-level boundary controls are specified under **Scope B**[span_8](start_span)[span_8](end_span).
