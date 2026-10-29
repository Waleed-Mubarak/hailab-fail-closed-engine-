| Requirement ID | Description | Implementation / Verification Status | Test Reference / Proof |
| :--- | :--- | :--- | :--- |
| **REQ-SCOPE-A-01** | Application-Level Zeroization & State Isolation | **PASSED** - Volatile key material zeroized; engine transitions into immutable state. | `tests/test_engine.py`, (`test_p0_04_zeroization_idempotence`) |
| **REQ-SCOPE-A-02** | Registry Identity Recycling (Mandatory Finding 3) | **PASSED** - Validated across 200 sequential engine iterations without state leakage or identifier reuse. | `tests/test_engine.py` (`test_registry_identity_recycling_200_iterations`) |
| **REQ-SCOPE-A-03** | Adversarial Sentinel Reconstruction (P0-03) | **PASSED** - Denies access under stub deletion, class-swapping, and attribute tampering. | `tests/test_engine.py` (`test_p0_03...` series) |
| **REQ-SCOPE-A-04** | Fail-Closed Layer 5 Enforcement | **PASSED** - Locks execution path deterministically upon contract or admissibility violation. | `tests/test_engine.py` (`test_p0_05_layer5_fail_closed_enforcement`) |
| **REQ-SCOPE-A-05** | OS Network Isolation Boundary Clarification | **EXCLUDED FROM SCOPE A** - Application-level flag (`is_isolated=True`) does not guarantee OS-level network isolation without verified `iptables` execution. | Explicitly documented in `README.md` & `THREAT_MODEL.md` |
| **REQ-SCOPE-A-06** | Low-level object.__setattr__ on engine slots (including identity storage) | **EXCLUDED FROM SCOPE A (Scope B)** - In-process runtime memory manipulation via low-level attribute overrides falls under Scope B and requires OS/container isolation. | Documented in `THREAT_MODEL.md` & `RELEASE_NOTES.md` |

**Note on Baseline & Scope Separation:**
This matrix reflects the Phase 5 Scope A certificate issued on 26 October 2026 for commit `191928d0e5354d8686c664a9aaa20e7ca2d323df`. Keep E-06 (partial), process termination via `os._exit(101)`, as a separate line. 

*(Boundary statements and exclusions now live in `README.md`, "Security Boundaries & Scope Exclusions")*
