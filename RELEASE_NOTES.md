# Release Notes - v1.0.0-rc (Scope A Candidate)

## Overview
This release finalizes **Scope A – Application-Level Assurance (Pending Final Certification)** for the HAI Lab Fail-Closed Engine, resolving all technical and documentation findings identified during the independent and adversarial reviews.

## Verification Artifacts & Target SHA
* **Frozen Commit SHA:** `191928d`
* **CI Test Suite Execution:** 100% PASS (Full regression suite passed across 20/20 test cases including 200-iteration registry identity recycling).

## Key Updates & Fixes

### 1. Mandatory Finding 3 Fix (Registry Identity Recycling)
* Fully resolved state inheritance and identifier reuse bugs across sequential engine lifecycles.
* Verified via a strict 200-iteration regression test (`test_registry_identity_recycling_200_iterations`) asserting zeroized state isolation and guaranteed instance UUID uniqueness (0/200 false zeroizations).

### 2. Adversarial Robustness & Code Alignment
* Enforced immutable fail-closed invariants against class swapping, sentinel reconstruction, and attribute tampering (P0-03/P0-04 tests).
* Aligned registry docstrings and code implementation by removing unused `weakref` references.
* **Low-Level Attribute Override Exclusion (`REQ-SCOPE-A-06`):** Low-level in-process attribute overrides via `object.__setattr__` targeting internal slots are explicitly excluded from Scope A and deferred to Scope B process isolation.

### 3. Boundary & Documentation Clarifications
* **THREAT_MODEL.md & COMPLIANCE_MATRIX.md Alignment:** Accurately reflects *Scope A – Application-Level Assurance (Pending Final Certification)* across all artifacts.
* **Network Isolation Clarification (`is_isolated=True` & `iptables`):** Setting `is_isolated=True` in code represents logical intent only. It **does not** establish OS-level network isolation unless concrete, verified execution results from `iptables` are confirmed by the host environment. OS-level network filtering remains strictly excluded from Scope A guarantees.

---

## Certification Summary
* **Regression Test Suite:** 100% PASS
* **Scope A Code Baseline:** Frozen (`191928d`) & Audited
* **Decision Status:** Scope A Conditionally Accepted — Awaiting Phase 5 Gatekeeper Certificate Sign-off.
