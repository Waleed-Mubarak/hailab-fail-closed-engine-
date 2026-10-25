# Release Notes - v1.0.0-rc (Scope A Candidate)

## Overview
This release finalizes **Scope A – Application-Level Assurance (Pending Final Certification)** for the HAI Lab Fail-Closed Engine, resolving all technical blockers identified during the adversarial review.

## Key Updates & Fixes

### 1. Mandatory Finding 3 Fix (Registry Identity Recycling)
* Fully resolved state inheritance and identifier reuse bugs across sequential engine lifecycles.
* Verified via a strict 200-iteration regression test (`test_registry_identity_recycling_200_iterations`) asserting zeroized state isolation and guaranteed instance UUID uniqueness.

### 2. Adversarial Robustness Enhancements (Red-Team Findings)
* Enforced immutable fail-closed invariants against class swapping, sentinel reconstruction, and attribute tampering (P0-03 tests).
* Verified zeroization idempotency ($Z^2 = Z$) and raw memory snapshot cleanup.

### 3. Boundary & Documentation Clarifications
* **THREAT_MODEL.md Update:** Removed premature "certified" status labels to accurately reflect *Scope A – Application-Level Assurance (Pending Final Certification)*.
* **Network Isolation Clarification (`is_isolated=True` & `iptables`):** Setting `is_isolated=True` in code represents logical intent only. It **does not** establish OS-level network isolation unless concrete, verified execution results from `iptables` are confirmed by the host environment. OS-level network filtering remains strictly excluded from Scope A guarantees.

---

## Certification Summary
* **Regression Test Suite:** 100% PASS
* **Scope A Code Baseline:** Frozen & Audited
* **Next Phase:** Final Documentation Sign-off & Scope B Hardware Integration Roadmap

