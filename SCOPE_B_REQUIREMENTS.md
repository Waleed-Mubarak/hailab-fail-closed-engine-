# SCOPE B TECHNICAL REQUIREMENTS & ACCEPTANCE SPECIFICATIONS

## 1. Scope & System Dependencies
This document specifies the exact requirements for **Phase 3 / Scope B** implementation. Scope B is evaluated independently from Scope A certification.

## 2. Decision B1: Process Separation Specification
- **Req-B1.1:** The engine must spawn a dedicated process boundary for sensitive payload handling.
- **Req-B1.2:** Communication between the CPython runtime and the isolated process must use unidirectional or restricted POSIX IPC channels.
- **Req-B1.3:** Failure or anomaly in the main CPython process must trigger instant zeroization inside the isolated process via independent hardware/kernel signals.

## 3. Explicit Non-Coverage Declarations (Exclusions)
- **Kernel-Level Vulnerabilities (Adversary B3):** Excluded. Scope B assumes kernel integrity.
- **Physical & Hardware Attacks (Adversary B4):** Excluded. Physical RAM extraction, bus sniffing, and cold-boot attacks require TEE/HSM hardware modules not covered in Scope B.

## 4. Verification & Audit Trail Requirements
- Every implementation file in `src/isolation/` and `tests/test_scope_b.py` will be bound to an explicit SHA-256 commit hash upon completion.

