# HAI Lab Fail-Closed Engine

Deterministic zeroization and autonomous fail-closed security engine for critical infrastructure and resilient architectures.

---

## Architectural & Scope A Specifications

This repository implements the certified Scope A Baseline for autonomous fail-closed security, adhering strictly to the following core parameters:

* Core Functionality: Deterministic volatile key-material RAM zeroization and terminal state enforcement.
* Certified Baseline Commit: 191928d0e5354d8686c664a9aaa20e7ca2d323df (Phase 5 Gatekeeper standards).

> Note on Certification Boundaries: Features such as Hysteresis Suppression and Integrated SHA-256 state tracking are experimental/extension mechanisms and are not part of the certified Scope A Baseline.

---

## Security Boundaries & Scope Exclusions

* Scope A Coverage: Governs volatile memory scrubbing (ctypes), immediate process termination on unhandled breaches (os._exit(101)), and runtime state locking strictly within src/engine.py.
* Scope A Exclusions: The Scope A certificate explicitly excludes:
  * REQ-SCOPE-A-05: OS-level network isolation boundaries.
  * REQ-SCOPE-A-06: Low-level in-process runtime memory and attribute manipulation (e.g., object.__setattr__, closure or frame introspection, and ctypes overrides).
* General Exclusions: 
  * Physical RAM extraction and hardware/cold-boot attacks are strictly excluded from both Scope A and Scope B.
  * Multi-process isolation boundaries are addressed separately under Scope B development.

---

## Installation & Setup

Install the package directly from your local development environment:

pip install .

---

## Quickstart & Implementation

Protect critical runtime workflows and data processing using the certified engine core (src/engine.py):

from src.engine import FailClosedEngine

engine = FailClosedEngine()

try:
    engine.execute_critical_operation()
except Exception:
    engine.zeroize()
    assert engine.is_zeroized()

---

## License

This project is licensed under the MIT License:

MIT License

Copyright (c) 2026 HAI Lab

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to persons to whom the
Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
