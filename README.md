Scope A – Application-Level Assurance (Pending Final Certification)

# Edge Zeroization Engine & Security Architecture

> *"Software isolation is a myth; hardware state is the only truth."*

Security-first architecture for mission-critical edge nodes, designed to prevent data extraction and ensure deterministic destruction under duress.

---

## 🔒 Security Guarantee Boundaries (Threat Model)

* **Scope A – Application-Level Assurance (Pending Final Certification):** Guarantees zeroization, registry isolation, and terminal state lockdown against public API abuse and application-level attack vectors. *(Note: OS-level network isolation via iptables is explicitly excluded from the current Scope A guarantee).*[span_3](start_span)[span_3](end_span)[span_4](start_span)[span_4](end_span)
* **Scope B (OS & Hardware Level - Future Roadmap):** In-process adversary memory protection requires OS-level process isolation (`seccomp`, containers) or hardware-enforced trusted execution environments (TEE/HSM).[span_5](start_span)[span_5](end_span)

 
 Guarantees zeroization, registry isolation, and terminal state lockdown against public API abuse and application-level attack vectors.
- **Scope B (OS & Hardware Level - Future Roadmap):** In-process adversary memory protection requires OS-level process isolation (`seccomp`, containers) or hardware-enforced trusted execution environments (TEE/HSM).

---


# Edge Zeroization Engine & Security Agent

> *"Software isolation is a myth; hardware state is the only truth."*

Security-first architecture for mission-critical edge nodes, designed to prevent data extraction and ensure deterministic destruction under duress.

---

## 📊 Project Status & Badges

![CI](https://img.shields.io/badge/CI-passing-brightgreen)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
[![DEV.to](https://img.shields.io/badge/DEV.to-Waleed--Mubarak-black)](https://dev.to)
[![Substack](https://img.shields.io/badge/Substack-HAI%20Lab-orange)](https://substack.com)

---

## 🚀 Quick Start & Installation

### 1. Clone the Repository
* Command: https://github.com/Waleed-Mubarak/hailab-fail-closed-engine-.git
* Directory: `cd hailab-fail-closed-engine-`

### 2. Basic Usage Example
* Script: `from src.engine import TurkashEngine`
* Code: `engine = TurkashEngine()`
* Trigger Check: `engine.check_duress_trigger(True)`
* Authorization A: `engine.authorize_recovery("Admin_A")`
* Authorization B: `engine.authorize_recovery("Admin_B")`

---

## 🎮 Interactive Demos & Simulations

Run the live interactive demonstrations directly from your terminal:

* **Main Engine Demo:** `python demo.py`
* **Edge Duress Simulation:** `python3 simulate_duress.py`

---

## 🧪 Running Tests & Verification

To run the test suite smoothly without any import path issues:

* Test Command: `PYTHONPATH=. pytest tests/`

---

## 🏗️ Repository Architecture & Design Principles

* **docs/**
  * └── Annex_A_Technical_Specification.md
  * └── Turkash_ASV_SDP_White_Paper_V2.pdf
* **src/**
  * └── ...

### Architectural Boundaries & Admissibility
1. **Quorum vs. Admissibility:** Reaching the administrative quorum alone does not authorize execution. Full execution admissibility is strictly governed by rules and state validation.
2. **Operational Integrity:** Multi-sample temporal filtering is applied alongside functions like `verify_chassis_sensors()` to enforce physical security invariants.

---

## 📜 License & Proprietary Notice

© 2026 Waleed Mubarak. All Rights Reserved.  
This repository contains proprietary deep-tech architecture. Unauthorized commercial use, duplication, or integration is strictly prohibited. For licensing inquiries, contact the author directly.
