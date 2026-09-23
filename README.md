# Edge Zeroization Engine & Security Agent

> **"Software isolation is a myth; hardware state is the only truth."**

**Security-first architecture for mission-critical edge nodes, designed to prevent data extraction and ensure deterministic destruction under duress.**

---

## 🏗️ Repository Architecture & Project Evolution

```text
docs/
├── Annex_A_Technical_Specification.pdf
└── Turkash_ASV_SDP_White_Paper_V2.pdf
src/
└── engine.py

# Autonomous Fail-Closed & Zeroization Engine
**Security-first architecture for mission-critical edge nodes, designed to prevent data extraction and ensure deterministic destruction under duress.**


docs/
    ├── Annex_A_Technical_Specification.pdf
    └── Turkash_ASV_SDP_White_Paper_V2.pdf
src/
    └── engine.py

## 🛡️ Layer 5: Sovereign Communication & Fail-Closed Enforcement

A security-first architecture layer designed to enforce strict cryptographic and hardware boundaries for mission-critical edge communications and state synchronization.

* **Core Components**:
  * `Layer5SecureEnforcementEngine`: The primary enforcement logic executing protocol validation and routing decisions.
  * `Layer5Context`: State management wrapper tracking session metadata, node identifiers, and security context parameters.
  * `MockHSMInterface`: Hardware Security Module abstraction layer verifying secure physical and cryptographic key bindings.
* **Security Policy & Invariants**:
  * **Hardware Binding Enforcement**: Triggers an immediate `FAIL_CLOSED_TRIGGERED` state with an `HSM_BINDING_VIOLATION` reason if the provided hardware key handle is unrecognized or invalid.
  * **Multi-Party Authorization (MPA) Quorum**: Enforces a strict signature threshold (minimum quorum of 2 valid signatures) to prevent unauthorized transmission. Any deficit results in an `INSUFFICIENT_MPA_QUORUM` fail-closed lockdown.

## 🚀 Quick Duress Simulation
## Architectural Boundaries & Admissibility Model
To run the live interactive demonstrator script showcasing the fail-closed defense against advanced class-level resurrection and state spoofing attacks, execute:


python demo.py

⁠
To ensure strict separation of concerns, the Turkash ASV-SDP engine enforces the following operational boundaries:

1. **Quorum vs. Admissibility:** 
   - Reaching the administrative quorum ($|\mathbb{A}| \ge q$) acts strictly as a structural gate. 
   - Full execution admissibility is evaluated through a broader contextual function: 
     $$\text{Admissibility}(T, t) = f(\mathbb{A}, \text{Policy}, \text{State}, \text{Revocation}, \dots)$$

2. **Operational Integrity:**
   - Multi-sample temporal filtering and transient noise suppression are handled upstream.
   - `verify_chassis_sensors()` functions strictly as an engine-state gate, ensuring clear boundaries between hardware triggers and logical authorization.

To test edge node behavior and observe the deterministic fail-closed and zeroization under duress:


python3 simulate_duress.py


## 🚀 Quick Start & Installation


git clone https://github.com/Waleed-Mubarak/hailab-fail-closed-engine-


To test the fail-closed engine, hysteresis suppression, and Multi-Party Authorization (MPA):

```python

from src.engine import TurkashEngine

engine = TurkashEngine()
engine.check_duress_trigger(True)
engine.authorize_recovery("Admin_A")
engine.authorize_recovery("Admin_B")
```

## 📄 License

© 2026 Waleed Mubarak. All Rights Reserved. This repository contains proprietary deep tech architecture. Unauthorized commercial use, duplication, or integration is strictly prohibited. For licensing inquiries, contact the author directly.


---

### 📊 Project Status & Badges

![CI Status](https://github.com/Waleed-Mubarak/hailab-fail-closed-engine-/actions/workflows/ci.yml/badge.svg)
![Python Version](https://img.shields.io/badge/python-3.10%252B-blue.svg)

