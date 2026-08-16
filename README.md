# Autonomous Fail-Closed & Zeroization Engine
**Security-first architecture for mission-critical edge nodes, designed to prevent data extraction and ensure deterministic destruction under duress.**


docs/
    ├── Annex_A_Technical_Specification.pdf
    └── Turkash_ASV_SDP_White_Paper_V2.pdf
src/
    └── engine.py

## 🚀 Quick Duress Simulation

To test edge node behavior and observe the deterministic fail-closed and zeroization under duress:


python3 simulate_duress.py


## 🚀 Quick Start & Installation


git clone [https://github.com/Waleed-Mubarak/fail-closed-zeroization-engine](https://github.com/Waleed-Mubarak/fail-closed-zeroization-engine)


To test the fail-closed engine, hysteresis suppression, and Multi-Party Authorization (MPA):

```python

from src.engine import TurkashEngine

engine = TurkashEngine()
engine.check_duress_trigger(True)
engine.authorize_recovery("Admin_A")
engine.authorize_recovery("Admin_B")
```

## 📄 License

This project is open-source under the MIT License.

---

### 📊 Project Status & Badges

![CI Status](https://github.com/Waleed-Mubarak/hailab-fail-closed-engine-/actions/workflows/ci.yml/badge.svg)
![Python Version](https://img.shields.io/badge/python-3.10%252B-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
