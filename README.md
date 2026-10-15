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
```bash
git clone [https://github.com/Waleed-Mubarak/hailab-fail-closed-engine-.git](https://github.com/Waleed-Mubarak/hailab-fail-closed-engine-.git)
cd hailab-fail-closed-engine-

from src.engine import TurkashEngine

# Initialize the fail-closed engine
engine = TurkashEngine()

# Check duress triggers & authorize recovery
engine.check_duress_trigger(True)
engine.authorize_recovery("Admin_A")
engine.authorize_recovery("Admin_B")

# Run the main engine demo
python demo.py

# Simulate duress scenarios on edge nodes
python3 simulate_duress.py

PYTHONPATH=. pytest tests/

docs/
├── Annex_A_Technical_Specification.md
└── Turkash_ASV_SDP_White_Paper_V2.pdf
src/
└── ...

