# Turkash ASV-SDP Engine

Turkash ASV-SDP: Upgraded Sovereign Engine combining legacy cryptographic integrity with Hysteresis suppression and Multi-Party Authorization (MPA).

## 📂 Repository Structure

docs/
    ├── HAI_Lab_Sovereign_API_Spec.pdf
    ├── Annex_A_Technical_Specification.pdf
    └── Turkash_ASV_SDP_White_Paper_V2.pdf
src/
    └── engine.py
README.md

## 🚀 Quick Start & Installation

### 🚀 Quick Duress Simulation
To test edge node behavior and observe the deterministic fail-closed and zeroization sequence under duress:
```bash
python3 simulate_duress.py

git clone https://github.com/Waleed-Mubarak/fail-closed-zeroization-engine

To test the fail-closed engine, hysteresis suppression, and Multi-Party Authorization (MPA):

from src.engine import TurkashEngine

engine = TurkashEngine()
engine.check_duress_trigger(True)
engine.authorize_recovery("Admin_A")
engine.authorize_recovery("Admin_B")

## 📄 License
This project is open-source under the MIT License.
