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
`git clone https://github.com/Waleed-Mubarak/hailab-fail-closed-engine-.git`  
`cd hailab-fail-closed-engine-`

### 2. Basic Usage Example
`from src.engine import TurkashEngine`  

`engine = TurkashEngine()`  
`engine.check_duress_trigger(True)`  
`engine.authorize_recovery("Admin_A")`  
`engine.authorize_recovery("Admin_B")`  

---

## 🎮 Interactive Demos & Simulations

Run the live interactive demonstrations directly from your terminal:

* **Main Engine Demo:** `python demo.py`
* **Edge Duress Simulation:** `python3 simulate_duress.py`

---

## 🧪 Running Tests & Verification

To run the test suite smoothly without any import path issues:

`PYTHONPATH=. pytest tests/`

---

## 🏗️ Repository Architecture & Design Principles

