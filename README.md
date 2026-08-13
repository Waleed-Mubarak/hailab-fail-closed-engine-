# 🛡️ HAI Lab: Sovereign Fail-Closed & Zeroization Engine

> **An autonomous, code-enforced security framework designed for Edge nodes operating in high-risk or hostile physical environments.**

---

## 🏛️ Core Architectural Logic

The engine operates on a continuous 50ms monitoring loop, implementing a robust security defense:

1. **Layer 1: Emergency Zeroization (Active Threat / Physical Siege)**
   * **Trigger:** Direct duress signal or chassis physical breach.
   * **Action:** Instant destruction of cryptographic keys from memory via kernel operations (`shred` / `sync`).
   * **Exit Code:** `101`

2. **Layer 2: Hard-Stop Fail-Closed (Integrity Degradation)**
   * **Trigger:** Heartbeat signal loss exceeding the **Hysteresis Threshold** (3 consecutive cycles / 150ms).
   * **Action:** Complete network interface isolation via `iptables` drop rules.
   * **Exit Code:** `102`

3. **Layer 3: Immutable Cryptographic Audit Trail**
   * **Trigger:** Any security-relevant state change (Initialization, Duress Detection, Zeroization).
   * **Action:** Generates SHA-256 cryptographically linked logs preserving event history immutability.
   * **Integrity Guarantee:** Sequential hashing ($Hash_n = \text{SHA256}(\text{Timestamp} + \text{Event} + \text{Details} + \text{Hash}_{n-1})$) prevents log tampering or retroactive modification.

---

## 📂 Repository Structure

```text
├── docs/
│   ├── HAI_Lab_Sovereign_API_Spec.pdf
│   └── Annex_A_Technical_Specification.pdf
├── src/
│   └── engine.py        # Reference Python logic implementation
└── README.md
⁠⁠```⁠
---
## 🚀 Quick Start & Installation
⁠⁠```bash
git clone https://github.com/Waleed-Mubarak/fail-closed-zeroization-engine.git
---

## 📄 License

This project is open-source, released **under** the [MIT License](LICENSE).

