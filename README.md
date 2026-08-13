* **Trigger:** Any security-relevant state change (Initialization, Duress Detection, Zeroization).
* **Action:** Generates SHA-256 cryptographically linked logs preserving event history immutability.
* **Integrity Guarantee:** Sequential hashing ($Hash_n = \text{SHA256}(\text{Timestamp} + \text{Event} + \text{Details} + \text{Hash}_{n-1})$) prevents log tampering or retroactive modification.

---

## 📂 Repository Structure

```text
├── docs/
│   ├── HAI_Lab_Sovereign_API_Spec.pdf
│   └── Annex_A_Technical_Specification.pdf
└── src/
    └── engine.py        # Reference Python logic implementation
└── README.md
```text
---

## 🚀 Quick Start & Installation

```bash
git clone https://github.com/Waleed-Mubarak/fail-closed-zeroization-engine.git
---

## 📄 License

This project is open-source, released under the [MIT License](LICENSE).

