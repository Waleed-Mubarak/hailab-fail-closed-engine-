# 📁 Architectural Documentation & Specifications

This directory contains the formal architectural specifications and technical standards for the **HAI Lab Sovereign Fail-Closed & Zeroization Engine**.

---

## 📄 Core Reference Documents

| Document | Description | Format | Status |
| :--- | :--- | :--- | :--- |
| **HAI_Lab_Sovereign_API_Spec** | Comprehensive API specification detailing signal hooks, state machine transitions, and system calls. | `PDF` | *Draft / Internal* |
| **Annex_A_Technical_Specification** | Detailed hardware integration guidelines, board-level duress sensor interfacing, and kernel module configuration. | `PDF` | *Draft / Internal* |
| **Turkash_ASV_SDP_White_Paper_V2** | Autonomous Sovereign Vault, Fail-Closed core, Hysteresis controls, and Multi-Party Authorization. | `PDF` | *Active* |

---

## 🏛️ System State Transitions

```text
[ NORMAL OPERATION ]
       |
       |---- (Direct Duress / Physical Breach)
       v
[ LAYER 1: Emergency RAM Zeroization ] (Exit Code 101)
       |
       |---- (Heartbeat Loss > 150ms / 3 Cycles)
       v
[ LAYER 2: Hard-Stop Network Drop ] (Exit Code 102)
