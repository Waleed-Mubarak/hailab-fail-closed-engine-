# THREAT_MODEL.md

## Overview & Scope
This document outlines the threat modeling, security assumptions, attack vectors, and mitigation strategies for the HAI Lab Fail-Closed & Zeroization Engine (hailab-fail-closed-engine).

The engine is a reference architecture designed for high-risk edge computing environments where physical security cannot be guaranteed, and persistent cloud connectivity is unavailable or untrusted.

---

## 1. System Asset Identification
The primary assets protected by the engine include:
* **Volatile Cryptographic Material:** Encryption keys, session tokens, and ephemeral identity credentials held in RAM.
* **Sensitive Execution State:** In-memory application state and cached telemetry logs.
* **Hardware Integrity:** Prevention of unauthorized physical or logical device takeover.

---

## 2. Threat Actor Profiles

### Actor Profile: Physical Interceptor
* **Capabilities & Resources:** Direct physical access, chassis disassembly, logic probes, cold-boot equipment.
* **Primary Objective:** Extract cryptographic keys from volatile memory.

### Actor Profile: Network Adversary
* **Capabilities & Resources:** Signal jamming, man-in-the-middle (MitM), packet injection, network isolation.
* **Primary Objective:** Prevent security alerts from reaching command centers while exploiting the device.

### Actor Profile: Malicious Insider
* **Capabilities & Resources:** Local unprivileged access, physical proximity, physical sensor manipulation.
* **Primary Objective:** Induce denial-of-service (DoS) or trick system into executing unprovoked zeroization.

---

## 3. Attack Vectors & Mitigation Strategies

### Threat 1: Physical Chassis Breach (Side-Channel & Cold Boot)
* **Description:** An attacker opens the hardware enclosure to perform direct physical inspection or cold-boot memory attacks.
* **Impact:** High (Potential full key/data compromise).
* **Mitigation:**
  * Physical chassis tamper switches monitor enclosure status.
  * Detection triggers immediate deterministic transition to FAIL-CLOSED state.
  * Engine executes instant volatile memory zeroization (overwriting memory locations before halting).

### Threat 2: Signal Jamming / Network Isolation
* **Description:** Adversaries sever wireless or wired network interfaces to isolate the node from central monitoring orchestrators.
* **Impact:** Medium to High (Loss of centralized command and control).
* **Mitigation:**
  * Autonomous local telemetry loop continuously evaluates network availability.
  * System does not rely on remote kill switch commands; decisions are evaluated and executed locally at the edge.

### Threat 3: Denial-of-Service via Forced Zeroization
* **Description:** An attacker deliberately introduces environmental noise or brief sensor anomalies to trick the system into triggering a destructive zeroization cycle.
* **Impact:** Medium (Service interruption and data loss).
* **Mitigation:**
  * Multi-sample temporal verification filtering ensures sensor anomalies are validated across consecutive polling cycles before executing destructive actions.

---

## 4. Trust Boundaries & Architectural Limitations

**Crucial Implementation Note:**
This reference implementation demonstrates deterministic fail-closed state transitions in user-space code.

1. **User Space vs. Kernel/Hardware Execution:**
   * In production deployments, user-space execution can be bypassed if an attacker achieves early root-level privilege.
   * **Production Requirement:** The deterministic state logic and zeroization triggers must be integrated into secure hardware enclaves (e.g., TPM, HSM) or kernel-level anti-tamper modules.

2. **Volatile Memory Persistence:**
   * Standard memory overwrites in high-level runtimes may leave residual traces due to garbage collection or swap space. Production builds require non-swappable pinned memory allocations (`mlock`).

---

## 5. Security Audit & Testing
The state engine logic is validated using automated deterministic test suites (`test_engine.py`) covering:
* Positive breach detection scenarios.
* Transient fault filtering (false-positive suppression).
* State transition immutability once FAIL-CLOSED is reached.
