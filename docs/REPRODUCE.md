# Autonomous Fail-Closed Engine — Independent Reproduction Guide (V0.4)

This guide provides step-by-step instructions for independent verifiers to clone, configure, execute, and verify the fail-closed zeroization engine in a secure or isolated environment.

## Prerequisites
* Python 3.10 or higher
* Git

## 1. Clone the Repository
Open your terminal and run the following command to clone the repository:
```bash
git clone https://github.com/Waleed-Mubarak/hailab-fail-closed-engine-.git

## 2. Execute Automated Adversarial Test Suite
To verify the core defense mechanisms, execute the unit test suite via Python:
```bash
python -m unittest discover tests/
### Expected Verification Results
* **test_p0_03 (Reflection Lockdown):** Must raise a PermissionError.
* **test_p0_04 (Idempotence Z^2 = Z):** Must achieve absolute memory zeroization stability.
* **Overall Status:** 0 failures required.

## 3. Review Evidence & Audit Chain
* docs/ATTACK_MATRIX.md
* docs/PROOF_REPORT.md
