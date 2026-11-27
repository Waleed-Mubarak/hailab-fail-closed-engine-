# HAILAB Forensic Bundle — Operational Runbook & Schema Spec (v1.4.0)

## 1. Purpose
Operational reference for verifying signed forensic bundles (`*.tar.gz`), validating hash-chained ledgers (`verification_ledger.jsonl`), running adversarial fail-closed checks, and handling verification failures or key rotations.

## 2. Schema & Fail-Closed Rules (v1.4.0)
- **Schema Version:** `1.4.0`
- **Signature Algorithm:** `Ed25519` over domain-separated canonical manifest payload.
- **Reserved Members:** `manifest.json`, `manifest.sig.json`, `signer_public.pem`.
- **Fail-Closed Guarantee:** Any invalid schema, untrusted or mismatched public key fingerprint, failed signature, unexpected archive member, artifact hash mismatch, or broken ledger link must result in rejection and a non-zero exit status.

## 3. Running Verification & Adversarial Tests
Run unit and adversarial tamper tests:
`PYTHONPATH=. python3 -m unittest discover -s tools -p "test_verify_bundle_adversarial.py" -v`

Verify a bundle against a trusted public key and ledger:
`python3 tools/verify_bundle.py <bundle.tar.gz> --trusted-pub-key keys/forensic_ed25519.pub --ledger reports/verification_ledger.jsonl`

## 4. Incident & Key Rotation Procedures
- **Signature / Untrusted Key Failure:** Quarantine the bundle immediately and verify the `SHA-256` fingerprint of the trusted public key before trusting any output.
- **Artifact Integrity / Allowlist Failure:** Discard or isolate the bundle as tampered; do not promote to release or ingestion.
- **Ledger Chain Break:** Halt automated ledger appends, inspect the broken link (`prev_entry_sha256` vs `entry_sha256`), and restore from a known-good baseline.
- **Key Rotation:** Generate a new `Ed25519` keypair, distribute the updated public key fingerprint via a trusted channel, and sign new bundles with the active key.

## 5. Certified Scope B Baseline & Attestation Boundary
- **Certified Subject:** Hailab Fail-Closed Engine Scope B worker (`src/scope_b/engine.py`)
- **Certified Commit:** `59a98bcf5c9c55454e750fe4d8a136235803717c` (baseline frozen at `22076ed`; `THREAT_MODEL.md` `159a52f8`; `SCOPE_B_REQUIREMENTS.md` `2e35f972`)
- **Platform & Date:** `x86_64 Linux` (verified running as root), certified `14 November 2026` by Dr. Hikmat M. Kerimov (Institute of Defense Technologies and Cybersecurity, Azerbaijan Technical University)
- **Certified Requirements (`REQ-SCOPE-B-01` to `REQ-SCOPE-B-07`):** Verified against real kernel mechanisms (oracle isolation and post-`ZEROIZE` refusal including malformed input, UID `65534` and `PR_SET_DUMPABLE 0` ptrace/dump isolation, `seccomp-bpf` with `SECCOMP_RET_KILL_PROCESS` / `SIGSYS`, `PR_SET_PDEATHSIG(SIGKILL)` with `ZEROIZE` wipe path, privilege separation with `CapEff = CapBnd = 0` and `PR_SET_NO_NEW_PRIVS`, `mlockall` memory locking with fail-closed startup halt, and dedicated watchdog under UID `65534` with `SIGKILL` containment).
- **Scope & Exclusions Notice:**
  - **Adversary B1 (in-process code in main process):** Partially in scope per frozen baseline; key confidentiality and post-zeroization refusal hold, while a compromised main process may still invoke allow-listed operations while the worker is active prior to `ZEROIZE`. Any public reference must include this partial-scope note.
  - **Adversaries B3 (kernel / ring-0) & B4 (physical / cold-boot):** Excluded per frozen baseline (require OS-vendor assurance and TEE/HSM respectively); must not be cited as protected by this certificate.
  - **Architecture & Re-Verification Rule:** The `seccomp` filter targets `x86_64` (`AUDIT_ARCH_X86_64`). Any modification to `src/scope_b/engine.py` or `tests/scope_b/test_engine.py`, or execution on another architecture, requires re-verification and does not alter Phase 5 Scope A (`191928d`).

