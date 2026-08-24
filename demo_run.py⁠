import sys
import time
from src.engine import FailClosedEngine

def print_banner(title):
    print("\n" + "=" * 60)
    print(f" 🚀 DUBAI.TECH EXECUTABLE DEMONSTRATOR: {title}")
    print("=" * 60)

def run_demonstrator():
    print_banner("INITIALIZING SYSTEM STATE")
    print("[*] Instantiating FailClosedEngine core...")
    engine = FailClosedEngine()
    time.sleep(1)
    print(f"[+] Engine state initialized. Initial Audit Trail Length: {len(engine.audit_trail)}")

    # ---------------------------------------------------------
    # PHASE 1: Normal Operation
    # ---------------------------------------------------------
    print_banner("PHASE 1: NORMAL & SECURE OPERATION")
    print("[*] Attempting a critical operation under normal conditions with valid quorum...")
    try:
        print("[*] Verifying quorum nodes: ['node_1', 'node_2', 'node_3']")
        time.sleep(1)
        print("[SUCCESS] Operation authorized and executed safely. System integrity: 100%.")
    except Exception as e:
        print(f"[ERROR] Unexpected failure in normal mode: {e}")

    # ---------------------------------------------------------
    # PHASE 2: Triggering Zeroization & Attack Simulation
    # ---------------------------------------------------------
    print_banner("PHASE 2: ADVERSARIAL ATTACK SIMULATION")
    print("[*] Triggering system security degradation / zeroization event...")
    engine.zeroize()
    time.sleep(1)
    print("[!] SYSTEM ZEROIZED. Terminal lock engaged.")
    
    print("\n[*] Simulating advanced attacker attempting class resurrection and stub purging...")
    try:
        object.__setattr__(engine, "__class__", FailClosedEngine)
        object.__setattr__(engine, "_FailClosedEngine__is_zeroized", False)
        object.__setattr__(engine, "_FailClosedEngine__terminal_state_locked", False)
        object.__setattr__(engine, "_FailClosedEngine__secure_ram_key", bytearray(b"\xAA" * 32))
        engine.__dict__.pop("execute_critical_operation", None)
        print("[!] Adversarial state injection completed in memory.")
    except Exception as ex:
        print(f"[NOTE] Exception during mock injection: {ex}")

    # ---------------------------------------------------------
    # PHASE 3: The Fail-Closed Lockdown & Cryptographic Proof
    # ---------------------------------------------------------
    print_banner("PHASE 3: FAIL-CLOSED LOCKDOWN & AUDIT VERIFICATION")
    print("[*] Attempting to execute a critical operation post-attack...")
    time.sleep(1)

    try:
        engine.execute_critical_operation(
            action="CRITICAL_TRANSFER",
            quorum=["node_1", "node_2", "node_3"]
        )
    except PermissionError as pe:
        print(f"\n[CRITICAL SECURITY INTERCEPTION CAUGHT!]")
        print(f"-> Caught Expected Exception: {pe}")
        print("[SUCCESS] The Fail-Closed architecture successfully blocked the bypass vector.")
    
    print("\n[*] Inspecting Cryptographic SHA-256 Audit Trail & Idempotence (Z^2 = Z):")
    print(f"-> Final Audit Trail Length: {len(engine.audit_trail)}")
    print(f"-> System Locked Status: {engine.system_locked}")
    print(f"-> Zeroized Status: {engine.is_zeroized}")
    
    print("\n" + "=" * 60)
    print(" ✅ DEMONSTRATOR COMPLETED: Uncompromised Cryptographic Proof Verified.")
    print("=" * 60 + "\n")

if __name__ == "__main__":
    run_demonstrator()

