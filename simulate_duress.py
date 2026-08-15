
#!/usr/bin/env python3
import sys
import time
import os

def print_banner():
    print("\033[1;31m" + "="*60)
    print("   TURKASH ASV-SDP ENGINE - INTERACTIVE DURESS SIMULATOR")
    print("   Mode: Deterministic Fail-Closed & Zeroization Test")
    print("="*60 + "\033[0m")

def simulate_node():
    print_banner()
    print("\n[*] Initializing secure edge node telemetry...")
    time.sleep(1)
    print("[+] Node status: \033[1;32mONLINE\033[0m | Integrity: \033[1;32mSECURE\033[0m")
    print("[*] Monitoring physical enclosure and network heartbeat...\n")

    for i in range(1, 4):
        print(f"[{i}s] Heartbeat normal. Environment stable. No duress detected.")
        time.sleep(1)

    print("\n\033[1;33m[!] WARNING: Environmental anomaly / Physical tampering detected!\033[0m")
    print("\033[1;31m[!] DURESS TRIGGERED: Initiating irreversible Fail-Closed sequence...\033[0m")
    time.sleep(1.5)

    print("\n[-] Wiping volatile cryptographic keys from RAM...")
    for progress in range(0, 101, 20):
        sys.stdout.write(f"\r[Progress] Zeroizing memory blocks: [{progress}%]")
        sys.stdout.flush()
        time.sleep(0.3)

    print("\n\n\033[1;31m[SUCCESS] State: FAIL-CLOSED REACHED.")
    print("[SUCCESS] All sensitive execution states and keys destroyed.")
    print("[SUCCESS] Node locked down permanently.\033[0m")
    print("="*60)

if __name__ == "__main__":
    simulate_node()
