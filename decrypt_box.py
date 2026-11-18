import os
import json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def decrypt_forensic_box(filename="hailab_forensic_blackbox.enc"):
    current_dir = os.path.dirname(os.path.abspath(__file__))
    file_path = os.path.join(current_dir, filename)

    if not os.path.exists(file_path):
        print(f"[-] Error: Forensic black-box file '{filename}' not found.")
        print("[*] Please trigger a panic/fail-closed event from the web app first to generate it.")
        return

    print(f"[+] Reading forensic black-box from: {file_path}")
    
    with open(file_path, "rb") as f:
        raw_data = f.read()

    # التأكد من أن حجم الملف يحتوي على الأقل على الـ Nonce (12 بايت) والمفتاح (32 بايت)
    if len(raw_data) < 44:
        print("[-] CRITICAL: File is too short or corrupted.")
        return

    # استخراج المكونات بنفس بنية الحفظ:
    # أول 12 بايت للـ Nonce، تليها 32 بايت للمفتاح، والباقي للـ Ciphertext
    nonce = raw_data[:12]
    key = raw_data[12:44]
    ciphertext = raw_data[44:]

    try:
        aesgcm = AESGCM(key)
        decrypted_payload = aesgcm.decrypt(nonce, ciphertext, None)
        snapshot = json.loads(decrypted_payload.decode('utf-8'))

        print("\n" + "=" * 70)
        print(" [√] FORENSIC BLACK-BOX SUCCESSFULLY DECRYPTED & VERIFIED")
        print("=" * 70)
        print(f"📅 Incident Timestamp : {snapshot.get('timestamp')}")
        print(f"🔢 Process ID (PID)   : {snapshot.get('pid')}")
        print(f"🧠 RAM Buffer Address : {snapshot.get('buffer_address')}")
        print(f"🛡️ Kernel Status      : {snapshot.get('kernel_status')}")
        print("=" * 70)
        print("📜 --- ENCLOSED AUDIT LOGS SNAPSHOT ---")
        print(snapshot.get('audit_logs', 'No logs available').strip())
        print("=" * 70)

    except Exception as e:
        print(f"[-] CRITICAL: Decryption failed! Integrity check or key mismatch. Error: {e}")

if __name__ == "__main__":
    decrypt_forensic_box()

