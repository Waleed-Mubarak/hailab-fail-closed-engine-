import time
import os
import hashlib
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class FailClosedEngine:
    def __init__(self):
        self._secure_ram_key = bytearray(os.urandom(32))
        self.is_zeroized = False
        self.system_locked = False
        self.audit_trail = []  # سجل التدقيق المشفر
        self._log_event("ENGINE_INITIALIZED", "Secure RAM key generated and engine booted.")

    def _log_event(self, event_type: str, details: str) -> None:
        """توليد سجل مشفر وغير قابل للتلاعب لكل حدث أمني"""
        timestamp = time.time()
        previous_hash = self.audit_trail[-1]["current_hash"] if self.audit_trail else "0" * 64
        
        # دمج البيانات لإنشاء بصمة تشفير (SHA-256) ترتبط بالسجل السابق
        raw_data = f"{timestamp}:{event_type}:{details}:{previous_hash}"
        current_hash = hashlib.sha256(raw_data.encode()).hexdigest()
        
        log_entry = {
            "timestamp": timestamp,
            "event": event_type,
            "details": details,
            "previous_hash": previous_hash,
            "current_hash": current_hash
        }
        self.audit_trail.append(log_entry)
        logging.info(f"Audit Log Recorded: [{event_type}] - Hash: {current_hash[:12]}...")

    def verify_chassis_sensors(self) -> bool:
        if self.system_locked or self.is_zeroized:
            return False
        return True

    def check_duress_trigger(self, duress_signal: bool) -> None:
        if duress_signal:
            self._log_event("DURESS_DETECTED", "Duress signal received. Forcing zeroization.")
            self.execute_zeroization()

    def execute_zeroization(self) -> None:
        if not self.is_zeroized:
            for i in range(len(self._secure_ram_key)):
                self._secure_ram_key[i] = 0
            
            self.is_zeroized = True
            self.system_locked = True
            self._log_event("ZEROIZATION_COMPLETE", "RAM key wiped and system locked in Fail-Closed state.")

    def get_key_status(self) -> str:
        if self.is_zeroized:
            return "ZEROIZED_SECURE"
        return "ACTIVE"
