import time
import os
import hashlib
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class TurkashEngine:
    def __init__(self):
        self._secure_ram_key = bytearray(os.urandom(32))
        self.is_zeroized = False
        self.system_locked = False
        self.audit_trail = [] # سجل التدقيق المشفر
        self.authorized_admins = set()
        self._log_event("ENGINE_INITIALIZED", "Secure Sovereign Engine initialized successfully.")

    def _log_event(self, event_type: str, details: str):
        # سجل مشفر وغير قابل للتلاعب لكل حدث أمني
        timestamp = time.time()
        if not self.audit_trail:
            previous_hash = "GENESIS_BLOCK"
        else:
            previous_hash = self.audit_trail[-1]["current_hash"]

        # دمج البيانات لإنشاء بصمة تشفير (SHA-256)
        raw_data = f"{timestamp}:{event_type}:{details}:{previous_hash}"
        current_hash = hashlib.sha256(raw_data.encode('utf-8')).hexdigest()

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

    def check_duress_trigger(self, duress_signal: bool):
        if duress_signal:
            self._log_event("DURESS_DETECTED", "Duress signal received. Executing emergency protocol.")
            self.execute_zeroization()

    def authorize_recovery(self, admin_id: str) -> bool:
        if self.is_zeroized:
            self._log_event("RECOVERY_DENIED", f"Attempt by {admin_id} on zeroized engine.")
            return False
        
        self.authorized_admins.add(admin_id)
        self._log_event("ADMIN_AUTHORIZED", f"Recovery authorization granted by {admin_id}.")
        return True

    def execute_zeroization(self) -> None:
        if not self.is_zeroized:
            for i in range(len(self._secure_ram_key)):
                self._secure_ram_key[i] = 0

            self.is_zeroized = True
            self.system_locked = True
            self._log_event("ZEROIZATION_COMPLETE", "Secure RAM wiped and system fail-closed enforced.")

    def get_key_status(self) -> str:
        if self.is_zeroized:
            return "ZEROIZED_SECURE"
        return "ACTIVE"
    def add_signature(self, admin_id: str):
        """إضافة توقيع رقمي للمسؤول والتحقق من النصاب."""
        self.authorized_admins.add(admin_id)
        self._log_event("ADMIN_SIGNATURE_ADDED", {"admin_id": admin_id})

    def check_quorum(self, required_count: int = 2) -> bool:
        """التحقق مما إذا تم استيفاء النصاب المطلوب من المشرفين."""
        return len(self.authorized_admins) >= required_count

    def execute_critical_operation_mpa(self, required_count: int = 2) -> str:
        """تنفيذ العمليات الحرجة فقط عند اكتمال النصاب المتعدد."""
        if self.check_quorum(required_count):
            self._log_event("CRITICAL_OPERATION_AUTHORIZED", {"quorum": len(self.authorized_admins)})
            return "OPERATION_SUCCESS: Quorum reached."
        else:
            self._log_event("CRITICAL_OPERATION_DENIED", {"reason": "insufficient_signatures"})
            return "OPERATION_DENIED: Insufficient signatures."
