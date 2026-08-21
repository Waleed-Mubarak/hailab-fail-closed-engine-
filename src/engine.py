import time
import os
import hashlib
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class TurkashEngine:
    def __init__(self):
        self._secure_ram_key = bytearray(os.urandom(32))
        self._is_zeroized = False
        self._system_locked = False
        self.audit_trail = [] 
        self.authorized_admins = set()
        self._log_event("ENGINE_INITIALIZED", "Secure Sovereign Engine initialized successfully.")

    @property
    def is_zeroized(self) -> bool:
        return self._is_zeroized

    @property
    def system_locked(self) -> bool:
        return self._system_locked

    def _log_event(self, event_type: str, details: str):
        timestamp = time.time()
        previous_hash = "GENESIS_BLOCK" if not self.audit_trail else self.audit_trail[-1]["current_hash"]
        
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
        if self._system_locked or self._is_zeroized:
            return False
        return True

    def check_duress_trigger(self, duress_signal: bool):
        if duress_signal:
            self._log_event("DURESS_DETECTED", "Duress signal received. Executing emergency protocol.")
            self.execute_zeroization()

    def authorize_recovery(self, admin_id: str) -> bool:
        # P0-03: منع محاولات الاستعادة أو تغيير الحالة إذا وصل المحرك للحالة النهائية (Terminal State) بصرامة
        if self._is_zeroized or self._system_locked:
            self._log_event("RECOVERY_DENIED", f"Attempt by {admin_id} on zeroized/locked engine (Terminal State Enforced).")
            return False
        
        self.authorized_admins.add(admin_id)
        self._log_event("ADMIN_AUTHORIZED", f"Recovery authorization granted by {admin_id}.")
        return True

    def execute_zeroization(self) -> None:
        # P0-04: ضمان ثبات التصفير والتحقق من Idempotence (Z^2 = Z) دون آثار مدمرة متكررة
        if not self._is_zeroized:
            for i in range(len(self._secure_ram_key)):
                self._secure_ram_key[i] = 0

            self._is_zeroized = True
            self._system_locked = True
            self._log_event("ZEROIZATION_COMPLETE", "Secure RAM wiped and system fail-closed enforced.")
        else:
            self._log_event("ZEROIZATION_REPEATED", "Engine already zeroized. Idempotency preserved; no secondary destructive transition.")

    def get_key_status(self) -> str:
        if self._is_zeroized:
            return "ZEROIZED_SECURE"
        return "ACTIVE"

    def add_signature(self, admin_id: str):
        if self._is_zeroized or self._system_locked:
            self._log_event("SIGNATURE_REJECTED", f"Cannot add signature for {admin_id}: Engine in terminal state.")
            return
        self.authorized_admins.add(admin_id)
        self._log_event("ADMIN_SIGNATURE_ADDED", f"Admin {admin_id} added.")

    def check_quorum(self, required_count: int = 2) -> bool:
        return len(self.authorized_admins) >= required_count

    def check_admissibility(self) -> bool:
        """P0-01 & P0-05: بوابة القبول الرسمية (Admissibility Boundary)"""
        if self._is_zeroized or self._system_locked:
            return False
        return True

    def execute_critical_operation_mpa(self, required_count: int = 2) -> str:
        """P0-01 & P0-05: تمرير كل عملية حرجة عبر بوابة القبول واشتراط النصاب"""
        if not self.check_admissibility():
            self._log_event("CRITICAL_OPERATION_DENIED", {"reason": "admissibility_boundary_failed_or_zeroized"})
            return "OPERATION_DENIED: Engine in terminal or locked state."

        if self.check_quorum(required_count):
            self._log_event("CRITICAL_OPERATION_AUTHORIZED", {"quorum": len(self.authorized_admins)})
            return "OPERATION_SUCCESS: Quorum reached."
        else:
            self._log_event("CRITICAL_OPERATION_DENIED", {"reason": "insufficient_signatures"})
            return "OPERATION_DENIED: Insufficient signatures."
