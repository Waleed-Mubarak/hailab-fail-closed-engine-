import time
import os
import hashlib
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class LockedFlag:
    """Descriptor آمن يمنع التراجع فقط (True -> False)، ويسمح بتكرار القيمة لدعم Idempotency (Z^2 = Z)."""
    def __init__(self, name, default=False):
        self.name = name
        self.default = default
        self._values = {}

    def __get__(self, instance, owner):
        if instance is None:
            return self
        return self._values.get(id(instance), self.default)

    def __set__(self, instance, value):
        inst_id = id(instance)
        current = self._values.get(inst_id, self.default)
        if current and not value:
            raise PermissionError("CRITICAL SECURITY VIOLATION: Terminal state is irreversible.")
        self._values[inst_id] = value


class TurkashEngine:
    _is_zeroized = LockedFlag("_is_zeroized", False)
    _system_locked = LockedFlag("_system_locked", False)
    _terminal_state_locked = LockedFlag("_terminal_state_locked", False)

    def __init__(self):
        super().__setattr__('_TurkashEngine__secure_ram_key', bytearray(os.urandom(32)))
        self._is_zeroized = False
        self._system_locked = False
        self._terminal_state_locked = False
        self.audit_trail = [] 
        self.authorized_admins = set()
        self._log_event("ENGINE_INITIALIZED", "Secure Sovereign Engine initialized with Immutable Descriptors.")

    def __setattr__(self, key, value):
        if key == '_TurkashEngine__secure_ram_key':
            if self._terminal_state_locked or self._is_zeroized:
                if value is not None:
                    raise PermissionError("CRITICAL SECURITY VIOLATION: Attempted state mutation on secure RAM is prohibited.")
        super().__setattr__(key, value)

    @property
    def is_zeroized(self) -> bool:
        memory_is_wiped = all(b == 0 for b in self.__secure_ram_key) if self.__secure_ram_key else True
        return self._is_zeroized or memory_is_wiped or self._terminal_state_locked

    @property
    def system_locked(self) -> bool:
        memory_is_wiped = all(b == 0 for b in self.__secure_ram_key) if self.__secure_ram_key else True
        return self._system_locked or memory_is_wiped or self._terminal_state_locked

    @property
    def secure_ram_key_status(self) -> str:
        if self.is_zeroized:
            return "ZEROIZED_TERMINAL_LOCKED"
        return "SECURELY_MANAGED_READ_ONLY"

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
        if self.system_locked or self.is_zeroized:
            return False
        return True

    def check_duress_trigger(self, duress_signal: bool):
        if duress_signal:
            self._log_event("DURESS_DETECTED", "Duress signal received. Executing emergency protocol.")
            self.execute_zeroization()

    def authorize_recovery(self, admin_id: str) -> bool:
        if self._terminal_state_locked or self._is_zeroized or self._system_locked:
            self._log_event("RECOVERY_DENIED", f"Attempt by {admin_id} on zeroized/locked engine.")
            return False
        
        memory_is_wiped = all(b == 0 for b in self.__secure_ram_key) if self.__secure_ram_key else True
        if memory_is_wiped:
            self._log_event("RECOVERY_DENIED", f"Attempt by {admin_id} on wiped memory.")
            return False
            
        self.authorized_admins.add(admin_id)
        self._log_event("ADMIN_AUTHORIZED", f"Recovery authorization granted by {admin_id}.")
        return True

    def execute_zeroization(self) -> bool:
        already_zeroized = self._terminal_state_locked

        if self.__secure_ram_key:
            for i in range(len(self.__secure_ram_key)):
                self.__secure_ram_key[i] = 0

        self._is_zeroized = True
        self._system_locked = True
        self._terminal_state_locked = True
        
        super().__setattr__('_TurkashEngine__secure_ram_key', None)

        def _permanent_deny(*args, **kwargs):
            raise PermissionError("CRITICAL_BLOCK: Engine is permanently zeroized.")

        self.execute_critical_operation_mpa = _permanent_deny
        self.check_admissibility = lambda *args, **kwargs: False
        self.authorize_recovery = _permanent_deny

        if not already_zeroized:
            self._log_event("ZEROIZATION_COMPLETE", "Secure RAM wiped and enforced via Immutable Descriptors.")
        else:
            self._log_event("ZEROIZATION_REPEATED", "Engine already zeroized. Idempotency preserved (Z^2 = Z).")
        return True

    def get_key_status(self) -> str:
        if self.is_zeroized:
            return "ZEROIZED_SECURE"
        return "ACTIVE"

    def add_signature(self, admin_id: str):
        if self.is_zeroized or self.system_locked:
            self._log_event("SIGNATURE_REJECTED", f"Cannot add signature for {admin_id}: Engine in terminal state.")
            return
        self.authorized_admins.add(admin_id)
        self._log_event("ADMIN_SIGNATURE_ADDED", f"Admin {admin_id} added.")

    def check_quorum(self, required_count: int = 2) -> bool:
        return len(self.authorized_admins) >= required_count

    def check_admissibility(self) -> bool:
        if self._terminal_state_locked or self._is_zeroized or self._system_locked:
            return False
        if self.__secure_ram_key is None:
            return False
        return not all(b == 0 for b in self.__secure_ram_key)

    def execute_critical_operation_mpa(self, required_count: int = 2) -> str:
        if self._terminal_state_locked or self._is_zeroized:
            raise PermissionError("CRITICAL_BLOCK: Terminal state zeroization is irreversible.")

        if not self.check_admissibility():
            self._log_event("CRITICAL_OPERATION_DENIED", {"reason": "admissibility_boundary_failed"})
            return "OPERATION_DENIED: Engine in terminal or locked state."

        if self.check_quorum(required_count):
            self._log_event("CRITICAL_OPERATION_AUTHORIZED", {"quorum": len(self.authorized_admins)})
            return "OPERATION_SUCCESS: Quorum reached."
        else:
            self._log_event("CRITICAL_OPERATION_DENIED", {"reason": "insufficient_signatures"})
            return "OPERATION_DENIED: Insufficient signatures."

    def inspect_raw_memory_snapshot(self) -> bytes:
        if self.__secure_ram_key is None:
            return b'\x00' * 32
        return bytes(self.__secure_ram_key)

FailClosedEngine = TurkashEngine
