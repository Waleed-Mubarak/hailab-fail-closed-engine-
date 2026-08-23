import time
import os
import hashlib
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class TurkashEngine:
    def __init__(self):
        # Strict encapsulation with double underscore (Name Mangling) for all critical terminal states
        super().__setattr__('_TurkashEngine__secure_ram_key', bytearray(os.urandom(32)))
        super().__setattr__('_TurkashEngine__is_zeroized', False)
        super().__setattr__('_TurkashEngine__system_locked', False)
        super().__setattr__('_TurkashEngine__terminal_state_locked', False)  # Completely private and immutable from outside tampering
        self.audit_trail = [] 
        self.authorized_admins = set()
        self._log_event("ENGINE_INITIALIZED", "Secure Sovereign Engine initialized successfully.")

    def __setattr__(self, key, value):
        # Fail-Closed Hardening: Once terminal state or zeroization is active, block any external attribute mutation completely
        protected_attributes = {
            '_TurkashEngine__terminal_state_locked', 
            '_TurkashEngine__is_zeroized', 
            '_TurkashEngine__system_locked',
            '_TurkashEngine__secure_ram_key'
        }
        
        if key in protected_attributes:
            current_terminal = self.__dict__.get('_TurkashEngine__terminal_state_locked', False)
            current_zeroized = self.__dict__.get('_TurkashEngine__is_zeroized', False)
            if current_terminal or current_zeroized:
                raise PermissionError("CRITICAL SECURITY VIOLATION: Attempted state mutation on a terminal/zeroized engine is strictly prohibited.")
        
        super().__setattr__(key, value)

    @property
    def is_zeroized(self) -> bool:
        memory_is_wiped = all(b == 0 for b in self.__secure_ram_key) if self.__secure_ram_key else True
        return self.__is_zeroized or memory_is_wiped or self.__terminal_state_locked

    @property
    def system_locked(self) -> bool:
        memory_is_wiped = all(b == 0 for b in self.__secure_ram_key) if self.__secure_ram_key else True
        return self.__system_locked or memory_is_wiped or self.__terminal_state_locked

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
        if self.__terminal_state_locked or self.__is_zeroized or self.__system_locked:
            self._log_event("RECOVERY_DENIED", f"Attempt by {admin_id} on zeroized/locked engine (Terminal State Enforced).")
            return False
        
        memory_is_wiped = all(b == 0 for b in self.__secure_ram_key) if self.__secure_ram_key else True
        if memory_is_wiped:
            self._log_event("RECOVERY_DENIED", f"Attempt by {admin_id} on wiped memory.")
            return False
            
        self.authorized_admins.add(admin_id)
        self._log_event("ADMIN_AUTHORIZED", f"Recovery authorization granted by {admin_id}.")
        return True

    def execute_zeroization(self) -> bool:
        # 1. Zero out the memory byte array
        if self.__secure_ram_key:
            for i in range(len(self.__secure_ram_key)):
                self.__secure_ram_key[i] = 0

        # 2. Set internal flags via object level to enforce locks
        super().__setattr__('_TurkashEngine__is_zeroized', True)
        super().__setattr__('_TurkashEngine__system_locked', True)
        super().__setattr__('_TurkashEngine__terminal_state_locked', True)
        
        # 3. Clear raw memory reference permanently
        super().__setattr__('_TurkashEngine__secure_ram_key', None)

        # 4. SELF-DESTRUCT / IRREVERSIBLE METHOD INVALIDATION (Stub-Replacement)
        def _permanent_deny(*args, **kwargs):
            raise PermissionError("CRITICAL_BLOCK: Engine is permanently zeroized and cannot execute operations.")

        # Overwrite critical methods directly on the instance dictionary
        self.execute_critical_operation_mpa = _permanent_deny
        self.check_admissibility = lambda *args, **kwargs: False
        self.authorize_recovery = _permanent_deny

        if not any(log["event"] == "ZEROIZATION_COMPLETE" for log in self.audit_trail):
            self._log_event("ZEROIZATION_COMPLETE", "Secure RAM wiped and system fail-closed enforced with structural method invalidation.")
        else:
            self._log_event("ZEROIZATION_REPEATED", "Engine already zeroized. Idempotency preserved (Z^2 = Z); state is invariant.")
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
        if self.__terminal_state_locked or self.__is_zeroized or self.__system_locked:
            return False
        if self.__secure_ram_key is None:
            return False
        memory_is_wiped = all(b == 0 for b in self.__secure_ram_key)
        if memory_is_wiped:
            return False
        return True

    def execute_critical_operation_mpa(self, required_count: int = 2) -> str:
        if not self.check_admissibility():
            self._log_event("CRITICAL_OPERATION_DENIED", {"reason": "admissibility_boundary_failed_or_zeroized"})
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
