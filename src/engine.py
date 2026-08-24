import time
import os
import hashlib
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class ImmutableSentinel:
    def __init__(self, value=False):
        self._val = value
        self._locked = False

    def get(self):
        return self._val

    def set(self, val):
        if self._locked and not val:
            raise PermissionError("CRITICAL SECURITY VIOLATION: Immutable terminal state is irreversible.")
        self._val = val
        if val:
            self._locked = True


class TurkashEngine:
    def __init__(self):
        super().__setattr__('_secure_ram_key', bytearray(os.urandom(32)))
        super().__setattr__('_is_zeroized_sentinel', ImmutableSentinel(False))
        super().__setattr__('_terminal_locked_sentinel', ImmutableSentinel(False))
        self.audit_trail = [] 
        self.authorized_admins = set()
        self._log_event("ENGINE_INITIALIZED", "Ultra-Hardened Sovereign Engine initialized with Immutable Sentinels.")

    def __setattr__(self, key, value):
        if key == '_secure_ram_key':
            sentinel = self.__dict__.get('_terminal_locked_sentinel')
            if sentinel and sentinel.get() and value is not None:
                raise PermissionError("CRITICAL SECURITY VIOLATION: Attempted state mutation on secure RAM is prohibited.")
        super().__setattr__(key, value)

    def _verify_absolute_integrity(self):
        ram = object.__getattribute__(self, '_secure_ram_key')
        is_zero_ram = all(b == 0 for b in ram) if ram is not None else True
        
        t_sentinel = object.__getattribute__(self, '_terminal_locked_sentinel')
        i_sentinel = object.__getattribute__(self, '_is_zeroized_sentinel')
        
        if is_zero_ram or (t_sentinel and t_sentinel.get()) or (i_sentinel and i_sentinel.get()):
            raise PermissionError("CRITICAL_BLOCK: Terminal state zeroization is irreversible.")

    @property
    def is_zeroized(self) -> bool:
        try:
            self._verify_absolute_integrity()
            return False
        except PermissionError:
            return True

    @property
    def system_locked(self) -> bool:
        return self.is_zeroized

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

    def authorize_recovery(self, admin_id: str) -> bool:
        try:
            self._verify_absolute_integrity()
        except PermissionError:
            self._log_event("RECOVERY_DENIED", f"Attempt by {admin_id} on zeroized/locked engine.")
            return False
            
        self.authorized_admins.add(admin_id)
        self._log_event("ADMIN_AUTHORIZED", f"Recovery authorization granted by {admin_id}.")
        return True

    def execute_zeroization(self) -> bool:
        ram = object.__getattribute__(self, '_secure_ram_key')
        if ram is not None:
            for i in range(len(ram)):
                ram[i] = 0

        object.__getattribute__(self, '_is_zeroized_sentinel').set(True)
        object.__getattribute__(self, '_terminal_locked_sentinel').set(True)
        
        super().__setattr__('_secure_ram_key', None)

        def _permanent_deny(*args, **kwargs):
            raise PermissionError("CRITICAL_BLOCK: Engine is permanently zeroized.")

        self.execute_critical_operation_mpa = _permanent_deny
        self.check_admissibility = lambda *args, **kwargs: False
        self.authorize_recovery = _permanent_deny

        self._log_event("ZEROIZATION_COMPLETE", "Secure RAM wiped and enforced via Immutable Sentinels.")
        return True

    def get_key_status(self) -> str:
        if self.is_zeroized:
            return "ZEROIZED_SECURE"
        return "ACTIVE"

    def add_signature(self, admin_id: str):
        try:
            self._verify_absolute_integrity()
        except PermissionError:
            self._log_event("SIGNATURE_REJECTED", f"Cannot add signature for {admin_id}: Engine in terminal state.")
            return
        self.authorized_admins.add(admin_id)
        self._log_event("ADMIN_SIGNATURE_ADDED", f"Admin {admin_id} added.")

    def check_quorum(self, required_count: int = 2) -> bool:
        return len(self.authorized_admins) >= required_count

    def check_admissibility(self) -> bool:
        try:
            self._verify_absolute_integrity()
            ram = object.__getattribute__(self, '_secure_ram_key')
            return ram is not None and not all(b == 0 for b in ram)
        except PermissionError:
            return False

    def execute_critical_operation_mpa(self, required_count: int = 2, action: str = "", quorum=None) -> str:
        self._verify_absolute_integrity()

        if not self.check_admissibility():
            self._log_event("CRITICAL_OPERATION_DENIED", {"reason": "admissibility_boundary_failed"})
            return "OPERATION_DENIED: Engine in terminal or locked state."

        effective_count = len(quorum) if isinstance(quorum, list) else required_count
        if self.check_quorum(effective_count):
            self._log_event("CRITICAL_OPERATION_AUTHORIZED", {"quorum": effective_count})
            return "OPERATION_SUCCESS: Quorum reached."
        else:
            self._log_event("CRITICAL_OPERATION_DENIED", {"reason": "insufficient_signatures"})
            return "OPERATION_DENIED: Insufficient signatures."

    def inspect_raw_memory_snapshot(self) -> bytes:
        ram = object.__getattribute__(self, '_secure_ram_key')
        if ram is None:
            return b'\x00' * 32
        return bytes(ram)

FailClosedEngine = TurkashEngine
