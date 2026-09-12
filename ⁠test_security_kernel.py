import time
import hashlib
import logging
import os

class ZeroizedEngineProxy:
    """وكيل مصفّر نهائي محصن ضد استعادة الكلاس أو التلاعب بالانعكاس (Hardened Against __class__ Restoration)"""
    
    def __setattr__(self, name, value):
        if name == '__class__':
            raise PermissionError("CRITICAL_SECURITY_BLOCK: __class__ mutation / restoration is permanently locked.")
        raise PermissionError("CRITICAL_BLOCK: Terminal state zeroization is irreversible.")

    def __delattr__(self, name):
        raise PermissionError("CRITICAL_BLOCK: Immutable terminal state.")

    @property
    def is_zeroized(self) -> bool:
        return True

    @property
    def system_locked(self) -> bool:
        return True

    @property
    def secure_ram_key_status(self) -> str:
        return "ZEROIZED_TERMINAL_LOCKED"

    def zeroize(self) -> bool:
        return True

    def execute_zeroization(self) -> bool:
        return True

    def add_signature(self, admin_id: str):
        raise PermissionError("CRITICAL_BLOCK: Terminal state zeroization is irreversible.")

    def check_quorum(self, required_count: int = 2) -> bool:
        return False

    def check_admissibility(self) -> bool:
        return False

    def execute_critical_operation(self, action: str = "", quorum=None) -> str:
        raise PermissionError("CRITICAL_BLOCK: ZEROIZED_TERMINAL_STATE")

    def inspect_raw_memory_snapshot(self) -> bytes:
        return b'\x00' * 32


class FailClosedEngine:
    def __init__(self):
        super().__setattr__('_FailClosedEngine__secure_ram_key', bytearray(os.urandom(32)))
        super().__setattr__('_FailClosedEngine__is_zeroized', False)
        super().__setattr__('_FailClosedEngine__terminal_state_locked', False)
        self.audit_trail = [] 
        self.authorized_admins = set()
        self._log_event("ENGINE_INITIALIZED", "Fail-Closed Sovereign Engine initialized.")

    def _verify_constitutional_integrity(self):
        """فحص جذري للـ __dict__ الخام لمنع الـ Fallback Bypass وتلاعب الـ Reflection (P0-03)."""
        raw_dict = object.__getattribute__(self, "__dict__")
        if (raw_dict.get("_FailClosedEngine__is_zeroized", False) or 
            raw_dict.get("_FailClosedEngine__terminal_state_locked", False) or 
            raw_dict.get("_FailClosedEngine__secure_ram_key", None) is None):
            raise PermissionError("CRITICAL_BLOCK: Terminal state zeroization is irreversible.")

    @property
    def is_zeroized(self) -> bool:
        try:
            self._verify_constitutional_integrity()
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
            self._verify_constitutional_integrity()
        except PermissionError:
            self._log_event("RECOVERY_DENIED", f"Attempt by {admin_id} on zeroized/locked engine.")
            return False
            
        self.authorized_admins.add(admin_id)
        self._log_event("ADMIN_AUTHORIZED", f"Recovery authorization granted by {admin_id}.")
        return True

    def zeroize(self) -> bool:
        """دالة التصفير مع تفعيل الثبات الرياضي Z^2 = Z وقفل الفئة نهائياً."""
        if self.is_zeroized:
            return True

        raw_dict = object.__getattribute__(self, "__dict__")
        ram = raw_dict.get("_FailClosedEngine__secure_ram_key")
        if ram is not None:
            for i in range(len(ram)):
                ram[i] = 0

        super().__setattr__('_FailClosedEngine__is_zeroized', True)
        super().__setattr__('_FailClosedEngine__terminal_state_locked', True)
        super().__setattr__('_FailClosedEngine__secure_ram_key', None)

        self._log_event("ZEROIZATION_COMPLETE", "Secure RAM wiped and terminal flags locked.")
        
        # قفل الفئة نهائياً وتحويل الكائن إلى الوكيل المحصن لمنع أي استعادة لاحقة
        self.__class__ = ZeroizedEngineProxy
        return True

    def execute_zeroization(self) -> bool:
        return self.zeroize()

    def add_signature(self, admin_id: str):
        self._verify_constitutional_integrity()
        self.authorized_admins.add(admin_id)
        self._log_event("ADMIN_SIGNATURE_ADDED", f"Admin {admin_id} added.")

    def check_quorum(self, required_count: int = 2) -> bool:
        return len(self.authorized_admins) >= required_count

    def check_admissibility(self) -> bool:
        try:
            self._verify_constitutional_integrity()
            raw_dict = object.__getattribute__(self, "__dict__")
            ram = raw_dict.get("_FailClosedEngine__secure_ram_key")
            return ram is not None and not all(b == 0 for b in ram)
        except PermissionError:
            return False

    def execute_critical_operation(self, action: str = "", quorum=None) -> str:
        self._verify_constitutional_integrity()

        if not self.check_admissibility():
            raise PermissionError("CRITICAL_BLOCK: Terminal state zeroization is irreversible.")

        effective_count = len(quorum) if isinstance(quorum, list) else 2
        if self.check_quorum(effective_count):
            self._log_event("CRITICAL_OPERATION_AUTHORIZED", {"quorum": effective_count})
            return "OPERATION_SUCCESS: Quorum reached."
        else:
            raise PermissionError("CRITICAL_BLOCK: Insufficient signatures.")

    def inspect_raw_memory_snapshot(self) -> bytes:
        raw_dict = object.__getattribute__(self, "__dict__")
        ram = raw_dict.get("_FailClosedEngine__secure_ram_key")
        if ram is None:
            return b'\x00' * 32
        return bytes(ram)

TurkashEngine = FailClosedEngine
