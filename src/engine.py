import os
import weakref

class _RegistrySentinelMeta(type):
    def __setattr__(cls, name, value):
        raise PermissionError("P0-05: Direct replacement or modification of the registry sentinel is strictly forbidden.")

class _RegistrySentinel(metaclass=_RegistrySentinelMeta):
    _zeroized_instances = weakref.WeakSet()
    # استخدام set عادي مع مراجع قوية لمنع تجاوز التتبع عبر .discard()
    _permanently_zeroized = set()

class FailClosedEngineMeta(type):
    def __setattr__(cls, name, value):
        # منع أي كتابة على مستوى الكلاس لحماية السجلات من الاستبدال
        raise PermissionError("P0-03/P0-05: Direct class modification or attribute replacement is strictly blocked.")

class FailClosedEngine(metaclass=FailClosedEngineMeta):
    _zeroized_instances = _RegistrySentinel._zeroized_instances
    _permanently_zeroized = _RegistrySentinel._permanently_zeroized

    def __init__(self, *args, **kwargs):
        self._quorum_reached = False
        self._FailClosedEngine__is_zeroized = False
        self._FailClosedEngine__terminal_state_locked = False
        self.system_locked = False
        self.secure_ram_key_status = "ACTIVE"
        # استعادة استخدام os.urandom(32) لضمان مفتاح عشوائي مشفر
        self._FailClosedEngine__secure_ram_key = bytearray(os.urandom(32))
        self.audit_trail = []
        self._zeroized_instances.add(self)

    @property
    def is_zeroized(self):
        return self._FailClosedEngine__is_zeroized or (self in self._permanently_zeroized)

    def __setattr__(self, name, value):
        if name == "__class__":
            raise PermissionError("P0-03: Direct class mutation is strictly blocked.")
        super().__setattr__(name, value)

    def __delattr__(self, name):
        if name in ("__class__", "_zeroized_instances", "_permanently_zeroized"):
            raise PermissionError("P0-03/P0-05: Deletion of constitutional attributes is strictly blocked.")
        super().__delattr__(name)

    def check_admissibility(self):
        # استعادة منطق فحص سلامة المفتاح والتحقق من عدم كونه أصفاراً
        if all(b == 0 for b in self._FailClosedEngine__secure_ram_key):
            raise PermissionError("P0-04: Cryptographically inert zero-initialized RAM key detected.")
        if self in self._permanently_zeroized or self._FailClosedEngine__is_zeroized:
            raise PermissionError("P0-03: CRITICAL_BLOCK - Engine is zeroized.")
        return True

    def _verify_constitutional_integrity(self):
        if type(self) is not FailClosedEngine and type(self) is not TurkashEngine:
            raise PermissionError("P0-03: Constitutional integrity violation detected.")
        self.check_admissibility()
        return True

    def execute_critical_operation(self, *args, **kwargs):
        self._verify_constitutional_integrity()

        quorum_flags = kwargs.get('quorum_flags') or kwargs.get('quorum') or (args[0] if args else None)
        
        if quorum_flags and all(quorum_flags):
            self._quorum_reached = True
            self.audit_trail.append("QUORUM_REACHED")
            return "OPERATION_SUCCESS: Quorum reached."
        
        self.zeroize()
        return "OPERATION_DENIED: Fail-closed triggered."

    def zeroize(self):
        self._permanently_zeroized.add(self)
        if not self._FailClosedEngine__is_zeroized:
            self._FailClosedEngine__is_zeroized = True
            self._FailClosedEngine__terminal_state_locked = True
            self.system_locked = True
            self.secure_ram_key_status = "ZEROIZED"
            self._FailClosedEngine__secure_ram_key = bytearray(b"\xFF" * 32)
            self.audit_trail.append("ZEROIZED")
        return "ENGINE_ZEROIZED"

    def inspect_raw_memory_snapshot(self):
        return {
            "zeroized": self._FailClosedEngine__is_zeroized or (self in self._permanently_zeroized),
            "system_locked": self.system_locked,
            "quorum_reached": self._quorum_reached,
            "secure_ram_key_status": self.secure_ram_key_status,
            "audit_trail": self.audit_trail
        }

TurkashEngine = FailClosedEngine
