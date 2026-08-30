import os

class _SecureRegistrySet(set):
    """مجموعة مشتقة ترث من set الأصلي لضمان مطابقة نوع الأنواع (Type Check)، مع حظر دائم لأي تعديل خارجي"""
    def discard(self, __value):
        raise PermissionError("P0-05: Direct mutation/discard from the zeroized registry is strictly forbidden.")

    def clear(self):
        raise PermissionError("P0-05: Direct clearing of the zeroized registry is strictly forbidden.")

    def remove(self, __value):
        raise PermissionError("P0-05: Direct mutation from the zeroized registry is strictly forbidden.")

    def pop(self):
        raise PermissionError("P0-05: Direct mutation from the zeroized registry is strictly forbidden.")

    def update(self, *s):
        raise PermissionError("P0-05: Direct update/mutation from the zeroized registry is strictly forbidden.")

    def intersection_update(self, *s):
        raise PermissionError("P0-05: Direct mutation from the zeroized registry is strictly forbidden.")

    def difference_update(self, *s):
        raise PermissionError("P0-05: Direct mutation from the zeroized registry is strictly forbidden.")

    def symmetric_difference_update(self, *s):
        raise PermissionError("P0-05: Direct mutation from the zeroized registry is strictly forbidden.")

    def add(self, __element):
        # السماح حصرياً بالتسجيل الداخلي للعمليات المشروعة
        super().add(__element)

class _RegistrySentinelMeta(type):
    def __setattr__(cls, name, value):
        raise PermissionError("P0-05: Direct replacement of the registry is strictly forbidden.")
    
    def __contains__(cls, engine):
        return engine in cls._permanently_zeroized

class _RegistrySentinel(metaclass=_RegistrySentinelMeta):
    _permanently_zeroized = _SecureRegistrySet()

    @classmethod
    def add(cls, engine):
        cls._permanently_zeroized.add(engine)

    @classmethod
    def discard(cls, engine):
        raise PermissionError("P0-05: Direct mutation/discard from the zeroized registry is strictly forbidden.")

    @classmethod
    def clear(cls):
        raise PermissionError("P0-05: Direct clearing of the zeroized registry is strictly forbidden.")

class FailClosedEngineMeta(type):
    def __setattr__(cls, name, value):
        raise PermissionError("P0-05: Direct class attribute modification on FailClosedEngine is strictly blocked.")

class FailClosedEngine(metaclass=FailClosedEngineMeta):
    _permanently_zeroized = _RegistrySentinel

    def __init__(self, *args, **kwargs):
        self._quorum_reached = False
        self._FailClosedEngine__is_zeroized = False
        self._FailClosedEngine__terminal_state_locked = False
        self.system_locked = False
        self.secure_ram_key_status = "ACTIVE"
        self._FailClosedEngine__secure_ram_key = bytearray(os.urandom(32))
        self.audit_trail = []

    @property
    def is_zeroized(self):
        return self._FailClosedEngine__is_zeroized or (self in self._permanently_zeroized)

    def __setattr__(self, name, value):
        if name == "__class__":
            raise PermissionError("P0-03: Direct class mutation is strictly blocked.")
        super().__setattr__(name, value)

    def __delattr__(self, name):
        if name in ("__class__", "_permanently_zeroized"):
            raise PermissionError("P0-03/P0-05: Deletion of constitutional attributes is strictly blocked.")
        super().__delattr__(name)

    def _check_admissibility(self):
        if all(b == 0 for b in self._FailClosedEngine__secure_ram_key):
            return False
        return True

    def _verify_constitutional_integrity(self):
        if type(self) is not FailClosedEngine and type(self) is not TurkashEngine:
            raise PermissionError("P0-03: Constitutional integrity violation detected.")
        if not self._check_admissibility():
            raise PermissionError("P0-04: RAM key admissibility check failed.")
        if self in self._permanently_zeroized or self.__dict__.get("_FailClosedEngine__is_zeroized", False):
            raise PermissionError("P0-03: CRITICAL_BLOCK - Engine is zeroized.")
        return True

    def execute_critical_operation(self, *args, **kwargs):
        self._verify_constitutional_integrity()
        
        if not self._check_admissibility() or self in self._permanently_zeroized or self.__dict__.get("_FailClosedEngine__is_zeroized", False):
            raise PermissionError("P0-03: CRITICAL_BLOCK - Operation denied on zeroized engine.")

        quorum_flags = kwargs.get('quorum_flags') or kwargs.get('quorum') or (args[0] if args else None)
        
        if quorum_flags and all(quorum_flags):
            self._quorum_reached = True
            self.audit_trail.append("QUORUM_REACHED")
            return "OPERATION_SUCCESS: Quorum reached."
        
        self.zeroize()
        return "DENY"

    def zeroize(self):
        self._permanently_zeroized.add(self)
        if not self.__dict__.get("_FailClosedEngine__is_zeroized", False):
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
