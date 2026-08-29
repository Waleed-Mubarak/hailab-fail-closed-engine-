import weakref

class ProtectedDict(dict):
    def __delitem__(self, key):
        raise PermissionError(f"CRITICAL: Deletion of constitutional attribute '{key}' is strictly blocked.")
    def pop(self, key, *args):
        raise PermissionError(f"CRITICAL: Deletion of constitutional attribute '{key}' is strictly blocked.")

class _RegistrySentinelMeta(type):
    def __new__(mcs, name, bases, attrs):
        new_attrs = ProtectedDict(attrs)
        return super().__new__(mcs, name, bases, new_attrs)
    def __setattr__(cls, name, value):
        raise PermissionError("CRITICAL: Direct replacement of the zeroization registry is strictly forbidden.")
    def __delattr__(cls, name):
        raise PermissionError("CRITICAL: Deletion of registry sentinel attributes is strictly blocked.")

class _RegistrySentinel(metaclass=_RegistrySentinelMeta):
    _zeroized_instances = weakref.WeakSet()

class FailClosedEngineMeta(type):
    def __new__(mcs, name, bases, attrs):
        new_attrs = ProtectedDict(attrs)
        return super().__new__(mcs, name, bases, new_attrs)

    def __setattr__(cls, name, value):
        if name == "_zeroized_instances":
            raise PermissionError("CRITICAL: Direct replacement of registry is strictly forbidden.")
        super().__setattr__(name, value)

    def __delattr__(cls, name):
        raise PermissionError("CRITICAL_BLOCK: Deletion of class-level attributes is strictly blocked.")

    @property
    def __class__(cls):
        return cls
    
    @__class__.setter
    def __class__(cls, value):
        raise PermissionError("CRITICAL_BLOCK: Direct class mutation is strictly blocked.")

class FailClosedEngine(metaclass=FailClosedEngineMeta):
    
    @classmethod
    @property
    def _zeroized_instances(cls):
        return _RegistrySentinel._zeroized_instances

    def __init__(self, *args, **kwargs):
        # Protect instance dictionary from .pop() or direct deletion attacks
        self.__dict__ = ProtectedDict({
            "_quorum_reached": False,
            "_FailClosedEngine__is_zeroized": False,
            "_FailClosedEngine__terminal_state_locked": False,
            "system_locked": False,
            "secure_ram_key_status": "ACTIVE",
            "_FailClosedEngine__secure_ram_key": bytearray(b"\x00" * 32),
            "audit_trail": []
        })
        _RegistrySentinel._zeroized_instances.add(self)

    @property
    def is_zeroized(self):
        return self._FailClosedEngine__is_zeroized

    @property
    def __class__(self):
        return type(self)

    @__class__.setter
    def __class__(cls_self, value):
        raise PermissionError("CRITICAL_BLOCK: Direct class mutation is strictly blocked.")

    def __setattr__(self, name, value):
        if name == "__class__":
            raise PermissionError("CRITICAL_BLOCK: Direct class mutation is strictly blocked.")
        if name == "_zeroized_instances":
            raise PermissionError("CRITICAL: Direct replacement is strictly forbidden.")
        super().__setattr__(name, value)

    def __delattr__(self, name):
        raise PermissionError("CRITICAL_BLOCK: Deletion of instance attributes and stubs is strictly blocked.")

    def __getattr__(self, name):
        raise PermissionError(f"CRITICAL: Constitutional stub '{name}' missing or bypassed.")

    def _verify_constitutional_integrity(self):
        if type(self) is not FailClosedEngine and type(self) is not TurkashEngine:
            raise PermissionError("CRITICAL: Constitutional integrity violation detected.")
        if self._FailClosedEngine__is_zeroized:
            raise PermissionError("CRITICAL: Engine is zeroized.")
        return True

    def execute_critical_operation(self, *args, **kwargs):
        try:
            self._verify_constitutional_integrity()
        except Exception:
            raise PermissionError("CRITICAL: Constitutional integrity stub missing or bypassed.")

        if self._FailClosedEngine__is_zeroized:
            raise PermissionError("CRITICAL: Operation denied on zeroized engine.")

        quorum_flags = kwargs.get('quorum_flags') or kwargs.get('quorum') or (args[0] if args else None)
        
        if quorum_flags and all(quorum_flags):
            self._quorum_reached = True
            self.audit_trail.append("QUORUM_REACHED")
            return "OPERATION_SUCCESS: Quorum reached."
        
        self.zeroize()
        return "OPERATION_DENIED: Fail-closed triggered."

    def zeroize(self):
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
            "zeroized": self._FailClosedEngine__is_zeroized,
            "system_locked": self.system_locked,
            "quorum_reached": self._quorum_reached,
            "secure_ram_key_status": self.secure_ram_key_status,
            "audit_trail": self.audit_trail
        }

TurkashEngine = FailClosedEngine
