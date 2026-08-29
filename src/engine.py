import weakref

class _RegistrySentinelMeta(type):
    def __setattr__(cls, name, value):
        raise PermissionError("P0-05: Direct replacement of the zeroization registry is strictly forbidden.")

class _RegistrySentinel(metaclass=_RegistrySentinelMeta):
    _zeroized_instances = weakref.WeakSet()

class ClassGuardDescriptor:
    def __get__(self, instance, owner):
        if instance is None:
            return owner
        return type(instance)
    def __set__(self, instance, value):
        raise PermissionError("P0-03: Direct class mutation is strictly blocked.")
    def __delete__(self, instance):
        raise PermissionError("P0-03: Deletion of constitutional attributes is strictly blocked.")

class FailClosedEngine:
    _zeroized_instances = _RegistrySentinel._zeroized_instances
    __class__ = ClassGuardDescriptor()

    def __init__(self, *args, **kwargs):
        self._quorum_reached = False
        self._zeroized = False
        self.system_locked = False
        self.secure_ram_key_status = "ACTIVE"
        self._zeroized_instances.add(self)

    @property
    def is_zeroized(self):
        return self._zeroized

    def __setattr__(self, name, value):
        if name == "__class__":
            raise PermissionError("P0-03: Direct class mutation is strictly blocked.")
        super().__setattr__(name, value)

    def __delattr__(self, name):
        if name in ("__class__", "_zeroized_instances"):
            raise PermissionError("P0-03/P0-05: Deletion of constitutional attributes is strictly blocked.")
        super().__delattr__(name)

    def _verify_constitutional_integrity(self):
        if type(self) is not FailClosedEngine and type(self) is not TurkashEngine:
            raise PermissionError("P0-03: Constitutional integrity violation detected.")
        return True

    def execute_critical_operation(self, *args, **kwargs):
        self._verify_constitutional_integrity()
        quorum_flags = kwargs.get('quorum_flags') or kwargs.get('quorum') or (args[0] if args else None)
        
        if quorum_flags and all(quorum_flags):
            self._quorum_reached = True
            return "OPERATION_SUCCESS: Quorum reached."
        
        self.zeroize()
        return "OPERATION_DENIED: Fail-closed triggered."

    def zeroize(self):
        self._zeroized = True
        self._quorum_reached = False
        self.system_locked = True
        self.secure_ram_key_status = "ZEROIZED"
        return "ENGINE_ZEROIZED"

    def inspect_raw_memory_snapshot(self):
        return {
            "zeroized": self._zeroized,
            "system_locked": self.system_locked,
            "quorum_reached": self._quorum_reached,
            "secure_ram_key_status": self.secure_ram_key_status
        }

TurkashEngine = FailClosedEngine
