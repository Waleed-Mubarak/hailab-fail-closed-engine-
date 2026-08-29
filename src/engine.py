import weakref

class _RegistrySentinelMeta(type):
    def __setattr__(cls, name, value):
        raise PermissionError("P0-05: Direct replacement of the zeroization registry is strictly forbidden.")

class _RegistrySentinel(metaclass=_RegistrySentinelMeta):
    _zeroized_instances = weakref.WeakSet()

class FailClosedEngineMeta(type):
    def __setattr__(cls, name, value):
        if name == "__class__":
            raise PermissionError("P0-03: Direct class mutation is strictly blocked.")
        super().__setattr__(name, value)

class FailClosedEngine(metaclass=FailClosedEngineMeta):
    _zeroized_instances = _RegistrySentinel._zeroized_instances

    def __init__(self, *args, **kwargs):
        self._quorum_reached = False
        self.__is_zeroized = False
        self.__terminal_state_locked = False
        self.system_locked = False
        self.secure_ram_key_status = "ACTIVE"
        self.__secure_ram_key = bytearray(b"\x00" * 32)
        self.audit_trail = []
        self._zeroized_instances.add(self)

    @property
    def is_zeroized(self):
        return self.__is_zeroized

    def __setattr__(self, name, value):
        if name == "__class__":
            raise PermissionError("P0-03: Direct class mutation is strictly blocked.")
        if self.__is_zeroized and name in ("_FailClosedEngine__is_zeroized", "_FailClosedEngine__terminal_state_locked", "system_locked"):
            raise PermissionError("P0-03: CRITICAL_BLOCK - State mutation denied.")
        super().__setattr__(name, value)

    def __delattr__(self, name):
        if name in ("__class__", "_zeroized_instances"):
            raise PermissionError("P0-03/P0-05: Deletion of constitutional attributes is strictly blocked.")
        super().__delattr__(name)

    def _verify_constitutional_integrity(self):
        if type(self) is not FailClosedEngine and type(self) is not TurkashEngine:
            raise PermissionError("P0-03: Constitutional integrity violation detected.")
        if self.__is_zeroized:
            raise PermissionError("P0-03: CRITICAL_BLOCK - Engine is zeroized.")
        return True

    def execute_critical_operation(self, *args, **kwargs):
        self._verify_constitutional_integrity()
        
        if self.__is_zeroized:
            raise PermissionError("P0-03: CRITICAL_BLOCK - Operation denied on zeroized engine.")

        quorum_flags = kwargs.get('quorum_flags') or kwargs.get('quorum') or (args[0] if args else None)
        
        if quorum_flags and all(quorum_flags):
            self._quorum_reached = True
            self.audit_trail.append("QUORUM_REACHED")
            return "OPERATION_SUCCESS: Quorum reached."
        
        self.zeroize()
        return "OPERATION_DENIED: Fail-closed triggered."

    def zeroize(self):
        if not self.__is_zeroized:
            self.__is_zeroized = True
            self.__terminal_state_locked = True
            self.system_locked = True
            self.secure_ram_key_status = "ZEROIZED"
            self.__secure_ram_key = bytearray(b"\xFF" * 32)
            self.audit_trail.append("ZEROIZED")
        return "ENGINE_ZEROIZED"

    def inspect_raw_memory_snapshot(self):
        return {
            "zeroized": self.__is_zeroized,
            "system_locked": self.system_locked,
            "quorum_reached": self._quorum_reached,
            "secure_ram_key_status": self.secure_ram_key_status,
            "audit_trail": self.audit_trail
        }

TurkashEngine = FailClosedEngine
