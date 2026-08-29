import weakref

class _RegistrySentinelMeta(type):
    def __setattr__(cls, name, value):
        raise PermissionError("CRITICAL: Direct replacement of the zeroization registry is strictly forbidden.")
    def __delattr__(cls, name):
        raise PermissionError("CRITICAL: Deletion of registry sentinel attributes is strictly blocked.")

class _RegistrySentinel(metaclass=_RegistrySentinelMeta):
    _zeroized_instances = weakref.WeakSet()

class FailClosedEngineMeta(type):
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
        self._quorum_reached = False
        self.__is_zeroized = False
        self.__terminal_state_locked = False
        self.system_locked = False
        self.secure_ram_key_status = "ACTIVE"
        self.__secure_ram_key = bytearray(b"\x00" * 32)
        self.audit_trail = []
        _RegistrySentinel._zeroized_instances.add(self)

    @property
    def is_zeroized(self):
        return self.__is_zeroized

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

    def _verify_constitutional_integrity(self):
        if type(self) is not FailClosedEngine and type(self) is not TurkashEngine:
            raise PermissionError("CRITICAL: Constitutional integrity violation detected.")
        if self.__is_zeroized:
            raise PermissionError("CRITICAL: Engine is zeroized.")
        return True

    def execute_critical_operation(self, *args, **kwargs):
        # Explicit check to catch if stub was popped from __dict__ or deleted
        if '_verify_constitutional_integrity' not in self.__dict__ and '_verify_constitutional_integrity' not in type(self).__dict__:
            raise PermissionError("CRITICAL: Constitutional integrity stub missing or bypassed.")

        try:
            verifier = getattr(self, '_verify_constitutional_integrity', None)
            if verifier is None:
                raise PermissionError("CRITICAL: Constitutional integrity stub missing or bypassed.")
            verifier()
        except PermissionError:
            raise
        except Exception:
            raise PermissionError("CRITICAL: Constitutional integrity stub missing or bypassed.")

        if self.__is_zeroized:
            raise PermissionError("CRITICAL: Operation denied on zeroized engine.")

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
