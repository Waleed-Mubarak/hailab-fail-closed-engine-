class FailClosedEngine(metaclass=FailClosedEngineMeta):
    """
    Fully Hardened Fail-Closed Engine complying with absolute security invariants.
    """
    __slots__ = (
        '__dict__',
        '_quorum_reached', 
        '_FailClosedEngine__is_zeroized', 
        '_FailClosedEngine__terminal_state_locked', 
        'system_locked', 
        'secure_ram_key_status', 
        '_FailClosedEngine__secure_ram_key', 
        'audit_trail'
    )
    _permanently_zeroized = _RegistrySentinel

    def __init__(self, *args, **kwargs):
        object.__setattr__(self, '_quorum_reached', False)
        object.__setattr__(self, '_FailClosedEngine__is_zeroized', False)
        object.__setattr__(self, '_FailClosedEngine__terminal_state_locked', False)
        object.__setattr__(self, 'system_locked', False)
        object.__setattr__(self, 'secure_ram_key_status', "ACTIVE")
        object.__setattr__(self, '_FailClosedEngine__secure_ram_key', bytearray(os.urandom(32)))
        object.__setattr__(self, 'audit_trail', [])

    @property
    def is_zeroized(self):
        return object.__getattribute__(self, '_FailClosedEngine__is_zeroized') or (_MASTER_REGISTRY.contains(self))

    def __setattr__(self, name, value):
        if object.__getattribute__(self, '_FailClosedEngine__terminal_state_locked') or object.__getattribute__(self, '_FailClosedEngine__is_zeroized'):
            raise PermissionError(f"CRITICAL_BLOCK: P0-03 / E-03: Critical security violation. Engine is locked/zeroized, attribute '{name}' is immutable.")

        critical_state_vars = (
            '_FailClosedEngine__is_zeroized',
            '_FailClosedEngine__terminal_state_locked',
            'system_locked',
            'secure_ram_key_status'
        )
        if name in critical_state_vars:
            raise PermissionError(f"CRITICAL_BLOCK: P0-03 / E-03: State variable '{name}' is strictly immutable.")

        if name == "__class__":
            raise PermissionError("CRITICAL_BLOCK: P0-03: Class mutation blocked.")

        super().__setattr__(name, value)

    def __delattr__(self, name):
        raise PermissionError("CRITICAL_BLOCK: P0-03: Deletion of attributes prohibited.")

    def _check_admissibility(self):
        try:
            key = object.__getattribute__(self, '_FailClosedEngine__secure_ram_key')
        except AttributeError:
            return False
        
        if not key or all(b == 0 for b in key):
            return False
        return True

    def _verify_constitutional_integrity(self):
        if type(self) is not FailClosedEngine and type(self) is not TurkashEngine:
            raise PermissionError("CRITICAL_BLOCK: P0-03: Constitutional integrity violation.")
        if not self._check_admissibility():
            raise PermissionError("CRITICAL_BLOCK: P0-04 - RAM key admissibility check failed.")
        if self.is_zeroized:
            raise PermissionError("CRITICAL_BLOCK: P0-03 - Engine is zeroized.")
        return True

    def execute_critical_operation(self, *args, **kwargs):
        self._verify_constitutional_integrity()
        quorum_flags = kwargs.get('quorum_flags') or kwargs.get('quorum') or (args[0] if args else None)

        if quorum_flags and all(quorum_flags):
            object.__setattr__(self, '_quorum_reached', True)
            object.__getattribute__(self, 'audit_trail').append("QUORUM_REACHED")
            return "OPERATION_SUCCESS: Quorum reached."

        self.zeroize()
        return "DENY"

    def zeroize(self):
        _MASTER_REGISTRY.add(self)
        
        try:
            trail = object.__getattribute__(self, 'audit_trail')
            if trail is not None:
                trail.append("ZEROIZED")
        except Exception:
            pass

        is_already_zeroized = object.__getattribute__(self, '_FailClosedEngine__is_zeroized')

        object.__setattr__(self, '_FailClosedEngine__is_zeroized', True)
        object.__setattr__(self, '_FailClosedEngine__terminal_state_locked', True)
        object.__setattr__(self, 'system_locked', True)
        object.__setattr__(self, 'secure_ram_key_status', "ZEROIZED")

        if not is_already_zeroized:
            try:
                key_buf = object.__getattribute__(self, '_FailClosedEngine__secure_ram_key')
            except AttributeError:
                key_buf = None

            if key_buf is not None:
                try:
                    buf_len = len(key_buf)
                    addr = ctypes.addressof((ctypes.c_char * buf_len).from_buffer(key_buf))
                    ctypes.memset(addr, 0x00, buf_len)
                    ctypes.memset(addr, 0xFF, buf_len)
                    ctypes.memset(addr, 0x00, buf_len)
                    for i in range(buf_len):
                        key_buf[i] = 0x00
                except Exception:
                    for i in range(len(key_buf)):
                        key_buf[i] = 0x00

            object.__setattr__(self, '_FailClosedEngine__secure_ram_key', None)

        return "ENGINE_ZEROIZED"

    def inspect_raw_memory_snapshot(self):
        return {
            "zeroized": self.is_zeroized,
            "system_locked": object.__getattribute__(self, 'system_locked'),
            "quorum_reached": object.__getattribute__(self, '_quorum_reached'),
            "secure_ram_key_status": object.__getattribute__(self, 'secure_ram_key_status'),
            "audit_trail": object.__getattribute__(self, 'audit_trail')
        }
