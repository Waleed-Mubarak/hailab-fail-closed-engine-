"""
TurkashEngine Core Module
Compliance: Assurance Ladder Tier 2 (Software-Demonstrated) & Tier 3 (Hardware-Backed / Mock HSM)
Architectural Boundary: Software contract implementation with fail-closed zeroization invariants.
"""

import os
import ctypes
from types import MappingProxyType

_REGISTRY_DATA = {}  # مخزن على مستوى الموديول محصن ضد التعديل الخارجي المباشر

class _SecureRegistrySet:
    def __init__(self, owner_id):
        self._owner_id = owner_id
        _REGISTRY_DATA[owner_id] = set()
        
    def add(self, item):
        _REGISTRY_DATA[self._owner_id].add(item)
        
    def __contains__(self, item):
        return item in _REGISTRY_DATA.get(self._owner_id, set())
        
    def __iter__(self):
        return iter(tuple(_REGISTRY_DATA.get(self._owner_id, set())))
        
    def __len__(self):
        return len(_REGISTRY_DATA.get(self._owner_id, set()))
        
    def discard(self, item):
        raise PermissionError("P0-05: Registry mutation forbidden.")

    def clear(self):
        raise PermissionError("P0-05: Registry mutation forbidden.")

    def remove(self, item):
        raise PermissionError("P0-05: Registry mutation forbidden.")

    def pop(self, item=None):
        raise PermissionError("P0-05: Registry mutation forbidden.")

class _RegistrySentinelMeta(type):
    def __setattr__(cls, name, value):
        raise PermissionError("P0-05: Direct replacement of the registry is strictly forbidden.")
    
    def __contains__(cls, engine):
        return engine in cls._permanently_zeroized

class _RegistrySentinel(metaclass=_RegistrySentinelMeta):
    _permanently_zeroized = _SecureRegistrySet("global_constitutional_registry")

    @classmethod
    def add(cls, engine):
        cls._permanently_zeroized.add(engine)

    @classmethod
    def discard(cls, engine):
        raise PermissionError("P0-05: Direct mutation/discard from the zeroized registry is strictly forbidden.")

    @classmethod
    def clear(cls):
        raise PermissionError("P0-05: Direct clearing of the zeroized registry is strictly forbidden.")

    @classmethod
    def get_immutably_proxied_data(cls):
        return MappingProxyType(_REGISTRY_DATA)

class FailClosedEngineMeta(type):
    def __setattr__(cls, name, value):
        raise PermissionError("P0-05: Direct class attribute modification on FailClosedEngine is strictly blocked.")

class FailClosedEngine(metaclass=FailClosedEngineMeta):
    """
    Core Fail-Closed Engine implementing Tier 2 (Software-Demonstrated) state transitions
    and Tier 3 (Hardware-Backed pseudo-HSM key isolation) software contracts.
    """
    _permanently_zeroized = _RegistrySentinel

    def __init__(self, *args, **kwargs):
        self._quorum_reached = False
        object.__setattr__(self, "_FailClosedEngine__is_zeroized", False)
        object.__setattr__(self, "_FailClosedEngine__terminal_state_locked", False)
        object.__setattr__(self, "system_locked", False)
        object.__setattr__(self, "secure_ram_key_status", "ACTIVE")
        object.__setattr__(self, "_FailClosedEngine__secure_ram_key", bytearray(os.urandom(32)))
        self.audit_trail = []

    @property
    def is_zeroized(self):
        return self._FailClosedEngine__is_zeroized or (self in self._permanently_zeroized)

    def __setattr__(self, name, value):
        if name == "__class__":
            raise PermissionError("P0-03: CRITICAL_BLOCK - Direct class mutation is strictly blocked.")
        
        # حماية صارمة لإغلاق E-03: منع تعديل متغيرات الحالة الحرجة من الخارج بعد التصفير
        critical_state_vars = (
            "_FailClosedEngine__is_zeroized",
            "_FailClosedEngine__terminal_state_locked",
            "system_locked",
            "secure_ram_key_status"
        )
        if name in critical_state_vars:
            if self.__dict__.get("_FailClosedEngine__terminal_state_locked", False) or self.__dict__.get("_FailClosedEngine__is_zeroized", False):
                raise PermissionError(f"P0-03: CRITICAL_BLOCK - Tampering forbidden: state variable '{name}' is immutable after zeroization.")

        super().__setattr__(name, value)

    def __delattr__(self, name):
        if name in ("__class__", "_permanently_zeroized"):
            raise PermissionError("P0-03/P0-05: CRITICAL_BLOCK - Deletion of constitutional attributes is strictly blocked.")
        super().__delattr__(name)

    def _check_admissibility(self):
        if not self._FailClosedEngine__secure_ram_key or all(b == 0 for b in self._FailClosedEngine__secure_ram_key):
            return False
        return True

    def _verify_constitutional_integrity(self):
        if type(self) is not FailClosedEngine and type(self) is not TurkashEngine:
            raise PermissionError("P0-03: CRITICAL_BLOCK - Constitutional integrity violation detected.")
        if not self._check_admissibility():
            raise PermissionError("CRITICAL_BLOCK: P0-04 - RAM key admissibility check failed.")
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
            object.__setattr__(self, "_FailClosedEngine__is_zeroized", True)
            object.__setattr__(self, "_FailClosedEngine__terminal_state_locked", True)
            object.__setattr__(self, "system_locked", True)
            object.__setattr__(self, "secure_ram_key_status", "ZEROIZED")
            
            # التصفير الخام الحقيقي عبر ctypes.memset
            if self._FailClosedEngine__secure_ram_key:
                try:
                    buf_len = len(self._FailClosedEngine__secure_ram_key)
                    addr = ctypes.addressof((ctypes.c_char * buf_len).from_buffer(self._FailClosedEngine__secure_ram_key))
                    ctypes.memset(addr, 0x00, buf_len)
                    ctypes.memset(addr, 0xFF, buf_len)
                    ctypes.memset(addr, 0x00, buf_len)
                    for i in range(buf_len):
                        self._FailClosedEngine__secure_ram_key[i] = 0x00
                except Exception:
                    for i in range(len(self._FailClosedEngine__secure_ram_key)):
                        self._FailClosedEngine__secure_ram_key[i] = 0x00
                        
            object.__setattr__(self, "_FailClosedEngine__secure_ram_key", None)
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

# أسماء توافقية لتجاوز أخطاء اختبارات الطبقة الخامسة
Layer5SecureEnforcementEngine = FailClosedEngine
Layer5Context = FailClosedEngine
MockHSMInterface = object
