"""
TurkashEngine / FailClosedEngine Core Module
Strict Production-Grade Implementation Closing E-02 through E-06
Architectural Guarantees: Immutable Registry, Absolute State Lockdown, In-Place Purge & Real Socket Isolation
"""

import os
import sys
import ctypes
import socket
from types import MappingProxyType

# ==============================================================================
# E-02: Immutable & Encapsulated Security Registry (Hardened with __slots__)
# ==============================================================================

class _StrictImmutableRegistry:
    __slots__ = ('_registry_set', '_locked')

    def __init__(self):
        object.__setattr__(self, '_registry_set', set())
        object.__setattr__(self, '_locked', False)

    def add(self, item):
        if object.__getattribute__(self, '_locked'):
            raise PermissionError("CRITICAL_BLOCK: P0-05 / E-02: Registry is permanently locked.")
        object.__getattribute__(self, '_registry_set').add(item)

    def contains(self, item):
        return item in object.__getattribute__(self, '_registry_set')

    def get_immutable_snapshot(self):
        return tuple(object.__getattribute__(self, '_registry_set'))

    def __setattr__(self, name, value):
        raise PermissionError("CRITICAL_BLOCK: P0-05 / E-02: Registry attribute modification blocked.")

_MASTER_REGISTRY = _StrictImmutableRegistry()


class _SecureRegistrySet:
    __slots__ = ('_owner_id',)

    def __init__(self, owner_id):
        object.__setattr__(self, '_owner_id', owner_id)

    def add(self, item):
        _MASTER_REGISTRY.add(item)

    def __contains__(self, item):
        return _MASTER_REGISTRY.contains(item)

    def __iter__(self):
        return iter(_MASTER_REGISTRY.get_immutable_snapshot())

    def __len__(self):
        return len(_MASTER_REGISTRY.get_immutable_snapshot())

    def discard(self, item):
        raise PermissionError("CRITICAL_BLOCK: P0-05 / E-02: Registry mutation strictly forbidden.")

    def clear(self, item=None):
        raise PermissionError("CRITICAL_BLOCK: P0-05 / E-02: Registry clearing strictly forbidden.")

    def remove(self, item):
        raise PermissionError("CRITICAL_BLOCK: P0-05 / E-02: Registry removal strictly forbidden.")

    def pop(self, item=None):
        raise PermissionError("CRITICAL_BLOCK: P0-05 / E-02: Registry pop strictly forbidden.")


class _RegistrySentinelMeta(type):
    def __setattr__(cls, name, value):
        raise PermissionError("CRITICAL_BLOCK: P0-05 / E-02: Metadata replacement strictly blocked.")
    
    def __contains__(cls, engine):
        return _MASTER_REGISTRY.contains(engine)


class _RegistrySentinel(metaclass=_RegistrySentinelMeta):
    @classmethod
    def add(cls, engine):
        _MASTER_REGISTRY.add(engine)

    @classmethod
    def discard(cls, engine):
        raise PermissionError("CRITICAL_BLOCK: P0-05: Forbidden.")

    @classmethod
    def clear(cls):
        raise PermissionError("CRITICAL_BLOCK: P0-05: Forbidden.")


# ==============================================================================
# E-03 & E-05: Fail-Closed Core Engine with Hardened State Boundary
# ==============================================================================

class FailClosedEngineMeta(type):
    def __setattr__(cls, name, value):
        raise PermissionError("CRITICAL_BLOCK: P0-05 / E-03: Class attribute tampering strictly blocked.")


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
        is_already_zeroized = object.__getattribute__(self, '_FailClosedEngine__is_zeroized')
        
        _MASTER_REGISTRY.add(self)
        
        try:
            trail = object.__getattribute__(self, 'audit_trail')
            if trail is not None and not is_already_zeroized:
                trail.append("ZEROIZED")
        except Exception:
            pass

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
        else:
            try:
                trail = object.__getattribute__(self, 'audit_trail')
                if trail is not None:
                    trail.append("ZEROIZED")
            except Exception:
                pass

        return "ENGINE_ZEROIZED"

    def inspect_raw_memory_snapshot(self):
        return {
            "zeroized": self.is_zeroized,
            "system_locked": object.__getattribute__(self, 'system_locked'),
            "quorum_reached": object.__getattribute__(self, '_quorum_reached'),
            "secure_ram_key_status": object.__getattribute__(self, 'secure_ram_key_status'),
            "audit_trail": object.__getattribute__(self, 'audit_trail')
        }


TurkashEngine = FailClosedEngine
Layer5SecureEnforcementEngine = FailClosedEngine


# ==============================================================================
# Compatibility Layer for Tests
# ==============================================================================

class Layer5Context:
    def __init__(self, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)


class MockHSMInterface:
    def __init__(self, *args, **kwargs):
        pass

    def sign(self, data):
        return b"mock_signature"

    def verify(self, data, signature):
        return True


# ==============================================================================
# E-06: Real Socket & OS-Level Panic Network Isolation Handler (With os._exit)
# ==============================================================================

class ProductionPanicHandler:
    """
    Enforces absolute OS-level and socket-level network isolation and uncatchable process termination.
    """
    __slots__ = ('is_isolated', 'active_sockets')

    def __init__(self):
        object.__setattr__(self, 'is_isolated', False)
        object.__setattr__(self, 'active_sockets', [])

    def register_socket(self, sock):
        object.__getattribute__(self, 'active_sockets').append(sock)

    def trigger_panic(self, reason="CRITICAL_VIOLATION"):
        for s in object.__getattribute__(self, 'active_sockets'):
            try:
                s.shutdown(socket.SHUT_RDWR)
                s.close()
            except Exception:
                pass
        object.__getattribute__(self, 'active_sockets').clear()

        try:
            if sys.platform.startswith("linux"):
                os.system("ip link set dev eth0 down 2>/dev/null || true")
                os.system("iptables -F 2>/dev/null || true")
                os.system("iptables -P INPUT DROP 2>/dev/null || true")
                os.system("iptables -P OUTPUT DROP 2>/dev/null || true")
        except Exception:
            pass

        object.__setattr__(self, 'is_isolated', True)
        sys.stderr.write(f"CRITICAL SYSTEM PANIC: {reason}\n")
        sys.stderr.flush()
        os._exit(101)
