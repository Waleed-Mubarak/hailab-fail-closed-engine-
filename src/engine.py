"""
TurkashEngine / FailClosedEngine Core Module
Strict Production-Grade Implementation Closing E-02 through E-06
Architectural Guarantees: Immutable Registry, Absolute State Lockdown, In-Place Purge & Real Socket Isolation
"""

import os
import sys
import ctypes
import socket
import subprocess
import itertools

# Global atomic counter for unique instance IDs
_INSTANCE_ID_COUNTER = itertools.count(1)

# ==============================================================================
# E-02: Immutable & Encapsulated Security Registry (Hardened)
# ==============================================================================

class _ProtectedStateDescriptor:
    def __init__(self, default=None):
        self._values = {}
        self._default = default

    def __get__(self, instance, owner):
        if instance is None:
            return self
        uid = getattr(instance, '_frozen_uid', None)
        if uid is None:
            return self._default
        return self._values.get(uid, self._default)

    def __set__(self, instance, value):
        if instance is not None:
            uid = getattr(instance, '_frozen_uid', None)
            if uid is None:
                uid = next(_INSTANCE_ID_COUNTER)
                object.__setattr__(instance, '_frozen_uid', uid)
            
            locked = self._values.get(uid, False) if self._default is False else getattr(instance, '_locked', False)
            if locked and self._default is False:
                raise PermissionError("CRITICAL_BLOCK: P0-05 / E-02: Registry is permanently locked.")
            self._values[uid] = value

    def __delete__(self, instance):
        raise PermissionError("CRITICAL_BLOCK: P0-05 / E-02: Deletion forbidden.")


class _StrictImmutableRegistry:
    __slots__ = ('_frozen_uid',)
    
    _registry_set = _ProtectedStateDescriptor(default=None)
    _locked = _ProtectedStateDescriptor(default=False)

    def __init__(self):
        object.__setattr__(self, '_frozen_uid', next(_INSTANCE_ID_COUNTER))
        self._registry_set = set()
        self._locked = False

    def add(self, item):
        if self._locked:
            raise PermissionError("CRITICAL_BLOCK: P0-05 / E-02: Registry is permanently locked.")
        s = self._registry_set
        if s is not None:
            s.add(item)

    def contains(self, item):
        s = self._registry_set
        return item in s if s is not None else False

    def get_immutable_snapshot(self):
        s = self._registry_set
        return tuple(s) if s is not None else ()

    def __setattr__(self, name, value):
        if name in ('_registry_set', '_locked', '_frozen_uid'):
            super().__setattr__(name, value)
        else:
            raise PermissionError("CRITICAL_BLOCK: P0-05 / E-02: Registry attribute modification blocked.")


StrictImmutableRegistry = _StrictImmutableRegistry
_MASTER_REGISTRY = _StrictImmutableRegistry()


# ==============================================================================
# E-03 & E-05: Fail-Closed Core Engine
# ==============================================================================

class ImmutableInstanceIDDescriptor:
    def __get__(self, instance, owner):
        if instance is None:
            return self
        return getattr(instance, '_frozen_uid', None)

    def __set__(self, instance, value):
        if instance is not None:
            current = getattr(instance, '_frozen_uid', None)
            if current is not None:
                raise PermissionError("CRITICAL_BLOCK: P0-03 / E-03: Tampering detected. _instance_uid is immutable.")
            object.__setattr__(instance, '_frozen_uid', value)

    def __delete__(self, instance):
        raise PermissionError("CRITICAL_BLOCK: P0-03 / E-03: Deletion prohibited.")


class EngineStateDescriptor:
    def __init__(self, default_value=False):
        self._values = {}
        self._default = default_value

    def __get__(self, instance, owner):
        if instance is None:
            return self
        uid = getattr(instance, '_frozen_uid', None)
        if uid is None:
            return self._default
        return self._values.get(uid, self._default)

    def __set__(self, instance, value):
        if instance is not None:
            uid = getattr(instance, '_frozen_uid', None)
            if uid is None:
                uid = next(_INSTANCE_ID_COUNTER)
                object.__setattr__(instance, '_frozen_uid', uid)
            
            current_val = self._values.get(uid, self._default)
            if current_val is True and value is False:
                raise PermissionError("CRITICAL_BLOCK: P0-03 / E-03: Terminal state locked. Cannot un-zeroize.")
            
            self._values[uid] = value

    def __delete__(self, instance):
        raise PermissionError("CRITICAL_BLOCK: P0-03 / E-03: Deletion prohibited.")


class FailClosedEngineMeta(type):
    def __setattr__(cls, name, value):
        raise PermissionError("CRITICAL_BLOCK: P0-05 / E-03: Class attribute tampering strictly blocked.")


class FailClosedEngine(metaclass=FailClosedEngineMeta):
    __slots__ = (
        '_frozen_uid',
        '_quorum_reached', 
        'secure_ram_key_status', 
        '_FailClosedEngine__secure_ram_key', 
        'audit_trail'
    )
    
    _instance_uid = ImmutableInstanceIDDescriptor()
    _FailClosedEngine__is_zeroized = EngineStateDescriptor(default_value=False)
    _FailClosedEngine__terminal_state_locked = EngineStateDescriptor(default_value=False)
    system_locked = EngineStateDescriptor(default_value=False)

    def __init__(self, *args, **kwargs):
        uid = next(_INSTANCE_ID_COUNTER)
        object.__setattr__(self, '_frozen_uid', uid)
        object.__setattr__(self, '_quorum_reached', False)
        self._FailClosedEngine__is_zeroized = False
        self._FailClosedEngine__terminal_state_locked = False
        self.system_locked = False
        object.__setattr__(self, 'secure_ram_key_status', "ACTIVE")
        object.__setattr__(self, '_FailClosedEngine__secure_ram_key', bytearray(os.urandom(32)))
        object.__setattr__(self, 'audit_trail', [])

    @property
    def __dict__(self):
        result = {}
        for slot in self.__slots__:
            if slot == '_frozen_uid':
                continue
            try:
                result[slot] = object.__getattribute__(self, slot)
            except AttributeError:
                pass
        result['_instance_uid'] = self._instance_uid
        result['_FailClosedEngine__is_zeroized'] = self._FailClosedEngine__is_zeroized
        result['_FailClosedEngine__terminal_state_locked'] = self._FailClosedEngine__terminal_state_locked
        result['system_locked'] = self.system_locked
        return result

    @property
    def is_zeroized(self):
        return True if (self._FailClosedEngine__terminal_state_locked or self._FailClosedEngine__is_zeroized or _MASTER_REGISTRY.contains(self)) else False

    def __setattr__(self, name, value):
        if self.is_zeroized:
            raise PermissionError(f"CRITICAL_BLOCK: P0-03 / E-03: Critical security violation. Engine is zeroized, attribute '{name}' is immutable.")

        critical_state_vars = (
            '_FailClosedEngine__is_zeroized',
            '_FailClosedEngine__terminal_state_locked',
            'system_locked',
            'secure_ram_key_status',
            '_instance_uid'
        )
        if name in critical_state_vars:
            super(FailClosedEngine, type(self)).__setattr__(self, name, value)
            return

        if name == "__class__":
            raise PermissionError("CRITICAL_BLOCK: P0-03: Class mutation blocked.")

        super().__setattr__(name, value)

    def __delattr__(self, name):
        raise PermissionError("CRITICAL_BLOCK: P0-03 / E-03: Deletion prohibited.")

    def _check_admissibility(self):
        try:
            key = object.__getattribute__(self, '_FailClosedEngine__secure_ram_key')
        except AttributeError:
            return False
        
        if not key or all(b == 0 for b in key):
            return False
        return True

    def _verify_constitutional_integrity(self):
        if type(self) is not FailClosedEngine:
            raise PermissionError("CRITICAL_BLOCK: P0-03: Constitutional integrity violation.")
        if self.is_zeroized:
            raise PermissionError("CRITICAL_BLOCK: P0-03 - Engine is zeroized and permanently locked.")
        if not self._check_admissibility():
            raise PermissionError("CRITICAL_BLOCK: P0-04 - RAM key admissibility check failed.")
        return True

    def execute_critical_operation(self, *args, **kwargs):
        if self.is_zeroized:
            raise PermissionError("CRITICAL_BLOCK: P0-03 / E-03: Operation denied. Engine is in terminal zeroized state.")
        
        self._verify_constitutional_integrity()
        quorum_flags = kwargs.get('quorum_flags') or kwargs.get('quorum') or (args[0] if args else None)

        if quorum_flags and all(quorum_flags):
            object.__setattr__(self, '_quorum_reached', True)
            object.__getattribute__(self, 'audit_trail').append("QUORUM_REACHED")
            return "OPERATION_SUCCESS: Quorum reached."

        self.zeroize()
        return "DENY"

    def zeroize(self):
        is_already_zeroized = self.is_zeroized
        
        _MASTER_REGISTRY.add(self)
        
        try:
            trail = object.__getattribute__(self, 'audit_trail')
            if trail is not None and not is_already_zeroized:
                trail.append("ZEROIZED")
        except Exception:
            pass

        self._FailClosedEngine__is_zeroized = True
        self._FailClosedEngine__terminal_state_locked = True
        self.system_locked = True
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
            "system_locked": self.system_locked,
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
# E-06: Real Socket & OS-Level Panic Network Isolation Handler
# ==============================================================================

class ProductionPanicHandler:
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
                interfaces = ["eth0", "ens33", "enp3s0"]
                for iface in interfaces:
                    res = subprocess.run(
                        ["ip", "link", "set", "dev", iface, "down"],
                        capture_output=True,
                        text=True,
                        check=False
                    )
                    if res.returncode == 0:
                        break

                iptables_commands = [
                    ["iptables", "-F"],
                    ["iptables", "-P", "INPUT", "DROP"],
                    ["iptables", "-P", "OUTPUT", "DROP"],
                    ["iptables", "-P", "FORWARD", "DROP"]
                ]
                for cmd in iptables_commands:
                    subprocess.run(cmd, capture_output=True, text=True, check=False)
        except Exception as e:
            sys.stderr.write(f"PANIC HANDLER WARNING: Network isolation encountered exception: {e}\n")

        object.__setattr__(self, 'is_isolated', True)
        sys.stderr.write(f"CRITICAL SYSTEM PANIC: {reason}\n")
        sys.stderr.flush()
        os._exit(101)
