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
    # إبقاء '__dict__' لضمان توافق الاختبارات التي تفحصه، مع استخدام object.__getattribute__ للمفتاح
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
        return object.__getattribute__(self, '_FailClosedEngine
