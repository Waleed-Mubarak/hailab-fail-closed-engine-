import weakref

class _RegistrySentinelMeta(type):
    def __setattr__(cls, name, value):
        raise PermissionError("P0-05: Direct replacement of the zeroization registry is strictly forbidden.")

class _RegistrySentinel(metaclass=_RegistrySentinelMeta):
    _zeroized_instances = weakref.WeakSet()

class FailClosedEngine:
    _zeroized_instances = _RegistrySentinel._zeroized_instances

    def __init__(self, *args, **kwargs):
        self._quorum_reached = False
        self._zeroized = False
        self._zeroized_instances.add(self)

    def __setattr__(self, name, value):
        if name == "__class__":
            raise PermissionError("P0-03: Direct class mutation is strictly blocked.")
        super().__setattr__(name, value)

    def _verify_constitutional_integrity(self):
        if type(self) is not FailClosedEngine and type(self) is not TurkashEngine:
            raise PermissionError("P0-03: Constitutional integrity violation detected.")
        return True

    def execute_critical_operation(self, quorum_flags=None):
        self._verify_constitutional_integrity()
        if quorum_flags and all(quorum_flags):
            self._quorum_reached = True
            return "OPERATION_SUCCESS: Quorum reached."
        self.zeroize()
        return "OPERATION_DENIED: Fail-closed triggered."

    def zeroize(self):
        self._zeroized = True
        self._quorum_reached = False
        return "ENGINE_ZEROIZED"

# توفير اسم TurkashEngine ليتوافق مع استيراد ملفات الاختبار (tests/test_engine.py)
TurkashEngine = FailClosedEngine
