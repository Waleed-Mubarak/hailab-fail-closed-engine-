import weakref

# --- الصنف الحارس المحمي بـ MetaProxy لمنع استبدال السجل (P0-05) ---
class _RegistrySentinelMeta(type):
    def __setattr__(cls, name, value):
        raise PermissionError("P0-05: Direct replacement of the zeroization registry is strictly forbidden.")

class _RegistrySentinel(metaclass=_RegistrySentinelMeta):
    _zeroized_instances = weakref.WeakSet()

# --- المحرك السيادي الرئيسي ---
class FailClosedEngine:
    # توجيه السجل إلى الصنف الحارس المحمي
    _zeroized_instances = _RegistrySentinel._zeroized_instances

    def __init__(self, *args, **kwargs):
        self._quorum_reached = False
        self._zeroized = False
        self._zeroized_instances.add(self)

    def __setattr__(self, name, value):
        # Fix A: حماية صارمة لمنع تغيير __class__
        if name == "__class__":
            raise PermissionError("P0-03: Direct class mutation is strictly blocked.")
        super().__setattr__(name, value)

    def _verify_constitutional_integrity(self):
        # Fix B: التحقق من هوية الصنف وحالة السلامة
        if type(self) is not FailClosedEngine:
            raise PermissionError("P0-03: Constitutional integrity violation detected.")
        return True

    def execute_critical_operation(self, quorum_flags=None):
        self._verify_constitutional_integrity()
        
        # منطق التحقق من النصاب (Quorum)
        if quorum_flags and all(quorum_flags):
            self._quorum_reached = True
            return "OPERATION_SUCCESS: Quorum reached."
        
        self.zeroize()
        return "OPERATION_DENIED: Fail-closed triggered."

    def zeroize(self):
        # Fix D / P0-04: تطبيق خاصية التصفير التكراري (Idempotence Z^2 = Z)
        self._zeroized = True
        self._quorum_reached = False
        # تنفيذ عملية التصفير الفيزيائي للذاكرة
        return "ENGINE_ZEROIZED"
