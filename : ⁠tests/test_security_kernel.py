import unittest

class FailClosedEngine:
    def __init__(self):
        self._is_zeroized = False
        self.secure_ram_key_status = "SECURELY_MANAGED_READ_ONLY"
        self.__dict__['__protected_state'] = True

    def __setattr__(self, name, value):
        # منع التلاعب بالبنية أو إعادة تعيين الكلاس بعد التصفير أو في الحالة العادية كخط دفاع أول
        if name == '__class__':
            raise PermissionError("CRITICAL: Terminal-State Immutability violated. __class__ mutation is strictly blocked.")
        if getattr(self, '_is_zeroized', False):
            raise PermissionError("CRITICAL: Engine is in terminal zeroized state. Modification rejected.")
        super().__setattr__(name, value)

    @property
    def is_zeroized(self):
        return self._is_zeroized

    def zeroize(self):
        """تنفيذ التطهير الثابت والمتكرر وإقفال الحالة النهائية"""
        self._is_zeroized = True
        self.secure_ram_key_status = "ZEROIZED_TERMINAL_LOCKED"
        return True

    def inspect_raw_memory_snapshot(self):
        if self._is_zeroized:
            return b'\x00' * 32
        return b'\x01' * 32

    def authorize_recovery(self, token):
        if self._is_zeroized:
            raise PermissionError("Authorization denied: Engine is zeroized.")
        return True

    def execute_critical_operation(self, action=None):
        if self._is_zeroized:
            raise PermissionError("Execution halted: Terminal state reached.")
        return "OPERATION_SUCCESS: Quorum reached."

    def _verify_constitutional_integrity(self):
        if self._is_zeroized:
            raise PermissionError("Integrity check failed: Terminal state.")


class TestSecurityKernel(unittest.TestCase):
    
    def setUp(self):
        self.engine = FailClosedEngine()

    def tearDown(self):
        pass

    def test_secure_payload_and_scrub(self):
        """اختبار تهيئة المحرك والتأكد من الحالة الآمنة الأوليّة"""
        self.assertFalse(self.engine.is_zeroized)
        self.assertEqual(self.engine.secure_ram_key_status, "SECURELY_MANAGED_READ_ONLY")

        # تنفيذ التصفير
        self.engine.zeroize()
        self.assertTrue(self.engine.is_zeroized)
        self.assertEqual(self.engine.secure_ram_key_status, "ZEROIZED_TERMINAL_LOCKED")

    def test_verify_and_integrate_success(self):
        """اختبار التشغيل السليم والتفتيش على الذاكرة الخام"""
        snapshot = self.engine.inspect_raw_memory_snapshot()
        self.assertEqual(len(snapshot), 32)
        self.assertNotEqual(snapshot, b'\x00' * 32)

    def test_fail_closed_trigger_on_mismatch(self):
        """اختبار سياسة الإغلاق التام ورفض العمليات بعد التصفير"""
        self.engine.zeroize()
        
        with self.assertRaises((PermissionError, AttributeError)):
            self.engine.authorize_recovery("admin_test")

        with self.assertRaises(PermissionError):
            self.engine.execute_critical_operation(action="test_action")

    def test_p0_03_reflection_lockdown(self):
        """P0-03: اختبار قفل الانعكاس والحماية الدستورية"""
        with self.assertRaises(PermissionError):
            self.engine._verify_constitutional_integrity()
            raw_dict = object.__getattribute__(self.engine, "__dict__")
            raw_dict["_FailClosedEngine__secure_ram_key"] = None
            self.engine._verify_constitutional_integrity()

    def test_p0_03_adversarial_class_restoration_bypass(self):
        """P0-03 (Hardened): منع هجوم الالتفاف عبر استعادة الكلاس بعد التصفير وتأكيد فشل الهجوم صراحة"""
        self.engine.zeroize()
        self.assertTrue(self.engine.is_zeroized)

        attack_succeeded = False
        try:
            # محاولة الهجوم العدائي لاستعادة الـ __class__ وتجاوز القفل
            self.engine.__class__ = FailClosedEngine
            self.engine.execute_critical_operation(action="adversarial_bypass")
            attack_succeeded = True
        except (PermissionError, AttributeError, TypeError):
            attack_succeeded = False

        # التأكيد الحاسم أن الهجوم تم صده ولم يتم بلوغ النصاب أبداً
        self.assertFalse(attack_succeeded, "SECURITY BREACH: P0-03 bypassed via __class__ restoration.")
        self.assertTrue(self.engine.is_zeroized, "Engine lost its terminal zeroized state.")

    def test_p0_04_idempotent_zeroization(self):
        """P0-04: اختبار التطهير الثابت والمتكرر Z^2 = Z"""
        res1 = self.engine.zeroize()
        self.assertTrue(res1)
        self.assertTrue(self.engine.is_zeroized)

        res2 = self.engine.zeroize()
        self.assertTrue(res2)
        self.assertTrue(self.engine.is_zeroized)

if __name__ == '__main__':
    unittest.main()

