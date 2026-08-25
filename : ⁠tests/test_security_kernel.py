import unittest
from engine import FailClosedEngine

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
        
        # محاولة تفويض صلاحية بعد التصفير يجب أن تفشل تماماً (Fail-Closed)
        result = self.engine.authorize_recovery("admin_test")
        self.assertFalse(result)

        with self.assertRaises(PermissionError):
            self.engine.execute_critical_operation(action="test_action")

    def test_p0_03_reflection_lockdown(self):
        """P0-03: اختبار قفل الانعكاس والحماية الدستورية (Reflection Lockdown / Constitutional Integrity)"""
        with self.assertRaises(PermissionError):
            self.engine._verify_constitutional_integrity()
            raw_dict = object.__getattribute__(self.engine, "__dict__")
            raw_dict["_FailClosedEngine__secure_ram_key"] = None
            self.engine._verify_constitutional_integrity()

    def test_p0_04_idempotent_zeroization(self):
        """P0-04: اختبار التطهير الثابت والمتكرر Z^2 = Z (Idempotent Zeroization Test)"""
        res1 = self.engine.zeroize()
        self.assertTrue(res1)
        self.assertTrue(self.engine.is_zeroized)

        res2 = self.engine.zeroize()
        self.assertTrue(res2)
        self.assertTrue(self.engine.is_zeroized)

if __name__ == '__main__':
    unittest.main()
