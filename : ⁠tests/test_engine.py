import unittest
from src.engine import TurkashEngine

class TestTurkashEngine(unittest.TestCase):
    
    def setUp(self):
        """إعداد كائن اختبار جديد قبل كل دالة اختبار"""
        self.engine = TurkashEngine()

    def test_initialization(self):
        """التحقق من الحالة الأولية للمحرك"""
        self.assertFalse(self.engine.is_zeroized)
        self.assertFalse(self.engine.system_locked)
        self.assertEqual(self.engine.get_key_status(), "ACTIVE")
        self.assertTrue(self.engine.verify_chassis_sensors())

    def test_multi_party_authorization(self):
        """التحقق من نظام المصادقة المتعددة (MPA)"""
        auth_1 = self.engine.authorize_recovery("Admin_A")
        auth_2 = self.engine.authorize_recovery("Admin_B")
        
        self.assertTrue(auth_1)
        self.assertTrue(auth_2)
        self.assertIn("Admin_A", self.engine.authorized_admins)
        self.assertIn("Admin_B", self.engine.authorized_admins)

    def test_duress_and_fail_closed(self):
        """التحقق من استجابة الإيقاف الفوري (Fail-Closed) وإلغاء التفعيل"""
        # محاكاة إرسال إشارة إكراه أو تهديد
        self.engine.check_duress_trigger(True)
        
        # التأكد من تفعيل حالة الحماية القصوى
        self.assertTrue(self.engine.is_zeroized)
        self.assertTrue(self.engine.system_locked)
        self.assertEqual(self.engine.get_key_status(), "ZEROIZED_SECURE")
        self.assertFalse(self.engine.verify_chassis_sensors())
        
        # التأكد من رفض أي محاولة مصادقة لاحقة بعد التصفية
        auth_after_zeroize = self.engine.authorize_recovery("Admin_C")
        self.assertFalse(auth_after_zeroize)

    def test_audit_trail_integrity(self):
        """التحقق من سلامة سجل التدقيق وتسلسل بصمات SHA-256"""
        self.assertGreater(len(self.engine.audit_trail), 0)
        first_entry = self.engine.audit_trail[0]
        self.assertEqual(first_entry["previous_hash"], "GENESIS_BLOCK")
        self.assertIn("current_hash", first_entry)

if __name__ == '__main__':
    unittest.main()
