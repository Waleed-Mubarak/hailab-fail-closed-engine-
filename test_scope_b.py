import unittest
from src.scope_b.engine import ScopeBEngine

class TestScopeBEngine(unittest.TestCase):
    def setUp(self):
        self.engine = ScopeBEngine()

    def test_syscall_policy_allowed(self):
        """التحقق من السماح باستدعاء مسموح ضمن القائمة البيضاء (REQ-SCOPE-B-01)"""
        result = self.engine.validate_syscall_policy(1)
        self.assertTrue(result)

    def test_syscall_policy_denied(self):
        """التحقق من رفض استدعاء غير مصرح به وتفعيل التدقيق (REQ-SCOPE-B-01 & 02)"""
        result = self.engine.validate_syscall_policy(999)
        self.assertFalse(result)
        self.assertEqual(self.engine.state, "ZEROIZED")
        self.assertTrue(len(self.engine.audit_log) > 0)

    def test_watchdog_signal_failure(self):
        """التحقق من استجابة الـ Watchdog عند انقطاع النبضة (REQ-SCOPE-B-03)"""
        result = self.engine.check_watchdog_signal(False)
        self.assertFalse(result)
        self.assertEqual(self.engine.state, "ZEROIZED")

if __name__ == "__main__":
    unittest.main()
