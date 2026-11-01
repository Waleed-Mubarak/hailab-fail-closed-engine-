import unittest
from src.scope_b.engine import ScopeBEngine

class TestScopeBEngine(unittest.TestCase):
    def setUp(self):
        self.engine = ScopeBEngine()

    def test_scope_b_initialization(self):
        """التحقق من تهيئة المحرك بنجاح"""
        self.assertIsNotNone(self.engine)

    def test_syscall_policy_allowed(self):
        """التحقق من السماح باستدعاء مسموح (REQ-SCOPE-B-01)"""
        result = self.engine.validate_syscall_policy(1)
        self.assertTrue(result)

    def test_syscall_policy_denied(self):
        """التحقق من رفض استدعاء غير مصرح وتفعيل التدقيق (REQ-SCOPE-B-01 & 02)"""
        result = self.engine.validate_syscall_policy(999)
        self.assertFalse(result)

    def test_watchdog_signal_failure(self):
        """التحقق من سلوك التدقيق عند الفشل المفاجئ (REQ-SCOPE-B-03)"""
        result = self.engine.handle_watchdog_failure()
        self.assertTrue(result)

if __name__ == '__main__':
    unittest.main()

