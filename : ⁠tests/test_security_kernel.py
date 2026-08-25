import unittest
import sys
import os

# إضافة مجلد src المطلق إلى مسار النظام لضمان عمل الاستيراد في أي بيئة CI
current_dir = os.path.dirname(os.path.abspath(__file__))
src_dir = os.path.abspath(os.path.join(current_dir, '../src'))
if src_dir not in sys.path:
    sys.path.insert(0, src_dir)

from security_kernel import ZeroizationKernel, verify_and_integrate, FailClosedEnforcementError

class TestSecurityKernel(unittest.TestCase):
    
    def setUp(self):
        # تهيئة نواة بذاكرة بحجم 512 بايت للاختبار
        self.kernel_size = 512
        self.kernel = ZeroizationKernel(size=self.kernel_size)

    def tearDown(self):
        try:
            self.kernel.buffer.close()
        except:
            pass

    def test_secure_payload_and_scrub(self):
        """اختبار كتابة البيانات الحساسة وتطهيرها بنجاح (Zeroization)"""
        test_data = b"Secret_Deterministic_Payload_2026"
        self.kernel.write_payload(test_data)
        
        # التأكد من كتابة البيانات في الذاكرة
        self.kernel.buffer.seek(0)
        read_data = self.kernel.buffer.read(len(test_data))
        self.assertEqual(read_data, test_data)

        # تنفيذ التطهير الجذري
        self.kernel.secure_scrub()
        
        # التأكد من أن الذاكرة أصبحت مملوءة بالأصفار تماماً (Zero Memory Footprint)
        self.kernel.buffer.seek(0)
        zeroed_data = self.kernel.buffer.read(len(test_data))
        self.assertEqual(zeroed_data, b'\x00' * len(test_data))

    def test_verify_and_integrate_success(self):
        """اختبار نجاح التكامل عند تطابق الرمز التعريفي Commit SHA"""
        expected_sha = "3be0185"
        current_sha = "3be0185"
        # يجب أن ينفذ دون إطلاق أي استثناء
        try:
            verify_and_integrate(current_sha, expected_sha, self.kernel)
        except FailClosedEnforcementError:
            self.fail("تم تفعيل الإغلاق الخاطئ رغم تطابق البصمة!")

    def test_fail_closed_trigger_on_mismatch(self):
        """اختبار تفعيل القفل عند الفشل (Fail-Closed) عند اختلاف الرمز التعريفي"""
        expected_sha = "3be0185"
        tampered_sha = "deadbeef" # بصمة غير مطابقة
        
        with self.assertRaises(FailClosedEnforcementError):
            verify_and_integrate(tampered_sha, expected_sha, self.kernel)

if __name__ == '__main__':
    unittest.main()
