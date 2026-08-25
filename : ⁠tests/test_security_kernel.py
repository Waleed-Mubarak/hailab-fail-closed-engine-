import unittest
import sys
import os

sys.path.insert(0, os.path.abspath("../src"))
from security_kernel import ZeroizationKernel, verify_and_integrate, FailClosedEnforcementError

class TestSecurityKernel(unittest.TestCase):
    
    def setUp(self):
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
        
        self.kernel.buffer.seek(0)
        read_data = self.kernel.buffer.read(len(test_data))
        self.assertEqual(read_data, test_data)

        self.kernel.secure_scrub()
        
        self.kernel.buffer.seek(0)
        zeroed_data = self.kernel.buffer.read(len(test_data))
        self.assertEqual(zeroed_data, b'\x00' * len(test_data))

    def test_verify_and_integrate_success(self):
        """اختبار نجاح التكامل عند تطابق الرمز التعريفي Commit SHA"""
        expected_sha = "3be0185"
        current_sha = "3be0185"
        try:
            verify_and_integrate(current_sha, expected_sha, self.kernel)
        except FailClosedEnforcementError:
            self.fail("تم تفعيل الإغلاق الخاطئ رغم تطابق البصمة!")

    def test_fail_closed_trigger_on_mismatch(self):
        """اختبار تفعيل القفل عند الفشل (Fail-Closed) عند اختلاف الرمز التعريفي"""
        expected_sha = "3be0185"
        tampered_sha = "deadbeef"
        
        with self.assertRaises(FailClosedEnforcementError):
            verify_and_integrate(tampered_sha, expected_sha, self.kernel)

if __name__ == '__main__':
    unittest.main()
