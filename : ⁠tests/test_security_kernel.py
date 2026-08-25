import unittest
from engine import ZeroizationKernel, verify_and_integrate, FailClosedEnforcementError

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
        """اختبار كتابة البيانات الحساسة وتطهيرها بنجاح"""
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
        """اختبار نجاح التكامل عند تطابق البصمة"""
        expected_sha = "3be0185"
        current_sha = "3be0185"
        try:
            verify_and_integrate(current_sha, expected_sha, self.kernel)
        except FailClosedEnforcementError:
            self.fail("خطأ في تطابق البصمة!")

    def test_fail_closed_trigger_on_mismatch(self):
        """اختبار تفعيل القفل عند اختلاف البصمة"""
        expected_sha = "3be0185"
        tampered_sha = "deadbeef"
        
        with self.assertRaises(FailClosedEnforcementError):
            verify_and_integrate(tampered_sha, expected_sha, self.kernel)

    def test_p0_03_reflection_lockdown(self):
        """P0-03: اختبار قفل الانعكاس وحماية الحارس (Reflection Lockdown / Sentinel Protection)"""
        with self.assertRaises((AttributeError, RuntimeError, TypeError)):
            # محاولة العبث بالخصائص الداخلية المحمية للنواة عبر الانعكاس الديناميكي
            setattr(self.kernel, '_protected_sentinel', 0xDEADBEEF)

    def test_p0_04_idempotent_zeroization(self):
        """P0-04: اختبار التطهير الثابت والمتكرر Z^2 = Z (Idempotent Zeroization Test)"""
        test_data = b"Idempotent_Test_Data"
        self.kernel.write_payload(test_data)
        
        # التطهير الأول
        self.kernel.secure_scrub()
        self.kernel.buffer.seek(0)
        first_pass = self.kernel.buffer.read(len(test_data))
        
        # التطهير الثاني (التحقق من الخاصية الثابتة Z^2 = Z)
        self.kernel.secure_scrub()
        self.kernel.buffer.seek(0)
        second_pass = self.kernel.buffer.read(len(test_data))
        
        self.assertEqual(first_pass, second_pass)
        self.assertEqual(second_pass, b'\x00' * len(test_data))

if __name__ == '__main__':
    unittest.main()
