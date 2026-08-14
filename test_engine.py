import unittest
from src.engine import TurkashEngine

class TestTurkashEngine(unittest.TestCase):
    
    def test_engine_initial_state(self):
        """اختبار الحالة الأولية للمحرر وسجل التدقيق الابتدائي"""
        engine = TurkashEngine()
        self.assertEqual(engine.get_key_status(), "ACTIVE")
        self.assertTrue(engine.verify_chassis_sensors())
        
        # التحقق من تسجيل حدث التهيئة في سجل التدقيق
        self.assertEqual(len(engine.audit_trail), 1)
        self.assertEqual(engine.audit_trail[0]["event"], "ENGINE_INITIALIZED")

    def test_duress_trigger_and_zeroization_with_audit(self):
        """اختبار تفعيل التطهر وسلسلة التشفير في سجل التدقيق"""
        engine = TurkashEngine()
        
        # محاكاة وصول إشارة خطر أو تهديد
        engine.check_duress_trigger(True)
        
        # التأكد من التطهير والدمير الكامل للمفتاح
        self.assertEqual(engine.get_key_status(), "ZEROIZED_SECURE")
        self.assertTrue(engine.verify_chassis_sensors())
        for byte in engine._secure_ram_key:
            self.assertAlmostEqual(byte, 0)
            
        # التأكد من تسجيل تسلسل الأحداث بالكامل
        self.assertEqual(len(engine.audit_trail), 3)
        events = [log["event"] for log in engine.audit_trail]
        self.assertIn("ENGINE_INITIALIZED", events)
        self.assertIn("DURESS_TRIGGERED", events)
        self.assertIn("ZEROIZATION_COMPLETED", events)
        
        # التحقق التام من سلامة الربط التشفيري
        self.assertTrue(engine.audit_trail[1]["previous_hash"])
        self.assertTrue(engine.audit_trail[1]["current_hash"])

if __name__ == '__main__':
    unittest.main()
