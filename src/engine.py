import unittest
from engine import TurkashEngine

class TestTurkashEngineHardening(unittest.TestCase):
    
    def test_p0_03_state_encapsulation_and_no_resurrection(self):
        engine = TurkashEngine()
        # التأكد من أن الحالة الابتدائية نشطة والمفتاح غير مسفر
        self.assertFalse(engine.is_zeroized)
        self.assertFalse(all(b == 0 for b in engine._secure_ram_key))
        
        # تنفيذ التصفير المدمر
        engine.execute_zeroization()
        
        # P0-03 Evidence: التحقق من أن الحالة النهائية تفرض إغلاق النظام ومسح المفتاح بالكامل وعدم قابليته للاسترجاع
        self.assertTrue(engine.is_zeroized)
        self.assertTrue(engine.system_locked)
        self.assertTrue(all(b == 0 for b in engine._secure_ram_key))

    def test_p0_04_zeroization_idempotence_and_destructive_invariance(self):
        engine = TurkashEngine()
        
        # التنفيذ الأول للتصفير (Destructive Transition)
        res_first = engine.execute_zeroization()
        self.assertTrue(res_first)
        
        # التقاط لقطة للحالة الفعلية تشمل الذاكرة الداخلية المدمرة وحالة القفل
        first_terminal_snapshot = (
            engine.is_zeroized, 
            bytes(engine._secure_ram_key), 
            engine.system_locked
        )
        
        # الاستدعاء الثاني للتصفير لتأكيد الـ Idempotence ($Z^2 = Z$)
        res_second = engine.execute_zeroization()
        self.assertTrue(res_second)
        
        # التقاط لقطة ثانية للمقارنة
        second_terminal_snapshot = (
            engine.is_zeroized, 
            bytes(engine._secure_ram_key), 
            engine.system_locked
        )
        
        # تأكيد قوي يثبت أن التحول المدمر ثابت تماماً ولا ينتج أي تغيير إضافي
        self.assertEqual(
            first_terminal_snapshot, 
            second_terminal_snapshot, 
            "Zeroization transition is not strictly invariant (Idempotence failure Z^2 != Z)"
        )

if __name__ == "__main__":
    unittest.main()
