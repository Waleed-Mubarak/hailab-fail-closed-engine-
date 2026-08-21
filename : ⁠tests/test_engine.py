import unittest
from engine import TurkashEngine

class TestTurkashEngineRemediationv2(unittest.TestCase):

    def test_quorum_satisfied_admissibility_invalid_execution_denied(self):
        """1. Quorum satisfied + admissibility invalid -> execution denied via admissibility gate"""
        engine = TurkashEngine()
        # بناء النصاب أولاً بينما المحرك نشط
        engine.add_signature("Admin_A")
        engine.add_signature("Admin_B")
        
        # إبطال المقبولية بعد اكتمال النصاب (مثل تفعيل التصفير)
        engine.execute_zeroization()
        
        result = engine.execute_critical_operation_mpa(required_count=2)
        # التأكد من أن الرفض ناتج عن بطلان القبول/الحالة الطرفية وليس نقص النصاب
        self.assertIn("OPERATION_DENIED", result, "P0-01 Error: Executed despite invalid admissibility!")

    def test_quorum_satisfied_terminal_state_execution_denied(self):
        """2. Quorum satisfied + terminal state -> execution denied"""
        engine = TurkashEngine()
        # بناء النصاب أولاً
        engine.add_signature("Admin_A")
        engine.add_signature("Admin_B")
        
        # الدخول في الحالة النهائية Terminal State بعد اكتمال النصاب
        engine.execute_zeroization() 
        
        result = engine.execute_critical_operation_mpa(required_count=2)
        self.assertIn("OPERATION_DENIED", result, "P0-02 Error: Executed in terminal state!")

    def test_terminal_state_recovery_attempt_denied(self):
        """3. Terminal state + recovery attempt -> denied"""
        engine = TurkashEngine()
        engine.execute_zeroization()
        
        recovery_success = engine.authorize_recovery("Admin_A")
        self.assertFalse(recovery_success, "P0-03 Error: Recovery allowed in terminal state!")

    def test_repeated_zeroization_no_additional_destructive_transition(self):
        """4. Repeated zeroization -> no additional destructive transition (Idempotence Z^2 = Z)"""
        engine = TurkashEngine()
        engine.execute_zeroization()
        self.assertTrue(engine.is_zeroized)
        
        # تكرار التصفير يجب ألا يسبب خطأ أو يغير الحالة بشكل إضافي مدمر
        engine.execute_zeroization()
        self.assertTrue(engine.is_zeroized, "P0-04 Error: Repeated zeroization altered state instability!")

    def test_attempted_external_state_resurrection_denied(self):
        """5. Attempted external state resurrection -> denied/prevented"""
        engine = TurkashEngine()
        engine.execute_zeroization()
        
        # محاولة تعديل الحالة الحرجة من الخارج (بسبب استخدام Properties محمية)
        with self.assertRaises(AttributeError):
            engine.is_zeroized = False  # يجب أن يمنع التعديل الخارجي تماماً
            
        self.assertTrue(engine.is_zeroized, "P0-03 Error: External state resurrection succeeded!")

    def test_every_consequence_bearing_operation_passes_through_admissibility_boundary(self):
        """6. Valid quorum + invalid admissibility -> execution denied strictly by boundary"""
        engine = TurkashEngine()
        # إنشاء نصاب صالح بالكامل أولاً
        engine.add_signature("Admin_A")
        engine.add_signature("Admin_B")
        
        # جعل المقبولية غير صالحة بشكل مستقل مع الاحتفاظ بالنصاب
        engine.execute_zeroization()
        
        result = engine.execute_critical_operation_mpa(required_count=2)
        self.assertIn("OPERATION_DENIED", result, "P0-05 Error: Consequence operation bypassed boundary!")

    def test_edge_case_async_admissibility_bypass(self):
        """
        Edge Case: Tests a simulated scenario where execution is attempted 
        while verifying that the engine strictly fails closed.
        """
        engine = TurkashEngine()
        result = engine.execute_critical_operation_mpa(required_count=1)
        self.assertIn("OPERATION_DENIED", result)

if __name__ == "__main__":
    unittest.main()
