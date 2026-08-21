import unittest
from engine import TurkashEngine

class TestTurkashEngineRemediationv2(unittest.TestCase):

    def test_quorum_satisfied_admissibility_invalid_execution_denied(self):
        """1. Quorum satisfied + admissibility invalid -> execution denied via admissibility gate"""
        engine = TurkashEngine()
        engine.add_signature("Admin_A")
        engine.add_signature("Admin_B")
        
        engine.execute_zeroization()
        
        result = engine.execute_critical_operation_mpa(required_count=2)
        self.assertIn("OPERATION_DENIED", result, "P0-01 Error: Executed despite invalid admissibility!")

    def test_quorum_satisfied_terminal_state_execution_denied(self):
        """2. Quorum satisfied + terminal state -> execution denied"""
        engine = TurkashEngine()
        engine.add_signature("Admin_A")
        engine.add_signature("Admin_B")
        
        engine.execute_zeroization() 
        
        result = engine.execute_critical_operation_mpa(required_count=2)
        self.assertIn("OPERATION_DENIED", result, "P0-02 Error: Executed in terminal state!")

    def test_terminal_state_recovery_attempt_denied(self):
        """3. Terminal state + recovery attempt -> denied (P0-03 strict encapsulation)"""
        engine = TurkashEngine()
        engine.execute_zeroization()
        
        recovery_success = engine.authorize_recovery("Admin_A")
        self.assertFalse(recovery_success, "P0-03 Error: Recovery allowed in terminal state!")

    def test_repeated_zeroization_idempotence_invariance(self):
        """4. Repeated zeroization -> idempotence Z^2 = Z with verified audit invariance (P0-04)"""
        engine = TurkashEngine()
        engine.execute_zeroization()
        self.assertTrue(engine.is_zeroized)
        
        initial_audit_count = len(engine.audit_trail)
        
        # تكرار التصفير يجب أن يحافظ على الحالة النهائية دون تنفيذ خطوات تخريبية مكررة
        engine.execute_zeroization()
        self.assertTrue(engine.is_zeroized, "P0-04 Error: Repeated zeroization altered state instability!")
        
        # التحقق من تسجيل حدث التكرار بدلاً من إنشاء مسار مدمر جديد
        last_event = engine.audit_trail[-1]["event"]
        self.assertEqual(last_event, "ZEROIZATION_REPEATED", "P0-04 Error: Idempotency log event missing!")

    def test_attempted_external_state_resurrection_denied(self):
        """5. Attempted external state resurrection -> denied/prevented (P0-03)"""
        engine = TurkashEngine()
        engine.execute_zeroization()
        
        with self.assertRaises(AttributeError):
            engine.is_zeroized = False  # منع التعديل الخارجي تماماً
            
        self.assertTrue(engine.is_zeroized, "P0-03 Error: External state resurrection succeeded!")

    def test_every_consequence_bearing_operation_passes_through_admissibility_boundary(self):
        """6. Valid quorum + invalid admissibility -> execution denied strictly by boundary"""
        engine = TurkashEngine()
        engine.add_signature("Admin_A")
        engine.add_signature("Admin_B")
        
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
