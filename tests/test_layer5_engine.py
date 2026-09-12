import sys
import os

# إضافة مجلد src إلى مسار البحث لضمان استيراد المحرك بنجاح
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from engine import Layer5SecureEnforcementEngine, Layer5Context, MockHSMInterface

def test_layer5_engine_initialization():
    hsm = MockHSMInterface()
    engine = Layer5SecureEnforcementEngine(hsm=hsm)
    assert engine is not None

def test_layer5_context_execution():
    hsm = MockHSMInterface()
    engine = Layer5SecureEnforcementEngine(hsm=hsm)
    context = Layer5Context(engine=engine)
    assert context is not None
