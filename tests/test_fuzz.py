"""
TurkashEngine Fuzz Testing Suite
Compliance: Adversarial Resilience & Automated Edge-Case Verification
"""

import sys
import os
import importlib.util
import pytest
from hypothesis import given, strategies as st

# تحميل المحرك ديناميكياً بغض النظر عن مكان وجوده (سواء في الجذر أو في src)
current_dir = os.path.dirname(os.path.abspath(__file__))
root_dir = os.path.abspath(os.path.join(current_dir, ".."))

engine_path = os.path.join(root_dir, "fail_closed_engine.py")
if not os.path.exists(engine_path):
    engine_path = os.path.join(root_dir, "src", "fail_closed_engine.py")

spec = importlib.util.spec_from_file_location("fail_closed_engine", engine_path)
fail_closed_module = importlib.util.module_from_spec(spec)
sys.modules["fail_closed_engine"] = fail_closed_module
spec.loader.exec_module(fail_closed_module)

from fail_closed_engine import FailClosedEngine

@given(
    action=st.text(min_size=0, max_size=100),
    quorum=st.lists(st.text(min_size=0, max_size=30), min_size=0, max_size=15)
)
def test_fail_closed_engine_fuzzing(action, quorum):
    engine = FailClosedEngine()
    
    try:
        engine.execute_critical_operation(action=action, quorum=quorum)
    except (PermissionError, ValueError, TypeError, AttributeError):
        # الاستثناءات الأمنية وأخطاء البنية متوقعة تحت التشويش العشوائي
        assert True
    except Exception as e:
        # منع أي انهيار غير متوقع للمحرك
        pytest.fail(f"Unexpected engine crash under fuzzing: {type(e).__name__}: {e}")

if __name__ == "__main__":
    pytest.main([__file__])
