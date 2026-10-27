"""
TurkashEngine Fuzz Testing Suite
Compliance: Adversarial Resilience & Automated Edge-Case Verification
"""

import sys
import os

# 1. إجبار بايثون على إضافة مجلد src ومجلد الجذر إلى بداية مسار البحث فوراً
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC_DIR = os.path.join(BASE_DIR, "src")

if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

# 2. الاستيراد يتم بعد إعداد المسارات مباشرة
from hypothesis import given, strategies as st
import pytest
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
        assert True
    except Exception as e:
        pytest.fail(f"Unexpected engine crash under fuzzing: {type(e).__name__}: {e}")

if __name__ == "__main__":
    pytest.main([__file__])
