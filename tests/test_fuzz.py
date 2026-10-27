"""
TurkashEngine Fuzz Testing Suite
Compliance: Adversarial Resilience & Automated Edge-Case Verification
"""

import sys
import os

# التوجيه الجذري الثابت والمباشر (نفس الطريقة الناجحة في ملف pilot_test.py)
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.abspath(os.path.join(current_dir, ".."))
src_dir = os.path.abspath(os.path.join(parent_dir, "src"))

if src_dir not in sys.path:
    sys.path.insert(0, src_dir)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

# نظام استيراد آمن ومباشر
try:
    from fail_closed_engine import FailClosedEngine
except ImportError:
    from src.fail_closed_engine import FailClosedEngine

from hypothesis import given, strategies as st
import pytest

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
