"""
TurkashEngine Fuzz Testing Suite
Compliance: Adversarial Resilience & Automated Edge-Case Verification
"""

import os
import sys

# إجبار بايثون على إضافة مجلد src لمسار البحث في السطور الأولى تماماً
sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
)

from fail_closed_engine import FailClosedEngine
from hypothesis import given, strategies as st
import pytest


@given(
    action=st.text(min_size=0, max_size=100),
    quorum=st.lists(st.text(min_size=0, max_size=30), min_size=0, max_size=15),
)
def test_fail_closed_engine_fuzzing(action, quorum):
  engine = FailClosedEngine()

  try:
    engine.execute_critical_operation(action=action, quorum=quorum)
  except (PermissionError, ValueError, TypeError, AttributeError):
    assert True
  except Exception as e:
    pytest.fail(
        f"Unexpected engine crash under fuzzing: {type(e).__name__}: {e}"
    )


if __name__ == "__main__":
  pytest.main([__file__])
