import pytest
from src.scope_b.engine import ScopeBEngine

def test_engine_initialization():
    """التحقق من أن المحرك يتم تهيئته بشكل سليم"""
    engine = ScopeBEngine()
    assert engine.initialized is True

def test_enforce_policy_passed():
    """التحقق من اجتياز البيانات السليمة للسياسة بنجاح"""
    engine = ScopeBEngine()
    context = {"secure": True}
    result = engine.enforce_policy(context)
    assert result["status"] == "PASSED"
    assert result["enforced"] is True

def test_fail_closed_on_breach():
    """التحقق من تفعيل آلية الفشل المغلق عند اكتشاف خرق (breach)"""
    engine = ScopeBEngine()
    context = {"breach": True}
    with pytest.raises(RuntimeError, match="Fail-Closed Enforced"):
        engine.enforce_policy(context)

def test_fail_closed_on_insecure():
    """التحقق من تفعيل آلية الفشل المغلق إذا كانت البيانات غير آمنة"""
    engine = ScopeBEngine()
    context = {"secure": False}
    with pytest.raises(RuntimeError, match="Fail-Closed Enforced"):
        engine.enforce_policy(context)

