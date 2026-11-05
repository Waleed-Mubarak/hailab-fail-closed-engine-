import pytest
from src.scope_b.engine import ScopeBEngine

def test_engine_initialization():
    """التحقق من أن المحرك يتم تهيئته بشكل سليم"""
    engine = ScopeBEngine()
    assert engine.initialized is True
    assert engine.watchdog_active is True

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

def test_validate_syscall_policy_allowed():
    """التحقق من السماح باستدعاءات النظام المصرح بها"""
    engine = ScopeBEngine(security_policy={"allowed_syscalls": ["read", "write"]})
    assert engine.validate_syscall_policy("read") is True

def test_validate_syscall_policy_blocked():
    """التحقق من منع استدعاءات النظام غير المصرح بها (Fail-Closed)"""
    engine = ScopeBEngine(security_policy={"allowed_syscalls": ["read"]})
    with pytest.raises(RuntimeError, match="Fail-Closed Enforced"):
        engine.validate_syscall_policy("execve")

def test_check_watchdog_signal_active():
    """التحقق من عمل مؤقت المراقبة المستقل"""
    engine = ScopeBEngine()
    assert engine.check_watchdog_signal() is True

def test_check_watchdog_signal_lost():
    """التحقق من تفعيل الفشل المغلق عند فقدان إشارة مؤقت المراقبة"""
    engine = ScopeBEngine()
    engine.watchdog_active = False
    with pytest.raises(RuntimeError, match="Fail-Closed Enforced"):
        engine.check_watchdog_signal()

def test_enforce_process_isolation_valid():
    """التحقق من نجاح عزل العمليات لمعرف عملية صحيح"""
    engine = ScopeBEngine()
    assert engine.enforce_process_isolation(1234) is True

def test_enforce_process_isolation_invalid():
    """التحقق من فشل عزل العمليات لمعرف عملية غير صالح"""
    engine = ScopeBEngine()
    with pytest.raises(RuntimeError, match="Fail-Closed Enforced"):
        engine.enforce_process_isolation(0)

def test_enforce_memory_hardening():
    """التحقق من تفعيل قفل وحماية الذاكرة"""
    engine = ScopeBEngine()
    assert engine.enforce_memory_hardening() is True
