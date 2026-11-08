import pytest
import os
from src.scope_b.engine import ScopeBEngine

def test_engine_initialization():
    """التحقق من تهيئة المحرك وتفعيل حمايات النواة الأساسية"""
    engine = ScopeBEngine()
    assert isinstance(engine.locked, bool)
    assert isinstance(engine.isolated, bool)

def test_memory_hardening_execution():
    """التحقق من دالة قفل الذاكرة وحمايتها"""
    engine = ScopeBEngine()
    # إذا كانت الصلاحيات تمنح القفل أو تم التحقق منها
    try:
        assert engine.enforce_memory_hardening() is True
    except RuntimeError as e:
        # إذا تم تفعيل الفشل المغلق بسبب صلاحيات النظام (مثل عدم توفر root)
        assert "FAIL-CLOSED" in str(e)

def test_process_isolation_valid_pid():
    """التحقق من عزل العمليات لمعرف عملية صحيح وتوافق القيود"""
    engine = ScopeBEngine()
    current_pid = os.getpid()
    assert engine.enforce_process_isolation(current_pid) is True

def test_process_isolation_invalid_pid():
    """التحقق من رفض معرفات العمليات غير الصالحة (ValueError)"""
    engine = ScopeBEngine()
    with pytest.raises(ValueError, match="Invalid PID"):
        engine.enforce_process_isolation(0)
    with pytest.raises(ValueError, match="Invalid PID"):
        engine.enforce_process_isolation(-1)

def test_watchdog_signal_active():
    """التحقق من استجابة مؤقت المراقبة للإشارة السليمة"""
    engine = ScopeBEngine()
    assert engine.check_watchdog_signal(True) is True

def test_watchdog_signal_lost():
    """التحقق من تفعيل الفشل المغلق عند فقدان إشارة مؤقت المراقبة"""
    engine = ScopeBEngine()
    with pytest.raises(RuntimeError, match="FAIL-CLOSED: Watchdog signal lost"):
        engine.check_watchdog_signal(False)
