import pytest
import ctypes
from src.memory_hardening import FailClosedEngine, InvalidatedBufferError

def test_memory_zeroization_and_dangling_references():
    """
    اختبار تصفير البيانات وتدمير المراجع المعلقة (Zeroization & Reference Destruction)
    """
    secret_data = b"SuperSecretKey123"
    engine = FailClosedEngine(secret_data)
    
    # التأكد من صحة البيانات قبل التطهير
    assert bytes(engine._buffer) == secret_data
    
    # تنفيذ التطهير الصريح
    engine.zeroize()
    
    # التحقق من أن المخزن والبيانات تم تصفيرها تماماً (امتلاء المخزن بالأصفار)
    assert all(b == 0 for b in engine._buffer)
    assert engine._is_invalidated is True

    # محاولة القراءة بعد التطهير يجب أن ترفع استثناء أمنياً
    with pytest.raises(InvalidatedBufferError):
        engine.read_data()

def test_multiple_purges_safety():
    """
    اختبار سلامة النظام عند تنفيذ التطهير المزدوج/المتكرر
    """
    engine = FailClosedEngine(b"TestKey999")
    assert engine.zeroize() is True
    # التطهير للمرة الثانية يجب ألا يسبب انهياراً أو أخطاء
    assert engine.zeroize() is True

def test_physical_zeroization_verification():
    """
    اختبار عدائي: التحقق من محو الذاكرة المادية تماماً عبر العنوان المؤشر عليه
    """
    secret_bytes = b"CriticalSecureMaterial"
    engine = FailClosedEngine(secret_bytes)
    
    addr = engine._addr
    size = engine.size
    
    # تنفيذ التطهير
    engine.zeroize()
    
    # الفحص المباشر للعنوان المادي للذاكرة عبر ctypes للتأكد من عدم بقاء أي أثر للبايتات
    raw_memory_check = ctypes.string_at(addr, size)
    assert all(b == 0 for b in raw_memory_check), "CRITICAL: Physical memory residue detected!"
