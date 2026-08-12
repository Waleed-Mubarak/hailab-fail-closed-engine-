from src.engine import FailClosedEngine

def test_engine_initial_state():
    """اختبار الحالة الأولية للمحرك وأن المفتاح نشط"""
    engine = FailClosedEngine()
    assert engine.get_key_status() == "ACTIVE"
    assert engine.verify_chassis_sensors() is True

def test_duress_trigger_and_zeroization():
    """اختبار تفاعل مستشعر الضغط وتفعيل التطهير الفوري (Zeroization)"""
    engine = FailClosedEngine()
    
    # محاكاة وصول إشارة ضغط/خطر
    engine.check_duress_trigger(True)
    
    # التأكد من مسح المفتاح وإغلاق النظام
    assert engine.get_key_status() == "ZEROIZED_SECURE"
    assert engine.verify_chassis_sensors() is False
    
    # التأكد من أن بايتات المفتاح تم تدميرها بالكامل وأصبحت أصفاراً
    for byte in engine._secure_ram_key:
        assert byte == 0
