from src.engine import FailClosedEngine

def test_engine_initial_state():
    """اختبار الحالة الأولية للمحرك وسجل التدقيق الابتدائي"""
    engine = FailClosedEngine()
    assert engine.get_key_status() == "ACTIVE"
    assert engine.verify_chassis_sensors() is True
    
    # التحقق من تسجيل حدث التهيئة في سجل التدقيق
    assert len(engine.audit_trail) == 1
    assert engine.audit_trail[0]["event"] == "ENGINE_INITIALIZED"

def test_duress_trigger_and_zeroization_with_audit():
    """اختبار تفعيل التطهير وسلسلة التشفير في سجل التدقيق"""
    engine = FailClosedEngine()
    
    # محاكاة وصول إشارة خطر
    engine.check_duress_trigger(True)
    
    # التأكد من التطهير والتدمير الكامل للمفتاح
    assert engine.get_key_status() == "ZEROIZED_SECURE"
    assert engine.verify_chassis_sensors() is False
    for byte in engine._secure_ram_key:
        assert byte == 0

    # التأكد من تسجيل تسلسل الأحداث بالكامل
    assert len(engine.audit_trail) == 3
    events = [log["event"] for log in engine.audit_trail]
    assert events == ["ENGINE_INITIALIZED", "DURESS_DETECTED", "ZEROIZATION_COMPLETE"]
    
    # التحقق التام من سلامة الربط التشفيري (Cryptographic Chaining)
    assert engine.audit_trail[1]["previous_hash"] == engine.audit_trail[0]["current_hash"]
    assert engine.audit_trail[2]["previous_hash"] == engine.audit_trail[1]["current_hash"]
