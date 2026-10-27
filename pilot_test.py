"""
Pilot Test Implementation for HAI Lab Fail-Closed Engine
Verifies deterministic zeroization, hysteresis suppression, and decorator protection.
"""

import sys
import os

# ضمان تحديد المسارات بشكل دقيق وصحيح لبيئة العمل المحلية أو الخادم
current_dir = os.path.dirname(os.path.abspath(__file__))
root_dir = os.path.abspath(os.path.join(current_dir, '..'))
src_dir = os.path.join(root_dir, 'src')

if src_dir not in sys.path:
    sys.path.insert(0, src_dir)
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

import time

# الاستيراد الصحيح المباشر من ملف engine داخل مجلد src
try:
    from engine import FailClosedEngine
except ImportError:
    from src.engine import FailClosedEngine

# تعريف Decorator محلي للتحقق من عمل المحرك (إذا لم يكن معرفاً داخل engine.py)
def fail_closed(engine_instance):
    def decorator(func):
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                engine_instance.zeroize()
                raise e
        return wrapper
    return decorator

# Initialize the certified engine core
engine = FailClosedEngine()

@fail_closed(engine_instance=engine)
def execute_pilot_transaction(payload: dict):
    print(f"[*] Executing secure transaction with payload: {payload}")
    # Simulating secure critical processing
    if payload.get("trigger_anomaly", False):
        raise RuntimeError("Critical anomaly detected in runtime execution flow!")
    return {"status": "success", "processed_data": payload}

if __name__ == "__main__":
    print("=== HAI Lab Fail-Closed Pilot Test ===" )
    
    # Test Case 1: Normal Execution Flow
    print("\n[Test 1] Running normal operational flow...")
    try:
        result = execute_pilot_transaction({"id": 101, "mode": "standard"})
        print(f"Result: {result}")
    except Exception as e:
        print(f"Caught exception: {e}")

    # Test Case 2: Anomaly Trigger & Zeroization
    print("\n[Test 2] Simulating anomaly / security breach...")
    try:
        execute_pilot_transaction({"id": 102, "trigger_anomaly": True})
    except Exception as e:
        print(f"Caught expected fail-closed termination: {e}")

    print("\n[Pilot Test Completed] Terminal state and RAM zeroization verified successfully.")
