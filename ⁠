import pytest
from src.engine import (
    check_secure_heartbeat,
    verify_chassis_sensors,
    check_duress_trigger
)

def test_heartbeat_sensor_default():
    """Verify default heartbeat sensor returns True under normal conditions."""
    assert check_secure_heartbeat() is True

def test_chassis_sensor_default():
    """Verify physical chassis integrity status is nominal by default."""
    assert verify_chassis_sensors() is True

def test_duress_trigger_default():
    """Verify duress trigger is inactive by default."""
    assert check_duress_trigger() is False
