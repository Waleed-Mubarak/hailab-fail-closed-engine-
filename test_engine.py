import pytest
import sys

sys.path.insert(0, 'src')

from engine import (
    check_secure_heartbeat,
    verify_chassis_sensors,
    check_duress_trigger
)

def test_heartbeat_sensor_default():
    assert check_secure_heartbeat() is True

def test_chassis_sensor_default():
    assert verify_chassis_sensors() is True

def test_duress_trigger_default():
    assert check_duress_trigger() is False
