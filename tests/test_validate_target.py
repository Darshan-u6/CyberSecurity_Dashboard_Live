import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from unittest.mock import MagicMock

# Mock dependencies that are not available in the environment
mock_modules = [
    'mysql', 'mysql.connector', 'fpdf', 'passlib', 'passlib.context',
    'ldap3', 'ldap3.utils', 'ldap3.utils.conv', 'requests', 'scapy', 'scapy.all', 'jose', 'packaging'
]

for module in mock_modules:
    m = MagicMock()
    sys.modules[module] = m
    # Special handling for packages
    if module in ['ldap3', 'mysql', 'passlib', 'scapy']:
        m.__path__ = []

from fastapi import HTTPException
from main import validate_target
import pytest

def test_validate_target_no_protocol():
    assert validate_target('example.com') == 'example.com'

def test_validate_target_with_http():
    assert validate_target('http://example.com') == 'example.com'

def test_validate_target_with_https():
    assert validate_target('https://example.com') == 'example.com'

def test_validate_target_with_port():
    assert validate_target('example.com:8080') == 'example.com'

def test_validate_target_with_path():
    assert validate_target('example.com/path/to/resource') == 'example.com'

def test_validate_target_with_http_and_port():
    assert validate_target('http://example.com:8080') == 'example.com'

def test_validate_target_with_http_port_and_path():
    assert validate_target('http://example.com:8080/path/to/resource') == 'example.com'

def test_validate_target_ip_address():
    assert validate_target('192.168.1.1') == '192.168.1.1'

def test_validate_target_ip_address_with_http():
    assert validate_target('http://192.168.1.1') == '192.168.1.1'

def test_validate_target_ip_address_with_port():
    assert validate_target('192.168.1.1:8080') == '192.168.1.1'

def test_validate_target_invalid_start_with_dash():
    with pytest.raises(HTTPException) as exc_info:
        validate_target('-example.com')
    assert exc_info.value.status_code == 400
    assert "Invalid Target Format: Cannot start with -" in exc_info.value.detail

def test_validate_target_invalid_characters():
    with pytest.raises(HTTPException) as exc_info:
        validate_target('example.com; drop table users')
    assert exc_info.value.status_code == 400
    assert "Invalid Target Format" in exc_info.value.detail

def test_validate_target_whitespace():
    assert validate_target('  example.com  ') == 'example.com'

def test_validate_target_whitespace_with_http():
    assert validate_target('  http://example.com  ') == 'example.com'
