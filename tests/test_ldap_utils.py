import sys
from unittest.mock import MagicMock

# Mock dependencies that are not available in the environment
mock_modules = [
    'fastapi', 'fastapi.responses', 'fastapi.middleware.cors', 'fastapi.staticfiles',
    'fastapi.security', 'pydantic', 'mysql', 'mysql.connector', 'fpdf', 'passlib', 'passlib.context',
    'ldap3', 'ldap3.utils', 'ldap3.utils.conv', 'uvicorn', 'requests', 'scapy', 'scapy.all', 'jose', 'starlette', 'starlette.middleware.base', 'packaging'
]

for module in mock_modules:
    m = MagicMock()
    sys.modules[module] = m
    # Special handling for packages
    if module in ['ldap3', 'mysql', 'fastapi', 'passlib', 'scapy', 'starlette']:
        m.__path__ = []

# Now we can import from main
from main import get_clean_ldap_attr

import pytest

class MockAttr:
    def __init__(self, value):
        self.value = value

def test_get_clean_ldap_attr_single_value():
    entry = {"cn": "John Doe"}
    assert get_clean_ldap_attr(entry, "cn") == "John Doe"

def test_get_clean_ldap_attr_list_value():
    entry = {"mail": ["john@example.com", "doe@example.com"]}
    assert get_clean_ldap_attr(entry, "mail") == "john@example.com"

def test_get_clean_ldap_attr_empty_list():
    entry = {"mail": []}
    assert get_clean_ldap_attr(entry, "mail", default="N/A") == "N/A"

def test_get_clean_ldap_attr_missing():
    entry = {"cn": "John Doe"}
    assert get_clean_ldap_attr(entry, "mail", default="missing@example.com") == "missing@example.com"

def test_get_clean_ldap_attr_with_value_property():
    attr = MockAttr("John Value")
    entry = {"cn": attr}
    assert get_clean_ldap_attr(entry, "cn") == "John Value"

def test_get_clean_ldap_attr_with_getattr_access():
    class EntryWithAttr:
        def __init__(self):
            self.cn = "John Attr"
        def __contains__(self, item): return False # Force getattr
        def __getitem__(self, item): raise KeyError(item)

    entry = EntryWithAttr()
    assert get_clean_ldap_attr(entry, "cn") == "John Attr"

def test_get_clean_ldap_attr_error_handling():
    class BuggyEntry:
        def __getattr__(self, name):
            raise RuntimeError("Something went wrong")
        def __getitem__(self, name):
            raise RuntimeError("Something went wrong")
        def __contains__(self, name):
            return True

    entry = BuggyEntry()
    # This should trigger the outer except Exception: pass and return default
    assert get_clean_ldap_attr(entry, "any_attr", default="Error Default") == "Error Default"

def test_get_clean_ldap_attr_none_value():
    entry = {"cn": None}
    assert get_clean_ldap_attr(entry, "cn", default="None Default") == "None Default"
