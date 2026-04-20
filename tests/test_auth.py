import sys
from unittest.mock import MagicMock
import pytest
from datetime import datetime, timedelta
from jose import jwt

# Mock dependencies that are not available in the environment
# IMPORTANT: we keep `jose` un-mocked as it's installed and we need it to decode tokens
mock_modules = [
    'fastapi', 'fastapi.responses', 'fastapi.middleware.cors', 'fastapi.staticfiles',
    'fastapi.security', 'pydantic', 'mysql', 'mysql.connector', 'fpdf', 'passlib', 'passlib.context',
    'ldap3', 'ldap3.utils', 'ldap3.utils.conv', 'uvicorn', 'requests', 'scapy', 'scapy.all', 'starlette', 'starlette.middleware.base', 'packaging'
]

for module in mock_modules:
    m = MagicMock()
    sys.modules[module] = m
    # Special handling for packages
    if module in ['ldap3', 'mysql', 'fastapi', 'passlib', 'scapy', 'starlette']:
        m.__path__ = []

# Now we can import from main
from main import create_access_token, SECRET_KEY, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES

def test_create_access_token_default_expiry():
    data = {"sub": "testuser", "role": "user"}
    token = create_access_token(data)

    # Assert it returns a string
    assert isinstance(token, str)

    # Decode to verify contents
    decoded = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])

    # Assert data was preserved
    assert decoded["sub"] == "testuser"
    assert decoded["role"] == "user"

    # Assert default expiration was set
    assert "exp" in decoded

    exp_time = datetime.utcfromtimestamp(decoded["exp"])
    expected_exp = datetime.utcnow() + timedelta(minutes=15)

    # The actual expiration should be very close to our calculated expected_exp
    assert abs((exp_time - expected_exp).total_seconds()) < 5

def test_create_access_token_custom_expiry():
    data = {"sub": "adminuser", "role": "admin"}
    custom_delta = timedelta(days=7)

    token = create_access_token(data, expires_delta=custom_delta)

    # Decode to verify contents
    decoded = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])

    assert decoded["sub"] == "adminuser"
    assert decoded["role"] == "admin"

    # Assert custom expiration was set
    assert "exp" in decoded

    exp_time = datetime.utcfromtimestamp(decoded["exp"])
    expected_exp = datetime.utcnow() + custom_delta

    # The actual expiration should be very close to our calculated expected_exp
    assert abs((exp_time - expected_exp).total_seconds()) < 5
