import pytest
from datetime import datetime, timezone
from jose import jwt
from freezegun import freeze_time

from generate_token import create_token, SECRET_KEY, ALGORITHM

@freeze_time("2024-01-01 12:00:00")
def test_create_token_payload_and_expiry():
    # Act
    token = create_token()

    # Assert
    assert isinstance(token, str)

    # Decode the token
    decoded_payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])

    # Check fixed claims
    assert decoded_payload.get("sub") == "irudayaraj"
    assert decoded_payload.get("role") == "admin"

    # Check expiry - Use timezone-aware datetime to avoid local timezone issues
    # 30 days from 2024-01-01 12:00:00 is 2024-01-31 12:00:00
    expected_expiry = datetime(2024, 1, 31, 12, 0, 0, tzinfo=timezone.utc).timestamp()
    assert decoded_payload.get("exp") == expected_expiry

def test_create_token_is_deterministic_with_same_time():
    with freeze_time("2024-01-01 12:00:00"):
        token1 = create_token()
        token2 = create_token()

    assert token1 == token2

def test_create_token_differs_with_different_time():
    with freeze_time("2024-01-01 12:00:00"):
        token1 = create_token()

    with freeze_time("2024-01-02 12:00:00"):
        token2 = create_token()

    assert token1 != token2
