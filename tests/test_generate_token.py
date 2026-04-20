import pytest
from datetime import datetime, timezone, timedelta
from jose import jwt
from generate_token import create_token, SECRET_KEY, ALGORITHM

def test_create_token_returns_string():
    """Test that create_token returns a string (the encoded JWT)."""
    token = create_token()
    assert isinstance(token, str)
    assert len(token) > 0

def test_create_token_payload():
    """Test that the decoded token contains the expected payload claims."""
    token = create_token()

    # Decode the token
    decoded_payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])

    assert "sub" in decoded_payload
    assert decoded_payload["sub"] == "irudayaraj"

    assert "role" in decoded_payload
    assert decoded_payload["role"] == "admin"

def test_create_token_expiration():
    """Test that the token contains a valid 'exp' claim in the future (approx 30 days)."""
    # Get current time before generating token
    now = datetime.now(timezone.utc)

    token = create_token()
    decoded_payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])

    assert "exp" in decoded_payload

    # Get expiration timestamp
    exp_timestamp = decoded_payload["exp"]

    # Convert timestamp back to datetime
    exp_datetime = datetime.fromtimestamp(exp_timestamp, tz=timezone.utc)

    # Check that expiration is in the future
    assert exp_datetime > now

    # Check that expiration is roughly 30 days from now
    # Allowing a small tolerance for execution time
    expected_exp = now + timedelta(days=30)
    difference = abs((exp_datetime - expected_exp).total_seconds())

    assert difference < 5  # Less than 5 seconds difference
