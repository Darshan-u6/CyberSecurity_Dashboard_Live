from datetime import datetime, timedelta
from jose import jwt
import os

SECRET_KEY = "CHANGE_THIS_IN_PRODUCTION_SECRET_KEY_12345"
ALGORITHM = "HS256"

def create_token():
    expire = datetime.utcnow() + timedelta(days=30)
    data = {"sub": "irudayaraj", "role": "admin", "exp": expire}
    encoded_jwt = jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

print(create_token())
