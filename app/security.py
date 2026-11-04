import asyncio
import hashlib
import hmac
import os
from datetime import datetime, timedelta, timezone

import jwt

from app.config import settings

ITERATIONS = 390_000


def _hash_sync(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, ITERATIONS)


async def hash_password(password: str) -> str:
    # Hashing is CPU-heavy, so run it in a thread to keep the event loop free.
    salt = os.urandom(16)
    digest = await asyncio.to_thread(_hash_sync, password, salt)
    return f"{salt.hex()}${digest.hex()}"


async def verify_password(password: str, stored: str) -> bool:
    salt_hex, digest_hex = stored.split("$")
    digest = await asyncio.to_thread(_hash_sync, password, bytes.fromhex(salt_hex))
    return hmac.compare_digest(digest.hex(), digest_hex)


def create_access_token(user_id: int) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "iat": now,
        "exp": now + timedelta(minutes=settings.access_token_minutes),
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def decode_token(token: str) -> dict:
    return jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])
