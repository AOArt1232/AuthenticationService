import jwt
from pydantic import ValidationError
from fastapi import Depends
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import User, get_session
from app.exceptions import raise_auth_error
from app.security import decode_token

bearer = HTTPBearer(auto_error=False)
INVALID_TOKEN = "Invalid or expired token"


async def get_current_user(
    creds: HTTPAuthorizationCredentials | None = Depends(bearer),
    session: AsyncSession = Depends(get_session),
) -> User:
    """Reads the 'Authorization: Bearer <token>' header and returns the logged-in user."""
    if creds is None:
        await raise_auth_error("Not authenticated")
    try:
        payload = decode_token(creds.credentials)
    except (jwt.PyJWTError, ValidationError):  # bad signature, expired, wrong content, not a JWT
        await raise_auth_error(INVALID_TOKEN)
    user = await session.get(User, payload.user_id)
    if user is None:
        # Same answer as a bad token, so a caller can't learn which user ids exist.
        await raise_auth_error(INVALID_TOKEN)
    return user
