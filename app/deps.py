from dataclasses import dataclass

import jwt
from fastapi import Depends
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import ValidationError
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import RevokedToken, User, get_session
from app.exceptions import raise_auth_error
from app.schemas import TokenPayload
from app.security import decode_token

bearer = HTTPBearer(auto_error=False)
INVALID_TOKEN = "Invalid or expired token"


@dataclass
class Auth:
    """The logged-in user plus the token they used (logout needs the token's id)."""

    user: User
    token: TokenPayload


async def get_auth(
    creds: HTTPAuthorizationCredentials | None = Depends(bearer),
    session: AsyncSession = Depends(get_session),
) -> Auth:
    """Reads the 'Authorization: Bearer <token>' header and checks the token is still valid."""
    if creds is None:
        await raise_auth_error("Not authenticated")
    try:
        payload = decode_token(creds.credentials)
    except (jwt.PyJWTError, ValidationError):  # bad signature, expired, wrong content, not a JWT
        await raise_auth_error(INVALID_TOKEN)
    user = await session.get(User, payload.user_id)
    # Unknown user, token from before a password change, or a logged-out token
    # all get the same answer, so a caller can't tell which one it was.
    if (
        user is None
        or payload.ver != user.token_version
        or await session.get(RevokedToken, payload.jti) is not None
    ):
        await raise_auth_error(INVALID_TOKEN)
    return Auth(user=user, token=payload)


async def get_current_user(auth: Auth = Depends(get_auth)) -> User:
    return auth.user
