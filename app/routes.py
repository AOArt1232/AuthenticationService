from datetime import datetime, timezone

from fastapi import APIRouter, Depends, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import RevokedToken, User, get_session
from app.deps import Auth, get_auth, get_current_user
from app.exceptions import ConflictError, raise_auth_error
from app.schemas import LoginIn, MessageOut, PasswordChangeIn, RegisterIn, TokenOut, UserOut
from app.security import DUMMY_HASH, create_access_token, hash_password, verify_password

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/register", response_model=UserOut, status_code=status.HTTP_201_CREATED)
async def register(data: RegisterIn, session: AsyncSession = Depends(get_session)):
    email = data.email.lower()
    if await session.scalar(select(User).where(User.email == email)):
        raise ConflictError("Email already registered")
    user = User(email=email, password_hash=await hash_password(data.password))
    session.add(user)
    try:
        await session.commit()
    except IntegrityError:  # two sign-ups with the same email at the same moment
        raise ConflictError("Email already registered")
    return UserOut(id=user.id, email=user.email)


@router.post("/login", response_model=TokenOut)
async def login(data: LoginIn, session: AsyncSession = Depends(get_session)):
    user = await session.scalar(select(User).where(User.email == data.email.lower()))
    # Always run the slow password check, even for unknown emails, so both
    # failures take the same time and can't be told apart by timing.
    password_ok = await verify_password(data.password, user.password_hash if user else DUMMY_HASH)
    if user is None or not password_ok:
        await raise_auth_error("Incorrect email or password")
    return TokenOut(access_token=create_access_token(user.id, user.token_version))


@router.get("/me", response_model=UserOut)
async def me(user: User = Depends(get_current_user)):
    """Protected: only works with a valid login token."""
    return UserOut(id=user.id, email=user.email)


@router.post("/logout", response_model=MessageOut)
async def logout(auth: Auth = Depends(get_auth), session: AsyncSession = Depends(get_session)):
    """Revokes the token used for this request, so it can't be used again."""
    session.add(
        RevokedToken(
            jti=auth.token.jti,
            expires_at=datetime.fromtimestamp(auth.token.exp, timezone.utc),
        )
    )
    await session.commit()
    return MessageOut(detail="Logged out")


@router.post("/change-password", response_model=MessageOut)
async def change_password(
    data: PasswordChangeIn,
    auth: Auth = Depends(get_auth),
    session: AsyncSession = Depends(get_session),
):
    """Needs the current password. Afterwards every existing token stops working."""
    user = await session.get(User, auth.user.id)
    if not await verify_password(data.old_password, user.password_hash):
        await raise_auth_error("Old password is incorrect", 400)
    if data.old_password == data.new_password:
        await raise_auth_error("New password must be different from the old one", 400)
    user.password_hash = await hash_password(data.new_password)
    user.token_version += 1  # logs out all devices
    await session.commit()
    return MessageOut(detail="Password changed, please log in again")
