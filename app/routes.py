from fastapi import APIRouter, Depends, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import User, get_session
from app.exceptions import ConflictError, raise_auth_error
from app.schemas import LoginIn, RegisterIn, TokenOut, UserOut
from app.security import create_access_token, hash_password, verify_password

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
    if user is None or not await verify_password(data.password, user.password_hash):
        await raise_auth_error("Incorrect email or password")
    return TokenOut(access_token=create_access_token(user.id))
