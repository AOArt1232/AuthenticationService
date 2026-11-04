import re

from pydantic import BaseModel, EmailStr, Field, field_validator

FORBIDDEN = set("@\"'<>")
SPECIAL = re.compile(r"[^A-Za-z0-9]")


def validate_password(value: str) -> str:
    if not 8 <= len(value) <= 24:
        raise ValueError("Password must be 8 to 24 characters long")
    if any(ch.isspace() for ch in value):
        raise ValueError("Password must not contain spaces")
    if FORBIDDEN & set(value):
        raise ValueError("Password must not contain @ \" ' < >")
    if not re.search(r"\d", value):
        raise ValueError("Password must contain a digit")
    if not re.search(r"[a-z]", value):
        raise ValueError("Password must contain a lowercase letter")
    if not re.search(r"[A-Z]", value):
        raise ValueError("Password must contain an uppercase letter")
    if not SPECIAL.search(value):
        raise ValueError("Password must contain a special character")
    return value


class RegisterIn(BaseModel):
    email: EmailStr
    password: str

    _check = field_validator("password")(validate_password)


class LoginIn(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1)


class UserOut(BaseModel):
    id: int
    email: EmailStr


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"

