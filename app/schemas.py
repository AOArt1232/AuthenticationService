import re

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

# Each rule is (pattern that must NOT match, error message), checked in order.
# All rules are compiled once, when the app starts, instead of on every call.
PASSWORD_RULES = [
    (re.compile(r"^(?!.{8,24}\Z)", re.S), "Password must be 8 to 24 characters long"),
    (re.compile(r"\s"), "Password must not contain spaces"),
    (re.compile(r"[@\"'<>]"), "Password must not contain @ \" ' < >"),
    (re.compile(r"^\D*\Z"), "Password must contain a digit"),
    (re.compile(r"^[^a-z]*\Z"), "Password must contain a lowercase letter"),
    (re.compile(r"^[^A-Z]*\Z"), "Password must contain an uppercase letter"),
    (re.compile(r"^[A-Za-z0-9]*\Z"), "Password must contain a special character"),
]


def validate_password(value: str) -> str:
    # Raise the message of the first rule the password breaks.
    error = next((msg for bad, msg in PASSWORD_RULES if bad.search(value)), None)
    if error:
        raise ValueError(error)
    return value


class RegisterIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: EmailStr
    password: str

    _check = field_validator("password")(validate_password)


class LoginIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: EmailStr
    # No full password rules here (old accounts may predate them), but cap the
    # length so nobody can make the server hash a huge string.
    password: str = Field(min_length=1, max_length=128)


class UserOut(BaseModel):
    id: int
    email: EmailStr


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"



class TokenPayload(BaseModel):
    """What must be inside a valid login token."""

    model_config = ConfigDict(extra="forbid")

    sub: str = Field(pattern=r"^[1-9][0-9]*$")  # the user's id, as a string
    iat: int
    exp: int

    @property
    def user_id(self) -> int:
        return int(self.sub)
