from fastapi import Request
from fastapi.responses import JSONResponse


class AuthError(Exception):
    def __init__(self, detail: str, status_code: int = 401):
        self.detail = detail
        self.status_code = status_code


class ConflictError(AuthError):
    def __init__(self, detail: str):
        super().__init__(detail, 409)


# Exception handlers are async, as required for anything raised from external calls.
async def auth_error_handler(request: Request, exc: AuthError) -> JSONResponse:
    headers = {"WWW-Authenticate": "Bearer"} if exc.status_code == 401 else None
    return JSONResponse({"detail": exc.detail}, status_code=exc.status_code, headers=headers)


async def raise_auth_error(detail: str, status_code: int = 401) -> None:
    raise AuthError(detail, status_code)
