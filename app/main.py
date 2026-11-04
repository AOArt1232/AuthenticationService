from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.db import close_db, init_db
from app.exceptions import AuthError, auth_error_handler
from app.routes import router


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    yield
    await close_db()


app = FastAPI(title="Auth service", lifespan=lifespan)
app.add_exception_handler(AuthError, auth_error_handler)
app.include_router(router)
