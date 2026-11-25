import os

from sqlalchemy.engine import make_url

# Tests drop and recreate every table, so they must never touch the real database.
# They use TEST_DATABASE_URL only, and always override DATABASE_URL with it,
# so a DATABASE_URL pointing at the working database is ignored here.
TEST_DATABASE_URL = os.environ.get(
    "TEST_DATABASE_URL", "postgresql+asyncpg://postgres:postgres@localhost:5432/auth_test"
)


def check_isolated(test_url: str, real_url: str | None) -> None:
    """Refuse to run unless the test database is clearly a separate, *_test database."""
    test = make_url(test_url)
    if not (test.database or "").endswith("_test"):
        raise RuntimeError(
            f"Refusing to run tests: database '{test.database}' does not end in '_test'. "
            "Set TEST_DATABASE_URL to a separate test database."
        )
    if real_url:
        real = make_url(real_url)
        same = (real.host, real.port or 5432, real.database) == (test.host, test.port or 5432, test.database)
        if same:
            raise RuntimeError(
                "Refusing to run tests: TEST_DATABASE_URL points at the same database as DATABASE_URL."
            )


check_isolated(TEST_DATABASE_URL, os.environ.get("DATABASE_URL"))
os.environ["DATABASE_URL"] = TEST_DATABASE_URL  # must happen before the app is imported

import pytest  # noqa: E402
from httpx import ASGITransport, AsyncClient  # noqa: E402
from sqlalchemy import text  # noqa: E402

from app.db import Base, engine  # noqa: E402
from app.main import app  # noqa: E402


@pytest.fixture
async def client():
    async with engine.begin() as conn:
        # Last check against the live connection, right before anything is deleted.
        name = await conn.scalar(text("select current_database()"))
        if not name.endswith("_test"):
            pytest.exit(f"Refusing to drop tables in '{name}': not a test database.", returncode=2)
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        yield c
    await engine.dispose()
