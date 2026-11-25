import pytest

from tests.conftest import check_isolated

TEST = "postgresql+asyncpg://postgres:postgres@localhost:5432/auth_test"


def test_accepts_separate_test_db():
    check_isolated(TEST, "postgresql+asyncpg://postgres:postgres@localhost:5432/auth")
    check_isolated(TEST, None)


@pytest.mark.parametrize(
    "test_url",
    [
        "postgresql+asyncpg://postgres:postgres@localhost:5432/auth",
        "postgresql+asyncpg://postgres:postgres@localhost:5432/production",
        "postgresql+asyncpg://postgres:postgres@localhost:5432/test_auth",
    ],
)
def test_rejects_non_test_db(test_url):
    with pytest.raises(RuntimeError, match="does not end in '_test'"):
        check_isolated(test_url, None)


def test_rejects_same_db_as_working():
    with pytest.raises(RuntimeError, match="same database"):
        check_isolated(TEST, TEST.replace("postgres:postgres", "admin:other"))
