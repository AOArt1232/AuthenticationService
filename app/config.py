from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    database_url: str = "postgresql+asyncpg://postgres:postgres@localhost:5432/auth"
    jwt_secret: str = "change-me-in-production-please-32b"
    jwt_algorithm: str = "HS256"
    access_token_minutes: int = 30


settings = Settings()
