from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    # We are not using DB or Redis for the demo
    DATABASE_URL: str = "sqlite:///./dummy.db"
    REDIS_URL: str = "redis://localhost:6379/0"

    ALLOWED_ORIGINS: list[str] = ["*"]

settings = Settings()
