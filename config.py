from pydantic_settings import BaseSettings
from typing import Optional

class Settings(BaseSettings):
    DATABASE_URL: str = "postgresql://postgres:postgres@localhost/fast_auth_db"
    
    SECRET_KEY: str = "your-secret-key-change-this-in-production"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    APP_NAME: str = "FastAPI Authentication Mnagement"
    ENVIRONMENT: str = "development"
    DEBUG: bool = True

    BCRYPT_ROUNDS: int = 12
    
    class Config:
        env_file = ".env"

settings = Settings()
