from pydantic import BaseModel


class Settings(BaseModel):
    db_uri: str = "postgresql+asyncpg://postgres:postgres@localhost/app"
    # echo: bool = False
    echo: bool = True


def get_settings() -> Settings:
    return Settings()
