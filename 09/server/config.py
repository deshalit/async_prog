from pydantic import BaseModel


class Settings(BaseModel):
    db_uri: str = "postgresql+asyncpg://postgres:postgres@localhost:5432/app"
    # echo: bool = False
    echo: bool = True
    last_delta_file: str = './.delta'


def get_settings() -> Settings:
    return Settings()
