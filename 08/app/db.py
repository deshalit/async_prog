from typing import Annotated
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.ext.asyncio import AsyncAttrs, create_async_engine, AsyncEngine, async_sessionmaker
from fastapi import Depends

from config import get_settings, Settings


def get_engine(settings: Annotated[Settings, Depends(get_settings)]) -> AsyncEngine:
    return create_async_engine(settings.db_uri, echo=settings.echo)


async def get_session(engine: Annotated[AsyncEngine, Depends(get_engine)]
) -> AsyncSession:
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    async with session_factory() as session:
        return session


class Base(DeclarativeBase, AsyncAttrs):
    pass


async def reset_database(engine: AsyncEngine):
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
