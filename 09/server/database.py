from contextlib import asynccontextmanager
from typing import Annotated, AsyncGenerator
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.ext.asyncio import AsyncAttrs, create_async_engine, AsyncEngine, async_sessionmaker
from fastapi import Depends

from config import get_settings, Settings


def create_engine(settings: Annotated[Settings, Depends(get_settings)]) -> AsyncEngine:
    return create_async_engine(settings.db_uri, echo=settings.echo)


_engine = create_engine(get_settings())


def get_engine() -> AsyncEngine:
    return _engine


session_maker = async_sessionmaker(_engine, class_=AsyncSession, expire_on_commit=False)


async def get_session() -> AsyncSession:
    async with session_maker() as session:
        yield session


class Base(DeclarativeBase, AsyncAttrs):
    pass


async def reset_database():
    async with _engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
