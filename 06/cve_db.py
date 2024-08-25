from sqlalchemy.ext.asyncio import create_async_engine, AsyncEngine, async_sessionmaker, AsyncSession
from config import DB_URI, DB_ECHO
from models import Base

# _engine: AsyncEngine = None


def get_engine() -> AsyncEngine:
    return create_async_engine(
        DB_URI,
        echo=DB_ECHO,
    )
    # global  _engine
    # if _engine is None:
    #     _engine = create_async_engine(
    #         DB_URI,
    #         echo=DB_ECHO,
    #     )
    # return _engine


async def create_db():
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)


def get_session(engine: AsyncEngine = None) -> AsyncSession:
    if engine is None:
        engine = get_engine()
    return async_sessionmaker(
        engine,
        autoflush=False,
        expire_on_commit=True,
    )()
