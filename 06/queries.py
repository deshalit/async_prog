from datetime import datetime

from sqlalchemy.future import select
from sqlalchemy.ext.asyncio import AsyncSession
from collections.abc import Sequence
from models import Cve


async def get_cves_by_published(session: AsyncSession, date1: datetime, date2: datetime=None) -> Sequence[Cve]:
    stmt = select(Cve).where(Cve.date_published >= date1)
    if date2 is not None:
        stmt = stmt.where(Cve.date_published <= date2)
    result = await session.execute(stmt.order_by(Cve.date_published))
    return result.scalars().all()


async def get_cves_by_updated(session: AsyncSession, date1: datetime, date2: datetime=None) -> Sequence[Cve]:
    stmt = select(Cve).where(Cve.date_updated >= date1)
    if date2 is not None:
        stmt = stmt.where(Cve.date_updated <= date2)
    result = await session.execute(stmt)
    return result.scalars().all()


async def get_cve_by_id(session: AsyncSession, cve_id: str) -> Cve:
    stmt = select(Cve).where(Cve.id == cve_id)
    result = (await session.scalars(stmt)).one()
    return result
