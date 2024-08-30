from sqlalchemy.future import select
from sqlalchemy.ext.asyncio import AsyncSession
from models import Cve, Description, Reference, ProblemType


async def read_cves(db_session: AsyncSession) -> list[Cve]:
    stmt = select(Cve)
    result = await db_session.execute(stmt.order_by(Cve.date_published))
    return list(result.scalars().all())


async def read_cve(cve_id: str, db_session: AsyncSession) -> Cve:
    stmt = select(Cve).where(Cve.id == cve_id)
    result = await db_session.execute(stmt.order_by(Cve.date_published))
    return result.scalars().one_or_none()

async def create_cve(cve_dict: dict, db_session: AsyncSession) -> Cve:
    descriptions_list = cve_dict['descriptions']
    cve_dict['descriptions'] = []
    problems_list = cve_dict['problem_types']
    cve_dict['problem_types'] = []
    references_list = cve_dict['references']
    cve_dict['references'] = []

    cve = Cve(**cve_dict)
    db_session.add(cve)

    descriptions = [Description(**d) for d in descriptions_list]
    for description in descriptions:
        db_session.add(description)
    cve.descriptions = descriptions

    problem_types = [ProblemType(**p) for p in problems_list]
    for p in problem_types:
        db_session.add(p)
    cve.problem_types = problem_types

    references = [Reference(**ref) for ref in references_list]
    for ref in references:
        db_session.add(ref)
    cve.references = references

    db_session.add(cve)
    await db_session.commit()
    await db_session.refresh(cve)

    return cve


async def delete_cve(cve_id: str, db_session: AsyncSession) -> bool:
    cve = await read_cve(cve_id, db_session)
    await db_session.delete(cve)
    await db_session.commit()
    cve = await read_cve(cve_id, db_session)
    return cve is None
