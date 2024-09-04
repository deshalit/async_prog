from datetime import datetime
import asyncio
from sqlalchemy import insert
from sqlalchemy.future import select
from sqlalchemy.ext.asyncio import AsyncSession
from models import Cve, Description, Reference, ProblemType

DEFAULT_LIMIT = 10
MIN_LIMIT = 1
MAX_LIMIT = 100


async def read_cves(
        db_session: AsyncSession,
        date_from: datetime|None = None,
        date_to: datetime|None = None,
        text: str|None = None,
        page_no: int = 1,
        limit: int = DEFAULT_LIMIT
) -> list[Cve]:
    offset = (page_no - 1) * limit
    stmt = select(Cve)
    if text:
        stmt = stmt.join(
            Cve.descriptions.and_(Description.text.contains(text))
        ).join(
            Cve.problem_types.and_(ProblemType.text.contains(text))
        )
    if date_from and date_to:
        stmt = stmt.where(Cve.date_published.between(date_from, date_to))
    elif date_from:
        stmt = stmt.where(Cve.date_published >= date_from)
    elif date_to:
        stmt = stmt.where(Cve.date_published <= date_to)

    result = await db_session.execute(
        stmt.order_by(Cve.date_published).limit(limit).offset(offset)
    )
    # await db_session.close()
    return list(result.scalars().all())


async def read_cve(cve_id: str, db_session: AsyncSession) -> Cve|None:
    stmt = select(Cve).where(Cve.id == cve_id)
    result = await db_session.execute(stmt.order_by(Cve.date_published))
    return result.scalars().first()

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

async def create_cves(cve_list: list[dict], db_session: AsyncSession) -> bool:
    cves, descriptions, references, problem_types = [], [], [], []
    for record in cve_list:
        cves.append(dict(
            id=record['id'],
            date_published=datetime.fromisoformat(record['date_published']),
            date_updated=datetime.fromisoformat(record['date_updated']),
            title=record['title']
        ))
        descriptions.extend([
            dict(
                cve_id=record['id'],
                lang=item['lang'],
                text=item['text']
            ) for item in record['descriptions']
        ])
        problem_types.extend([
            dict(
                cve_id=record['id'],
                lang=item['lang'],
                text=item['text'],
            ) for item in record['problem_types']
        ])
        references.extend([
            dict(
                cve_id=record['id'],
                name=item['name'],
                url=item['url']
            ) for item in record['references']
        ])
    await db_session.execute(
        insert(Cve).values(cves)
    )
    coroutines = []
    if descriptions:
        coroutines.append(db_session.execute(
            insert(Description).values(descriptions)
        ))
    if problem_types:
        coroutines.append(db_session.execute(
            insert(ProblemType).values(problem_types)
        ))
    if references:
        coroutines.append(db_session.execute(
            insert(Reference).values(references)
        ))
    if coroutines:
        await asyncio.gather(*[asyncio.create_task(c) for c in coroutines])
    await db_session.commit()
    return True

async def delete_cve(cve_id: str, db_session: AsyncSession) -> bool:
    cve = await read_cve(cve_id, db_session)
    await db_session.delete(cve)
    await db_session.commit()
    cve = await read_cve(cve_id, db_session)
    return cve is None
