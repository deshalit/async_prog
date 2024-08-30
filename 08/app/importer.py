from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncEngine
from sqlalchemy import insert

from db import get_session
from models import Cve, Description, ProblemType, Reference


async def import_cves(engine: AsyncEngine, source: list[dict]):
    async with await get_session(engine) as session:
        cves, descriptions, references, problem_types = [], [], [], []
        for record in source:
            cves.append(dict(
                id=record['id'],
                date_published=datetime.fromisoformat(record['date_published']),
                date_updated=datetime.fromisoformat(record['date_published']),
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
        await session.execute(
            insert(Cve).values(cves)
        )
        if descriptions:
            await session.execute(
                insert(Description).values(descriptions)
            )
        if problem_types:
            await session.execute(
                insert(ProblemType).values(problem_types)
            )
        if references:
            await session.execute(
                insert(Reference).values(references)
            )
        await session.commit()
