from datetime import datetime
from typing import Annotated, List
from fastapi import APIRouter, Depends, status, Query, Path
from sqlalchemy.ext.asyncio import AsyncSession

from schemas import Cve
from database import get_session
import crud


cves = APIRouter(prefix="/cves")

Session = Annotated[AsyncSession, Depends(get_session)]

Limit = Annotated[int, Query(
    ge=crud.MIN_LIMIT,
    le=crud.MAX_LIMIT,
    description="Enter the number of records per result (1...100)",
    title="Limit"
)]

CveId = Annotated[str, Path(description="Enter CVE id to search (example: CVE-2001-0001)", example="CVE-2001-0001")]


@cves.get("/",  response_model=List[Cve])
async def read_cves(
        db_session: Session,
        datefrom: Annotated[str | None, Query(description="The left range for date_published", title="From datetime", example="2021-10-31T23:12:00")] = None,
        dateto: Annotated[str | None, Query(description="The right range for date_published", example="2021-10-31T23:12:00", title="To datetime")] = None,
        text: Annotated[str | None, Query(description="Enter the text to search")] = None,
        page: Annotated[int, Query(ge=1, description="page index from 1", title="Page number")] = 1,
        limit: Limit = crud.DEFAULT_LIMIT
):
    date_to = datetime.fromisoformat(dateto) if dateto else None
    date_from = datetime.fromisoformat(datefrom) if datefrom else None
    records = await crud.read_cves(db_session, date_from, date_to, text, page, limit)
    return [Cve.model_validate(rec) for rec in records]


@cves.get("/{cve_id}")
async def read_cve(cve_id: CveId, db_session: Session) -> Cve | None:
    result = await crud.read_cve(cve_id, db_session)
    return Cve.model_validate(result) if result else None


@cves.post("/", status_code=status.HTTP_201_CREATED)
async def create_cve(cve: Annotated[Cve, Depends()], db_session: Session) -> Cve:
    cve_model = await crud.create_cve(cve.model_dump(), db_session)
    return Cve.model_validate(cve_model)


@cves.post("/bulk", status_code=status.HTTP_201_CREATED)
async def create_cves(cves: list[dict], db_session: Session) -> bool:
    return await crud.create_cves(cves, db_session)

