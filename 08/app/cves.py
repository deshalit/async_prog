from typing import Annotated
from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

from schemas import Cve, CveId
from db import get_session
import crud


cves_api = APIRouter(prefix="/cves")

session_dep = Annotated[AsyncSession, Depends(get_session)]

@cves_api.get("/")
async def read_cves(db_session: session_dep) -> list[Cve]:
    records = await crud.read_cves(db_session)
    return [Cve.model_validate(rec) for rec in records]


@cves_api.get("/{cve_id}")
async def read_cve(cve_id: Annotated[CveId, Depends()], db_session: session_dep) -> Cve | None:
    return Cve.model_validate(await crud.read_cve(cve_id.id, db_session))


@cves_api.post("/", status_code=status.HTTP_201_CREATED)
async def create_cve(cve: Annotated[Cve, Depends()], db_session: session_dep) -> Cve:
    cve_model = await crud.create_cve(cve.model_dump(), db_session)
    return Cve.model_validate(cve_model)

