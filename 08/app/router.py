from fastapi import APIRouter
from cves import cves_api

api = APIRouter(prefix="/api")
api.include_router(cves_api)
