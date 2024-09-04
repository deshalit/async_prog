from fastapi import APIRouter
from cves import cves

api = APIRouter(prefix="/api")
api.include_router(cves)
