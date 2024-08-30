from contextlib import asynccontextmanager
from fastapi import FastAPI
from config import get_settings
from db import get_engine, reset_database
from router import api
from startup_db import STARTUP_DB
from importer import import_cves


@asynccontextmanager
async def lifespan(_app: FastAPI):
    engine = get_engine(get_settings())
    await reset_database(engine)
    await import_cves(engine, STARTUP_DB)
    yield


app = FastAPI(lifespan=lifespan)
app.include_router(api)
