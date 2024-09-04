from fastapi import FastAPI
from router import api


app = FastAPI()
app.include_router(api)
