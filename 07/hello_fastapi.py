from typing import Annotated
from fastapi import FastAPI, Depends
from pydantic import BaseModel


app = FastAPI()


class HomeAnswer(BaseModel):
    message: str

_answer = HomeAnswer(message= "Hello, World!! (from fastapi app)")


def get_home_answer() -> HomeAnswer:
    return _answer


@app.get("/", response_model=HomeAnswer)
async def home(answer: Annotated[HomeAnswer, Depends(get_home_answer)]):
    return answer

