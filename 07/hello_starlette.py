from starlette.applications import Starlette
from starlette.responses import HTMLResponse
from starlette.routing import Route


async def homepage(request):
    return HTMLResponse(b"<h1>Hello, World!!</h1><h2>from starlette app</h2>")


app = Starlette(
    routes=[
        Route("/", homepage),
    ],
)
