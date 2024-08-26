import logging

logging.basicConfig(level=logging.DEBUG)


async def app(scope, receive, send):
    if scope["type"] != "http":
        return

    request = await receive()
    if request['type'] == 'http.request' and scope['path'] == '/' and not scope['query_string']:
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [
                    [b"content-type", b"text/html"],
                ],
            }
        )
        await send(
            {
                "type": "http.response.body",
                "body": b"<h1>Hello, World!!</h1><h2>from asgi app</h2>",
            }
        )
