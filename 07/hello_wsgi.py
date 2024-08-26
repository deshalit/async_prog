import time
import logging

def app(env, start_response):
    # time.sleep(3)

    logging.basicConfig(level=logging.DEBUG)
    logger = logging.getLogger(__name__)

    if env['REQUEST_METHOD'] == 'GET' and env['PATH_INFO'] == '/':
        start_response("200 OK", [("Content-Type", "text/html")])
        return [b"<h1>Hello, World!</h1><h2>from wsgi app</h2>"]
