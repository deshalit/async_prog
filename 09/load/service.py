import asyncio
import logging
from loader import load
from loader_config import LoaderConfig as cfg
from socket_client import SocketClient

logging.basicConfig(level=cfg.LOG_LEVEL)


async def main():
    while True:
        result = await SocketClient.run()
        if result:
            await load()


if __name__ == '__main__':
    asyncio.run(main())