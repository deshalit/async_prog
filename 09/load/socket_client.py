import asyncio
import logging
from collections.abc import Coroutine

from loader_config import LoaderConfig as cfg
from delta.delta_config import DeltaConfig

logging.basicConfig(level=cfg.LOG_LEVEL)
logger = logging.getLogger('loader.socket')

class SocketClient:
    receive: asyncio.Future | None = None
    connection_lost: asyncio.Future | None = None
    exec: Coroutine

    @classmethod
    async def wait_for_connection_lost(cls):
        await cls.connection_lost

    @classmethod
    async def wait_for_message(cls):
        await cls.receive

    @classmethod
    async def run(cls):
        while True:
            loop = asyncio.get_running_loop()

            cls.connection_lost = loop.create_future()
            transport, _ = await loop.create_connection(
                lambda: ClientProtocol(),
                DeltaConfig.SERVICE_HOST, DeltaConfig.SERVICE_PORT
            )
            try:
                task_lost = asyncio.create_task(cls.wait_for_connection_lost()),
                task_received = asyncio.create_task(cls.wait_for_message())
                await asyncio.wait([task_lost, task_received], return_when=asyncio.FIRST_COMPLETED)
                if task_received.result():
                    return True
            finally:
                transport.close()


class ClientProtocol(asyncio.Protocol):

    def data_received(self, raw_data):
        data = raw_data.decode()
        logger.debug(f'Received: {data}')
        if data == DeltaConfig.MESSAGE:
            SocketClient.receive.set_result(True)

    def connection_lost(self, exc):
        logger.debug('The server closed the connection')
        SocketClient.connection_lost.set_result(True)
