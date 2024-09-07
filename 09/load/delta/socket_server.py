import asyncio

from delta_config import DeltaConfig as cfg


class SocketServer:
    changed = False
    transport = None

    @classmethod
    async def loop(cls):
        if cls.changed and cls.transport:
            print(f"Send: {cfg.MESSAGE}")
            cls.transport.write(cfg.MESSAGE.encode())
            cls.changed = False
        await asyncio.sleep(10)

    @classmethod
    async def run(cls):
        loop = asyncio.get_running_loop()
        server = await loop.create_server(
            lambda: ServerProtocol(), cfg.SERVICE_HOST, cfg.SERVICE_PORT
        )
        async with server:
            await asyncio.gather(server.serve_forever(), cls.loop())


class ServerProtocol(asyncio.Protocol):

    def connection_made(self, transport):
        info = transport.get_extra_info('socket')
        print(f'Connection from {info.getpeername()}')
        SocketServer.transport = transport

    def connection_lost(self, exc):
        SocketServer.transport = None
        print('Client disconnected')


