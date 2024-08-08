import asyncio
import datetime
import json
import random

clients = []

DEFAULT_INTERVAL = 5


class ServerProtocol(asyncio.Protocol):

    def __init__(self):
        self.transport = None

    def connection_made(self, transport):
        info = transport.get_extra_info('socket')
        print(f'Connection from {info.getpeername()}')
        self.transport = transport
        clients.append(self.transport)

    def connection_lost(self, exc):
        clients.remove(self.transport)
        print('Client disconnected')


class DataProvider:
    @staticmethod
    def get_data() -> dict:
        return {
            'time': datetime.datetime.now().strftime('%d.%m.%Y %H:%M:%S'),
            'temperature': 25 + round(random.random() * 10, 1),
            'humidity': random.randint(50, 70),
            'wind': {
                'speed': round(5. + random.random() * 15, 1),
                'direction': random.choice(['NW', 'SW', 'NE', 'SE'])
            }
        }


class DataSender:
    def __init__(self, provider: DataProvider, interval=DEFAULT_INTERVAL):
        self.interval = interval
        self.provider = provider

    @staticmethod
    async def send_client(client, data: dict):
        client.write(json.dumps(data).encode())

    async def loop(self):
        while True:
            await asyncio.sleep(self.interval)
            data = self.provider.get_data()
            await self.send_all(data)

    async def send_all(self, data: dict):
        tasks = [
            asyncio.create_task(self.send_client(client, data)) for client in clients
        ]
        await asyncio.gather(*tasks)


async def main():
    provider = DataProvider()
    sender = DataSender(provider)
    loop = asyncio.get_running_loop()
    server = await loop.create_server(
        lambda: ServerProtocol(), '127.0.0.1', 8888
    )
    async with server:
        await asyncio.gather(server.serve_forever(), sender.loop())


if __name__ == '__main__':
    asyncio.run(main())
