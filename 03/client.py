import asyncio
import json


class MeteoClientProtocol(asyncio.Protocol):
    def __init__(self, on_lost: asyncio.Future):
        self.on_connection_lost = on_lost

    def data_received(self, raw_data):
        data = json.loads(raw_data.decode())
        message = (f'{data["time"]}: Temperature: {data["temperature"]}, humidity: {data["humidity"]}%, '
                   f'wind speed: {data["wind"]["speed"]} mps, wind direction: {data["wind"]["direction"]}')
        print(message)

    def connection_lost(self, exc):
        print('The server closed the connection')
        self.on_connection_lost.set_result(True)


async def main():
    loop = asyncio.get_running_loop()

    connection_lost = loop.create_future()
    transport, _ = await loop.create_connection(
        lambda: MeteoClientProtocol(connection_lost),
        '127.0.0.1', 8888)

    try:
        await connection_lost
    finally:
        transport.close()


asyncio.run(main())
