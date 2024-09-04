import asyncio
import logging
import aiohttp
from aiohttp import ClientSession
from itertools import batched
from loader_config import LoaderConfig as cfg


ParsedFiles = dict[str, dict | bool]


class Loader:

    def __init__(self, worker_id: int, logger: logging.Logger, files: ParsedFiles):
        self.worker_id = worker_id
        self.queue = asyncio.Queue()
        self.bad_queue = asyncio.Queue()
        self.logger = logger
        self.parsed_files = files

    async def import_batch(self, session: aiohttp.ClientSession, batch: list[str]):
        record_values = [
            self.parsed_files[file_name] for file_name in batch
        ]
        async with session.post(cfg.URI, json=record_values) as response:
            if response.status == 201:
                for file_name in batch:
                    self.parsed_files[file_name] = True
            else:
                self.logger.error(f'Failed to post. Status: {response.status}, '
                                  f'reason: "{response.reason}", text: "{response.text()}"')

    async def import_many(self, session: aiohttp.ClientSession):
        while not self.queue.empty():
            batch: list[str] = await self.queue.get()
            await asyncio.sleep(.1)
            await self.import_batch(session, batch)

    async def execute_many(self):
        for batch in batched(self.parsed_files, cfg.BATCH_SIZE):
            await self.queue.put(batch)
        print('Worker', self.worker_id, ': input queue contains', self.queue.qsize(), 'batches')
        task_count = cfg.IMPORT_TASK_COUNT
        async with ClientSession() as session:
            tasks = [
                asyncio.create_task(self.import_many(session)) for _ in range(task_count)
            ]
            await asyncio.gather(
                *tasks,
                asyncio.create_task(self.import_monitor(tasks))
            )

    async def import_monitor(self, tasks: list[asyncio.Task]):
        batches_total = self.queue.qsize()
        last_progress = 0
        done_tasks = []
        print('Worker', self.worker_id, ': task monitor started (there are', len(tasks), 'tasks)')
        while len(done_tasks) < len(tasks):
            await asyncio.sleep(cfg.IMPORT_MONITOR_INTERVAL)
            done_tasks = [task for task in tasks if task.done() or task.cancelled()]
            remain = self.queue.qsize()
            progress = ((batches_total - remain) * 100) // (batches_total + 1)
            if progress > last_progress:
                print('Worker', self.worker_id, ': imported', progress, '%')
                last_progress = progress

        print('Worker', self.worker_id, ': task monitor finished')
