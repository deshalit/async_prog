from itertools import batched
import asyncio
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import insert

from common import timer
from cve_db import get_session
from models import Cve, Description, ProblemType, Reference
from config import IMPORT_TASK_COUNT, DB_BATCH_SIZE, IMPORT_MONITOR_INTERVAL


async def import_cves(queue: asyncio.Queue):
    async with get_session() as session:
        while not queue.empty():
            batch: list[dict] = await queue.get()
            queue.task_done()
            await import_batch(session, batch)
            await session.flush()
            await session.commit()


async def import_batch(session: AsyncSession, batch):
    cves, descriptions, references, problem_types = [], [], [], []
    for record in batch:
        cves.append(dict(
            id=record['id'],
            date_published=record['date_published'],
            date_updated=record['date_published'],
            title=record['title']
        ))
        descriptions.extend([
            dict(
                cve_id=record['id'],
                lang=item['lang'],
                text=item['text']
            ) for item in record['descriptions']
        ])
        problem_types.extend([
            dict(
                cve_id=record['id'],
                lang=item['lang'],
                text=item['text'],
            ) for item in record['problem_types']
        ])
        references.extend([
            dict(
                cve_id=record['id'],
                name=item['name'],
                url=item['url']
            ) for item in record['references']
        ])
    await session.execute(
        insert(Cve).values(cves)
    )
    if descriptions:
        await session.execute(
            insert(Description).values(descriptions)
        )
    if problem_types:
        await session.execute(
            insert(ProblemType).values(problem_types)
        )
    if references:
        await session.execute(
            insert(Reference).values(references)
        )


async def make_import(worker_id: int, parsed_records: list[dict]):
    queue = asyncio.Queue()
    for batch in batched(parsed_records, DB_BATCH_SIZE):
        await queue.put(batch)
    print('Worker', worker_id, ': input queue contains', queue.qsize(), 'batches (every batch contains', DB_BATCH_SIZE,
          'records)')
    with timer(f'Worker {worker_id} : importing'):
        task_count = IMPORT_TASK_COUNT
        tasks = [
            asyncio.create_task(import_cves(queue)) for _ in range(task_count)
        ]
        await asyncio.gather(
            *tasks,
            asyncio.create_task(import_monitor(worker_id, tasks, queue))
        )


async def import_monitor(worker_id: int, tasks: list[asyncio.Task], queue: asyncio.Queue):
    batches_total = queue.qsize()
    last_progress = 0
    done_tasks = []
    print('Worker', worker_id, ': task monitor started (there are', len(tasks), 'tasks)')
    while len(done_tasks) < len(tasks):
        await asyncio.sleep(IMPORT_MONITOR_INTERVAL)
        done_tasks = [task for task in tasks if task.done() or task.cancelled()]
        batches_remain = queue.qsize()
        progress = ((batches_total-batches_remain) * 100) // (batches_total + 1)
        if progress > last_progress:
            print('Worker', worker_id, ': imported', progress, '%')
            last_progress = progress
    print('Worker', worker_id, ': task monitor finished')
