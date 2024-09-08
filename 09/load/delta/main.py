import asyncio
import json
import aiohttp
import re
import aiofiles
import os
import logging
from datetime import datetime
from aiohttp import ClientSession

from delta_config import DeltaConfig as cfg

import sys
sys.path.append(
    os.path.dirname(
        os.path.dirname(__file__)
    )
)
from loader_config import LoaderConfig
from socket_server import SocketServer


logging.basicConfig(level=cfg.LOG_LEVEL)
logger = logging.getLogger('delta_checker')

pattern = re.compile(r'(\d{4}-\d{2}.+)\",$')


def get_local_last_datetime() -> datetime:
    file_name = os.path.join(LoaderConfig.DIR, cfg.DELTA_FILE_NAME)
    logger.info(f'Reading "{file_name}"')
    with open(file_name, 'r') as f:
        delta = json.load(f)
    last_date_str = delta['fetchTime']
    logger.info(f'Datetime "{last_date_str}" has read')
    return datetime.fromisoformat(last_date_str)


def set_local_last_datetime(delta: dict):
    file_name = os.path.join(LoaderConfig.DIR, cfg.DELTA_FILE_NAME)
    logger.info(f'Writing "{file_name}"')
    with open(file_name, 'w') as f:
        json.dump(delta, f, indent=2)


async def fetch_and_save_files(queue: asyncio.Queue, session: aiohttp.ClientSession):
    while not queue.empty():
        cve_id, url = await queue.get()
        queue.task_done()
        logger.debug(f'Getting {url}')
        async with session.get(url) as response:
            if not response.ok:
                logger.error(f'Cannot reach {url}: code {response.status}, answer is "{await response.text()}"')
            text = await response.text()
        file_name = os.path.join(
            LoaderConfig.DIR,
            cve_id + '.json'
        )
        async with aiofiles.open(file_name, 'w') as f:
            await f.writelines(text)
            # json.dump(data, f, indent=4)
        logger.debug(f'CVE file "{file_name}" has written')


async def find_next_fetch_time(stream: aiohttp.StreamReader, lines: list[str]) -> datetime or False:
    line = ''
    while not (stream.at_eof() or ("fetchTime" in line)):
        line = (await stream.readline()).decode()
        lines.append(line)
    if "fetchTime" in line:
        time_string = pattern.findall(line)
        return datetime.fromisoformat(time_string[0])
    else:
        logger.debug('Achieved EOF: ' + str(stream.at_eof()) + '\n' + ''.join(lines[-7:]))
        return False


async def get_newest_delta(session: ClientSession, local_date: datetime):
    url = cfg.URL_PATH + cfg.DELTA_FILE_NAME
    logger.info(f'Getting "{url}"')
    async with session.get(url) as response:
        if response.status != 200:
            logger.error(f'Cannot read {url}: code {response.status}')
            return False
        text = await response.text()
    delta = json.loads(text)
    fetch_time = datetime.fromisoformat(delta['fetchTime'])
    if fetch_time == local_date:
        logger.info('The last fetch time is still unchanged')
        return False
    return delta


async def download_files(session: ClientSession, local_date: datetime) -> bool:
    url = cfg.URL_PATH + cfg.DELTA_LOG_FILE_NAME
    logger.info(f'Getting "{url}"')
    async with session.get(url) as response:
        if response.status != 200:
            logger.error(f'Cannot read {url}: code {response.status}, answer is "{await response.text()}"')
            return False
        lines = []
        fetch_time = datetime(year=2030, month=12, day=31, tzinfo=local_date.tzinfo)
        while fetch_time > local_date and (not response.content.at_eof()):
            next_fetch_time = await find_next_fetch_time(response.content, lines)
            if next_fetch_time:
                fetch_time = next_fetch_time

    if fetch_time <= local_date:
        # finalize our json: remove the last beginning and close the array
        lines.pop()  # remove line with "fetchTime"
        lines[-1] = ']'  # "  {" -> "]"
        lines[-2] = lines[-2].replace('},', '}')  # "}," -> "}"

    deltas = json.loads(''.join(lines))
    queue = asyncio.Queue()
    for delta in deltas:
        for record in delta.get('new', []):
            await queue.put(
                (record['cveId'], record['githubLink'])
            )
        for record in delta.get('updated', []):
            await queue.put(
                (record['cveId'], record['githubLink'])
            )
    record_count = queue.qsize()
    logger.info(f'There are {record_count} records to download')
    if record_count:
        task_count = max(1, min(record_count // 5, cfg.MAX_DOWNLOAD_TASK_COUNT))
        logger.info(f'The number of tasks: {task_count}')
        tasks = []
        for _ in range(task_count):
            tasks.append(asyncio.create_task(fetch_and_save_files(queue, session)))
        await asyncio.wait([
            *tasks,
            asyncio.create_task(monitor_queue(queue, tasks))
        ])

async def monitor_queue(queue: asyncio.Queue, tasks: list[asyncio.Task]):
    total = queue.qsize()
    last_progress = 0
    done = []
    logger.info(f'Download monitor started (there are {total} files)')
    while len(done) < len(tasks):
        await asyncio.sleep(cfg.MONITOR_INTERVAL)
        done = [task for task in tasks if task.done() or task.cancelled()]
        remain = queue.qsize()
        progress = ((total - remain) * 100) // (total + 1)
        if progress > last_progress:
            logger.info(f'Progress: {progress} % ({remain} files remain')
            last_progress = progress
    logger.info('Monitor finished')

async def notify_download_complete():
    logger.info('All CVEs are downloaded')


async def check_delta() -> bool:
    last_date = get_local_last_datetime()
    async with aiohttp.ClientSession() as session:
        delta = await get_newest_delta(session, last_date)
        if delta:
            await download_files(session, last_date)
            set_local_last_datetime(delta)
    return delta


async def delta_task():
    while True:
        if await check_delta():
            await notify_download_complete()
        await asyncio.sleep(cfg.CHECK_INTERVAL)


async def main():
    await asyncio.gather(
        asyncio.create_task(delta_task()),
        asyncio.create_task(SocketServer.run())
    )


if __name__ == '__main__':
    asyncio.run(main())
