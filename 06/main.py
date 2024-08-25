import os
import asyncio
import multiprocessing as mp
from argparse import ArgumentParser

from scanner import collect_files
from common import timer, CveException
from config import PARSE_NOTIFY_LIMIT
from parser import parse_file
from importer import make_import


def mp_handler(worker_no: int, files: list[str]):
    parsed_batch, all_parsed, total  = [], [], len(files)
    print('Worker', worker_no, ':', total, 'files to be parsed')
    for file in files:
        content = parse_file(file)
        if content:
            parsed_batch.append(content)
            if len(parsed_batch) >= PARSE_NOTIFY_LIMIT:
                all_parsed.extend(parsed_batch)
                parsed_batch = []
                print('Worker', worker_no, ': parsed', len(all_parsed) * 100 // total, '%')
    if parsed_batch:
        all_parsed.extend(parsed_batch)
    print('Worker', worker_no, ': start importing')
    asyncio.run(make_import(worker_no, all_parsed))
    print('Worker', worker_no, ': import completed')


async def main(cve_path: str):
    files = []
    print('Start scanning')
    with timer('scanning directory tree'):
        await collect_files(cve_path, files)
    total_file_count = len(files)
    print('Files collected:', total_file_count)

    worker_count = mp.cpu_count()
    chunk_size = total_file_count // worker_count
    chunks = []
    for i in range(worker_count):
        chunks.append(
            files[chunk_size * i: chunk_size * (i + 1)]
        )
    chunks[-1] += files[chunk_size * worker_count:]

    with timer("Handling files collected"):
        processes = []
        for worker_no, chunk in enumerate(chunks, 1):
            processes.append(
                mp.Process(
                    target=mp_handler,
                    args=(worker_no, chunk),
                    daemon=True
                )
            )
        try:
            for process in processes:
                process.start()
            while True:
                alive_processes = [process for process in processes if process.is_alive()]
                if not alive_processes:
                    break
        except KeyboardInterrupt:
            for process in processes:
                process.terminate()
                process.join()


if __name__ == '__main__':
    parser = ArgumentParser()
    parser.add_argument('path', help='Path to the CVE directory')
    args = parser.parse_args()
    path = args.path
    if not os.path.exists(path):
        raise CveException('Invalid directory name')
    print('CVE files directory:', path)
    asyncio.run(main(path))
