import os
import asyncio
import logging
import multiprocessing as mp

from scanner import collect_files, FileNames
from loader_config import LoaderConfig as cfg
from parser import parse_cve_file
from importer import Importer, ParsedFiles


logging.basicConfig(level=cfg.LOG_LEVEL)


class LoaderException(Exception):
    pass


def clean_files(worker_no: int, files: ParsedFiles, logger: logging.Logger):
    logger.info(f'Worker {worker_no}: cleaning the directory {cfg.DIR}')
    for file, result in files.items():
        if result is True:
            delete_file(file)
    logger.info(f'Worker {worker_no}: cleaning completed')


def delete_file(file: str):
    os.unlink(file)


def parse_files(worker_no: int, files: FileNames, logger: logging.Logger) -> ParsedFiles:
    portion, parsed_files, total = dict(), dict(), len(files)
    logger.info(f'Worker {worker_no}: {total} files to be parsed')
    for file in files:
        content = parse_cve_file(file)
        if not content:
            logger.debug(f'Worker {worker_no}: file "{file}" was ignored')
            delete_file(file)
        else:
            portion[file] = content
            if len(portion) >= cfg.PARSE_NOTIFY_LIMIT:
                parsed_files.update(portion)
                portion = dict()
                logger.info(f'Worker {worker_no}: parsed {(len(parsed_files) * 100) // total} %')
    if portion:
        parsed_files.update(portion)
    logger.info(f'Worker {worker_no}: parsing is complete: {len(parsed_files)} files are ready')
    return parsed_files


def mp_handler(worker_no: int, files: FileNames):
    logger = logging.getLogger(f'loader.{worker_no}')
    parsed_files = parse_files(worker_no, files, logger)

    logger.info(f'Worker {worker_no}: start importing')
    loader = Importer(worker_no, logger, parsed_files)
    asyncio.run(loader.execute_many())
    logger.info(f'Worker {worker_no}: import completed')

    clean_files(worker_no, loader.parsed_files, logger)


async def scan_directory(logger: logging.Logger) -> FileNames:
    cve_path = cfg.DIR
    if not os.path.exists(cve_path):
        raise LoaderException(f'Invalid directory "{cve_path}"')
    logger.info(f'Start scanning from "{cve_path}"')
    files = await collect_files(cve_path)
    total_file_count = len(files)
    logger.info(f'Files collected: {total_file_count}')
    return files


def prepare_execution(files: FileNames, logger: logging.Logger) -> list[list[str]]:
    total_file_count = len(files)
    worker_count = 1 if total_file_count < 100 else mp.cpu_count()
    logger.debug(f'Worker count: {worker_count}')
    chunk_size = total_file_count // worker_count
    chunks = []
    for i in range(worker_count):
        chunks.append(
            files[chunk_size * i: chunk_size * (i + 1)]
        )
    chunks[-1] += files[chunk_size * worker_count:]
    return chunks


async def load():
    logger = logging.getLogger('loading.main')

    files = await scan_directory(logger)
    chunks = prepare_execution(files, logger)

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
    asyncio.run(load())