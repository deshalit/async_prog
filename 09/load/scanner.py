import asyncio
import os
from aiofiles import os as aos

FileNames = list[str]


async def scan_dirs(path: str, lock: asyncio.Lock) -> FileNames:

    async def accept_file(file_item: os.DirEntry):
        name, extension = os.path.splitext(file_item.name)
        if name.startswith('CVE-') and extension == '.json':
            async with lock:
                files.append(file_item.path)

    async def scan_directory(parent_path: str):
        iterator = await aos.scandir(parent_path)
        for item in iterator:
            if item.is_file():
                await accept_file(item)
            elif item.is_dir():
                await scan_directory(item.path)

    files = []
    await scan_directory(path)
    return files


async def collect_files(path: str) -> FileNames:
    files_lock = asyncio.Lock()
    return await scan_dirs(path, files_lock)
