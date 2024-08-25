import asyncio
import os
from aiofiles import os as aos



async def scan_dirs(root_path: str, files: list[str], lock: asyncio.Lock):

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

    await scan_directory(root_path)


async def collect_files(path: str, files: list[str]):
    files_lock = asyncio.Lock()
    await scan_dirs(path, files, files_lock)


