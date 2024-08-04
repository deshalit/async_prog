import os
import random
import aiohttp
import asyncio
import argparse

DEFAULT_OUTPUT_DIR = '.'
DEFAULT_TIMEOUT = 1

input_file_name = ''
output_dir = DEFAULT_OUTPUT_DIR
timeout = DEFAULT_TIMEOUT

loaded = dict()


class EInputFileNotFound(Exception):
    pass


class ENoInputSites(Exception):
    pass


def resolve_args():
    global input_file_name, output_dir, timeout
    parser = argparse.ArgumentParser()
    parser.add_argument('file_name', help='Name of the input file')
    parser.add_argument('--output_dir', help='Name of the output directory (current by default)',
                        default=DEFAULT_OUTPUT_DIR)
    parser.add_argument('--timeout', help='timeout in seconds (float)', default=DEFAULT_TIMEOUT, type=float)
    args = parser.parse_args()
    input_file_name = args.file_name
    output_dir = args.output_dir
    timeout = args.timeout


def get_site_list() -> list[str]:
    if not os.path.exists(input_file_name):
        raise EInputFileNotFound(f'File "{input_file_name}" does not exist')
    with open(input_file_name, 'r') as f:
        result = f.readlines()

    # rid off special chars at the end of each line, then
    # trim each line (cut off leading and trailing spaces)
    result = [line.rstrip('\r\n').strip() for line in result]
    result = [line for line in result if line]  # filter out empty lines
    if len(result) == 0:
        raise ENoInputSites(f'File "{input_file_name}" does not contain any site link')
    return result


def get_output_name(url: str) -> str:
    """Return file name by url"""
    output_name = (url
                   .removeprefix('http://')
                   .removeprefix('https://')
                   .replace('/', '_')
                   .replace(':', '_')
                   .replace('#', '_')
                   .replace('?', '_')
                   .replace('&', '_')
                   )
    return os.path.join(output_dir, output_name + '.txt')


async def load_url(session: aiohttp.ClientSession, url: str):
    async with session.get(url) as response:
        text = await response.text()
        file_name = get_output_name(url)
        with open(file_name, 'w', encoding='utf-8') as f:
            f.write(text)
        loaded[url] = file_name


def create_task(session: aiohttp.ClientSession, url: str) -> asyncio.Task:
    return asyncio.create_task(load_url(session, url), name=url)


def create_tasks(session: aiohttp.ClientSession, urls: list[str]) -> list[asyncio.Task]:
    return [create_task(session, url) for url in urls]


def print_report(urls: list[str]):
    for url in urls:
        if url in loaded:
            print(f'Generated file "{loaded[url]}"')
        else:
            print("The site was timed out:", url)


async def method_wait(urls: list[str]):
    async with aiohttp.ClientSession() as session:
        done, pending = await asyncio.wait(
            create_tasks(session, urls),
            return_when=asyncio.ALL_COMPLETED,
            timeout=timeout
        )
    if pending:
        print("Warning! The following sites are timed out:", ', '.join([t.get_name() for t in list(pending)]))
    file_list = [f'"{item}"' for item in loaded.values()]
    if file_list:
        print('Files were generated:', ', '.join(file_list))


async def method_as_completed(urls: list[str]):
    async with aiohttp.ClientSession() as session:
        try:
            tasks = create_tasks(session, urls)
            for result in asyncio.as_completed(tasks, timeout=timeout):
                await result
        except asyncio.TimeoutError:
            print("Warning: some sites were timed out")
    print_report(urls)


async def method_gather(urls: list[str]):
    async with aiohttp.ClientSession() as session:
        try:
            async with asyncio.timeout(timeout):
                tasks = create_tasks(session, urls)
                await asyncio.gather(*tasks)
        except asyncio.TimeoutError:
            print("Warning: some sites were timed out")
    print_report(urls)


async def method_group(urls: list[str]):
    session_timeout = aiohttp.ClientTimeout(total=timeout)
    async with aiohttp.ClientSession(timeout=session_timeout) as session:
        async with asyncio.TaskGroup() as group:
            try:
                for url in urls:
                    group.create_task(load_url(session, url), name=url)
            except ExceptionGroup as eg:
                if eg.subgroup(asyncio.TimeoutError):
                    print("Warning: some sites were timed out")
    print_report(urls)


if __name__ == '__main__':
    resolve_args()
    print("Input file: ", input_file_name)
    print("Output directory: ", output_dir)
    print('Timeout:', timeout)
    methods = [method_as_completed, method_wait, method_group, method_gather]
    method = random.choice(methods)
    print('Using', method.__name__)
    asyncio.run(method(get_site_list()))
