import asyncio
import os
import time
import multiprocessing as mp
from contextlib import contextmanager
from concurrent.futures import ProcessPoolExecutor
from argparse import ArgumentParser

DEFAULT_WORD = "ära"
MAX_CPU = 8
MONITORING_INTERVAL = 5
NOTIFICATION_STEP = 1_00_000

Chunk = list[int]
Chunks = list[Chunk]


@contextmanager
def timer(msg: str):
    start = time.perf_counter()
    yield
    print(f"{msg} took {time.perf_counter() - start:.2f} seconds")


def mp_execute(file_name: str, start_pos, line_count, counter, lock, worker_no):
    step = NOTIFICATION_STEP
    words = {}
    lines_done = 0
    print(f'Worker', worker_no, 'started from position', start_pos, 'for', line_count, 'lines')
    with open(file_name, "r") as file:
        file.seek(start_pos)
        for _ in range(line_count):
            line = file.readline()
            _word, _, match_count, _ = line.split("\t")
            words[_word] = words.get(_word, 0) + int(match_count)
            lines_done += 1
            if lines_done % step == 0:
                with lock:
                    counter.value += step
    remainder =  lines_done % step
    if remainder:
        with lock:
            counter.value += remainder
    print(f'Worker', worker_no, 'finished with', len(words), 'words')
    return words


def reduce_words(target: dict, source: dict):
    for key, value in source.items():
        target[key] = target.get(key, 0) + value


async def monitoring(total, counter, counter_lock):
    interval_seconds = MONITORING_INTERVAL
    value = 0
    while value < total:
        with counter_lock:
            value = counter.value
        print(f"Progress: {value} ( {value * 100 // total}% )")
        await asyncio.sleep(interval_seconds)


def collect_chunks() -> tuple[int, Chunks]:
    chunk_count = min(MAX_CPU, mp.cpu_count())
    file_size = os.path.getsize(input_file_name)
    chunk_size = file_size // chunk_count
    chunks = []
    prev_position = 0
    total_line_count = 0
    with open(input_file_name, "rb") as file:
        for _ in range(chunk_count):
            chunk_lines = file.readlines(chunk_size)
            line_count = len(chunk_lines)
            total_line_count += line_count
            if line_count == 0:
                break
            curr_position = file.tell()
            chunks.append([prev_position, line_count])
            prev_position = curr_position
    return total_line_count, chunks


async def main():
    loop = asyncio.get_event_loop()

    words = {}

    print('Preparing...')
    with timer("Preparation"):
        total, chunks = collect_chunks()
    print('Prepared. Total lines:', total, ', workers:', len(chunks))
   

    with mp.Manager() as manager:
        counter = manager.Value("i", 0)
        counter_lock = manager.Lock()


        monitoring_task = asyncio.shield(
            asyncio.create_task(monitoring(total, counter, counter_lock))
        )

        with ProcessPoolExecutor() as executor:
            with timer("Processing data"):
                results = []
                for worker_no, chunk in enumerate(chunks, 1):
                    position, line_count = chunk
                    results.append(
                        loop.run_in_executor(
                            executor,
                            mp_execute,
                            input_file_name,
                            position,
                            line_count,
                            counter,
                            counter_lock,
                            worker_no
                        )
                    )

                done, _ = await asyncio.wait(results)

        monitoring_task.cancel()

    with timer("Reducing results"):
        for result in done:
            reduce_words(words, result.result())

    with timer("Printing results"):
        print("Total words: ", len(words))
        print(f"Total count for word '{word}':", words.get(word, 0))


if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument('file_name', help='Name of the input file')
    parser.add_argument('--word', help='The word whose number of occurrences we will count',
                        default=DEFAULT_WORD, required=False)
    args = parser.parse_args()
    input_file_name = args.file_name
    word = args.word
    if not os.path.exists(input_file_name):
        raise Exception('Invalid input file name')
    print('Input file:', input_file_name)
    print(f'The word: "{word}"')
    with timer("Total time"):
      asyncio.run(main())
