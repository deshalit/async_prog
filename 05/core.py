import time
from contextlib import contextmanager
import asyncio
from concurrent.futures import ProcessPoolExecutor
import multiprocessing as mp


DEFAULT_WORD = "ära"
MAX_CPU = 8
MONITORING_INTERVAL = 5
NOTIFICATION_STEP = 1_50_000

Chunk = list[int]
Chunks = list[Chunk]


@contextmanager
def timer(msg: str):
    start = time.perf_counter()
    yield
    print(f"{msg} took {time.perf_counter() - start:.2f} seconds")


class LineProcessor:

    def __init__(self, counter, lock: mp.Lock, worker_no: int, file_name: str, *params, step=NOTIFICATION_STEP):
        self.counter = counter
        self.lock = lock
        self.step = step
        self.params = params
        self.words = dict()
        self.worker_no = worker_no
        self.file_name = file_name

    def analyze_line(self, line: str):
        _word, _, match_count, _ = line.split("\t")
        self.words[_word] = self.words.get(_word, 0) + int(match_count)

    def notify_lines_done(self, lines_done: int):
        if lines_done % self.step == 0:
            with self.lock:
                self.counter.value += self.step

    def notify_lines_remainder(self, value: int):
        remainder = value % self.step
        if remainder > 0:
            with self.lock:
                self.counter.value += remainder

    def run(self):
        pass


class Core:

    def __init__(self, file_name: str, word: str, processor_class):
        self.input_file_name = file_name
        self.word = word
        self.line_processing_class = processor_class

    @staticmethod
    def get_worker_count() -> int:
        return min(MAX_CPU, mp.cpu_count())

    @staticmethod
    def reduce_words(target: dict, source: dict):
        for key, value in source.items():
            target[key] = target.get(key, 0) + value

    @staticmethod
    async def monitoring(total: int, counter, counter_lock):
        interval_seconds = MONITORING_INTERVAL
        value = 0
        while value < total:
            with counter_lock:
                value = counter.value
            print(f"Progress: {value} ( {value * 100 // total}% )")
            await asyncio.sleep(interval_seconds)

    def prepare(self) -> tuple[int, Chunks]:
        return 0, []

    def mp_execute(self, counter, lock, worker_no, *params) -> dict[str, int]:
        line_processor = self.line_processing_class(counter, lock, worker_no, self.input_file_name, *params)
        line_processor.run()
        print(f'Worker', worker_no, 'finished with', len(line_processor.words), 'words')
        return line_processor.words

    async def main(self):
        loop = asyncio.get_event_loop()

        words = dict()

        print('Preparing...')
        with timer("Preparation"):
            total, chunks = self.prepare()
        print('Prepared. Total lines:', total, ', workers:', len(chunks))

        with mp.Manager() as manager:
            counter = manager.Value("i", 0)
            counter_lock = manager.Lock()

            monitoring_task = asyncio.shield(
                asyncio.create_task(self.monitoring(total, counter, counter_lock))
            )

            with ProcessPoolExecutor() as executor:
                with timer("Processing data"):
                    results = []
                    for worker_no, chunk in enumerate(chunks, 1):
                        results.append(
                            loop.run_in_executor(
                                executor,
                                self.mp_execute,
                                counter,
                                counter_lock,
                                worker_no,
                                *chunk
                            )
                        )

                    done, pending = await asyncio.wait(results)

            monitoring_task.cancel()

        with timer("Reducing results"):
            for result in done:
                self.reduce_words(words, result.result())
            for task in pending:
                if task.done():
                    self.reduce_words(words, task.result())
                else:
                    print('some task is still pending')

        with timer("Printing results"):
            print("Total words: ", len(words))
            print(f"Total count for word '{self.word}':", words.get(self.word, 0))

    def execute(self):
        with timer("Total time"):
            asyncio.run(self.main())
