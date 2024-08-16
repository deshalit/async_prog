from core import Core, Chunks, LineProcessor

lines = []


class LineIndexesProcessor(LineProcessor):
    def run(self):
        index_start, index_end = self.params
        print(f'Worker', self.worker_no, 'started from line', index_start, 'to line', index_end)
        for i in range(index_start, index_end + 1):
            line = lines[i]
            self.analyze_line(line)
            lines_done = i - index_start + 1
            self.notify_lines_done(lines_done)
        self.notify_lines_remainder(index_end - index_start + 1)


class LineIndexesMethod(Core):

    def __init__(self, file_name: str, word: str):
        super().__init__(file_name, word, LineIndexesProcessor)

    def prepare(self) -> tuple[int, Chunks]:
        global lines
        chunk_count = self.get_worker_count()
        chunks = []
        with open(self.input_file_name, "r") as file:
            lines = file.readlines()
        total_line_count = len(lines)
        chunk_size = total_line_count // chunk_count
        remainder = total_line_count % chunk_count
        for i in range(chunk_count):
            chunks.append([chunk_size * i, chunk_size * (i + 1)])
        chunks[-1][1] += remainder - 1
        return total_line_count, chunks