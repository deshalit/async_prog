import os
from core import Core, Chunks, LineProcessor


class OffsetCountProcessor(LineProcessor):
    def run(self):
        offset, line_count = self.params
        print(f'Worker', self.worker_no, 'started from offset', offset, 'for', line_count, 'lines')
        lines_done = 0
        with open(self.file_name, "r") as file:
            file.seek(offset)
            for _ in range(line_count):
                line = file.readline()
                self.analyze_line(line)
                lines_done += 1
                self.notify_lines_done(lines_done)
        self.notify_lines_remainder(lines_done)


class OffsetCountMethod(Core):
    def __init__(self, file_name: str, word: str):
        super().__init__(file_name, word, OffsetCountProcessor)

    def prepare(self) -> tuple[int, Chunks]:
        chunk_count = self.get_worker_count()
        file_size = os.path.getsize(self.input_file_name)
        chunk_size = file_size // chunk_count
        chunks = []
        prev_position = 0
        total_line_count = 0
        with open(self.input_file_name, "rb") as file:
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
