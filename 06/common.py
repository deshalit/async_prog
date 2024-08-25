import time
from contextlib import contextmanager

@contextmanager
def timer(msg: str):
    start = time.perf_counter()
    yield
    print(f"{msg} took {time.perf_counter() - start:.2f} seconds")


class CveException(Exception):
    """To shut up the linter """
    pass
