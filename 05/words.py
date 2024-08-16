from argparse import ArgumentParser
import os
from core import DEFAULT_WORD
from line_indexes_method import LineIndexesMethod
from offset_count_method import OffsetCountMethod

if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument('file_name', help='Name of the input file')
    parser.add_argument('--word', help='The word whose number of occurrences we will count',
                        default=DEFAULT_WORD, required=False)
    args = parser.parse_args()
    file_name = args.file_name
    if not os.path.exists(file_name):
        raise Exception('Invalid input file name')
    print('Input file:', file_name)
    word = args.word
    print(f'The word: "{word}"')

    method = OffsetCountMethod(file_name, word)
    # method = LineIndexesMethod(file_name, word)
    method.execute()
