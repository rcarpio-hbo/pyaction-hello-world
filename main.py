import os
import sys
from typing import List

from actions import io


def main(args: List[str]) -> None:
    """main function

    Args:
        args: STDIN arguments
    """

    # reading the name variable from `with`
    name = os.environ["INPUT_NAME"]
    message = f"Hello {name}!"

    # writing to the buffer
    io.write_to_output({"phrase": message})

    # now, people can echo `phrase`
    # print(message)


if __name__ == "__main__":
    main(sys.argv)

