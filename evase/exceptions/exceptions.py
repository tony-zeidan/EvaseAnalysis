from pathlib import Path
from typing import Union





class EvasePathException(Exception):

    def __init__(self, path: Union[str, Path], message: str = None):
        """
        Custom exception to display cases where Evase fails due to processing files incorrectly
        or where paths are passed incorrectly.

        :param path: The path given that caused the error
        :param message: The message
        """

        if message is None:
            message = "There was an error with the path given."
        message = f'{message} Passed: {str(path)}'

        super().__init__(message)
