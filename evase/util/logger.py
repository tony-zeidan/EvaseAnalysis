import logging
import os
from pathlib import Path


class AnalysisLogger(object):

    log_path = Path(Path.cwd(), 'analysis-log.log')

    def __init__(self, log_path: str):
        """
        A logger for the entirety of the analysis period.

        :param log_path: The path to the log directory
        """
        if os.path.isdir(log_path):
            log_path = AnalysisLogger.log_path

            logging.basicConfig(filename=f'{log_path}',
                                filemode='w',
                                format='%(asctime)s - %(module)s - %(levelname)s - %(message)s',
                                datefmt='%H:%M:%S',
                                level=logging.DEBUG)

            self.logger = logging.getLogger(__file__)
        else:
            raise NotADirectoryError("The path you gave was not a directory.")

    def make_log(self, msg: str, level):
        """
        Make a log.

        :param msg: The log message
        :param level: The level of logging
        """

        self.logger.log(level, msg)

    def info(self, msg: str):
        """
        Make an info log.

        :param msg: The log message
        """
        self.logger.info(msg)

    # Singleton class
    def __new__(cls, *args, **kw):
        if not hasattr(cls, '_instance'):
            orig = super(AnalysisLogger, cls)
            cls._instance = orig.__new__(cls, *args, **kw)
        return cls._instance
