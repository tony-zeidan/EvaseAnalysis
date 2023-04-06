import logging
from pathlib import Path
from evase.util.fileutil import check_path


class AnalysisLogger(object):

    log_path = Path(Path.cwd(), 'analysis-log.log')

    def __init__(self):
        """
        A logger for the entirety of the analysis period.
        """
        AnalysisLogger.log_path = check_path(AnalysisLogger.log_path, file_ok=True, file_req=True, absolute_req=False, ret_absolute=True, notexists_ok=True)
        log_path = AnalysisLogger.log_path

        logger = logging.getLogger(__file__)
        logger.setLevel(logging.INFO)
        formatter = logging.Formatter('%(asctime)s - %(message)s')
        handler = logging.FileHandler(log_path)
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        self.logger = logger

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
