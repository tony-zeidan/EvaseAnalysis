import logging
import os


class AnalysisLogger(object):

    def __init__(self, log_path: str):
        """
        A logger for the entirety of the analysis period.

        :param log_path: The path to the log directory
        """
        if os.path.isdir(log_path):
            self.__log_path = os.path.join(log_path, 'analysis-log.log')

            logging.basicConfig(filename=f'{log_path}',
                                filemode='w',
                                format='%(asctime)s - %(module)s - %(levelname)s - %(message)s',
                                datefmt='%H:%M:%S',
                                level=logging.DEBUG)

            self.logger = logging.getLogger(".sim")
        else:
            raise NotADirectoryError("The path you gave was not a directory.")

    def make_log(self, msg: str, level):
        """
        Make a log.

        :param msg: The log message
        :param level: The level of logging
        """

        self.logger.log(level, msg)

    # Singleton class
    def __new__(cls, *args, **kw):
        if not hasattr(cls, '_instance'):
            orig = super(AnalysisLogger, cls)
            cls._instance = orig.__new__(cls, *args, **kw)
        return cls._instance
