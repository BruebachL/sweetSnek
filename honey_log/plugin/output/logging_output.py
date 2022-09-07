import logging


def setup_filebeat_logger(log_name):
    log = logging.Logger(log_name)
    log_handler = logging.FileHandler(log_name)
    log_formatter = logging.Formatter(fmt="%(message)-160s",
                                         datefmt='%Y-%m-%d %H:%M:%S')
    log_handler.setFormatter(log_formatter)
    log.addHandler(log_handler)
    return log


filebeat_logger = setup_filebeat_logger("filebeat.log")


def handle(event, config):
    event = event.replace('\n', '').replace('\"', '"')
    filebeat_logger.debug(event)
