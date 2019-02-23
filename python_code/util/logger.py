import logging
import logging.handlers

def setup_logger(logger_name, log_file, level=logging.INFO):

    # Remove the content of the log
    open(log_file, 'w').close()

    # Define the logger
    main_logger = logging.getLogger(logger_name)

    #formatter = logging.Formatter('%(asctime)s :: %(levelname)s | %(message)s')
    formatter = logging.Formatter('%(levelname)s | %(message)s')
    handler = logging.handlers.RotatingFileHandler(log_file, maxBytes=200000000000, backupCount=5)
    handler.setFormatter(formatter)

    main_logger.setLevel(level)
    main_logger.addHandler(handler)
