# logger.py
import logging
import os


# This module sets up a logger for the application.
def setup_logging(config, worker_name="proc"):
    try:
        prefix = f"{worker_name}.{os.getpid()}"
    except:
        # If os.getpid() fails, we are likely in a non-standard environment.
        # Create a random number for the worker name.
        import random
        prefix = f"{worker_name}.x{random.randint(1, 10000)}"

    # Handle both cases: config dict passed directly or full config with 'logging' key
    logging_config = config.get('logging', config) if isinstance(config, dict) else config

    log_file = logging_config.get('file', 'logs/app.log')
    log_level = logging_config.get('level', 'INFO')

    # Create the directory if it doesn't exist
    log_dir = os.path.dirname(log_file)
    if log_dir and not os.path.exists(log_dir):
        os.makedirs(log_dir, exist_ok=True)

    log_format = f"[{prefix}] %(asctime)s - %(levelname)s - %(message)s"
    logging.basicConfig(
        filename=log_file,
        level=getattr(logging, log_level),
        datefmt="%Y-%m-%d %H:%M:%S",
        format=log_format,
    )
