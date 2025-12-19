import logging
import os
import sys
from logging.handlers import RotatingFileHandler


def setup_logger(name: str, log_dir: str = "logs", level: int = logging.INFO) -> logging.Logger:
    os.makedirs(log_dir, exist_ok=True)
    logger = logging.getLogger(name)
    logger.setLevel(level)
    if not logger.handlers:
        # Console handler with UTF-8 encoding
        ch = logging.StreamHandler(sys.stdout)
        ch.setLevel(level)
        # Force UTF-8 encoding for console output
        if hasattr(sys.stdout, 'reconfigure'):
            try:
                sys.stdout.reconfigure(encoding='utf-8')
            except:
                pass
        ch.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s"))
        logger.addHandler(ch)

        # File handler with UTF-8 encoding
        fh = RotatingFileHandler(
            os.path.join(log_dir, f"{name}.log"), 
            maxBytes=1_000_000, 
            backupCount=3,
            encoding='utf-8'
        )
        fh.setLevel(level)
        fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s"))
        logger.addHandler(fh)
    return logger
