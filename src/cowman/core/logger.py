"""Logging subsystem for COWMAN using Rich."""

import logging
import sys
from typing import Optional
from rich.logging import RichHandler

_LOGGER_INITIALIZED = False


def setup_logger(level_name: str = "INFO", log_file: Optional[str] = None) -> logging.Logger:
    """Configure and return the root COWMAN logger with Rich formatting."""
    global _LOGGER_INITIALIZED

    level = getattr(logging, level_name.upper(), logging.INFO)
    logger = logging.getLogger("cowman")

    if not _LOGGER_INITIALIZED:
        logger.setLevel(level)
        logger.handlers.clear()

        # Rich console handler for pretty terminal output
        console_handler = RichHandler(
            rich_tracebacks=True,
            show_time=True,
            show_level=True,
            show_path=False,
            tracebacks_suppress=[sys],
            markup=True,
        )
        console_handler.setLevel(level)
        logger.addHandler(console_handler)

        if log_file:
            try:
                file_handler = logging.FileHandler(log_file, encoding="utf-8")
                file_handler.setLevel(level)
                file_format = logging.Formatter(
                    "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
                    datefmt="%Y-%m-%d %H:%M:%S",
                )
                file_handler.setFormatter(file_format)
                logger.addHandler(file_handler)
            except Exception:
                pass  # Fall back to console only if file cannot be opened

        logger.propagate = False
        _LOGGER_INITIALIZED = True
    else:
        logger.setLevel(level)
        for h in logger.handlers:
            h.setLevel(level)

    return logger


def get_logger(name: Optional[str] = None) -> logging.Logger:
    """Retrieve a child logger under the cowman hierarchy."""
    if name:
        return logging.getLogger(f"cowman.{name}")
    return logging.getLogger("cowman")
