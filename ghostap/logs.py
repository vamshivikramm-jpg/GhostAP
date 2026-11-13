"""Log files (F074): rotating file log plus the existing console output."""
from __future__ import annotations

import logging
import logging.handlers
import os
from typing import Optional

LOGGER_NAME = "ghostap"


def setup_logging(cfg: Optional[dict] = None) -> logging.Logger:
    """Log to data/logs/ghostap.log (1 MB x 5 files) at the configured level.

    Safe to call more than once. If the file cannot be opened (read-only disk,
    permissions), logging continues to stderr only.
    """
    log = logging.getLogger(LOGGER_NAME)
    conf = (cfg or {}).get("logging", {})
    log.setLevel(getattr(logging, str(conf.get("level", "INFO")).upper(), logging.INFO))
    path = conf.get("file")
    if path and not any(isinstance(h, logging.handlers.RotatingFileHandler) for h in log.handlers):
        try:
            os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
            fh = logging.handlers.RotatingFileHandler(path, maxBytes=1_000_000, backupCount=5)
            fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
            log.addHandler(fh)
        except OSError as e:
            logging.getLogger(LOGGER_NAME).warning("cannot write log file %s: %s", path, e)
    if not any(type(h) is logging.StreamHandler for h in log.handlers):
        sh = logging.StreamHandler()
        sh.setLevel(logging.WARNING)            # the console keeps showing only problems
        sh.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
        log.addHandler(sh)
    return log


def get_logger(name: str = "") -> logging.Logger:
    return logging.getLogger(LOGGER_NAME + ("." + name if name else ""))
