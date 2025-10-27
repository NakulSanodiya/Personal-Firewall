import json
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Dict

from .utils import ensure_dir

def setup_logger(log_dir: str, level: str = "INFO") -> logging.Logger:
    ensure_dir(log_dir)
    log_path = Path(log_dir) / "firewall.log"
    logger = logging.getLogger("pfw")
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    logger.propagate = False

    if not logger.handlers:
        fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
        fh = RotatingFileHandler(log_path, maxBytes=5 * 1024 * 1024, backupCount=3)
        fh.setFormatter(fmt)
        fh.setLevel(logging.DEBUG)
        ch = logging.StreamHandler()
        ch.setFormatter(fmt)
        ch.setLevel(logging.INFO)
        logger.addHandler(fh)
        logger.addHandler(ch)

    return logger

def json_log(logger: logging.Logger, event: str, data: Dict[str, Any], level: str = "info") -> None:
    record = {"event": event, **data}
    msg = json.dumps(record, separators=(",", ":"), sort_keys=True)
    getattr(logger, level.lower(), logger.info)(msg)
