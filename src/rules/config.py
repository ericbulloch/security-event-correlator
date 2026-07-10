import logging
from pathlib import Path
from typing import Any, Dict

import yaml

logger = logging.getLogger(__name__)

_PROJECT_ROOT = Path(__file__).parent.parent.parent
_CONFIG_PATH = _PROJECT_ROOT / "config" / "rules.yml"


def load_rules_config() -> Dict[str, Any]:
    """
    Load config/rules.yml and return the 'rules' dict.

    If the file does not exist, logs a warning and returns an empty dict so
    every rule falls back to its own built-in defaults — the system works
    out of the box without any config file.

    If the file exists but is malformed (bad YAML or missing 'rules' key),
    raises an exception so the misconfiguration is caught at startup rather
    than silently ignored.

    To customize: cp config/rules.yml.example config/rules.yml
    """
    if not _CONFIG_PATH.exists():
        logger.warning(
            "config/rules.yml not found — all rules will use built-in defaults. "
            "Copy config/rules.yml.example to config/rules.yml to customize."
        )
        return {}

    try:
        with _CONFIG_PATH.open() as fh:
            data = yaml.safe_load(fh) or {}
    except yaml.YAMLError as exc:
        raise ValueError(f"Failed to parse config/rules.yml: {exc}") from exc

    if not isinstance(data.get("rules"), dict):
        raise ValueError(
            "config/rules.yml must have a top-level 'rules' mapping. "
            "See config/rules.yml.example for the expected structure."
        )

    logger.info("Loaded rules config from %s", _CONFIG_PATH)
    return data["rules"]
