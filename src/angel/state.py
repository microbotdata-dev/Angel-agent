"""Angel State Management — persists state between runs."""

import json
import logging
from pathlib import Path
from typing import Any
from datetime import datetime, timezone

log = logging.getLogger("angel.state")


class AngelState:
    """Lightweight state persistence. JSON-based, no DB needed."""

    def __init__(self, path: Path):
        self.path = path
        self.data = self._load()

    def _load(self) -> dict:
        if self.path.exists():
            try:
                with open(self.path) as f:
                    return json.load(f)
            except (json.JSONDecodeError, OSError) as e:
                log.warning(f"Could not load state: {e}")
        return {
            "angel_version": "0.1.0",
            "first_run": datetime.now(timezone.utc).isoformat(),
            "last_check": None,
            "total_checks": 0,
            "total_findings": 0,
            "findings_history": [],
            "watch_hashes": {},
            "known_ports": [],
            "known_processes": [],
        }

    @property
    def watch_hashes(self) -> dict:
        return self.data.get("watch_hashes", {})

    @watch_hashes.setter
    def watch_hashes(self, value: dict):
        self.data["watch_hashes"] = value

    @property
    def last_check(self) -> Any:
        return self.data.get("last_check")

    @last_check.setter
    def last_check(self, value: str):
        self.data["last_check"] = value

    @property
    def findings_history(self) -> list:
        return self.data.get("findings_history", [])

    @findings_history.setter
    def findings_history(self, value: list):
        self.data["findings_history"] = value

    def save(self):
        self.data["total_checks"] += 1
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "w") as f:
            json.dump(self.data, f, indent=2, default=str)
