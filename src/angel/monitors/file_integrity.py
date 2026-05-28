"""
File Integrity Monitor — detects changes to critical system files.
"""

import os
import hashlib
import logging
from pathlib import Path
from typing import Optional

log = logging.getLogger("angel.monitors.file_integrity")


def check_integrity(config: dict, state, learning) -> list[dict]:
    """Check watched files for changes by comparing SHA-256 hashes."""
    findings = []
    paths = config.get("watch_paths", [])

    current_hashes = {}
    for path_str in paths:
        path = Path(path_str).expanduser()
        if path.exists():
            try:
                current_hashes[path_str] = compute_hash(str(path))
            except Exception as e:
                log.warning(f"Could not hash {path}: {e}")

    saved = state.watch_hashes or {}

    # Check for changes
    for path_str, current_hash in current_hashes.items():
        if path_str in saved:
            if saved[path_str] != current_hash:
                findings.append({
                    "type": "file_changed",
                    "key": f"changed:{path_str}",
                    "severity": "HIGH",
                    "title": f"File changed: {Path(path_str).name}",
                    "description": path_str,
                    "details": f"File: {path_str}\nOld hash: {saved[path_str][:16]}...\nNew hash: {current_hash[:16]}...",
                    "action": "Verify this change was intentional. If not, investigate immediately.",
                })
        else:
            # New file being tracked
            findings.append({
                "type": "file_new_tracked",
                "key": f"new_tracked:{path_str}",
                "severity": "LOW",
                "title": f"Now tracking: {Path(path_str).name}",
                "description": path_str,
                "details": f"File: {path_str}\nHash: {current_hash[:16]}...",
                "action": "This file will be monitored for changes from now on.",
            })

    # Check for files that disappeared
    for path_str in saved:
        if path_str not in current_hashes:
            findings.append({
                "type": "file_missing",
                "key": f"missing:{path_str}",
                "severity": "HIGH",
                "title": f"Tracked file missing: {Path(path_str).name}",
                "description": path_str,
                "details": f"File: {path_str}\nLast known hash: {saved.get(path_str, '?')[:16]}...",
                "action": "Verify this file was intentionally deleted or moved.",
            })

    # Save current state
    state.watch_hashes = current_hashes

    return findings


def compute_hash(filepath: str) -> str:
    """Compute SHA-256 hash of a file."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()
