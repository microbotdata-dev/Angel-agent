"""
Secret Scanner — finds plaintext secrets in files and configs.
No API needed. Pure pattern matching.
"""

import os
import re
import logging
from pathlib import Path
from typing import Optional

log = logging.getLogger("angel.monitors.secrets")

# Common secret patterns (expandable in config)
DEFAULT_PATTERNS = [
    "API_KEY",
    "API_SECRET",
    "PASSWORD",
    "TOKEN",
    "SECRET",
    "PRIVATE_KEY",
    "AUTH_TOKEN",
    "ACCESS_KEY",
    "SECRET_KEY",
    "BEARER",
]

# File types to scan
SCAN_EXTENSIONS = {".env", ".sh", ".py", ".js", ".ts", ".json", ".yaml", ".yml", ".toml", ".conf", ".cfg", ".ini", ".txt"}
SKIP_DIRS = {"node_modules", ".git", "venv", ".venv", "env", "__pycache__", ".cache", "vendor", ".next", "dist", "build"}


def scan_secrets(config: dict, learning) -> list[dict]:
    """Scan configured paths for plaintext secrets."""
    findings = []
    paths = config.get("paths", [])
    patterns = config.get("patterns", DEFAULT_PATTERNS)
    exclude = set(config.get("exclude_patterns", [])) | SKIP_DIRS

    for path_str in paths:
        path = Path(path_str).expanduser()
        if not path.exists():
            log.warning(f"Path does not exist: {path}")
            continue

        if path.is_file():
            findings.extend(_check_file(path, patterns, learning))
        elif path.is_dir():
            findings.extend(_scan_directory(path, patterns, exclude, learning))

    return findings


def _scan_directory(directory: Path, patterns: list[str], exclude: set, learning) -> list[dict]:
    """Recursively scan a directory for secrets."""
    findings = []
    for root, dirs, files in os.walk(directory):
        # Skip excluded directories
        dirs[:] = [d for d in dirs if d not in exclude and not d.startswith(".")]

        for filename in files:
            ext = Path(filename).suffix.lower()
            if ext not in SCAN_EXTENSIONS:
                continue
            filepath = Path(root) / filename
            findings.extend(_check_file(filepath, patterns, learning))

    return findings


def _check_file(filepath: Path, patterns: list[str], learning) -> list[dict]:
    """Check a single file for secrets."""
    findings = []
    try:
        # Skip large files
        if filepath.stat().st_size > 1024 * 1024:  # 1MB
            return []

        with open(filepath, "r", errors="ignore") as f:
            content = f.read()

        for i, line in enumerate(content.split("\n"), 1):
            line_stripped = line.strip()
            if not line_stripped or line_stripped.startswith("#") or line_stripped.startswith("//"):
                continue

            for pattern in patterns:
                if pattern.upper() in line_stripped.upper():
                    # Try to extract the value
                    value = _extract_value(line_stripped)
                    if value and len(value) > 4:
                        findings.append({
                            "type": "secret_plaintext",
                            "key": f"{filepath}:{i}:{pattern}",
                            "severity": "HIGH",
                            "title": f"Secret pattern '{pattern}' in plaintext",
                            "description": f"{filepath.name}:{i}",
                            "details": f"File: {filepath}\nLine: {i}\nPattern: {pattern}\nValue: {value[:50]}{'...' if len(value) > 50 else ''}",
                            "action": "Move this secret to a password manager (KeePass/Bitwarden) and remove from file.",
                        })
                        break  # One alert per line
    except (OSError, UnicodeDecodeError) as e:
        log.debug(f"Could not read {filepath}: {e}")

    return findings


def _extract_value(line: str) -> Optional[str]:
    """Extract the value part from a key=value or "key": "value" line."""
    # key=value or key: value
    for sep in ["=", ":", "=>"]:
        if sep in line:
            parts = line.split(sep, 1)
            if len(parts) == 2:
                val = parts[1].strip().strip('"').strip("'").strip(";")
                if val and val != "YOUR_KEY_HERE" and not val.startswith("$"):
                    return val
    return None
