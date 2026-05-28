"""
Secret Scanner — finds plaintext secrets in files and configs.
Two modes:
  - default (mode: "exact"): detects only known API key formats (sk-..., ghp_..., etc.)
  - mode: "thorough": also catches generic patterns (TOKEN, SECRET, PASSWORD) in config files
"""

import os
import re
import logging
from pathlib import Path
from typing import Optional

log = logging.getLogger("angel.monitors.secrets")

# ── EXACT patterns — real API key signatures ──────────────────────────
EXACT_PATTERNS = [
    (r'sk-[a-zA-Z0-9]{20,}', "OpenAI/DeepSeek API Key (sk-...)"),
    (r'sk-ant-[a-z0-9]{20,}', "Anthropic API Key (sk-ant-...)"),
    (r'ghp_[a-zA-Z0-9]{36}', "GitHub Personal Access Token (ghp_)"),
    (r'gho_[a-zA-Z0-9]{36}', "GitHub OAuth Access Token (gho_)"),
    (r'ghu_[a-zA-Z0-9]{36}', "GitHub User Access Token (ghu_)"),
    (r'ghs_[a-zA-Z0-9]{36}', "GitHub App Token (ghs_)"),
    (r'github_pat_[a-zA-Z0-9]{22,}_[a-zA-Z0-9]{59,}', "GitHub PAT (github_pat_)"),
    (r'AIza[0-9A-Za-z\-_]{35}', "Google API Key (AIza...)"),
    (r'-----BEGIN\s+(RSA|EC|OPENSSH|PGP|DSA|PRIVATE)\s+KEY-----', "Private Key"),
    (r'(?:xox[parb]-)(?:[a-zA-Z0-9]){10,}', "Slack Token (xox*)"),
    (r'(?:pk|sk)_(?:test|live)_[a-zA-Z0-9]{24,}', "Stripe API Key"),
    (r'AKIA[0-9A-Z]{16}', "AWS Access Key (AKIA...)"),
    (r'[0-9]{8,}:[a-zA-Z0-9_-]{35,}', "Telegram Bot Token"),
    (r'tvly-[a-zA-Z0-9]{20,}', "Tavily API Key"),
]

# ── THOROUGH patterns — generic keywords, only in config files ───────
THOROUGH_PATTERNS = [
    "API_KEY",
    "API_SECRET",
    "PASSWORD",
    "TOKEN",
    "SECRET",
    "AUTH_TOKEN",
    "ACCESS_KEY",
    "SECRET_KEY",
]

# Config-like file extensions (for thorough mode)
CONFIG_EXTENSIONS = {".env", ".env.example", ".env.local", ".yaml", ".yml", ".json", ".toml", ".ini", ".conf", ".cfg"}
CODE_EXTENSIONS = {".sh", ".py", ".js", ".ts", ".java", ".go", ".rb", ".php", ".rs", ".swift", ".kt"}
SCAN_EXTENSIONS = CONFIG_EXTENSIONS | CODE_EXTENSIONS | {".txt", ".md", ".xml", ".properties"}

SKIP_DIRS = {"node_modules", ".git", "venv", ".venv", "env", "__pycache__", ".cache",
             "vendor", ".next", "dist", "build", ".npm", ".yarn", "target", "bin", "obj"}


def scan_secrets(config: dict, learning) -> list[dict]:
    """Scan configured paths for plaintext secrets."""
    findings = []
    paths = config.get("paths", [])
    mode = config.get("mode", "exact")
    exclude = set(config.get("exclude_patterns", [])) | SKIP_DIRS

    for path_str in paths:
        path = Path(path_str).expanduser()
        if not path.exists():
            log.warning(f"Path does not exist: {path}")
            continue

        if path.is_file():
            findings.extend(_check_file(path, mode, learning))
        elif path.is_dir():
            findings.extend(_scan_directory(path, mode, exclude, learning))

    return findings


def _scan_directory(directory: Path, mode: str, exclude: set, learning) -> list[dict]:
    """Recursively scan a directory for secrets. No symlink following."""
    findings = []
    for root, dirs, files in os.walk(directory, followlinks=False):
        # Filter out skipped dirs + dot dirs
        dirs[:] = [d for d in dirs if d not in exclude and not d.startswith(".")]

        for filename in files:
            ext = Path(filename).suffix.lower()
            if ext not in SCAN_EXTENSIONS:
                continue
            filepath = Path(root) / filename
            findings.extend(_check_file(filepath, mode, learning))

    return findings


def _check_file(filepath: Path, mode: str, learning) -> list[dict]:
    """Check a single file for secrets using exact patterns and optional thorough mode."""
    findings = []
    try:
        if filepath.stat().st_size > 1024 * 1024:  # 1MB skip
            return []
        if filepath.is_symlink():
            return []

        with open(filepath, "r", errors="ignore") as f:
            content = f.read()

        ext = filepath.suffix.lower()
        is_config = ext in CONFIG_EXTENSIONS

        for i, line in enumerate(content.split("\n"), 1):
            line_stripped = line.strip()
            if not line_stripped or line_stripped.startswith("#") or line_stripped.startswith("//"):
                continue

            # Always check exact patterns (real API keys)
            for pattern, description in EXACT_PATTERNS:
                match = re.search(pattern, line_stripped)
                if match:
                    findings.append({
                        "type": "secret_exact",
                        "key": f"exact:{filepath}:{i}:{pattern[:20]}",
                        "severity": "CRITICAL",
                        "title": f"{description} in plaintext",
                        "description": f"{filepath.name}:{i}",
                        "details": f"File: {filepath}\nLine: {i}\nType: {description}\n🔒 Value redacted",
                        "action": "Move this key to KeePass/vault immediately and rotate it.",
                    })
                    break  # One pattern per line

            # Thorough mode: check generic keywords (config files only, lower severity)
            if mode == "thorough" or mode == "deep":
                if is_config:
                    for keyword in THOROUGH_PATTERNS:
                        if keyword.upper() in line_stripped.upper():
                            value = _extract_value(line_stripped)
                            if value and len(value) > 4:
                                # Check if the value looks like a real secret (high entropy)
                                if _has_high_entropy(value):
                                    findings.append({
                                        "type": "secret_plaintext",
                                        "key": f"config:{filepath}:{i}:{keyword}",
                                        "severity": "HIGH",
                                        "title": f"'{keyword}' with credential-like value in config",
                                        "description": f"{filepath.name}:{i}",
                                        "details": f"File: {filepath}\nLine: {i}\nPattern: {keyword}\n🔒 Value redacted",
                                        "action": "Move this secret to a password manager.",
                                    })
                                    break
    except (OSError, UnicodeDecodeError) as e:
        log.debug(f"Could not read {filepath}: {e}")

    return findings


def _extract_value(line: str) -> Optional[str]:
    """Extract value from 'key=value' or 'key: value'."""
    for sep in ["=", ":", "=>"]:
        if sep in line:
            parts = line.split(sep, 1)
            if len(parts) == 2:
                val = parts[1].strip().strip('"').strip("'").strip(";")
                if not val or len(val) <= 4:
                    continue
                if val.startswith("$") or val.startswith("process.env") or val.startswith("env."):
                    continue
                if val.upper() in ["YOUR_KEY_HERE", "YOUR_SECRET_HERE", "CHANGE_ME", "PLACEHOLDER", "***", "XXXXX", "TODO"]:
                    continue
                return val
    return None


def _has_high_entropy(text: str) -> bool:
    """Check if text looks like a real secret (high entropy = random-looking)."""
    if len(text) < 8:
        return False
    has_upper = any(c.isupper() for c in text)
    has_lower = any(c.islower() for c in text)
    has_digit = any(c.isdigit() for c in text)
    has_special = any(c in "!@#$%^&*()_+-=[]{}|;:',.<>?/`~" for c in text)
    categories = sum([has_upper, has_lower, has_digit, has_special])
    return categories >= 3
