"""
Deep Scanner — searches shell history, logs, and databases for secret exposure.
"""

import os
import re
import logging
import subprocess
from pathlib import Path
from typing import Optional

log = logging.getLogger("angel.monitors.deep")

# Patterns that indicate secrets in shell commands
SHELL_SECRET_PATTERNS = [
    (r'export\s+\w*(?:API_KEY|SECRET|TOKEN|PASSWORD|KEY)\s*=', "API Key in export"),
    (r'curl\s+.*-H\s*["\']Authorization:\s*Bearer\s+\S+', "Bearer token in curl"),
    (r'curl\s+.*-H\s*["\']X-API-Key:\s*\S+', "API Key in curl header"),
    (r'curl\s+.*-u\s*["\']?\w+:\w+', "Credentials in curl -u"),
    (r'pass[word]?\s*[:=]\s*\S{8,}', "Password on command line"),
    (r'github_pat_\w+|ghp_\w+|gho_\w+|ghu_\w+|ghs_\w+', "GitHub token in shell"),
    (r'sk-[a-zA-Z0-9]{20,}', "OpenAI/DeepSeek API key"),
    (r'AIza[0-9A-Za-z\-_]{35}', "Google API key"),
    (r'-----BEGIN\s+(?:RSA|EC|OPENSSH)\s+PRIVATE\s+KEY-----', "Private key in shell output"),
    (r'login\s+.*-p\s+\S+', "Password in login command"),
]

# Files to scan for secrets
HISTORY_FILES = [
    "~/.zsh_history",
    "~/.bash_history",
    "~/.python_history",
]

LOG_PATTERNS = [
    "*.log", "*.out", "*.err",
]


def scan_deep(config: dict, learning) -> list[dict]:
    """Deep scan: shell history, logs, and more."""
    findings = []

    # 1. Shell History
    if config.get("shell_history", True):
        for hist_path in HISTORY_FILES:
            path = Path(hist_path).expanduser()
            if path.exists():
                results = _scan_shell_history(path)
                findings.extend(results)

    # 2. Log files (recent only)
    if config.get("logs", {}).get("enabled", False):
        log_dirs = config.get("logs", {}).get("paths", [])
        for dir_str in log_dirs:
            dir_path = Path(dir_str).expanduser()
            if dir_path.exists():
                results = _scan_logs(dir_path)
                findings.extend(results)

    # 3. Environment variables with secrets
    if config.get("env_check", True):
        results = _scan_env_vars()
        findings.extend(results)

    return findings


def _scan_shell_history(hist_path: Path) -> list[dict]:
    """Scan shell history for commands containing secrets."""
    findings = []
    try:
        # Read as binary, decode with errors='ignore' to handle binary content
        with open(hist_path, "rb") as f:
            raw = f.read()

        # History files can be huge — only read last 10MB and last 5000 lines
        if len(raw) > 10 * 1024 * 1024:
            raw = raw[-10 * 1024 * 1024:]

        content = raw.decode("utf-8", errors="ignore")
        lines = content.split("\n")[-5000:]

        for i, line in enumerate(lines):
            line_stripped = line.strip()
            if not line_stripped:
                continue

            for pattern, description in SHELL_SECRET_PATTERNS:
                match = re.search(pattern, line_stripped, re.IGNORECASE)
                if match:
                    # Sanitize: show only first/last 3 chars of the secret value
                    sanitized = _sanitize_line(line_stripped, match)
                    findings.append({
                        "type": "shell_secret",
                        "key": f"shell:{hist_path.name}:{len(lines)-i}",
                        "severity": "HIGH",
                        "title": f"{description} in shell history",
                        "description": f"Line ~{len(lines)-i} commands ago",
                        "details": f"File: {hist_path}\nCommand: {sanitized[:200]}",
                        "action": "Clear shell history: `history -c && cat /dev/null > ~/.zsh_history`",
                    })
                    break  # One pattern per line
    except (OSError, UnicodeDecodeError) as e:
        log.debug(f"Could not read {hist_path}: {e}")

    return findings


def _sanitize_line(line: str, match: re.Match) -> str:
    """Replace the matched secret with [REDACTED]."""
    try:
        start, end = match.start(), match.end()
        return line[:start] + "[REDACTED]" + line[end:]
    except Exception:
        return line[:50] + "[REDACTED]"


def _scan_logs(log_dir: Path) -> list[dict]:
    """Scan log files for recent secret exposure."""
    findings = []
    try:
        # Only scan last 3 days of logs (check mtime)
        import time
        three_days = time.time() - (3 * 24 * 3600)

        for log_file in log_dir.rglob("*.log"):
            if not log_file.is_file():
                continue
            if log_file.stat().st_mtime < three_days:
                continue
            if log_file.stat().st_size > 5 * 1024 * 1024:  # Skip files >5MB
                continue

            try:
                with open(log_file, "r", errors="ignore") as f:
                    content = f.read()

                for pattern, description in SHELL_SECRET_PATTERNS:
                    if re.search(pattern, content, re.IGNORECASE):
                        findings.append({
                            "type": "log_secret",
                            "key": f"log:{log_file.name}",
                            "severity": "MEDIUM",
                            "title": f"Secret pattern in log: {log_file.name}",
                            "description": f"{description} found in recent log file",
                            "details": f"File: {log_file}\nPattern: {description}\n🔒 Value redacted",
                            "action": "Check if this log contains active secrets. Rotate if needed.",
                        })
                        break
            except (OSError, UnicodeDecodeError):
                continue
    except Exception as e:
        log.warning(f"Log scan failed: {e}")

    return findings


def _scan_env_vars() -> list[dict]:
    """Check for secrets in exported environment variables."""
    findings = []
    try:
        result = subprocess.run(
            ["env"],
            capture_output=True, text=True, timeout=5,
        )
        for line in result.stdout.strip().split("\n"):
            for pattern, description in SHELL_SECRET_PATTERNS[:3]:  # Only check exported keys
                if re.search(pattern, line, re.IGNORECASE):
                    key_name = line.split("=")[0] if "=" in line else "?"
                    findings.append({
                        "type": "env_secret",
                        "key": f"env:{key_name}",
                        "severity": "MEDIUM",
                        "title": f"Secret in environment variable: {key_name}",
                        "description": f"Environment variable may contain sensitive data",
                        "details": f"Variable: {key_name}\n🔒 Value redacted",
                        "action": "Check if this should be in an env file, not exported in shell.",
                    })
                    break
    except Exception as e:
        log.warning(f"Env scan failed: {e}")

    return findings
