"""
Git Secrets Scanner — checks git repos for committed secrets.
Uses regex patterns (no external tool dependency).
"""

import os
import re
import logging
import subprocess
from pathlib import Path
from typing import Optional

log = logging.getLogger("angel.monitors.git_secrets")

# Patterns that should never be in git history
SECRET_REGEXES = [
    (r'api[_-]?key["\']?\s*[:=]\s*["\']?(sk-[a-zA-Z0-9]{20,})', "API Key (sk-...)"),
    (r'api[_-]?key["\']?\s*[:=]\s*["\']?([a-fA-F0-9]{32,})', "API Key (hex 32+)"),
    (r'api[_-]?secret["\']?\s*[:=]\s*["\']?([a-zA-Z0-9]{20,})', "API Secret"),
    (r'token["\']?\s*[:=]\s*["\']?([a-zA-Z0-9._-]{20,})', "Token"),
    (r'password["\']?\s*[:=]\s*["\']?([^\s\'"]{8,})', "Password"),
    (r'-----BEGIN\s+(RSA|EC|OPENSSH)\s+PRIVATE\s+KEY-----', "Private Key"),
    (r'ghp_[a-zA-Z0-9]{36}', "GitHub PAT"),
    (r'gho_[a-zA-Z0-9]{36}', "GitHub OAuth"),
    (r'Telegram.*\d{8,}:[a-zA-Z0-9_-]{20,}', "Telegram Bot Token"),
]


def scan_git_secrets(config: dict, learning) -> list[dict]:
    """Scan configured git repos for committed secrets."""
    findings = []
    repos = config.get("repos", [])

    for repo_str in repos:
        repo = Path(repo_str).expanduser()
        if not repo.exists():
            continue
        if not (repo / ".git").exists():
            # Check subdirectories
            for sub in repo.iterdir():
                if sub.is_dir() and (sub / ".git").exists():
                    findings.extend(_scan_repo(sub, learning))
            continue
        findings.extend(_scan_repo(repo, learning))

    return findings


def _scan_repo(repo: Path, learning) -> list[dict]:
    """Scan a single git repo for secrets."""
    findings = []
    log.info(f"Scanning git repo: {repo}")

    try:
        result = subprocess.run(
            ["git", "grep", "-n", "-I", "--ignore-case", "-E",
             "api_key|api_secret|password|token|secret|private_key"],
            capture_output=True, text=True, timeout=60, cwd=str(repo),
        )
        if result.returncode == 0 and result.stdout.strip():
            lines = result.stdout.strip().split("\n")
            for line in lines[:20]:  # Limit
                findings.append({
                    "type": "git_secret",
                    "key": f"git_secret:{repo.name}:{line[:60]}",
                    "severity": "CRITICAL",
                    "title": f"Secret found in git repo: {repo.name}",
                    "description": f"Potential credential in committed code",
                    "details": f"File: {repo}\n{line[:200]}",
                    "action": "Remove from git history with `git filter-branch` or `bfg`.",
                })
    except subprocess.TimeoutExpired:
        log.warning(f"Git grep timed out for {repo}")
    except FileNotFoundError:
        log.warning("Git not found on system")
    except Exception as e:
        log.error(f"Error scanning {repo}: {e}")

    return findings
