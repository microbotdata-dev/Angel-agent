"""
Git Secrets Scanner — checks git repos for committed secrets.
Uses regex patterns for accurate detection (not just grep).
"""

import os
import re
import logging
import subprocess
from pathlib import Path
from typing import Optional

log = logging.getLogger("angel.monitors.git_secrets")

# Patterns that should never be in git history (key → description)
SECRET_PATTERNS = [
    (r'["\']?(?:api[_-]?key|api[_-]?secret)["\']?\s*[:=]\s*["\']?(sk-[a-zA-Z0-9]{20,})["\']?', "API Key (sk-...)"),
    (r'["\']?(?:api[_-]?key|api[_-]?secret)["\']?\s*[:=]\s*["\']?([a-fA-F0-9]{32,})["\']?', "API Key (hex 32+)"),
    (r'["\']?(?:token|auth_token|bearer)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9._-]{20,})["\']?', "Auth Token"),
    (r'["\']?password["\']?\s*[:=]\s*["\']?([^\s\'"]{8,})["\']?', "Password"),
    (r'-----BEGIN\s+(?:RSA|EC|OPENSSH)\s+PRIVATE\s+KEY-----', "Private Key"),
    (r'ghp_[a-zA-Z0-9]{36}', "GitHub PAT"),
    (r'gho_[a-zA-Z0-9]{36}', "GitHub OAuth Access Token"),
    (r'(?:bot|:)[0-9]{8,}:[a-zA-Z0-9_-]{35,}', "Telegram Bot Token"),
    (r'["\']?secret["\']?\s*[:=]\s*["\']?([a-zA-Z0-9!@#$%^&*()_+\-=\[\]{}|;:,.<>?]{16,})["\']?', "Generic Secret"),
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
    """Scan a single git repo for secrets using regex patterns."""
    findings = []
    log.info(f"Scanning git repo: {repo.name}")

    # Use git grep to find potentially interesting lines, then validate with regex
    try:
        result = subprocess.run(
            ["git", "grep", "-n", "-I", "--ignore-case", "-E",
             "api_key|api_secret|password|token|secret|private_key|BEGIN.*PRIVATE"],
            capture_output=True, text=True, timeout=120, cwd=str(repo),
        )
        if result.returncode != 0 or not result.stdout.strip():
            return []

        lines = result.stdout.strip().split("\n")
        for line in lines:
            line_stripped = line.strip()
            if not line_stripped:
                continue

            # Extract file and content
            match = re.match(r'^([^:]+):(\d+):(.+)$', line_stripped)
            if not match:
                continue
            filepath, lineno, content = match.group(1), match.group(2), match.group(3)

            # Apply regex patterns to validate it's a real secret
            matched_type = None
            for pattern, description in SECRET_PATTERNS:
                if re.search(pattern, content, re.IGNORECASE):
                    matched_type = description
                    break

            if matched_type:
                findings.append({
                    "type": "git_secret",
                    "key": f"git:{repo.name}:{filepath}:{lineno}",
                    "severity": "CRITICAL",
                    "title": f"{matched_type} in git repo: {repo.name}",
                    "description": f"{filepath}:{lineno}",
                    "details": f"Repo: {repo.name}\nFile: {filepath}\nLine: {lineno}\nType: {matched_type}\n🔒 Secret value redacted",
                    "action": f"Remove from git history using `git filter-branch` or BFG Repo-Cleaner. Then rotate the credential.",
                })
    except subprocess.TimeoutExpired:
        log.warning(f"Git grep timed out for {repo}")
    except FileNotFoundError:
        log.warning("Git not found on system")
    except Exception as e:
        log.error(f"Error scanning {repo}: {e}")

    return findings
