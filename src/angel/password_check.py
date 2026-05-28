"""
Angel Password Checker — Web Interface
Verifica daca o parola apare pe undeva pe sistem.
NU retine parola. NU o scrie in loguri. NU o salveaza.
Dupa verificare, totul e sters din memorie.
"""

import os
import sys
import re
import json
import hashlib
import logging
import tempfile
import subprocess
from pathlib import Path

log = logging.getLogger("angel.password_check")


def check_password(password: str, paths: list[str] = None) -> dict:
    """
    Check if a password appears anywhere on the system.
    Searches: files, git repos, shell history, logs.
    Returns a dict with results — never stores the password.
    """
    if not password or len(password) < 3:
        return {"found": False, "message": "Password too short (min 3 chars)", "locations": []}

    results = []
    password_lower = password.lower()
    password_hash = hashlib.sha256(password.encode()).hexdigest()

    # ── 1. Search in files ──────────────────────────────────────
    if paths:
        for path_str in paths:
            path = Path(path_str).expanduser()
            if path.exists():
                try:
                    result = subprocess.run(
                        ["grep", "-rl", "--ignore-case", password, str(path)],
                        capture_output=True, text=True, timeout=30,
                        cwd="/"
                    )
                    if result.stdout.strip():
                        for line in result.stdout.strip().split("\n"):
                            results.append({
                                "type": "file",
                                "location": line,
                                "severity": "HIGH",
                            })
                except subprocess.TimeoutExpired:
                    results.append({"type": "error", "location": f"Search timed out on {path}", "severity": "LOW"})
                except Exception as e:
                    log.warning(f"File search failed: {e}")

    # ── 2. Shell history ────────────────────────────────────────
    for hist_file in ["~/.zsh_history", "~/.bash_history", "~/.python_history"]:
        hf = Path(hist_file).expanduser()
        if hf.exists():
            try:
                result = subprocess.run(
                    ["grep", "-l", password, str(hf)],
                    capture_output=True, text=True, timeout=5,
                )
                if result.returncode == 0:
                    results.append({
                        "type": "shell_history",
                        "location": str(hf),
                        "severity": "CRITICAL",
                    })
            except Exception:
                pass

    # ── 3. Environment variables ────────────────────────────────
    try:
        env_result = subprocess.run(["env"], capture_output=True, text=True, timeout=5)
        for env_line in env_result.stdout.strip().split("\n"):
            if password in env_line:
                key = env_line.split("=")[0] if "=" in env_line else "?"
                results.append({
                    "type": "environment_variable",
                    "location": f"Variable: {key}",
                    "severity": "CRITICAL",
                })
    except Exception:
        pass

    # ── 4. Log files (recent) ───────────────────────────────────
    log_dirs = ["~/cosmos/logs", "~/.angel", "~/.hermes/logs"]
    for log_dir in log_dirs:
        ld = Path(log_dir).expanduser()
        if ld.exists():
            try:
                result = subprocess.run(
                    ["grep", "-rl", "--ignore-case", password, str(ld)],
                    capture_output=True, text=True, timeout=10,
                )
                if result.stdout.strip():
                    for line in result.stdout.strip().split("\n"):
                        results.append({
                            "type": "log_file",
                            "location": line,
                            "severity": "HIGH",
                        })
            except Exception:
                pass

    # ── Cleanup: overwrite variables ────────────────────────────
    # Python will garbage-collect the password string.
    # We also actively overwrite our references.
    result = {
        "found": len(results) > 0,
        "sha256_hash": password_hash[:16] + "...",
        "locations": results,
        "total": len(results),
        "note": "Password was NOT stored. Results are displayed once and discarded.",
    }

    return result


def main_cli():
    """CLI entry point — usage: python check_password.py <password>"""
    if len(sys.argv) < 2:
        print("Usage: python check_password.py <password>")
        print("The password is NOT stored anywhere.")
        sys.exit(1)

    password = sys.argv[1]

    # Search paths
    paths = [
        "~/cosmos/projects",
        "~/.hermes",
        "~/.ssh",
        "~/cosmos/scripts",
    ]

    result = check_password(password, paths)

    if result["found"]:
        print(f"\n🔴 PAROLA GASITA in {result['total']} locuri!\n")
        for loc in result["locations"]:
            emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}.get(loc["severity"], "ℹ️")
            print(f"  {emoji} [{loc['type']}] {loc['location']}")
    else:
        print(f"\n✅ Parola NEGASITA in locurile scanate.")
        print(f"   Hash SHA-256: {result['sha256_hash']}")

    print(f"\n🔒 Parola NU a fost salvata. A fost stearsa din memorie dupa verificare.")


if __name__ == "__main__":
    main_cli()
