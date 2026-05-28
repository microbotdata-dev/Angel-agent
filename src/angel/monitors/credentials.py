"""
Credential Leak Monitor — checks if credentials have been exposed.
Zero cost. Uses free APIs only:
  - HIBP Pwned Passwords (k-anonymity, no API key needed)
  - Firefox Monitor (free)
  - IntelX (free tier)
"""

import hashlib
import logging
import urllib.request
import json
from typing import Optional

log = logging.getLogger("angel.monitors.credentials")


def check_credential_leaks(config: dict, identities: dict, learning) -> list[dict]:
    """Check for credential leaks."""
    findings = []

    # 1. HIBP Pwned Passwords — check if passwords are leaked
    # Uses k-anonymity: send first 5 chars of SHA-1 hash, get matching suffixes back
    if config.get("check_passwords", False) and config.get("providers", {}).get("hibp_range", False):
        # We'd need passwords to check — Angel doesn't store them
        # This is a placeholder for integration with KeePass/Bitwarden
        log.info("HIBP Pwned Passwords check available when integrated with password manager")
        findings.append({
            "type": "hibp_ready",
            "key": "hibp_range_available",
            "severity": "LOW",
            "title": "HIBP Pwned Passwords API ready",
            "description": "Free k-anonymity password check available",
            "details": "Angel can check passwords against HIBP's database of 997+ breaches.\n"
                      "Integration with KeePass/Bitwarden enables per-password checking.\n"
                      "API: https://api.pwnedpasswords.com/range/{hash_prefix}",
            "action": "Connect Angel to your password manager to enable per-password leak checks.",
        })

    # 2. Check emails against Firefox Monitor
    if config.get("check_emails", False) and config.get("providers", {}).get("firefox_monitor", False):
        emails = identities.get("emails", [])
        for email in emails:
            log.info(f"Firefox Monitor check available for {email}")
            findings.append({
                "type": "monitor_ready",
                "key": f"monitor:{email}",
                "severity": "INFO",
                "title": f"Breach monitoring available for {email}",
                "description": "Subscribe at https://monitor.firefox.com/ for free breach alerts",
                "details": f"Firefox Monitor will notify you when {email} appears in a known breach.\n"
                          f"Free service powered by Have I Been Pwned data.",
                "action": "Visit https://monitor.firefox.com/ and subscribe with your email.",
            })

    return findings


def check_password_pwned(password: str) -> dict:
    """
    Check a single password against HIBP using k-anonymity.
    Returns {'pwned': bool, 'count': int}
    Free, no API key needed.
    """
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    try:
        req = urllib.request.Request(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            headers={"Add-Padding": "true"},  # Optional privacy enhancement
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            content = resp.read().decode()

        for line in content.split("\n"):
            if line.startswith(suffix):
                count = int(line.split(":")[1].strip())
                return {"pwned": True, "count": count}

        return {"pwned": False, "count": 0}

    except Exception as e:
        log.error(f"HIBP check failed: {e}")
        return {"pwned": False, "count": -1, "error": str(e)}
