"""
Angel Ticket System — tracks password checks with traffic light status.
Works locally (JSON files). When n8n is available, also syncs there.
  🟢 GREEN  = not found / resolved
  🔴 RED    = found, in progress
  🟡 YELLOW = being cleaned up
"""

import os
import json
import logging
import urllib.request
import urllib.error
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional

log = logging.getLogger("angel.ticket")

TICKETS_DIR = Path.home() / ".angel" / "tickets"
N8N_WEBHOOK = "http://127.0.0.1:5678/webhook/angel/ticket"


def _ensure_dir():
    TICKETS_DIR.mkdir(parents=True, exist_ok=True)


def _next_id() -> int:
    """Generate next ticket number."""
    _ensure_dir()
    existing = [int(f.stem) for f in TICKETS_DIR.glob("*.json") if f.stem.isdigit()]
    return max(existing) + 1 if existing else 1


def _ticket_path(ticket_id) -> Path:
    return TICKETS_DIR / f"{ticket_id}.json"


def mask_password(password: str) -> str:
    """Show only first and last char: 'p*****a'"""
    if len(password) <= 2:
        return "***"
    return password[0] + "*" * (len(password) - 2) + password[-1]


def recommend(finding_types: list[str]) -> dict:
    """Recommend action based on where password was found."""
    if any(t in ("shell_history", "environment_variable", "git") for t in finding_types):
        return {
            "severity": "red",
            "action": "change",
            "message": "🔴 SCHIMBA parola! Expusa in loc vizibil (git / istoric shell / variabile mediu).",
        }
    elif any(t in ("file", "log", "config") for t in finding_types):
        return {
            "severity": "yellow",
            "action": "move",
            "message": "🟡 Muta in KeePass si sterge din fisier. Nu e urgent dar recomandat.",
        }
    else:
        return {
            "severity": "green",
            "action": "none",
            "message": "✅ Parola nu apare niciun. E in siguranta.",
        }


def create(password_mask: str, findings: list = None) -> dict:
    """Create a new ticket. Returns ticket dict."""
    _ensure_dir()
    ticket_id = _next_id()

    ticket = {
        "id": ticket_id,
        "created": datetime.now(timezone.utc).isoformat(),
        "updated": datetime.now(timezone.utc).isoformat(),
        "password_mask": password_mask,
        "status": "green",  # green / red / yellow
        "findings": findings or [],
        "recommendation": {},
        "history": [],
    }

    # Save locally
    with open(_ticket_path(ticket_id), "w") as f:
        json.dump(ticket, f, indent=2)

    # Try n8n sync (non-blocking)
    _try_n8n_sync("create", ticket)

    log.info(f"📋 Ticket #{ticket_id} creat ({password_mask})")
    return ticket


def update(ticket_id: int, status: str, message: str = "", findings: list = None):
    """Update ticket status with traffic light."""
    path = _ticket_path(ticket_id)
    if not path.exists():
        log.warning(f"Ticket #{ticket_id} not found")
        return None

    with open(path) as f:
        ticket = json.load(f)

    old_status = ticket["status"]
    ticket["status"] = status
    ticket["updated"] = datetime.now(timezone.utc).isoformat()
    ticket["history"].append({
        "from": old_status,
        "to": status,
        "message": message,
        "timestamp": ticket["updated"],
    })

    if findings is not None:
        ticket["findings"] = findings
        ticket["recommendation"] = recommend([f.get("type", "") for f in findings])

    with open(path, "w") as f:
        json.dump(ticket, f, indent=2)

    _try_n8n_sync("update", ticket)
    log.info(f"📋 Ticket #{ticket_id}: {status} — {message}")
    return ticket


def get(ticket_id: int) -> Optional[dict]:
    """Get ticket by ID."""
    path = _ticket_path(ticket_id)
    if path.exists():
        with open(path) as f:
            return json.load(f)
    return None


def list_recent(limit: int = 10) -> list[dict]:
    """List recent tickets, newest first."""
    _ensure_dir()
    tickets = []
    for f in sorted(TICKETS_DIR.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True):
        with open(f) as fh:
            tickets.append(json.load(fh))
    return tickets[:limit]


def stats() -> dict:
    """Get ticket statistics."""
    tickets = list_recent(1000)
    return {
        "total": len(tickets),
        "green": sum(1 for t in tickets if t.get("status") == "green"),
        "red": sum(1 for t in tickets if t.get("status") == "red"),
        "yellow": sum(1 for t in tickets if t.get("status") == "yellow"),
    }


# ── n8n sync (optional) ───────────────────────────────────────────────

def _try_n8n_sync(action: str, ticket: dict):
    """Try to sync with n8n. Swallows errors silently."""
    try:
        data = json.dumps({
            "action": action,
            "ticket": ticket,
        }).encode()
        req = urllib.request.Request(
            N8N_WEBHOOK,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        urllib.request.urlopen(req, timeout=3)
        log.debug(f"✅ n8n sync: {action} ticket #{ticket.get('id')}")
    except Exception:
        log.debug(f"n8n not available (sync deferred)")
        pass
