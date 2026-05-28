"""Angel Notifier — sends alerts to Discord, Telegram, SMS."""

import json
import logging
import urllib.request
import urllib.error
from typing import Optional
from datetime import datetime, timezone

log = logging.getLogger("angel.notifier")


class Notifier:
    """Multi-channel notification system."""

    def __init__(self, config: dict):
        self.config = config
        self.discord_webhook = config.get("discord", {}).get("webhook_url", "")

    def send_alert(self, finding: dict):
        """Send a single finding as alert."""
        severity = finding.get("severity", "LOW")
        emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}.get(severity, "ℹ️")

        message = (
            f"{emoji} **{severity}** — {finding.get('title', 'Unknown')}\n"
            f"_{finding.get('description', '')}_\n"
        )
        if finding.get("details"):
            message += f"```\n{finding['details']}\n```\n"
        if finding.get("action"):
            message += f"💡 *{finding['action']}*"

        self._send_discord(message)

    def send_digest(self, findings_by_severity: dict):
        """Send daily digest with all findings."""
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        total = sum(len(v) for v in findings_by_severity.values())

        message = f"📋 **Angel Daily Report** — {now}\n\n"
        message += f"**{total} finding(s) today**\n\n"

        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            items = findings_by_severity.get(severity, [])
            if items:
                emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}[severity]
                message += f"**{emoji} {severity} ({len(items)})**\n"
                for item in items:
                    message += f"  • {item.get('title', '?')}\n"
                message += "\n"

        message += "---\n"
        message += "_💡 Use `angel --feedback <id> ignore` to reduce noise_"

        self._send_discord(message)

    def _send_discord(self, message: str):
        """Send message to Discord webhook."""
        if not self.discord_webhook:
            log.debug("No Discord webhook configured, printing to stdout:")
            print(message)
            return

        payload = json.dumps({"content": message}).encode()
        req = urllib.request.Request(
            self.discord_webhook,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            urllib.request.urlopen(req, timeout=10)
            log.debug("Sent to Discord")
        except urllib.error.HTTPError as e:
            log.error(f"Discord webhook error: {e.code} {e.reason}")
        except Exception as e:
            log.error(f"Discord send failed: {e}")
