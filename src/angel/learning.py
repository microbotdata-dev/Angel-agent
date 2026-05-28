"""
Angel Learning Engine — improves detection without code changes.

How it works:
- Every finding has a unique ID based on its type and context
- User can 'confirm' (real threat), 'ignore' (false positive), 'always_ignore'
- The engine remembers patterns and auto-filters known false positives
- Creates suppression rules automatically based on feedback
- All rules are in a JSON file — no code modification needed
"""

import json
import logging
import hashlib
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional

log = logging.getLogger("angel.learning")


class LearningEngine:
    """Config-driven learning. No code changes needed to improve."""

    def __init__(self, rules_path: Path):
        self.path = rules_path
        self.rules = self._load()

    def _load(self) -> dict:
        if self.path.exists():
            try:
                with open(self.path) as f:
                    return json.load(f)
            except (json.JSONDecodeError, OSError):
                pass
        return {
            "version": 1,
            "created": datetime.now(timezone.utc).isoformat(),
            "updated": None,
            "suppression_rules": [],    # Patterns to auto-ignore
            "escalation_rules": [],     # Patterns to bump severity
            "known_processes": [],      # Learned normal processes
            "known_ports": [],          # Learned normal ports
            "feedback_log": [],         # All feedback ever given
            "stats": {
                "total_findings": 0,
                "confirmed": 0,
                "ignored": 0,
                "always_ignore": 0,
            },
        }

    def save(self):
        self.rules["updated"] = datetime.now(timezone.utc).isoformat()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "w") as f:
            json.dump(self.rules, f, indent=2)

    def compute_finding_id(self, finding: dict) -> str:
        """Stable ID for a finding type. Same pattern = same ID."""
        raw = f"{finding.get('type')}:{finding.get('key', '')}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def record_feedback(self, finding_id: str, action: str):
        """Record user feedback on a finding."""
        self.rules["feedback_log"].append({
            "finding_id": finding_id,
            "action": action,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        self.rules["stats"][action] = self.rules["stats"].get(action, 0) + 1
        self.rules["stats"]["total_findings"] += 1

        if action == "always_ignore":
            self.rules["suppression_rules"].append({
                "pattern": finding_id,
                "reason": "user_feedback",
                "created": datetime.now(timezone.utc).isoformat(),
            })

        self.save()
        log.info(f"📝 Learned: {finding_id} → {action} ({self.rules['stats']['total_findings']} total)")

    def filter_findings(self, findings: list[dict]) -> list[dict]:
        """Filter out known false positives based on learned rules."""
        filtered = []
        for finding in findings:
            finding_id = self.compute_finding_id(finding)
            finding["id"] = finding_id

            # Check suppression rules
            suppressed = False
            for rule in self.rules.get("suppression_rules", []):
                if rule["pattern"] == finding_id:
                    suppressed = True
                    log.debug(f"🔇 Suppressed: {finding.get('title')} (learned)")
                    break

            if not suppressed:
                # Check escalation rules
                for rule in self.rules.get("escalation_rules", []):
                    if rule["pattern"] == finding_id:
                        finding["severity"] = rule["target_severity"]
                        break

                filtered.append(finding)

        return filtered

    def learn_normal_process(self, name: str):
        """Add a process to known-good list after seeing it repeatedly."""
        self.rules["known_processes"].append({
            "name": name,
            "first_seen": datetime.now(timezone.utc).isoformat(),
        })

    def learn_normal_port(self, port: int, process: str):
        """Add a port to known-good list."""
        self.rules["known_ports"].append({
            "port": port,
            "process": process,
            "first_seen": datetime.now(timezone.utc).isoformat(),
        })

    def is_process_known(self, name: str) -> bool:
        """Check if we've learned this process as normal."""
        return any(p["name"] == name for p in self.rules.get("known_processes", []))

    def is_port_known(self, port: int) -> bool:
        return any(p["port"] == port for p in self.rules.get("known_ports", []))

    def get_stats(self) -> dict:
        """Get learning stats."""
        return {
            "suppression_rules": len(self.rules.get("suppression_rules", [])),
            "escalation_rules": len(self.rules.get("escalation_rules", [])),
            "known_processes": len(self.rules.get("known_processes", [])),
            "known_ports": len(self.rules.get("known_ports", [])),
            "total_feedback": self.rules.get("stats", {}).get("total_findings", 0),
        }
