"""
Angel Agent — Main Orchestrator
=================================
Personal security guardian that monitors credentials, secrets, ports,
processes, and file integrity. Learns from user interaction without
code changes — purely config-driven.

Usage:
    python -m src.angel.core --config config.yaml
"""

import os
import sys
import json
import time
import yaml
import logging
import argparse
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional

from .state import AngelState
from .learning import LearningEngine
from .notifier import Notifier

log = logging.getLogger("angel")


class AngelAgent:
    """The Angel — your personal security guardian."""

    def __init__(self, config_path: str):
        self.config = self._load_config(config_path)
        self.data_dir = Path(self.config.get("angel", {}).get("data_dir", "~/.angel")).expanduser()
        self.data_dir.mkdir(parents=True, exist_ok=True)

        self.state = AngelState(self.data_dir / "angel_state.json")
        self.learning = LearningEngine(self.data_dir / "learned_rules.json")
        self.notifier = Notifier(self.config.get("notifications", {}))

        self._setup_logging()

    def _setup_logging(self):
        level = getattr(logging, self.config.get("angel", {}).get("log_level", "info").upper(), logging.INFO)
        logging.basicConfig(
            level=level,
            format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            handlers=[
                logging.StreamHandler(),
                logging.FileHandler(self.data_dir / "angel.log"),
            ],
        )

    def _load_config(self, path: str) -> dict:
        path = Path(path).expanduser()
        if not path.exists():
            log.error(f"Config not found: {path}")
            print(f"❌ Config not found: {path}")
            print(f"   Copy config/config.example.yaml to {path} and edit it.")
            sys.exit(1)
        with open(path) as f:
            return yaml.safe_load(f)

    def run_once(self) -> list[dict]:
        """Run one full check cycle. Returns list of findings."""
        findings = []
        monitors_cfg = self.config.get("monitors", {})

        log.info("🔍 Angel check cycle starting...")

        # --- 1. Secret Scanner ---
        if monitors_cfg.get("secrets", {}).get("enabled", False):
            from .monitors.secrets import scan_secrets
            result = scan_secrets(monitors_cfg["secrets"], self.learning)
            findings.extend(result)

        # --- 2. Git Secrets ---
        if monitors_cfg.get("git_secrets", {}).get("enabled", False):
            from .monitors.git_secrets import scan_git_secrets
            result = scan_git_secrets(monitors_cfg["git_secrets"], self.learning)
            findings.extend(result)

        # --- 3. Credential Leaks ---
        if monitors_cfg.get("credential_leaks", {}).get("enabled", False):
            from .monitors.credentials import check_credential_leaks
            result = check_credential_leaks(
                monitors_cfg["credential_leaks"],
                self.config.get("identities", {}),
                self.learning,
            )
            findings.extend(result)

        # --- 4. Port Scanner ---
        if monitors_cfg.get("ports", {}).get("enabled", False):
            from .monitors.ports import scan_ports
            result = scan_ports(monitors_cfg["ports"], self.learning)
            findings.extend(result)

        # --- 5. Process Monitor ---
        if monitors_cfg.get("processes", {}).get("enabled", False):
            from .monitors.processes import check_processes
            result = check_processes(monitors_cfg["processes"], self.learning)
            findings.extend(result)

        # --- 6. File Integrity ---
        if monitors_cfg.get("file_integrity", {}).get("enabled", False):
            from .monitors.file_integrity import check_integrity
            result = check_integrity(monitors_cfg["file_integrity"], self.state, self.learning)
            findings.extend(result)

        # Apply learning — filter out known false positives
        findings = self.learning.filter_findings(findings)

        # Save state
        self.state.last_check = datetime.now(timezone.utc).isoformat()
        self.state.findings_history.append({
            "timestamp": self.state.last_check,
            "count": len(findings),
            "severity": self._compute_severity(findings),
        })
        self.state.save()

        log.info(f"✅ Angel check complete — {len(findings)} finding(s)")
        return findings

    def report_findings(self, findings: list[dict]):
        """Send findings to configured channels."""
        if not findings:
            log.info("✅ Clean bill of health — no findings to report.")
            return

        # Group by severity
        by_severity = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": []}
        for f in findings:
            by_severity.setdefault(f.get("severity", "LOW"), []).append(f)

        # Always notify CRITICAL and HIGH
        for severity in ["CRITICAL", "HIGH"]:
            for finding in by_severity[severity]:
                self.notifier.send_alert(finding)

        # MEDIUM and LOW go to daily digest
        if by_severity["MEDIUM"] or by_severity["LOW"]:
            self.notifier.send_digest(by_severity)

    def _compute_severity(self, findings: list[dict]) -> str:
        sevs = [f.get("severity", "LOW") for f in findings]
        if "CRITICAL" in sevs:
            return "CRITICAL"
        if "HIGH" in sevs:
            return "HIGH"
        if "MEDIUM" in sevs:
            return "MEDIUM"
        return "LOW"

    def handle_feedback(self, finding_id: str, action: str):
        """
        Handle user feedback on a finding.
        action: 'confirm' (it was real), 'ignore' (false positive),
                'always_ignore' (never show again)
        """
        self.learning.record_feedback(finding_id, action)
        log.info(f"📝 Feedback recorded: {finding_id} → {action}")

    def run_loop(self):
        """Run continuously with configured interval."""
        interval = self.config.get("angel", {}).get("check_interval", 1800)
        log.info(f"♾️  Angel starting continuous mode (interval: {interval}s)")

        while True:
            try:
                findings = self.run_once()
                self.report_findings(findings)
            except Exception as e:
                log.error(f"❌ Check cycle failed: {e}", exc_info=True)

            time.sleep(interval)


def main():
    parser = argparse.ArgumentParser(description="Angel Agent — Personal Security Guardian")
    parser.add_argument("--config", "-c", default="~/.angel/config.yaml",
                       help="Path to config file")
    parser.add_argument("--once", action="store_true",
                       help="Run one check cycle and exit")
    parser.add_argument("--feedback", nargs=2, metavar=("FINDING_ID", "ACTION"),
                       help="Record feedback on a finding (confirm/ignore/always_ignore)")
    parser.add_argument("--version", action="store_true",
                       help="Show version")

    args = parser.parse_args()

    if args.version:
        from src import __version__
        print(f"Angel Agent v{__version__}")
        return

    agent = AngelAgent(args.config)

    if args.feedback:
        agent.handle_feedback(*args.feedback)
    elif args.once:
        findings = agent.run_once()
        agent.report_findings(findings)
    else:
        agent.run_loop()


if __name__ == "__main__":
    main()
