"""
Unit tests for Angel Agent — core components.
"""

import os
import sys
import json
import tempfile
import hashlib
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from angel.learning import LearningEngine
from angel.state import AngelState
from angel.notifier import Notifier


# ── Learning Engine Tests ──────────────────────────────────────────────

def test_learning_engine_creates_file():
    """Learning engine should create rules file on first use."""
    with tempfile.TemporaryDirectory() as d:
        learn = LearningEngine(Path(d) / "rules.json")
        assert learn.rules["version"] == 1
        assert learn.path.exists() is False  # created on save, not init
        learn.save()
        assert learn.path.exists()


def test_finding_id_stable():
    """Same finding should produce same ID."""
    with tempfile.TemporaryDirectory() as d:
        learn = LearningEngine(Path(d) / "rules.json")
        f1 = {"type": "secret_plaintext", "key": "/path/file:42:TOKEN"}
        f2 = {"type": "secret_plaintext", "key": "/path/file:42:TOKEN"}
        assert learn.compute_finding_id(f1) == learn.compute_finding_id(f2)


def test_finding_id_different():
    """Different findings should produce different IDs."""
    with tempfile.TemporaryDirectory() as d:
        learn = LearningEngine(Path(d) / "rules.json")
        f1 = {"type": "secret_plaintext", "key": "/path/file:42:TOKEN"}
        f2 = {"type": "secret_plaintext", "key": "/path/file:99:TOKEN"}
        assert learn.compute_finding_id(f1) != learn.compute_finding_id(f2)


def test_filter_findings_suppression():
    """Findings with suppression rules should be filtered out."""
    with tempfile.TemporaryDirectory() as d:
        learn = LearningEngine(Path(d) / "rules.json")
        finding = {"type": "test", "key": "abc", "severity": "HIGH"}
        fid = learn.compute_finding_id(finding)

        # Record as always_ignore
        learn.record_feedback(fid, "always_ignore")

        # Should be filtered out
        filtered = learn.filter_findings([finding])
        assert len(filtered) == 0


def test_filter_findings_keep_confirmed():
    """Confirmed findings should remain."""
    with tempfile.TemporaryDirectory() as d:
        learn = LearningEngine(Path(d) / "rules.json")
        finding = {"type": "test", "key": "abc", "severity": "HIGH"}
        fid = learn.compute_finding_id(finding)

        learn.record_feedback(fid, "confirm")
        filtered = learn.filter_findings([finding])
        assert len(filtered) == 1


def test_learning_stats():
    """Stats should track feedback correctly."""
    with tempfile.TemporaryDirectory() as d:
        learn = LearningEngine(Path(d) / "rules.json")
        f1 = {"type": "test", "key": "a"}
        f2 = {"type": "test", "key": "b"}
        f3 = {"type": "test", "key": "c"}

        learn.record_feedback(learn.compute_finding_id(f1), "always_ignore")
        learn.record_feedback(learn.compute_finding_id(f2), "confirm")
        learn.record_feedback(learn.compute_finding_id(f3), "ignore")

        stats = learn.get_stats()
        assert stats["total_feedback"] == 3
        assert stats["suppression_rules"] == 1


# ── State Tests ─────────────────────────────────────────────────────────

def test_state_creates_file():
    """State should create and load correctly."""
    with tempfile.TemporaryDirectory() as d:
        state = AngelState(Path(d) / "state.json")
        assert state.data["angel_version"] == "0.1.0"
        assert state.data.get("total_checks", 0) == 0  # 0 before first save
        state.save()
        assert state.path.exists()


def test_state_persistence():
    """State should persist across instances."""
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "state.json"
        state1 = AngelState(path)
        state1.last_check = "2026-01-01T00:00:00"
        state1.save()

        state2 = AngelState(path)
        assert state2.last_check == "2026-01-01T00:00:00"


def test_state_watch_hashes():
    """Watch hashes should be settable and retrievable."""
    with tempfile.TemporaryDirectory() as d:
        state = AngelState(Path(d) / "state.json")
        state.watch_hashes = {"/etc/hosts": "abc123"}
        state.save()

        state2 = AngelState(Path(d) / "state.json")
        assert state2.watch_hashes["/etc/hosts"] == "abc123"


# ── Notifier Tests ──────────────────────────────────────────────────────

def test_notifier_stdout_fallback():
    """Notifier should print to stdout when no webhook configured."""
    notifier = Notifier({})
    finding = {
        "type": "test",
        "severity": "HIGH",
        "title": "Test Alert",
        "description": "This is a test",
    }
    # Should not crash — prints to stdout
    notifier.send_alert(finding)
    print("✅ Notifier stdout fallback works")


def test_notifier_digest():
    """Digest should group by severity."""
    notifier = Notifier({})
    findings = {
        "CRITICAL": [{"type": "test", "title": "Critical 1"}],
        "HIGH": [{"type": "test", "title": "High 1"}],
        "MEDIUM": [],
        "LOW": [],
    }
    notifier.send_digest(findings)
    print("✅ Notifier digest works")


# ── Run all tests ──────────────────────────────────────────────────────

if __name__ == "__main__":
    tests = [
        test_learning_engine_creates_file,
        test_finding_id_stable,
        test_finding_id_different,
        test_filter_findings_suppression,
        test_filter_findings_keep_confirmed,
        test_learning_stats,
        test_state_creates_file,
        test_state_persistence,
        test_state_watch_hashes,
        test_notifier_stdout_fallback,
        test_notifier_digest,
    ]

    passed = 0
    failed = 0
    for test in tests:
        try:
            test()
            print(f"  ✅ {test.__name__}")
            passed += 1
        except Exception as e:
            print(f"  ❌ {test.__name__}: {e}")
            failed += 1

    print(f"\n{'='*40}")
    print(f"Results: {passed} passed, {failed} failed, {len(tests)} total")
    if failed:
        sys.exit(1)
    else:
        print("All tests passed! 🎉")
