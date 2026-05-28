"""
Process Monitor — detects unknown or suspicious processes.
"""

import subprocess
import logging
from typing import Optional

log = logging.getLogger("angel.monitors.processes")


def check_processes(config: dict, learning) -> list[dict]:
    """Check running processes against known-good list."""
    findings = []
    known = set(config.get("known_processes", []))

    try:
        processes = _get_processes()
    except Exception as e:
        log.error(f"Process check failed: {e}")
        return []

    # Top CPU consumers
    sorted_by_cpu = sorted(processes, key=lambda p: p.get("cpu", 0), reverse=True)
    for proc in sorted_by_cpu[:5]:
        name = proc.get("name", "?")
        cpu = proc.get("cpu", 0)
        mem = proc.get("mem", 0)

        if cpu > 50 and name not in known and not learning.is_process_known(name):
            findings.append({
                "type": "high_cpu",
                "key": f"cpu:{name}",
                "severity": "MEDIUM",
                "title": f"High CPU usage: {name} ({cpu:.1f}%)",
                "description": f"Process consuming significant CPU",
                "details": f"Process: {name}\nCPU: {cpu:.1f}%\nMemory: {mem:.1f}%\nPID: {proc.get('pid', '?')}",
                "action": f"Check if {name} is expected. Use `angel --feedback <id> always_ignore` if normal.",
            })

    # Processes with network connections that are unknown
    try:
        net_procs = _get_processes_with_network()
        for name in set(net_procs):
            if name and name not in known and not learning.is_process_known(name):
                findings.append({
                    "type": "network_process",
                    "key": f"net:{name}",
                    "severity": "MEDIUM",
                    "title": f"Unknown process with network access: {name}",
                    "description": "A process you haven't seen before has network connections",
                    "details": f"Process: {name}",
                    "action": f"Verify {name} is legitimate. Consider blocking with LuLu if suspicious.",
                })
    except Exception as e:
        log.warning(f"Network process check failed: {e}")

    return findings


def _get_processes() -> list[dict]:
    """Get process list with CPU and memory."""
    result = subprocess.run(
        ["ps", "aux"],
        capture_output=True, text=True, timeout=10,
    )

    processes = []
    for line in result.stdout.strip().split("\n")[1:]:
        parts = line.split()
        if len(parts) >= 11:
            try:
                processes.append({
                    "name": parts[10],
                    "pid": parts[1],
                    "cpu": float(parts[2]),
                    "mem": float(parts[3]),
                    "user": parts[0],
                })
            except (ValueError, IndexError):
                continue

    return processes


def _get_processes_with_network() -> list[str]:
    """Get unique process names that have active network connections."""
    result = subprocess.run(
        ["lsof", "-iTCP", "-sTCP:ESTABLISHED", "-P", "-n"],
        capture_output=True, text=True, timeout=10,
    )

    names = set()
    for line in result.stdout.strip().split("\n")[1:]:
        parts = line.split()
        if len(parts) >= 9:
            names.add(parts[0])

    return list(names)
