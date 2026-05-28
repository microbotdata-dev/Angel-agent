"""
Process Monitor — detects unknown or suspicious processes.
Uses psutil for reliable cross-platform process info.
"""

import logging
import psutil

log = logging.getLogger("angel.monitors.processes")


def check_processes(config: dict, learning) -> list[dict]:
    """Check running processes against known-good list."""
    findings = []
    known = set(config.get("known_processes", []))

    # Top CPU consumers
    for proc in sorted(psutil.process_iter(["pid", "name", "cpu_percent", "memory_percent"]),
                       key=lambda p: p.info.get("cpu_percent", 0) or 0,
                       reverse=True)[:10]:
        try:
            name = proc.info.get("name", "?") or "?"
            cpu = proc.info.get("cpu_percent", 0) or 0
            mem = proc.info.get("memory_percent", 0) or 0
            pid = proc.info.get("pid", "?")

            if cpu > 50 and name not in known and not learning.is_process_known(name):
                findings.append({
                    "type": "high_cpu",
                    "key": f"cpu:{name}",
                    "severity": "MEDIUM",
                    "title": f"High CPU usage: {name} ({cpu:.1f}%)",
                    "description": f"Process consuming significant CPU ({cpu:.1f}%)",
                    "details": f"Process: {name}\nCPU: {cpu:.1f}%\nMemory: {mem:.1f}%\nPID: {pid}",
                    "action": f"Check if {name} is expected. Use `angel --feedback <id> always_ignore` if normal.",
                })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    # Processes with network connections that are unknown
    try:
        conn_procs = set()
        for conn in psutil.net_connections(kind="inet"):
            if conn.pid and conn.status == "ESTABLISHED":
                try:
                    p = psutil.Process(conn.pid)
                    conn_procs.add(p.name())
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

        for name in conn_procs:
            if name and name not in known and not learning.is_process_known(name):
                findings.append({
                    "type": "network_process",
                    "key": f"net:{name}",
                    "severity": "MEDIUM",
                    "title": f"Unknown process with network access: {name}",
                    "description": f"A new process ({name}) has active network connections",
                    "details": f"Process: {name}",
                    "action": f"Verify {name} is legitimate. Consider blocking with LuLu if suspicious.",
                })
    except (psutil.AccessDenied, Exception) as e:
        log.warning(f"Network process check failed: {e}")

    return findings
