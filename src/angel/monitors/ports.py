"""
Port Scanner — monitors listening ports and detects unexpected services.
"""

import subprocess
import logging
from typing import Optional

log = logging.getLogger("angel.monitors.ports")


def scan_ports(config: dict, learning) -> list[dict]:
    """Scan listening ports and compare against known-good list."""
    findings = []
    known_ports = set(config.get("known_ports", []))

    try:
        ports = _get_listening_ports()
    except Exception as e:
        log.error(f"Port scan failed: {e}")
        return [{
            "type": "port_scan_error",
            "key": "port_scan_failed",
            "severity": "MEDIUM",
            "title": "Port scan failed",
            "description": str(e),
            "details": "",
            "action": "Check that lsof is available (`which lsof`).",
        }]

    for port_info in ports:
        port = port_info["port"]
        process = port_info.get("process", "unknown")
        address = port_info.get("address", "")

        # Skip if learning already knows this port
        if learning.is_port_known(port):
            continue

        if port not in known_ports:
            severity = "HIGH" if address == "0.0.0.0" else "MEDIUM"
            findings.append({
                "type": "unknown_port",
                "key": f"port:{port}:{process}",
                "severity": severity,
                "title": f"Unknown port {port} ({process})",
                "description": f"Service listening on port {port}",
                "details": f"Port: {port}\nProcess: {process}\nAddress: {address}\n"
                          f"PID: {port_info.get('pid', '?')}",
                "action": f"Verify {process} is legitimate. Use `angel --feedback <id> always_ignore` if expected.",
            })

    # Check for missing expected ports
    current_ports = {p["port"] for p in ports}
    for expected in known_ports:
        if expected not in current_ports and not learning.is_port_known(expected):
            findings.append({
                "type": "missing_port",
                "key": f"missing:{expected}",
                "severity": "LOW",
                "title": f"Expected port {expected} is not listening",
                "description": "A service you expect might be down",
                "details": f"Port: {expected}",
                "action": "Check if the service is running: `lsof -iTCP:{expected} -sTCP:LISTEN`",
            })

    return findings


def _get_listening_ports() -> list[dict]:
    """Get all listening TCP ports using lsof."""
    result = subprocess.run(
        ["lsof", "-iTCP", "-sTCP:LISTEN", "-P", "-n"],
        capture_output=True, text=True, timeout=15,
    )

    ports = []
    for line in result.stdout.strip().split("\n")[1:]:  # Skip header
        parts = line.split()
        if len(parts) >= 9:
            process = parts[0]
            pid = parts[1]
            address_port = parts[8]
            address = address_port.split(":")[0] if ":" in address_port else "*"
            port_str = address_port.rsplit(":", 1)[-1] if ":" in address_port else address_port

            try:
                port = int(port_str)
            except ValueError:
                continue

            ports.append({
                "port": port,
                "process": process,
                "pid": pid,
                "address": address,
            })

    return ports
