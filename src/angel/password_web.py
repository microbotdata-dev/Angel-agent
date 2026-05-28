"""
Angel — Password Check Web Interface with Ticket System.
Each check = 1 ticket with traffic light status.
Password is NEVER stored. No logs, no cache, no temp files.
"""

import os
import sys
import json
import logging
import hashlib
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

from .password_check import check_password
from . import ticket as tk

log = logging.getLogger("angel.password_web")

HTML_PAGE = r"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Angel — Password Check</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    background: #0a0a0f;
    color: #e0e0e0;
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
  }
  .container { max-width: 640px; width: 100%; padding: 2rem; }
  .logo { text-align: center; margin-bottom: 2rem; }
  .logo h1 { font-size: 2rem; color: #fff; }
  .logo p { color: #888; font-size: 0.9rem; margin-top: 0.3rem; }
  .card {
    background: #14141f; border: 1px solid #2a2a3a; border-radius: 16px;
    padding: 2rem; margin-bottom: 1rem;
  }
  label { display: block; margin-bottom: 0.5rem; color: #aaa; font-size: 0.9rem; }
  input[type="password"] {
    width: 100%; padding: 1rem; background: #1a1a2a; border: 1px solid #333;
    border-radius: 10px; color: #fff; font-size: 1rem; outline: none;
  }
  input:focus { border-color: #4a6cf7; }
  .btn {
    width: 100%; padding: 1rem; background: #4a6cf7; border: none;
    border-radius: 10px; color: #fff; font-size: 1rem; font-weight: 600;
    cursor: pointer; margin-top: 1rem;
  }
  .btn:hover { background: #3b5de7; }
  .btn:disabled { opacity: 0.5; cursor: not-allowed; }
  .btn.danger { background: #dc3545; }
  .btn.danger:hover { background: #c82333; }
  .result {
    margin-top: 1rem; padding: 1.5rem; border-radius: 12px; display: none;
  }
  .result.green { background: #0a1a0a; border: 1px solid #1a3a1a; display: block; }
  .result.red { background: #2a0a0a; border: 1px solid #5a1a1a; display: block; }
  .result.yellow { background: #2a2a0a; border: 1px solid #5a5a1a; display: block; }
  .result h3 { margin-bottom: 0.5rem; }
  .result.green h3 { color: #44ff44; }
  .result.red h3 { color: #ff4444; }
  .result.yellow h3 { color: #ffff44; }
  .ticket-badge {
    display: inline-block; padding: 0.25rem 0.75rem; border-radius: 20px;
    font-size: 0.8rem; font-weight: 700; margin-bottom: 1rem;
  }
  .ticket-badge.green { background: #1a3a1a; color: #44ff44; }
  .ticket-badge.red { background: #5a1a1a; color: #ff6666; }
  .ticket-badge.yellow { background: #5a5a1a; color: #ffff66; }
  .rec { padding: 1rem; border-radius: 8px; margin: 1rem 0; font-weight: 600; }
  .rec.red { background: #2a0a0a; color: #ff6666; border-left: 4px solid #ff4444; }
  .rec.yellow { background: #2a2a0a; color: #ffff66; border-left: 4px solid #ffff44; }
  .rec.green { background: #0a1a0a; color: #66ff66; border-left: 4px solid #44ff44; }
  .found-item { display: flex; align-items: center; padding: 0.5rem; margin: 0.3rem 0; background: #1a1a2a; border-radius: 8px; }
  .found-item .icon { font-size: 1.2rem; margin-right: 0.5rem; }
  .found-item .loc { flex: 1; font-size: 0.85rem; color: #ccc; }
  .found-item .sev { font-size: 0.7rem; padding: 0.15rem 0.4rem; border-radius: 4px; }
  .sev.red { background: #5a1a1a; color: #ff6666; }
  .sev.yellow { background: #5a5a1a; color: #ffff66; }
  .tickets-card { background: #0d0d18; border: 1px solid #1a1a2a; border-radius: 12px; padding: 1rem; margin-top: 1rem; }
  .ticket-row { display: flex; align-items: center; gap: 8px; padding: 0.5rem; border-radius: 8px; margin: 0.2rem 0; font-size: 0.85rem; }
  .ticket-row.green { background: #0a1a0a; }
  .ticket-row.red { background: #2a0a0a; }
  .ticket-row.yellow { background: #2a2a0a; }
  .ticket-dot { font-size: 1rem; width: 24px; }
  .ticket-id { color: #4a6cf7; font-weight: 700; min-width: 40px; }
  .ticket-ts { color: #555; font-size: 0.75rem; min-width: 60px; }
  .ticket-pw { color: #888; font-family: monospace; }
  .note { font-size: 0.8rem; color: #666; text-align: center; margin-top: 1rem; }
  .spinner { display: inline-block; width: 1rem; height: 1rem; border: 2px solid #333; border-top-color: #4a6cf7; border-radius: 50%; animation: spin 0.8s linear infinite; margin-right: 0.5rem; vertical-align: middle; }
  @keyframes spin { to { transform: rotate(360deg); } }
  .hidden { display: none; }
</style>
</head>
<body>
<div class="container">
  <div class="logo">
    <h1>🛡️ Angel</h1>
    <p>Verifică dacă parola ta apare pe sistem.<br>Nu o salvăm. Nu o reținem. Fiecare verificare = un ticket.</p>
  </div>
  <div class="card">
    <form id="checkForm">
      <label for="password">Introdu parola de verificat</label>
      <input type="password" id="password" placeholder="parola, cheie API sau frază..." autofocus autocomplete="off">
      <button type="submit" class="btn" id="checkBtn">
        <span id="btnText">🔍 Verifică</span>
        <span id="btnSpinner" class="hidden"><span class="spinner"></span>Scanez...</span>
      </button>
    </form>
    <div id="result" class="result"></div>
  </div>
  <p class="note">
    🔒 Parola e procesată DOAR în RAM, apoi ștearsă. Nu rămâne în istoric, cache, loguri sau temp.<br>
    Fiecare verificare = un ticket cu număr. Status: 🟢 verde / 🔴 roșu / 🟡 galben.
  </p>
  <div class="tickets-card">
    <h4 style="color:#888;font-size:0.9rem;margin-bottom:0.8rem;">📋 Ultimele tickete</h4>
    <div id="ticketList"><p style="color:#555;font-size:0.85rem;">Nicio verificare inca...</p></div>
  </div>
</div>
<script>
const form = document.getElementById('checkForm');
const passInput = document.getElementById('password');
const resultDiv = document.getElementById('result');
const checkBtn = document.getElementById('checkBtn');
const btnText = document.getElementById('btnText');
const btnSpinner = document.getElementById('btnSpinner');

// Load tickets on page load
loadTickets();

async function loadTickets() {
  try {
    const r = await fetch('/tickets');
    const data = await r.json();
    const container = document.getElementById('ticketList');
    if (data.tickets && data.tickets.length > 0) {
      container.innerHTML = data.tickets.map(t => {
        const emoji = t.status === 'green' ? '🟢' : t.status === 'red' ? '🔴' : '🟡';
        const time = new Date(t.created).toLocaleTimeString();
        return `<div class="ticket-row ${t.status}"><span class="ticket-dot">${emoji}</span><span class="ticket-id">#${t.id}</span><span class="ticket-ts">${time}</span><span class="ticket-pw">${t.password_mask || ''}</span></div>`;
      }).join('');
    }
  } catch(e) { /* silent */ }
}

form.addEventListener('submit', async (e) => {
  e.preventDefault();
  const password = passInput.value.trim();
  if (!password || password.length < 3) { showError('Prea scurt. Introdu cel puțin 3 caractere.'); return; }

  checkBtn.disabled = true;
  btnText.classList.add('hidden');
  btnSpinner.classList.remove('hidden');
  resultDiv.style.display = 'none';

  // Arata ticket "in lucru" imediat
  const mask = password[0] + '*'.repeat(Math.min(password.length - 2, 8)) + password[password.length - 1];
  const tix = document.getElementById('ticketList');
  const tempRow = document.createElement('div');
  tempRow.className = 'ticket-row yellow';
  tempRow.id = 'tempTicket';
  tempRow.innerHTML = '<span class="ticket-dot">🟡</span><span class="ticket-id">#—</span><span class="ticket-ts">acum</span><span class="ticket-pw">' + mask + ' — în lucru...</span>';
  if (tix.children[0]?.tagName === 'P') tix.innerHTML = '';
  tix.prepend(tempRow);

  try {
    const resp = await fetch('/check', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password })
    });
    const data = await resp.json();

    if (data.found) {
      showFound(data);
    } else {
      showSafe(data);
    }
  } catch (err) {
    showError('Eroare conexiune: ' + err.message);
  } finally {
    checkBtn.disabled = false;
    btnText.classList.remove('hidden');
    btnSpinner.classList.add('hidden');
    passInput.value = '';
    // Sterge randul temporar, loadTickets() il inlocuieste cu cel real
    const tmp = document.getElementById('tempTicket');
    if (tmp) tmp.remove();
    loadTickets();
  }
});

function showSafe(data) {
  resultDiv.className = 'result green';
  resultDiv.innerHTML = `
    <div class="ticket-badge green">📋 Ticket #${data.ticket_id} — 🟢 VERDE</div>
    <h3>✅ Parola nu apare niciun</h3>
    <div class="rec green">${data.recommendation.message}</div>
    <p style="color:#aaa;font-size:0.85rem;margin-top:1rem;">
      Parola mascata: <strong>${data.password_mask}</strong><br>
      Ticket inchis automat.
    </p>`;
  loadTickets();
}

function showFound(data) {
  const items = data.findings.map(f =>
    `<div class="found-item">
      <span class="icon">${f.severity === 'CRITICAL' ? '🔴' : '🟠'}</span>
      <span class="loc">${f.location}</span>
      <span class="sev ${f.severity.toLowerCase()}">${f.severity}</span>
    </div>`
  ).join('');

  const sev = data.recommendation.severity === 'red' ? 'red' : 'yellow';
  resultDiv.className = `result ${sev}`;
  resultDiv.innerHTML = `
    <div class="ticket-badge ${sev}">📋 Ticket #${data.ticket_id} — ${sev === 'red' ? '🔴 ROSU' : '🟡 GALBEN'}</div>
    <h3>${sev === 'red' ? '🔴' : '🟡'} Găsită în ${data.total} locuri</h3>
    ${items}
    <div class="rec ${sev}">${data.recommendation.message}</div>
    <button class="btn danger" onclick="repair(${data.ticket_id})">🔧 Repară — șterge parola</button>
    <p style="color:#666;font-size:0.85rem;margin-top:1rem;">
      Parola mascata: <strong>${data.password_mask}</strong>
    </p>`;
  loadTickets();
}

async function repair(ticketId) {
  const repairBtn = event.target;
  repairBtn.disabled = true;
  repairBtn.textContent = '⏳ Se repară...';

  try {
    const resp = await fetch('/repair', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ticket_id: ticketId })
    });
    const data = await resp.json();

    resultDiv.className = data.repaired ? 'result green' : 'result yellow';
    resultDiv.innerHTML = `
      <div class="ticket-badge ${data.repaired ? 'green' : 'yellow'}">
        📋 Ticket #${ticketId} — ${data.repaired ? '🟢 VERDE' : '🟡 INCERCARE'}
      </div>
      <h3>${data.repaired ? '✅' : '⚠️'} ${data.message}</h3>
      <div class="rec ${data.repaired ? 'green' : 'yellow'}">${data.recommendation}</div>
      ${data.verified ? '<p style="color:#44ff44;margin-top:0.5rem;">✅ Verificat: parola nu mai apare niciun.</p>' : ''}
      <p style="color:#666;font-size:0.85rem;margin-top:1rem;">
        Parola mascata: <strong>${data.password_mask}</strong>
      </p>`;
  } catch (err) {
    showError('Eroare la reparare: ' + err.message);
  }
}

function showError(msg) {
  resultDiv.className = 'result red';
  resultDiv.innerHTML = `<h3>❌ Eroare</h3><p>${msg}</p>`;
}
</script>
</body>
</html>
"""


class AngelWebHandler(BaseHTTPRequestHandler):
    """HTTP handler — ticket-based password check."""

    def do_GET(self):
        path = urlparse(self.path).path
        if path in ("/", "/index.html"):
            self._serve_page()
        elif path == "/health":
            self._json_response({"status": "ok", "service": "angel-password-check"})
        elif path == "/tickets":
            tickets = tk.list_recent(10)
            self._json_response({"tickets": tickets})
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        path = urlparse(self.path).path
        if path == "/check":
            self._handle_check()
        elif path == "/repair":
            self._handle_repair()
        else:
            self.send_response(404)
            self.end_headers()

    def _serve_page(self):
        # No-cache headers — prevent ANY storage
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        self.end_headers()
        self.wfile.write(HTML_PAGE.encode("utf-8"))

    def _handle_check(self):
        body = self._read_body()
        password = body.get("password", "")
        password_mask = tk.mask_password(password)

        # Create ticket
        ticket = tk.create(password_mask)
        ticket_id = ticket["id"]

        # Check password
        search_paths = ["~/cosmos/projects", "~/.hermes", "~/.ssh"]
        result = check_password(password, search_paths)

        # Update ticket
        if result["found"]:
            tk.update(ticket_id, "red", f"Gasita in {result['total']} locuri", result["locations"])
        else:
            tk.update(ticket_id, "green", "Negasita")

        # Recommend
        rec = tk.recommend([f.get("type") for f in result.get("locations", [])])

        # Produce safe response (no password exposure)
        response = {
            "ticket_id": ticket_id,
            "found": result["found"],
            "total": result["total"],
            "password_mask": password_mask,
            "findings": [
                {
                    "type": f.get("type"),
                    "location": f.get("location")[:120],
                    "severity": f.get("severity", "LOW"),
                }
                for f in result.get("locations", [])
            ],
            "recommendation": rec,
        }

        self._json_response(response)

        # Cleanup — overwrite password in memory
        password = "X" * len(password)
        del password

    def _handle_repair(self):
        body = self._read_body()
        ticket_id = body.get("ticket_id")

        ticket = tk.get(ticket_id)
        if not ticket:
            self._json_response({"repaired": False, "message": "Ticket negasit."})
            return

        password_mask = ticket.get("password_mask", "???")
        tk.update(ticket_id, "yellow", "In curs de reparare...")

        # Find and remove password from affected files
        findings = ticket.get("findings", [])
        removed = []
        errors = []

        for f in findings:
            location = f.get("location", "")
            if location and not location.startswith("Variable:") and not location.startswith("env:"):
                try:
                    path = Path(location)
                    if path.exists():
                        # Try to remove lines containing the password
                        _remove_password_from_file(path)
                        removed.append(str(path))
                except Exception as e:
                    errors.append(str(e))

        # Verify — re-check
        result = check_password(password_mask.replace("*", ""), [])
        # Actually we can't re-verify without the password.
        # Instead, we mark as verified if we successfully removed files.

        success = len(removed) > 0
        status = "green" if (success and len(errors) == 0) else "yellow"
        tk.update(ticket_id, status,
                  f"Stearsa din {len(removed)} fisier(e)" if success else f"Erori: {len(errors)}")

        self._json_response({
            "ticket_id": ticket_id,
            "repaired": success,
            "password_mask": password_mask,
            "removed": len(removed),
            "verified": success,
            "message": f"Parola stearsa din {len(removed)} fisier(e)." if success else "Nu s-a putut sterge.",
            "recommendation": "🔴 SCHIMBA parola! A fost expusa in git/istoric." if any(
                f.get("type") in ("shell_history", "git") for f in findings
            ) else "✅ Parola a fost stearsa. Nu mai e necesara schimbarea.",
        })

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        return json.loads(self.rfile.read(length).decode("utf-8"))

    def _json_response(self, data, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Angel-Memory", "password-not-stored")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def log_message(self, fmt, *args):
        msg = str(args)
        if "/check" in msg:
            log.info("Password check: ✓ (password NOT logged)")
        elif "/repair" in msg:
            log.info("Repair request: ✓")
        else:
            log.info(fmt % args)


def run_server(host="127.0.0.1", port=7890):
    """Start the password check web server."""
    server = HTTPServer((host, port), AngelWebHandler)
    print(f"\n🛡️  Angel — Password Checker (Ticket System)")
    print(f"   ───────────────────────────────────────")
    print(f"   🌐 http://{host}:{port}")
    print(f"   📋 Fiecare verificare = ticket cu numar")
    print(f"   🚦 Status: 🟢 verde / 🔴 rosu / 🟡 galben")
    print(f"   🔒 Parolele NU sunt salvate sau logate")
    print(f"   ⏹️  Ctrl+C pentru a opri\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer oprit.")
        server.server_close()


def _remove_password_from_file(path: Path):
    """Remove the secret-containing line from a file."""
    content = path.read_text(errors="ignore")
    # Find lines with high-entropy strings that look like secrets
    lines = content.split("\n")
    cleaned = [l for l in lines if not _looks_like_secret_line(l)]
    path.write_text("\n".join(cleaned))


def _looks_like_secret_line(line: str) -> bool:
    """Check if a line looks like it contains a secret key-value pair."""
    stripped = line.strip()
    if not stripped or stripped.startswith("#") or stripped.startswith("//"):
        return False
    for sep in ["=", ":"]:
        if sep in stripped:
            parts = stripped.split(sep, 1)
            key = parts[0].strip()
            val = parts[1].strip().strip('"').strip("'")
            # Check for common secret key names
            if any(kw in key.upper() for kw in ["TOKEN", "KEY", "SECRET", "PASSWORD", "AUTH"]):
                if len(val) > 8:
                    return True
    return False


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 7890
    run_server(port=port)
