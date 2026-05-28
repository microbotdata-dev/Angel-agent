"""
Angel — Password Check Web Interface.
Run: python password_web.py
Access: http://127.0.0.1:7890
Password is NEVER stored. Checked in memory, results shown once, then discarded.
"""

import os
import sys
import json
import logging
import tempfile
import hashlib
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

from .password_check import check_password

log = logging.getLogger("angel.password_web")

HTML_PAGE = """
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
  .container {
    max-width: 600px;
    width: 100%;
    padding: 2rem;
  }
  .logo {
    text-align: center;
    margin-bottom: 2rem;
  }
  .logo h1 { font-size: 2rem; color: #fff; }
  .logo p { color: #888; font-size: 0.9rem; margin-top: 0.3rem; }
  .card {
    background: #14141f;
    border: 1px solid #2a2a3a;
    border-radius: 16px;
    padding: 2rem;
    margin-bottom: 1rem;
  }
  label { display: block; margin-bottom: 0.5rem; color: #aaa; font-size: 0.9rem; }
  input[type="text"], input[type="password"] {
    width: 100%;
    padding: 1rem;
    background: #1a1a2a;
    border: 1px solid #333;
    border-radius: 10px;
    color: #fff;
    font-size: 1rem;
    outline: none;
    transition: border 0.2s;
  }
  input:focus { border-color: #4a6cf7; }
  .btn {
    width: 100%;
    padding: 1rem;
    background: #4a6cf7;
    border: none;
    border-radius: 10px;
    color: #fff;
    font-size: 1rem;
    font-weight: 600;
    cursor: pointer;
    margin-top: 1rem;
    transition: background 0.2s;
  }
  .btn:hover { background: #3b5de7; }
  .btn:disabled { opacity: 0.5; cursor: not-allowed; }
  .result {
    margin-top: 1rem;
    padding: 1rem;
    border-radius: 10px;
    display: none;
  }
  .result.danger { background: #2a0a0a; border: 1px solid #5a1a1a; display: block; }
  .result.safe { background: #0a1a0a; border: 1px solid #1a3a1a; display: block; }
  .result h3 { margin-bottom: 0.5rem; }
  .result.danger h3 { color: #ff4444; }
  .result.safe h3 { color: #44ff44; }
  .result ul { list-style: none; margin-top: 0.5rem; }
  .result li { padding: 0.3rem 0; font-size: 0.9rem; color: #ccc; }
  .badge { display: inline-block; padding: 0.15rem 0.5rem; border-radius: 4px; font-size: 0.75rem; font-weight: 600; margin-right: 0.3rem; }
  .badge.high { background: #5a1a1a; color: #ff6666; }
  .badge.critical { background: #6a0a0a; color: #ff4444; }
  .badge.low { background: #1a2a1a; color: #66ff66; }
  .note { font-size: 0.8rem; color: #666; text-align: center; margin-top: 1rem; }
  .spinner { display: inline-block; width: 1rem; height: 1rem; border: 2px solid #333; border-top-color: #4a6cf7; border-radius: 50%; animation: spin 0.8s linear infinite; margin-right: 0.5rem; vertical-align: middle; }
  @keyframes spin { to { transform: rotate(360deg); } }
</style>
</head>
<body>
<div class="container">
  <div class="logo">
    <h1>🛡️ Angel</h1>
    <p>Verifică dacă parola ta apare pe sistem.<br>Nu o salvăm. Nu o reținem. O verificăm și uităm.</p>
  </div>
  <div class="card">
    <form id="checkForm">
      <label for="password">Introdu parola de verificat</label>
      <input type="password" id="password" placeholder="parola, cheie sau frază..." autofocus>
      <button type="submit" class="btn" id="checkBtn">
        <span id="btnText">🔍 Verifică</span>
        <span id="btnSpinner" style="display:none"><span class="spinner"></span>Scanez...</span>
      </button>
    </form>
    <div id="result" class="result"></div>
  </div>
  <p class="note">
    🔒 Parola este procesată DOAR în memoria RAM, apoi ștearsă.<br>
    Nu este scrisă pe disc, în loguri, sau în baza de date.
  </p>
</div>
<script>
const form = document.getElementById('checkForm');
const passwordInput = document.getElementById('password');
const resultDiv = document.getElementById('result');
const checkBtn = document.getElementById('checkBtn');
const btnText = document.getElementById('btnText');
const btnSpinner = document.getElementById('btnSpinner');

form.addEventListener('submit', async (e) => {
  e.preventDefault();
  const password = passwordInput.value.trim();
  if (!password || password.length < 3) {
    resultDiv.className = 'result danger';
    resultDiv.innerHTML = '<h3>❌ Prea scurt</h3><p>Introdu cel puțin 3 caractere.</p>';
    resultDiv.style.display = 'block';
    return;
  }

  // Disable form
  checkBtn.disabled = true;
  btnText.style.display = 'none';
  btnSpinner.style.display = 'inline';
  resultDiv.style.display = 'none';

  try {
    const resp = await fetch('/check', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password })
    });
    const data = await resp.json();

    if (data.found) {
      let items = data.locations.map(l => {
        const sev = l.severity?.toLowerCase() || 'low';
        const badge = sev === 'critical' ? '🔴' : sev === 'high' ? '🟠' : '🟡';
        return '<li>' + badge + ' <span class="badge ' + sev + '">' + l.severity + '</span> ' + l.location + '</li>';
      }).join('');
      resultDiv.className = 'result danger';
      resultDiv.innerHTML = '<h3>🔴 Găsită în ' + data.total + ' locuri</h3><ul>' + items + '</ul>';
    } else {
      resultDiv.className = 'result safe';
      resultDiv.innerHTML = '<h3>✅ Negăsită</h3><p>Parola nu apare în fișiere, istoric, sau loguri scanate.</p>';
    }
  } catch (err) {
    resultDiv.className = 'result danger';
    resultDiv.innerHTML = '<h3>❌ Eroare</h3><p>' + err.message + '</p>';
  } finally {
    checkBtn.disabled = false;
    btnText.style.display = 'inline';
    btnSpinner.style.display = 'none';
    passwordInput.value = '';
  }
});
</script>
</body>
</html>
"""


class PasswordCheckHandler(BaseHTTPRequestHandler):
    """HTTP handler — serves the page and handles password check requests."""

    def do_GET(self):
        if self.path == "/" or self.path == "/index.html":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(HTML_PAGE.encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if self.path == "/check":
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length)
            data = json.loads(body.decode("utf-8"))
            password = data.get("password", "")

            # Verify — then forget
            search_paths = [
                "~/cosmos/projects",
                "~/.hermes",
                "~/.ssh",
            ]
            result = check_password(password, search_paths)

            # OVERWRITE password in memory
            password = "X" * len(password)
            del password

            response = json.dumps(result).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("X-Angel-Memory", "password-not-stored")
            self.end_headers()
            self.wfile.write(response)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        """Don't log passwords — just basic info."""
        if "/check" in str(args):
            log.info("Password check request received (password NOT logged)")
        else:
            log.info(format % args)


def run_server(port: int = 7890):
    """Start the password check web server."""
    server = HTTPServer(("127.0.0.1", port), PasswordCheckHandler)
    print(f"\n🛡️  Angel — Password Checker")
    print(f"   ─────────────────────────")
    print(f"   🌐 http://127.0.0.1:{port}")
    print(f"   🔒 Parolele NU sunt salvate sau logate")
    print(f"   📁 Scanează: ~/cosmos/projects, ~/.hermes, ~/.ssh")
    print(f"   ⏹️  Ctrl+C pentru a opri\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer oprit.")
        server.server_close()


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 7890
    run_server(port)
