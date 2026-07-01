"""
web_ui.py — Local HTTP server surface for PromptGuard.

Serves a single-page HTML/CSS/JS interface at GET / and accepts
POST /scan requests that delegate to scanner.scan(). Built entirely
on Python's standard library http.server module — no third-party
packages, no CDN resources, no outbound network calls.

Usage:
    python web_ui.py [--port PORT]

Routes:
    GET  /      Serve the inline single-page application.
    POST /scan  Accept JSON body {"text": "..."}, return JSON ScanResult.
"""

import argparse
import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

import scanner


class PromptGuardHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the PromptGuard web UI."""

    def do_GET(self):
        """Handle GET requests — serve the single-page HTML application."""
        if self.path == "/":
            page = _build_html_page()
            body = page.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self._send_error(404, "Not Found")

    def do_POST(self):
        """Handle POST requests — route POST /scan."""
        if self.path == "/scan":
            self._handle_scan()
        else:
            self._send_error(404, "Not Found")

    def _handle_scan(self):
        """Parse JSON body, call scanner.scan(), return JSON ScanResult."""
        try:
            length = int(self.headers.get("Content-Length", 0))
            raw_body = self.rfile.read(length)
            body = json.loads(raw_body.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
            self._send_error(400, "Invalid JSON")
            return

        if "text" not in body:
            self._send_error(400, "Missing 'text' field")
            return

        try:
            result = scanner.scan(body["text"])
        except Exception:
            self._send_error(500, "Internal scan error")
            return

        data = {
            "verdict": result.verdict,
            "findings": [
                {
                    "type": f.type,
                    "severity": f.severity,
                    "start": f.start,
                    "end": f.end,
                    "masked_preview": f.masked_preview,
                }
                for f in result.findings
            ],
            "redacted_text": result.redacted_text,
        }
        self._send_json(200, data)

    def _send_json(self, status: int, data: dict):
        """Serialize data to JSON and send as HTTP response."""
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_error(self, status: int, message: str):
        """Send a plain-text error response."""
        body = message.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        """Override to suppress default request logging to stdout."""
        pass


def _build_html_page() -> str:
    """Return the inline HTML/CSS/JS single-page application as a string."""
    return """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>PromptGuard</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: system-ui, -apple-system, sans-serif;
      background: #f5f5f5;
      color: #222;
      padding: 2rem;
      max-width: 900px;
      margin: 0 auto;
    }
    h1 { font-size: 1.8rem; margin-bottom: 0.25rem; }
    .subtitle { color: #666; margin-bottom: 1.5rem; font-size: 0.95rem; }
    label { display: block; font-weight: 600; margin-bottom: 0.4rem; }
    textarea {
      width: 100%;
      height: 160px;
      padding: 0.75rem;
      border: 1px solid #ccc;
      border-radius: 6px;
      font-size: 0.95rem;
      font-family: monospace;
      resize: vertical;
    }
    button {
      margin-top: 0.75rem;
      padding: 0.6rem 1.4rem;
      background: #2563eb;
      color: #fff;
      border: none;
      border-radius: 6px;
      font-size: 1rem;
      cursor: pointer;
    }
    button:hover { background: #1d4ed8; }
    button:disabled { background: #93c5fd; cursor: not-allowed; }
    .result-section { margin-top: 2rem; }
    .verdict-row { display: flex; align-items: center; gap: 1rem; margin-bottom: 1rem; }
    .verdict-label { font-weight: 600; font-size: 1rem; }
    .badge {
      display: inline-block;
      padding: 0.25rem 0.75rem;
      border-radius: 9999px;
      font-weight: 700;
      font-size: 0.9rem;
      letter-spacing: 0.05em;
      text-transform: uppercase;
    }
    .badge-block { background: #ef4444; color: #fff; }
    .badge-warn  { background: #f59e0b; color: #fff; }
    .badge-safe  { background: #22c55e; color: #fff; }
    .badge-none  { background: #e5e7eb; color: #6b7280; }
    h2 { font-size: 1.1rem; margin-bottom: 0.5rem; margin-top: 1.25rem; }
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 0.9rem;
    }
    th {
      text-align: left;
      background: #e5e7eb;
      padding: 0.5rem 0.75rem;
      font-weight: 600;
    }
    td { padding: 0.45rem 0.75rem; border-bottom: 1px solid #e5e7eb; }
    tr:last-child td { border-bottom: none; }
    .sev-high   { color: #dc2626; font-weight: 600; }
    .sev-medium { color: #d97706; font-weight: 600; }
    .empty-row td { color: #9ca3af; font-style: italic; }
    pre#redacted-output {
      background: #1e293b;
      color: #e2e8f0;
      padding: 1rem;
      border-radius: 6px;
      font-size: 0.88rem;
      white-space: pre-wrap;
      word-break: break-all;
      min-height: 4rem;
    }
    .error-msg { color: #dc2626; font-size: 0.9rem; margin-top: 0.5rem; }
  </style>
</head>
<body>
  <h1>&#128737; PromptGuard</h1>
  <p class="subtitle">Local privacy firewall — scan your prompt before sending it to an AI service.</p>

  <label for="input-text">Prompt text</label>
  <textarea id="input-text" placeholder="Paste your prompt here..."></textarea>
  <button id="scan-btn" onclick="runScan()">Scan</button>
  <p id="error-msg" class="error-msg" style="display:none"></p>

  <div class="result-section" id="result-section" style="display:none">
    <div class="verdict-row">
      <span class="verdict-label">Verdict:</span>
      <span id="verdict-badge" class="badge badge-none">—</span>
    </div>

    <h2>Findings</h2>
    <table id="findings-table">
      <thead>
        <tr><th>Type</th><th>Severity</th><th>Masked Preview</th></tr>
      </thead>
      <tbody id="findings-body"></tbody>
    </table>

    <h2>Redacted Text</h2>
    <pre id="redacted-output"></pre>
  </div>

  <script>
    async function runScan() {
      const btn = document.getElementById('scan-btn');
      const errMsg = document.getElementById('error-msg');
      const text = document.getElementById('input-text').value;

      btn.disabled = true;
      errMsg.style.display = 'none';

      try {
        const resp = await fetch('/scan', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ text })
        });

        if (!resp.ok) {
          const msg = await resp.text();
          throw new Error(`Server error ${resp.status}: ${msg}`);
        }

        const data = await resp.json();
        renderResult(data);
      } catch (err) {
        errMsg.textContent = err.message;
        errMsg.style.display = 'block';
      } finally {
        btn.disabled = false;
      }
    }

    function renderResult(data) {
      document.getElementById('result-section').style.display = 'block';

      // Verdict badge
      const badge = document.getElementById('verdict-badge');
      badge.textContent = data.verdict;
      badge.className = 'badge';
      if (data.verdict === 'BLOCK') badge.classList.add('badge-block');
      else if (data.verdict === 'WARN') badge.classList.add('badge-warn');
      else badge.classList.add('badge-safe');

      // Findings table
      const tbody = document.getElementById('findings-body');
      tbody.innerHTML = '';
      if (data.findings.length === 0) {
        const tr = document.createElement('tr');
        tr.className = 'empty-row';
        tr.innerHTML = '<td colspan="3">No findings</td>';
        tbody.appendChild(tr);
      } else {
        data.findings.forEach(f => {
          const tr = document.createElement('tr');
          const sevClass = f.severity === 'HIGH' ? 'sev-high' : 'sev-medium';
          tr.innerHTML = `<td>${escHtml(f.type)}</td>` +
                         `<td class="${sevClass}">${escHtml(f.severity)}</td>` +
                         `<td><code>${escHtml(f.masked_preview)}</code></td>`;
          tbody.appendChild(tr);
        });
      }

      // Redacted text
      document.getElementById('redacted-output').textContent = data.redacted_text;
    }

    function escHtml(s) {
      return String(s)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
    }

    // Allow Ctrl+Enter to submit
    document.getElementById('input-text').addEventListener('keydown', function(e) {
      if (e.ctrlKey && e.key === 'Enter') runScan();
    });
  </script>
</body>
</html>"""


def main():
    """Parse arguments, validate port, and start the HTTP server."""
    parser = argparse.ArgumentParser(description="PromptGuard Web UI")
    parser.add_argument("--port", type=int, default=8080,
                        help="Port to listen on (1–65535, default: 8080)")
    args = parser.parse_args()

    if not (1 <= args.port <= 65535):
        print(f"error: --port must be between 1 and 65535, got {args.port}", file=sys.stderr)
        sys.exit(1)

    server = HTTPServer(("localhost", args.port), PromptGuardHandler)
    print(f"PromptGuard running at http://localhost:{args.port}/", file=sys.stderr)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
